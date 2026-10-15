#!/usr/bin/env python3
"""ssh-mux：保持 SSH 连接，供后续命令和文件传输使用。

两种连接模式：
- `jump`：直连或通过标准跳板机，使用 `ControlMaster` 让多个命令共用连接。
- `shell`：通过堡垒机的交互式终端登录，由后台进程保持登录状态。

主机信息保存在 INI 配置文件中，命令行通过主机别名选择目标。
`shell` 模式使用 `pty`（伪终端）模拟终端输入输出，
命令行工具通过 Unix 套接字与后台进程通信。
"""

import argparse
import configparser
import fcntl
import glob
import hashlib
import importlib.util
import json
import os
import pty
import random
import re
import select
import shlex
import shutil
import signal
import socket
import stat
import string
import struct
import subprocess
import sys
import termios
import time

CONFIG_PATH = os.environ.get(
    "SSH_MUX_CONFIG", os.path.expanduser("~/.config/ssh-mux/hosts.conf")
)
SOCKET_DIR = os.environ.get("SSH_MUX_SOCKET_DIR", "/tmp")
try:
    PERSIST = int(os.environ.get("SSH_MUX_PERSIST", "600"))  # 空闲自动退出秒数
except ValueError:
    print(
        f"ssh-mux: SSH_MUX_PERSIST 必须是整数秒数: {os.environ.get('SSH_MUX_PERSIST')!r}",
        file=sys.stderr,
    )
    sys.exit(1)
AUTH_STEP_TIMEOUT = 30  # 每一步登录提示的最长等待
DAEMON_BOOT_TIMEOUT = 90  # 等待后台进程完成登录的基准秒数（短链路）
BOOT_BASE_TIMEOUT = 30  # 进程启动与套接字准备的耗时估算
BOOT_PER_HOP_TIMEOUT = 45  # 每一步登录（认证应答与终端就绪）的串行耗时估算
BOOT_PER_PROXY_TIMEOUT = 60  # 每个远端代理程序准备（探测、传送程序、校验）的耗时估算
XFER_TIMEOUT = 3600  # 每两台主机之间传输文件的超时秒数
DEBUG_PTY = bool(
    os.environ.get("SSH_MUX_DEBUG")
)  # 设为非空值后，将终端收到的数据写入后台进程日志

# 识别 `pty` 输出里的各类提示
PW_RX = re.compile(rb"(?i)password[^:\n]{0,40}:\s*$")
LOGIN_RX = re.compile(rb"(?i)login(\s+as)?:\s*$")
YESNO_RX = re.compile(rb"\(yes/no[^)]*\)\s*\??\s*$")
FAIL_RX = re.compile(
    rb"Permission denied|HOST IDENTIFICATION HAS CHANGED|Connection refused|Connection timed out"
)
ANSI_RX = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def die(msg):
    print(f"ssh-mux: {msg}", file=sys.stderr)
    sys.exit(1)


def parse_int(value, what):
    """解析用户输入的整数，失败时说明是哪个值、为什么错"""
    try:
        return int(value)
    except (TypeError, ValueError):
        die(f"{what} 必须是整数: {value!r}")


def rand_token(n=8):
    return "".join(random.choices(string.ascii_lowercase + string.digits, k=n))


def tail(buf, n=300):
    return buf[-n:].replace(b"\r", b"").decode("utf-8", "replace").strip()


def clean_output(data):
    data = ANSI_RX.sub(b"", data)
    text = data.replace(b"\r\n", b"\n").replace(b"\r", b"").decode("utf-8", "replace")
    if text.startswith("\n"):
        text = text[1:]
    return text


def runtime_dir():
    """所有连接文件放在当前用户独占的目录中，拒绝符号链接和开放权限。"""
    path = os.path.join(SOCKET_DIR, f"ssh-mux-{os.getuid()}")
    os.makedirs(SOCKET_DIR, exist_ok=True)
    try:
        os.mkdir(path, 0o700)
    except FileExistsError:
        pass
    info = os.lstat(path)
    if (
        not stat.S_ISDIR(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) != 0o700
    ):
        die(f"运行目录必须属于当前用户、权限为 700 且不能是符号链接: {path}")
    return path


# ---------- 配置 ----------


class Host:
    def __init__(self, alias, sec):
        self.alias = alias
        self.host = sec.get("host", "").strip()
        self.port = parse_int(sec.get("port", "22"), f"[{alias}] 的 `port`")
        self.user = sec.get("user", "").strip() or os.environ.get("USER") or "root"
        self.password = sec.get("password", "")
        self.via = sec.get("via", "").strip() or None
        self.via_mode = sec.get("via_mode", "jump").strip() or "jump"
        self.routing = sec.get("routing", "").strip()
        # 逐段代理字段：控制“上一节点 → 该主机”这一段
        self.proxy = sec.get("proxy", "").strip()
        self.proxy_host = sec.get("proxy_host", "").strip()
        self.proxy_port = sec.get("proxy_port", "").strip()
        self.proxy_user = sec.get("proxy_user", "")
        self.proxy_password = sec.get("proxy_password", "")

    def addr(self):
        return f"{self.user}@{self.host}:{self.port}"

    def has_proxy_fields(self):
        return bool(
            self.proxy
            or self.proxy_host
            or self.proxy_port
            or self.proxy_user
            or self.proxy_password
        )


def load_config():
    if not os.path.isfile(CONFIG_PATH):
        die(f"配置文件不存在: {CONFIG_PATH}(格式参考同目录的 `hosts.conf.example`)")
    cp = configparser.ConfigParser(
        interpolation=None
    )  # 禁用变量替换，保留密码中的 % 字符
    cp.read(CONFIG_PATH)
    return cp


def valid_alias(alias):
    """别名会拼进 socket/日志/pid 文件名，禁止路径相关字符"""
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", alias) or ".." in alias:
        die(
            f"别名只能包含字母、数字、_、-、.(最长 32,不能以 . 开头,不能含 ..): {alias!r}"
        )
    return alias


def get_host(cp, alias):
    valid_alias(alias)
    if not cp.has_section(alias):
        known = ", ".join(cp.sections()) or "(空)"
        die(f"配置中没有 [{alias}],现有: {known}")
    h = Host(alias, cp[alias])
    if not h.host:
        die(f"[{alias}] 缺少 `host` 字段")
    return h


def host_mode(h):
    """`jump` = `ControlMaster` 多路复用;`shell` = `pty` 会话链(堡垒机)"""
    if not h.via:
        return "jump"
    return h.via_mode


def build_chain(cp, alias):
    """返回 [最外层, ..., 目标] 的 `via` 链,检测循环引用"""
    names = []
    cur = alias
    while cur:
        if cur in names:
            die(f"`via` 配置存在循环: {' -> '.join(names + [cur])}")
        names.append(cur)
        cur = get_host(cp, cur).via
    return [get_host(cp, n) for n in reversed(names)]


# ---------- 逐段代理规划 ----------

# 地址中的空白、回车、换行、NUL、% 会改变 shell 命令或协议文本的含义，一律拒绝
_PROXY_BAD_ADDR = frozenset(" \t\r\n\x00%")


class ProxySpec:
    """一段连接的有效代理：类型、地址、端口和可选凭据。"""

    def __init__(self, kind, host, port, user=None, password=None):
        self.kind = kind
        self.host = host
        self.port = port
        self.user = user
        self.password = password

    def to_dict(self):
        return {
            "type": self.kind,
            "host": self.host,
            "port": self.port,
            "user": self.user,
            "password": self.password,
        }


def proxy_addr_ok(value, what):
    """代理与目标地址作为字面量传递，不依赖 %h/%p 展开。"""
    if not value:
        raise ValueError(f"{what}地址为空")
    if any(c in _PROXY_BAD_ADDR for c in value):
        raise ValueError(f"{what}地址含空白、回车、换行、NUL 或 % 等非法字符")
    if not all(ord(c) < 128 for c in value):
        raise ValueError(f"{what}地址含非 ASCII 字符，请改用 Punycode 或地址字面量")
    return value


def proxy_port_ok(value, what):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ValueError(f"{what}端口必须是整数: {value!r}")
    if not 1 <= port <= 65535:
        raise ValueError(f"{what}端口超出 1-65535 范围: {value!r}")
    return port


def make_proxy(kind, host, port, user, password):
    """校验一段显式代理配置；任何问题都抛出 ValueError，由调用方拒绝连接。"""
    if kind not in ("http", "socks5"):
        raise ValueError(f"未知代理类型或不支持代理链表达式: {kind!r}")
    host = proxy_addr_ok(host, "代理")
    if not port and port != 0:
        raise ValueError(f"代理 {kind} 缺少 `proxy_port`")
    port = proxy_port_ok(port, "代理")
    if user:
        if kind == "http":
            if any(c in user for c in (":", "\r", "\n", "\x00")):
                raise ValueError("代理用户名包含冒号、回车、换行或空字节")
        else:
            ulen = len(user.encode("utf-8"))
            if (
                not 1 <= ulen <= 255
                or not 1 <= len((password or "").encode("utf-8")) <= 255
            ):
                raise ValueError("SOCKS5 代理用户名和密码各须为 1-255 字节")
    elif password:
        raise ValueError("只有代理密码而没有用户名")
    return ProxySpec(kind, host, port, user or None, password)


def parse_default_proxy(raw):
    """解析 `SSH_MUX_PROXY`：只接受不含用户信息的 http://主机:端口 或 socks5://主机:端口。"""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit(raw.strip())
    except ValueError:
        raise ValueError("SSH_MUX_PROXY 无法解析")
    if parts.scheme not in ("http", "socks5"):
        raise ValueError("SSH_MUX_PROXY 协议必须是 http 或 socks5")
    if parts.username is not None or parts.password is not None:
        raise ValueError("SSH_MUX_PROXY 不能包含用户名或密码")
    if parts.path not in ("", "/") or parts.query or parts.fragment:
        raise ValueError("SSH_MUX_PROXY 格式应为 协议://主机:端口")
    host = parts.hostname or ""
    try:
        port = parts.port
    except ValueError:
        port = None
    if port is None:
        raise ValueError("SSH_MUX_PROXY 缺少端口或端口非法，格式应为 协议://主机:端口")
    return make_proxy(parts.scheme, host, port, None, None)


def effective_proxy(entry, origin, env=None, strict=True):
    """计算一段连接的有效代理。`entry` 是该段目标条目（用户名路由时为堡垒机），
    `origin` 是段起点（`@local` 或上一节点别名）。

    逐段优先级：`proxy=direct` 忽略同条目其余代理字段；显式 `http`/`socks5`
    使用显式配置；完全没有代理字段时，仅起点为 `@local` 的段读取
    `SSH_MUX_PROXY`；其他段默认直连。配置错误一律拒绝，不得直连。
    """
    env = os.environ if env is None else env
    try:
        if entry.proxy:
            if entry.proxy == "direct":
                return None  # 显式直连忽略同条目其余代理字段
            return make_proxy(
                entry.proxy,
                entry.proxy_host,
                entry.proxy_port,
                entry.proxy_user or None,
                entry.proxy_password or None,
            )
        if (
            entry.proxy_host
            or entry.proxy_port
            or entry.proxy_user
            or entry.proxy_password
        ):
            raise ValueError(f"[{entry.alias}] 只有 proxy_* 字段而没有 `proxy`")
        if origin == "@local":
            raw = env.get("SSH_MUX_PROXY", "").strip()
            if raw:
                return parse_default_proxy(raw)
        return None
    except ValueError as exc:
        if strict:
            die(f"代理配置错误（{origin} → {entry.alias}）: {exc}")
        return None


class Segment:
    """一段正向连接：起点、实际监听端点、逻辑目标、有效代理和未使用原因。"""

    def __init__(self, origin, entry, target, proxy, unused=None):
        self.origin = origin  # "@local" 或上一节点别名
        self.entry = entry  # 实际连接的 Host（用户名路由时是堡垒机）
        self.target = target  # 逻辑目标 Host
        self.proxy = proxy  # ProxySpec 或 None
        self.unused = unused  # 目标条目的代理未使用原因（如有）


def plan_segments(cp, alias, env=None, strict=True):
    """沿 `via` 链逐段规划到 `alias` 的正向连接。"""
    chain = build_chain(cp, alias)
    hops = shell_hops(chain)
    segments = []
    origin = "@local"
    for h in hops:
        entry, unused = h, None
        if h.via:
            via = get_host(cp, h.via)
            if via.routing == "username":
                # 用户名路由：入口段取堡垒机的代理和监听地址；
                # 目标上的 http/socks5 代理标为未使用，proxy=direct 不提示
                entry = via
                if h.proxy and h.proxy != "direct":
                    unused = (
                        f"[{h.alias}] 的代理配置未使用：本机实际连接用户名路由堡垒机 "
                        f"[{via.alias}]，请把代理配置在 [{via.alias}] 上"
                    )
        proxy = effective_proxy(entry, origin, env=env, strict=strict)
        segments.append(Segment(origin, entry, h, proxy, unused))
        origin = h.alias
    return segments


def proxy_identity_records(cp, alias, env=None):
    """路径上各段有效代理的有序记录：起点、实际端点、类型、地址、端口。

    不含用户名、密码、配置来源或临时路径；未使用字段不进入记录。
    """
    records = []
    for seg in plan_segments(cp, alias, env=env, strict=False):
        if seg.proxy:
            records.append(
                [
                    seg.origin,
                    seg.entry.alias,
                    seg.proxy.kind,
                    seg.proxy.host,
                    seg.proxy.port,
                ]
            )
    return records


def local_jump_prefix(hops):
    """开头连续可由本机 `jump_connect()` 建立的标准跳板路径长度。"""
    count = 0
    for i, h in enumerate(hops):
        if i == 0:
            if h.via:
                break  # 用户名路由入口不作为标准跳板路径的一部分
        elif h.via != hops[i - 1].alias or h.via_mode != "jump":
            break
        count += 1
    return count


def describe_proxy(cp, h):
    """`list`/`status` 的代理显示：类型、地址和段归属，隐藏用户名密码。

    不解析 `SSH_MUX_PROXY`，非法环境变量不影响列出主机。
    """
    if not h.has_proxy_fields():
        return ""
    if h.alias == "local":
        return "  proxy=未使用（[local] 的代理字段不控制本机出站）"
    if h.via:
        try:
            via = get_host(cp, h.via)
        except BaseException:
            via = None
        if via is not None and via.routing == "username":
            if h.proxy == "direct":
                return "  proxy=direct"
            return f"  proxy=未使用（用户名路由入口是堡垒机 [{h.via}]）"
    if not h.proxy:
        return "  proxy=无效（只有 proxy_* 字段而没有 proxy）"
    if h.proxy == "direct":
        return "  proxy=direct"
    if h.proxy in ("http", "socks5"):
        origin = h.via or "@local"
        addr = f"{h.proxy}://{h.proxy_host or '?'}:{h.proxy_port or '?'}"
        return f"  proxy={addr}（{origin} → {h.alias}）"
    return f"  proxy=无效（未知类型 {h.proxy!r}）"


def shell_hops(chain):
    """跳过 `routing=username` 的堡垒机：这类堡垒机直接转到目标，不提供独立终端"""
    hops = []
    for i, h in enumerate(chain):
        if h.routing == "username":
            if h.via:
                die(f"[{h.alias}] `routing=username` 的堡垒机不支持再配置 `via`")
            if i == len(chain) - 1:
                die(f"目标主机 [{h.alias}] 不能配置 `routing`")
            continue
        if h.routing:
            die(f"[{h.alias}] `routing` 只支持 `username`")
        hops.append(h)
    return hops


def ssh_step(cp, h):
    """登录主机 `h` 的 ssh 参数和认证序列 [(提示正则, 应答)]"""
    base = ["ssh", "-o", "StrictHostKeyChecking=no"]
    if h.via:
        via = get_host(cp, h.via)
        if via.routing == "username":
            # 用户名路由堡垒机:登录名 <堡垒机账号>/<目标IP>/any
            # 先填写堡垒机密码，再根据目标机的提示填写用户名和密码
            args = base + ["-p", str(via.port), f"{via.user}/{h.host}/any@{via.host}"]
            auth = [(PW_RX, via.password), (LOGIN_RX, h.user), (PW_RX, h.password)]
            return args, auth
    args = base + ["-p", str(h.port), f"{h.user}@{h.host}"]
    auth = [(PW_RX, h.password)]
    return args, auth


def build_shell_plan(cp, alias):
    """`shell` 模式的登录步骤：本机发起首次登录，后续在上一台主机的终端中执行。

    每步为 `(args, auth)` 或 `(args, auth, meta)`。meta 可能的键：
    - `jump_socket`：经本机已建立的标准跳板控制连接打开终端，值是末节点别名。
    - `local_proxy`：本机首段代理，值含 `proxy` 和 `target`，凭据文件由守护进程准备。
    - `prepare`：远端终端段代理，值含 `origin`、`proxy`、`target`，登录时在段起点准备。
    - `unused_hint`：目标条目的代理未使用原因。
    整条路径无代理时保持原有执行计划。
    """
    chain = build_chain(cp, alias)
    hops = shell_hops(chain)
    if not hops:
        die(f"[{alias}] 连接链为空")
    segments = plan_segments(cp, alias)
    any_proxy = any(seg.proxy for seg in segments)
    # 使用代理的混合登录链：开头连续的标准跳板在本机建立，再开终端
    prefix = local_jump_prefix(hops) if any_proxy else 0
    steps = []
    if prefix:
        last = hops[prefix - 1]
        args = [
            "ssh",
            "-tt",
            "-o",
            "StrictHostKeyChecking=no",
            "-o",
            f"ControlPath={jump_sock_file(cp, last)}",
            "-p",
            str(last.port),
            f"{last.user}@{last.host}",
        ]
        steps.append((args, [], {"jump_socket": last.alias}))
        start = prefix
    else:
        args, auth = ssh_step(cp, hops[0])
        meta = {}
        seg = segments[0]
        if seg.unused:
            meta["unused_hint"] = seg.unused
        if seg.proxy:
            meta["local_proxy"] = {
                "proxy": seg.proxy.to_dict(),
                "target": {"host": seg.entry.host, "port": seg.entry.port},
            }
        steps.append((args, auth, meta))
        start = 1
    for i in range(start, len(hops)):
        h = hops[i]
        args, auth = ssh_step(cp, h)
        seg = segments[i]
        meta = {}
        if seg.unused:
            meta["unused_hint"] = seg.unused
        if seg.proxy:
            meta["prepare"] = {
                "origin": seg.origin,
                "proxy": seg.proxy.to_dict(),
                "target": {"host": seg.entry.host, "port": seg.entry.port},
            }
        steps.append((args, auth, meta))
    return steps


# ---------- `shell` 模式:`pty` 会话 ----------

# 独立模块也由远端执行器使用；按文件位置加载，允许从任意工作目录调用。
_pty_spec = importlib.util.spec_from_file_location(
    "ssh_mux_pty",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_pty.py"),
)
_pty_module = importlib.util.module_from_spec(_pty_spec)
_pty_spec.loader.exec_module(_pty_module)
PtySession = _pty_module.PtySession

_transfer_spec = importlib.util.spec_from_file_location(
    "ssh_mux_transfer",
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_transfer.py"),
)
_transfer_module = importlib.util.module_from_spec(_transfer_spec)
_transfer_spec.loader.exec_module(_transfer_module)


# ---------- 远端代理程序准备与资源归属 ----------


class ProxySetupError(Exception):
    """远端运行条件不满足或准备失败；错误只含节点和原因，不含秘密。"""


class RemoteJanitor:
    """登记远端代理资源（节点别名、远端目录、重建材料），按持有者隔离清理。"""

    def __init__(self):
        self.by_holder = {}
        # 已成功清理的持有者：区分"从未登记"与"已清理"，重复清理不再告警
        self.cleaned = set()

    def register(self, holder, node, remote_dir, materials=None):
        """materials 是断线重建所需材料：该段的 proxy 字典与目标 host/port。"""
        self.cleaned.discard(holder)
        self.by_holder.setdefault(holder, []).append((node, remote_dir, materials))

    def pop(self, holder):
        return self.by_holder.pop(holder, [])

    def known(self, holder):
        """持有者登记过或已成功清理过都算已知；守护进程重启后两者皆空。"""
        return holder in self.by_holder or holder in self.cleaned


def proxy_from_dict(data):
    """从 JSON 字典还原并校验代理配置；错误信息不含凭据内容。"""
    if not isinstance(data, dict):
        raise ValueError("代理配置必须是对象")
    return make_proxy(
        data.get("type"),
        data.get("host"),
        data.get("port"),
        data.get("user") or None,
        data.get("password"),
    )


REMOTE_PROXY_DIR = "/tmp/.ssh_mux_px_"


def remote_cleanup_command(remote_dir):
    """先结束所属辅助进程，再删除所属目录。

    kill 前校验进程身份（命令行含 ssh_proxy.py），避免 PID 复用误杀；
    `ps` 不可用时退化为不 kill，代理进程随连接结束自行退出。
    """
    q = shlex.quote(remote_dir)
    return (
        "pid=$(cat {q}/proxy.pid 2>/dev/null); "
        'if ps -p "$pid" -o args= 2>/dev/null | grep -q "ssh_proxy[.]py"; '
        'then kill "$pid" 2>/dev/null; fi; '
        "sleep 0.2; rm -rf -- {q}"
    ).format(q=q)


def prepare_remote_proxy(
    sess, node_alias, proxy_dict, target, holder, janitor, log, fixed_dir=None
):
    """在 `sess` 当前所在节点准备代理辅助程序和该段配置。

    先探测 Python 3.4+ 与所需标准库；不满足时报出节点和原因，不安装软件。
    程序与含凭据的配置都经私有输入通道发送，命令行不包含秘密。
    返回远端目录和启动命令；资源连同重建材料（proxy 字典、目标）登记在
    `holder` 名下。指定 `fixed_dir` 时重建到原目录（断线恢复后重发的命令
    仍引用旧路径）；同名目录可能因仅网络闪断而仍存在，幂等覆盖不报错。
    """
    probe = "command -v python3 >/dev/null 2>&1 && python3 -c " + shlex.quote(
        "import sys,socket,select,json,base64,os\n"
        "sys.exit(0 if sys.version_info >= (3, 4) else 1)"
    )
    out, code = sess.exec(probe, 30)
    if code != 0:
        raise ProxySetupError(
            f"节点 {node_alias} 缺少兼容的 Python 3.4+ 或标准库，"
            "无法准备代理程序；不会自动安装软件"
        )
    if fixed_dir is None:
        directory = REMOTE_PROXY_DIR + rand_token()
        make_dir = "umask 077; mkdir -m 700 -- {0} && test -w {0}"
    else:
        directory = fixed_dir
        # 重建到原目录：目录可能已存在，存在时只修正权限并确认可写；
        # 拒绝符号链接——远端命令行与 ps 会暴露该路径，防同机用户预置链接
        make_dir = (
            "umask 077; (mkdir -m 700 -- {0} 2>/dev/null"
            " || (test ! -L {0} && test -d {0}))"
            " && chmod 700 -- {0} && test -w {0}"
        )
    out, code = sess.exec(make_dir.format(shlex.quote(directory)), 15)
    if code != 0:
        raise ProxySetupError(f"节点 {node_alias} 无法创建权限 700 的可写临时目录")
    # 目录创建成功立即登记：后续发送或校验失败时，清理路径能覆盖部分写入的目录
    janitor.register(
        holder,
        node_alias,
        directory,
        {
            "proxy": proxy_dict,
            "target": {"host": target["host"], "port": target["port"]},
        },
    )
    script_path = os.path.join(
        os.path.dirname(os.path.abspath(__file__)), "ssh_proxy.py"
    )
    with open(script_path, "rb") as f:
        script = f.read()
    sess.send_private(script, directory + "/ssh_proxy.py")
    config = {
        "proxy": proxy_dict,
        "target": {"host": target["host"], "port": target["port"]},
        "relay": None,
        "log": directory + "/proxy.log",
        "pidfile": directory + "/proxy.pid",
        "timeout": 10,
    }
    sess.send_private(json.dumps(config).encode(), directory + "/px.json")
    # 用 python3 校验权限（远端本就要求 python3）：stat -c %a 在 BSD/macOS 上不存在
    verify = (
        "test -f {d}/ssh_proxy.py && test -f {d}/px.json && test ! -L {d}/px.json && "
        "python3 -c {s} {d}/px.json"
    ).format(
        d=shlex.quote(directory),
        s=shlex.quote(
            "import os,sys,stat\n"
            "sys.exit(0 if stat.S_IMODE(os.lstat(sys.argv[1]).st_mode)==0o600 else 1)"
        ),
    )
    out, code = sess.exec(verify, 15)
    if code != 0:
        raise ProxySetupError(f"节点 {node_alias} 的代理配置接收结果校验失败")
    command = "python3 {} {}".format(
        shlex.quote(directory + "/ssh_proxy.py"), shlex.quote(directory + "/px.json")
    )
    log(f"已在 {node_alias} 准备代理程序 {directory}")
    return {"dir": directory, "command": command}


def attach_proxy_support(sess, cp, plan, janitor, holder, cred_ns, log, hinted):
    """为终端会话挂上代理支持：跳板前缀重建、本机首段凭据、远端准备。"""

    meta0 = plan[0][2] if len(plan[0]) > 2 else {}

    def before_start():
        # 混合链：套接字消失时先按原路径重建标准跳板段，不直接连接末端
        if meta0.get("jump_socket"):
            jump_connect(cp, get_host(cp, meta0["jump_socket"]), quiet=True)
        if meta0.get("local_proxy"):
            cfg = ensure_proxy_cred_file(
                cred_ns,
                proxy_from_dict(meta0["local_proxy"]["proxy"]),
                meta0["local_proxy"]["target"]["host"],
                meta0["local_proxy"]["target"]["port"],
            )
            return ["-o", local_proxy_command(cfg)]
        return []

    def on_step(s, meta):
        if meta.get("unused_hint") and meta["unused_hint"] not in hinted:
            hinted.add(meta["unused_hint"])
            log("提示: " + meta["unused_hint"])
        if meta.get("prepare"):
            info = prepare_remote_proxy(
                s,
                meta["prepare"]["origin"],
                meta["prepare"]["proxy"],
                meta["prepare"]["target"],
                holder,
                janitor,
                log,
            )
            return ["-o", "ProxyCommand=" + info["command"]]
        return []

    def after_start():
        # 初始启动与断线重建后都会调用；初始启动时 janitor 里没有其他
        # 持有者，自然是无操作。断线重建时：
        # - session 持有者的登录段已由 on_step 在 start() 过程中用新随机
        #   目录重新准备并登记；旧登记保留，仅用于事后清理，不重复准备；
        # - 其他持有者（如 xfer-*）的资源必须重建到原目录——重发的命令
        #   仍引用旧路径。
        pending = []
        for other in list(janitor.by_holder):
            if other == holder:
                continue
            for node, directory, materials in janitor.pop(other):
                pending.append((other, node, directory, materials))
        for other, node, directory, materials in pending:
            if not materials:
                # 无重建材料的旧登记：保留登记以便清理，无法重建
                janitor.register(other, node, directory)
                continue
            try:
                prepare_remote_proxy(
                    sess,
                    node,
                    materials["proxy"],
                    materials["target"],
                    other,
                    janitor,
                    log,
                    fixed_dir=directory,
                )
            except BaseException as exc:
                # 重建失败不让会话恢复本身崩溃：登记回原条目，记录日志；
                # 该段重试会随后失败并报出原因
                janitor.register(other, node, directory, materials)
                log(
                    f"重建 {node} 上的代理资源 {directory} 失败"
                    f"({type(exc).__name__}: {exc})；该段重试将报错"
                )

    sess.before_start = before_start
    sess.on_step = on_step
    sess.after_start = after_start


def management_exec(cp, node_alias, command, timeout, log, janitor=None, depth=0):
    """在指定节点执行管理命令（只到该节点，不继续建立下一段）。

    `jump` 节点走控制连接；`shell` 节点开独立管理会话，会话自己的代理
    资源登记在临时持有者名下，用完递归清理。
    """
    if depth > 8:
        raise ProxySetupError("管理会话层级过深")
    h = get_host(cp, node_alias)
    if host_mode(h) == "jump":
        if jump_exec(cp, h, command) != 0:
            raise ProxySetupError(f"节点 {node_alias} 的管理命令失败")
        return
    janitor = janitor or RemoteJanitor()
    plan = build_shell_plan(cp, node_alias)
    sess = PtySession(plan, log)
    ns = "m_" + rand_token()
    sub_holder = "mgmt-" + rand_token()
    attach_proxy_support(sess, cp, plan, janitor, sub_holder, ns, log, set())
    try:
        sess.start()
        out, code = sess.exec(command, timeout)
        if code != 0:
            raise ProxySetupError(f"节点 {node_alias} 的管理命令失败（退出码 {code}）")
    finally:
        sess.close()
        drop_proxy_cred_file(ns)
        cleanup_holder_resources(cp, janitor, sub_holder, log, depth=depth + 1)


def cleanup_holder_resources(
    cp, janitor, holder, log, depth=0, local_node=None, sess=None
):
    """按持有者清理远端代理资源；失败报告节点和残留路径，不覆盖原错误。"""
    leftovers = []
    for node, directory, _materials in janitor.pop(holder):
        cmd = remote_cleanup_command(directory)
        try:
            if sess is not None and node == local_node:
                out, code = sess.exec(cmd, 30)
                if code != 0:
                    raise ProxySetupError(f"清理命令退出码 {code}")
            else:
                management_exec(
                    cp, node, cmd, 30, log, janitor=janitor, depth=depth + 1
                )
        except BaseException as exc:
            # 清理失败（含管理连接 `die` 的 SystemExit）只报告节点和残留路径
            log(f"清理 {node} 上的 {directory} 失败: {exc}")
            leftovers.append({"node": node, "path": directory, "error": str(exc)[:200]})
    return leftovers


def do_prepare_proxy(sess, req, janitor, self_alias, log):
    """传统传输的守护进程准备请求：在当前会话所在节点准备下一段代理。"""
    holder = req.get("holder") or ""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", holder):
        return {"status": "error", "error": "持有者标识非法"}
    try:
        proxy = proxy_from_dict(req.get("proxy"))
        target = req.get("target") or {}
        thost = proxy_addr_ok(target.get("host"), "目标")
        tport = proxy_port_ok(target.get("port"), "目标")
        info = prepare_remote_proxy(
            sess,
            self_alias,
            proxy.to_dict(),
            {"host": thost, "port": tport},
            holder,
            janitor,
            log,
        )
        return {"status": "ok", "dir": info["dir"], "proxy_command": info["command"]}
    except (ValueError, ProxySetupError, TimeoutError, ConnectionError) as exc:
        return {"status": "error", "error": str(exc)}


def do_cleanup_proxy(cp, sess, req, janitor, self_alias, log):
    """清理持有者名下的远端代理资源，返回残留路径。"""
    holder = req.get("holder") or ""
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,64}", holder):
        return {"status": "error", "error": "持有者标识非法"}
    known = janitor.known(holder)
    leftovers = cleanup_holder_resources(
        cp, janitor, holder, log, local_node=self_alias, sess=sess
    )
    janitor.cleaned.add(holder)
    reply = {"status": "ok", "leftovers": leftovers}
    if not known:
        # 守护进程重启后 janitor 为空：持有者从未登记，远端目录可能残留
        reply["warning"] = (
            f"持有者 {holder} 未登记（守护进程可能已重启）；"
            "远端 /tmp/.ssh_mux_px_* 目录可能残留，请检查并手动删除"
        )
    return reply


def do_private_write(sess, req, log):
    """专用私有输入请求：正文与 shell 命令字段分开，只作为接收程序的标准输入。"""
    path = req.get("path") or ""
    data = req.get("data")
    if not isinstance(data, str) or not path:
        return {"status": "error", "error": "私有输入请求缺少 path 或 data"}
    if not re.fullmatch(r"/tmp/\.ssh_mux_[A-Za-z0-9_.-]+(/[A-Za-z0-9_.-]+)*", path):
        return {"status": "error", "error": "私有输入路径不在允许的临时目录内"}
    try:
        sess.send_private(data.encode("utf-8"), path, 60)
        return {"status": "ok"}
    except Exception as exc:
        # 错误和日志都不保存正文或可还原正文的编码
        log(f"私有输入发送失败: {type(exc).__name__}")
        return {"status": "error", "error": f"私有输入发送失败: {type(exc).__name__}"}


# ---------- `shell` 模式:守护进程 ----------


def _load_config_lenient():
    """供连接标识计算读取配置；文件缺失或损坏时按无代理处理。"""
    try:
        if not os.path.isfile(CONFIG_PATH):
            return None
        cp = configparser.ConfigParser(interpolation=None)  # 禁用变量替换
        cp.read(CONFIG_PATH)
        return cp
    except Exception:
        return None


def shell_identity_key(alias):
    """终端会话标识：无代理时与原摘要输入完全相同；有代理时追加有序记录。"""
    identity = [os.path.realpath(CONFIG_PATH), valid_alias(alias)]
    cp = _load_config_lenient()
    if cp is not None:
        try:
            records = proxy_identity_records(cp, alias)
        except BaseException:
            records = []
        if records:
            identity.append(records)
    return hashlib.sha256(json.dumps(identity).encode()).hexdigest()[:16]


def shell_prefix(alias):
    return os.path.join(runtime_dir(), f"s_{shell_identity_key(alias)}_")


def shell_cred_ns(alias, session):
    """会话级本机代理凭据命名空间：同一别名的不同会话互不干扰。"""
    return f"s_{shell_identity_key(alias)}_{session}"


def shell_sock(alias, session):
    return shell_prefix(alias) + session + ".sock"


def shell_log_path(alias, session):
    return shell_prefix(alias) + session + ".log"


def shell_err_path(alias, session):
    return shell_prefix(alias) + session + ".err"


def shell_control_path(alias, session):
    return shell_prefix(alias) + session + ".ctl"


def shell_lock_path(alias, session):
    return shell_prefix(alias) + session + ".lock"


def do_exec(sess, req, log):
    command = req.get("command", "")
    try:
        timeout = min(int(req.get("timeout", 120)), 7200)
    except (TypeError, ValueError):
        return {
            "status": "error",
            "error": f"`timeout` 必须是整数: {req.get('timeout')!r}",
        }
    password = req.get("password") or None
    try:
        out, code = sess.exec(command, timeout, password)
        return {"status": "ok", "exit": code, "output": out}
    except TimeoutError as exc:
        # 超时的命令可能已经执行，不能重发；会话无法继续使用时重新连接
        try:
            sess.rebuild()
            log("命令超时后会话已重建")
        except Exception:
            pass
        return {"status": "error", "error": str(exc)}
    except ConnectionError as exc:
        # 连接断开后，重新登录并重试一次。无法确认原命令是否已经执行，
        # 调用方需要确保重复执行不会产生额外影响。
        log(f"会话断开({exc}),尝试重建")
        try:
            sess.rebuild()
            out, code = sess.exec(command, timeout, password)
            return {"status": "ok", "exit": code, "output": out, "reconnected": True}
        except Exception as exc2:
            return {"status": "error", "error": f"会话重建失败: {exc2}"}


def daemon_main(alias, session):
    valid_alias(alias)
    valid_session(session)
    os.umask(0o077)
    # 文件锁由内核在进程退出时释放，不依赖可能被复用的 pid。
    with open(shell_lock_path(alias, session), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return
        _daemon_main(alias, session)


def _daemon_main(alias, session):
    logf = open(shell_log_path(alias, session), "a", buffering=1)
    # 日志可能包含远程输出和密码提示,只允许属主读写
    os.chmod(shell_log_path(alias, session), 0o600)

    def log(msg):
        print(time.strftime("[%H:%M:%S]"), msg, file=logf)

    err_path = shell_err_path(alias, session)
    try:
        os.unlink(err_path)
    except FileNotFoundError:
        pass
    sock = shell_sock(alias, session)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    ctl_path = shell_control_path(alias, session)
    ctl = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sess = None
    janitor = RemoteJanitor()
    cred_ns = shell_cred_ns(alias, session)
    hinted = set()
    cp = None

    def cleanup_session_resources():
        """会话持有的远端代理资源随会话关闭清理；失败报告节点和残留路径。"""
        try:
            leftovers = cleanup_holder_resources(cp, janitor, "session", log)
            for item in leftovers:
                log("远端残留: {node}:{path}（{error}）".format(**item))
        except BaseException as exc:
            log(f"代理资源清理失败: {exc}")
        drop_proxy_cred_file(cred_ns)

    try:
        cp = load_config()
        drop_proxy_cred_file(cred_ns)  # 旧实例已退出（本进程持有锁），回收残留凭据
        plan = build_shell_plan(cp, alias)
        sess = PtySession(plan, log)
        attach_proxy_support(sess, cp, plan, janitor, "session", cred_ns, log, hinted)
        sess.start()
        try:
            os.unlink(sock)
        except FileNotFoundError:
            pass
        srv.bind(sock)
        os.chmod(sock, 0o600)  # socket 可以远程执行命令,只允许属主连接
        try:
            os.unlink(ctl_path)
        except FileNotFoundError:
            pass
        ctl.bind(ctl_path)
        os.chmod(ctl_path, 0o600)
        ctl.listen(4)
        # 登录并绑定成功后才写 pid 文件,启动失败的路径不会留下残留
        with open(shell_pid_path(alias, session), "w") as f:
            f.write(str(os.getpid()))
        os.chmod(shell_pid_path(alias, session), 0o600)
    except (Exception, SystemExit) as exc:
        # 登录失败(含配置错误调用 `die` 导致的 SystemExit)时把原因写入
        # `.err` 文件,命令行工具读取后显示失败原因
        detail = "启动中断(详见日志)" if isinstance(exc, SystemExit) else str(exc)
        with open(err_path, "w") as f:
            f.write(detail)
        os.chmod(err_path, 0o600)
        log(f"建立会话失败: {detail}")
        srv.close()
        ctl.close()
        if sess is not None:
            sess.close()
        cleanup_session_resources()
        try:
            os.unlink(sock)
        except FileNotFoundError:
            pass
        try:
            os.unlink(ctl_path)
        except FileNotFoundError:
            pass
        sys.exit(1)
    srv.listen(4)
    log(f"守护进程就绪,socket {sock}")
    last_active = time.time()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))

    def handle_control():
        # 命令运行期间也处理停止请求，由守护进程自己退出。
        conn, _ = ctl.accept()
        stop = False
        with conn:
            conn.settimeout(1)
            try:
                data = b""
                while b"\n" not in data and len(data) < 4096:
                    chunk = conn.recv(4096)
                    if not chunk:
                        break
                    data += chunk
                req = json.loads(data.decode())
                cmd = req.get("cmd") if isinstance(req, dict) else None
                stop = cmd == "stop"
                reply = (
                    {"status": "ok", "alias": alias, "session": session}
                    if cmd in ("ping", "stop")
                    else {"status": "error", "error": "控制接口只接受 ping 和 stop"}
                )
                conn.sendall(json.dumps(reply).encode() + b"\n")
            except (OSError, ValueError):
                pass
        if stop:
            log("收到 `stop`,退出")
            raise SystemExit(0)

    sess.control_socket = ctl
    sess.on_control = handle_control

    try:
        while True:
            r, _, _ = select.select([srv, ctl], [], [], 5)
            if not r:
                if time.time() - last_active > PERSIST:
                    log(f"空闲超过 {PERSIST} 秒,退出")
                    break
                continue
            if ctl in r:
                handle_control()
            if srv not in r:
                continue
            conn, _ = srv.accept()
            last_active = time.time()
            try:
                conn.settimeout(60)  # 只约束请求行的读取,不限制 `exec` 执行时长
                req_first = conn.recv(65536)
                # 读完整条 JSON 行
                while b"\n" not in req_first and len(req_first) < 4_000_000:
                    more = conn.recv(65536)
                    if not more:
                        break
                    req_first += more
                try:
                    req = json.loads(req_first.decode())
                    if not isinstance(req, dict):
                        raise ValueError("请求不是 JSON 对象")
                except (ValueError, UnicodeDecodeError):
                    req = None
                if req is None:
                    reply = {"status": "error", "error": "请求不是合法的 JSON 对象"}
                elif req.get("cmd") == "stop":
                    conn.sendall(b'{"status":"ok"}\n')
                    log("收到 `stop`,退出")
                    break
                elif req.get("cmd") == "ping":
                    reply = {"status": "ok", "alias": alias, "session": session}
                elif req.get("cmd") == "exec":
                    reply = do_exec(sess, req, log)
                elif req.get("cmd") == "prepare_proxy":
                    # 传统传输的专用准备请求，不假定登录计划已包含下一跳
                    reply = do_prepare_proxy(sess, req, janitor, alias, log)
                elif req.get("cmd") == "cleanup_proxy":
                    reply = do_cleanup_proxy(cp, sess, req, janitor, alias, log)
                elif req.get("cmd") == "private_write":
                    # 含凭据请求走专用输入通道，与普通执行命令分开处理
                    reply = do_private_write(sess, req, log)
                else:
                    reply = {"status": "error", "error": f"未知请求 {req.get('cmd')}"}
                conn.sendall(json.dumps(reply, ensure_ascii=False).encode() + b"\n")
            except Exception as exc:
                log(f"处理请求出错: {exc}")
            finally:
                conn.close()
            last_active = time.time()
    finally:
        srv.close()
        ctl.close()
        try:
            os.unlink(ctl_path)
        except FileNotFoundError:
            pass
        try:
            os.unlink(sock)
        except FileNotFoundError:
            pass
        try:
            os.unlink(shell_pid_path(alias, session))
        except FileNotFoundError:
            pass
        sess.close()
        cleanup_session_resources()
        log("守护进程退出")


# ---------- 命令行工具与后台进程通信 ----------


def rpc(alias, session, req, timeout=30):
    """向守护进程发一条请求;连不上返回 `None`"""
    path = (
        shell_control_path(alias, session)
        if req.get("cmd") in ("ping", "stop")
        else shell_sock(alias, session)
    )
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if (
        not stat.S_ISSOCK(info.st_mode)
        or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        die(f"拒绝连接不属于当前用户或权限不安全的套接字: {path}")
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(path)
    except OSError:
        s.close()
        return None
    try:
        s.sendall(json.dumps(req, ensure_ascii=False).encode() + b"\n")
        chunks = []
        while True:
            c = s.recv(1 << 20)
            if not c:
                break
            chunks.append(c)
    except (OSError, TimeoutError):
        s.close()
        return None  # 守护进程忙(如在执行长命令)或无响应
    finally:
        s.close()
    try:
        return json.loads(b"".join(chunks).decode())
    except (ValueError, UnicodeDecodeError):
        # 守护进程异常退出或返回了截断的响应,给调用方可读的错误而不是 traceback
        return {
            "status": "error",
            "error": "守护进程返回了无法解析的响应(可能已异常退出)",
        }


def shell_pid_path(alias, session):
    return shell_prefix(alias) + session + ".pid"


def daemon_pid_alive(alias, session):
    """通过文件锁判断会话是否存活；pid 文件仅供诊断。"""
    with open(shell_lock_path(alias, session), "a") as lock:
        try:
            fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return True
        return False


def kill_stale_daemon(alias, session):
    """仅清理已退出进程的信息，不依据残留 pid 终止进程。"""
    if daemon_pid_alive(alias, session):
        die(f"会话 {alias}/{session} 仍持有锁，但控制接口无响应；未清理活动会话")
    try:
        os.unlink(shell_pid_path(alias, session))
    except FileNotFoundError:
        pass


def ping_session(alias, session, timeout=5):
    r = rpc(alias, session, {"cmd": "ping"}, timeout=timeout)
    return r is not None and r.get("status") == "ok"


def hint_unused_proxies(alias):
    """用户名路由内部目标上的代理字段未使用：首次建连提示实际入口别名。"""
    try:
        cp = load_config()
        for seg in plan_segments(cp, alias, strict=False):
            if seg.unused:
                print(f"ssh-mux: 提示: {seg.unused}", file=sys.stderr)
    except BaseException:
        pass


def daemon_boot_timeout(cp, alias):
    """按链路长度估算守护进程启动期限。

    每一步登录（认证应答与终端就绪）和每个远端代理程序准备都串行耗时，
    深链路加代理准备的启动时间会超过 90 秒基准（真机实测两级终端链加
    一次远端准备约 95 秒）。混合链开头的标准跳板段每段各计一步登录。
    本机首段的代理握手计入所在步，不单独加准备时间。
    规划失败时返回基准值，配置错误仍由守护进程照常报告。
    """
    try:
        hops = shell_hops(build_chain(cp, alias))
        segments = plan_segments(cp, alias, strict=False)
        prefix = local_jump_prefix(hops) if any(seg.proxy for seg in segments) else 0
        remote_prepares = sum(
            1 for seg in segments[prefix:] if seg.proxy and seg.origin != "@local"
        )
    except BaseException:
        return DAEMON_BOOT_TIMEOUT
    estimated = (
        BOOT_BASE_TIMEOUT
        + BOOT_PER_HOP_TIMEOUT * len(hops)
        + BOOT_PER_PROXY_TIMEOUT * remote_prepares
    )
    return max(DAEMON_BOOT_TIMEOUT, estimated)


def ensure_daemon(alias, session):
    """确保后台进程已经启动，并等待完成到目标主机的登录"""
    # 先严格校验代理配置：配置改坏时即使已有会话可复用也拒绝，不静默绕过代理
    cp = load_config()
    plan_segments(cp, alias)
    if ping_session(alias, session):
        return
    fresh = True  # 本次调用真正建立了连接；复用已有会话时不重复提示
    err = shell_err_path(alias, session)
    try:
        os.unlink(err)
    except FileNotFoundError:
        pass
    if not daemon_pid_alive(alias, session):
        logf = open(shell_log_path(alias, session), "ab")
        subprocess.Popen(
            [sys.executable, os.path.abspath(__file__), "_daemon", alias, session],
            stdin=subprocess.DEVNULL,
            stdout=logf,
            stderr=subprocess.STDOUT,
            start_new_session=True,
            env=ssh_env(),
        )
        logf.close()  # 子进程已继承副本,父进程关闭避免文件描述符泄漏
    # 后台进程可能正在登录或执行长命令，定期检查是否可以接受请求；
    # 期限按链路长度估算，深链路和远端代理准备需要更长时间
    boot_timeout = daemon_boot_timeout(cp, alias)
    deadline = time.time() + boot_timeout
    while time.time() < deadline:
        if os.path.isfile(err):
            with open(err) as f:
                die(
                    f"建立会话失败: {f.read().strip()}(日志 {shell_log_path(alias, session)})"
                )
        if ping_session(alias, session):
            if fresh:
                hint_unused_proxies(alias)
            return
        time.sleep(0.5)
    try:
        with open(shell_log_path(alias, session), "rb") as f:
            f.seek(0, os.SEEK_END)
            f.seek(max(0, f.tell() - 500))
            logtail = f.read().decode("utf-8", "replace").strip()
    except OSError:
        logtail = ""
    hint = f",日志末尾: {logtail}" if logtail else ""
    die(
        f"守护进程在 {boot_timeout} 秒内不可用(可能在执行长命令){hint},"
        f"日志: {shell_log_path(alias, session)}"
    )


# ---------- `jump` 模式:`ControlMaster` ----------


def jump_sock_file(cp, h):
    # 相同私网地址可能属于不同网络，必须将整条登录路径计入连接身份。
    identity = [
        os.path.realpath(CONFIG_PATH),
        [
            [item.alias, item.host, item.port, item.user, item.via_mode, item.routing]
            for item in build_chain(cp, h.alias)
        ],
    ]
    # 整条路径无有效代理时保持原标识；有代理时追加有序记录（不含凭据和来源）
    records = proxy_identity_records(cp, h.alias)
    if records:
        identity.append(records)
    digest = hashlib.sha256(
        json.dumps(identity, ensure_ascii=True).encode()
    ).hexdigest()[:32]
    return os.path.join(runtime_dir(), f"ssh_mux_j_{digest}")


def _jump_cred_ns(cpath):
    """连接实例的凭据命名空间：取控制套接字路径的摘要部分。"""
    return "j_" + os.path.basename(cpath).rsplit("ssh_mux_j_", 1)[-1]


def proxy_cred_dir(ns):
    """本机代理凭据目录：runtime_dir 下权限 700，按连接实例隔离。"""
    if not re.fullmatch(r"[A-Za-z0-9_-]+", ns):
        die(f"凭据命名空间非法: {ns!r}")
    return os.path.join(runtime_dir(), "px_" + ns)


def prepare_proxy_cred_file(
    ns, proxy, target_host, target_port, relay=None, timeout=10
):
    """写入本机代理配置文件（目录 700、文件 600），返回路径。

    凭据只经私有文件传递；外层 ssh、sshpass 和转发子进程的环境与参数都不含秘密。
    """
    directory = proxy_cred_dir(ns)
    if os.path.isdir(directory):
        shutil.rmtree(directory, ignore_errors=True)
    os.makedirs(directory, mode=0o700)
    os.chmod(directory, 0o700)
    config = {
        "proxy": proxy.to_dict(),
        "target": {"host": target_host, "port": target_port},
        "relay": relay,
        "log": os.path.join(directory, "proxy.log"),
        "timeout": timeout,
    }
    path = os.path.join(directory, "config.json")
    with open(path, "w") as f:
        json.dump(config, f)
    os.chmod(path, 0o600)
    return path


def ensure_proxy_cred_file(ns, proxy, target_host, target_port, relay=None, timeout=10):
    """凭据文件存在则保留（不覆写运行中的实例），丢失时按当前配置重新准备。"""
    path = os.path.join(proxy_cred_dir(ns), "config.json")
    if os.path.isfile(path):
        return path
    return prepare_proxy_cred_file(ns, proxy, target_host, target_port, relay, timeout)


def drop_proxy_cred_file(ns):
    """连接停止、建立失败或确认失效后回收凭据；清理失败报告残留路径。"""
    directory = proxy_cred_dir(ns)
    if os.path.isdir(directory):
        shutil.rmtree(directory, ignore_errors=True)
        if os.path.exists(directory):
            print(
                f"ssh-mux: 代理凭据目录未能清理，请手动删除: {directory}",
                file=sys.stderr,
            )


def strip_proxy_env(env):
    """移除残留的同名代理变量；本工具不把代理凭据放入任何子进程环境。"""
    for name in ("SSH_MUX_PROXY_USER", "SSH_MUX_PROXY_PASS"):
        env.pop(name, None)
    return env


def ssh_env(extra=None):
    """调用 ssh/scp/sshpass 的环境：剥除残留的代理凭据变量后再叠加 `extra`。"""
    env = strip_proxy_env(dict(os.environ))
    if extra:
        env.update(extra)
    return env


def proxy_command_escape(value):
    """`ProxyCommand` 会做 % 展开；我们的路径不含合法令牌，全部按字面转义。"""
    return value.replace("%", "%%")


def local_proxy_command(config_path):
    """本机首段代理命令；包装进程只执行一次 setsid，避免 sshpass 退出时挂断辅助进程。"""
    py = shlex.quote(sys.executable)
    script = shlex.quote(os.path.abspath(__file__))
    inner = f"{py} {script} _proxy {shlex.quote(config_path)}"
    wrapped = (
        f"{py} -c 'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "
        + inner
    )
    return "ProxyCommand=" + proxy_command_escape(wrapped)


def jump_data_opts(cp, h):
    """`jump_exec()`、`jump_scp()` 和文件流共用的连接选项。

    有代理时附带 `ProxyCommand`，控制套接字失效时也不会直连回退。
    末段无代理但经跳板时，附带经上一跳套接字的 `-W` 转发命令兜底：
    套接字在检查与复用之间失效时，ssh 不会从本机直连目标。
    """
    opts = ["-o", f"ControlPath={jump_sock_file(cp, h)}"]
    seg = plan_segments(cp, h.alias)[-1]
    if seg.proxy:
        cfg = os.path.join(
            proxy_cred_dir(_jump_cred_ns(jump_sock_file(cp, h))), "config.json"
        )
        opts += ["-o", local_proxy_command(cfg)]
    elif h.via:
        # 与 jump_connect 非代理分支相同的跳板转发命令；套接字存活时 ssh 直接
        # 走 ControlPath，该选项仅在失效时兜底。数据连接不经 sshpass，无需
        # setsid 包装
        via = get_host(cp, h.via)
        via_cpath = jump_sock_file(cp, via)
        opts += [
            "-o",
            f"ProxyCommand=ssh -o ControlPath={shlex.quote(via_cpath)} "
            f"-W %h:%p {shlex.quote(f'{via.user}@{via.host}')}",
        ]
    return opts


def jump_check(cp, h):
    return (
        subprocess.run(
            [
                "ssh",
                "-o",
                f"ControlPath={jump_sock_file(cp, h)}",
                "-p",
                str(h.port),
                "-O",
                "check",
                f"{h.user}@{h.host}",
            ],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            env=ssh_env(),
        ).returncode
        == 0
    )


def jump_connect(cp, h, quiet=False):
    cpath = jump_sock_file(cp, h)
    via_cpath = None
    if h.via:
        via = get_host(cp, h.via)
        if via.routing or host_mode(via) == "shell":
            die(
                f"[{via.alias}] 是堡垒机(仅交互终端),[{h.alias}] 不能用 `via_mode=jump`"
            )
        jump_connect(cp, via, quiet=True)
        via_cpath = jump_sock_file(cp, via)
    # 严格校验代理配置后才谈复用：配置改坏时已有连接也拒绝，不静默绕过代理
    seg = plan_segments(cp, h.alias)[-1]
    if jump_check(cp, h):
        if not quiet:
            print(f"已连接: {h.alias} ({h.addr()})")
        return
    try:
        os.unlink(cpath)  # 清理异常断开残留的 socket
    except FileNotFoundError:
        pass
    # 目标条目的代理控制“上一节点 → 该主机”这一段；配置错误一律拒绝，不直连
    cred_ns = _jump_cred_ns(cpath)
    drop_proxy_cred_file(cred_ns)  # 回收旧实例凭据，再按当前配置重新准备
    cmd = [
        "ssh",
        "-o",
        "StrictHostKeyChecking=accept-new",
        "-o",
        "ControlMaster=yes",
        "-o",
        f"ControlPath={cpath}",
        "-o",
        f"ControlPersist={PERSIST}",
        "-o",
        "ConnectTimeout=10",
        "-p",
        str(h.port),
    ]
    if seg.proxy:
        # 地址经校验后作为字面量经配置文件传给辅助程序，不依赖 %h/%p 展开
        proxy_addr_ok(seg.proxy.host, "代理")
        proxy_addr_ok(h.host, "目标")
        relay = None
        if via_cpath:
            # 标准跳板的代理段：复用跳板控制连接跑 `ssh -W 代理地址:端口`，
            # 本机辅助程序在该字节通道上完成握手；跳板无需 Python。
            relay = [
                "ssh",
                "-o",
                f"ControlPath={via_cpath}",
                "-W",
                # 代理地址含冒号（IPv6 字面量）时必须加方括号
                "{}:{}".format(
                    f"[{seg.proxy.host}]" if ":" in seg.proxy.host else seg.proxy.host,
                    seg.proxy.port,
                ),
                f"{via.user}@{via.host}",
            ]
        cfg = prepare_proxy_cred_file(cred_ns, seg.proxy, h.host, h.port, relay)
        cmd += ["-o", local_proxy_command(cfg)]
    elif via_cpath:
        # 不用 `-J`:ProxyJump 的内层 ssh 不继承命令行的 -o 选项,会绕开
        # 跳板机的 ControlMaster 重新认证,密码登录时必然失败。这里让内层
        # ssh 显式复用跳板机的 master 套接字,内层不再需要认证。
        # 内层先用当前 Python 执行 setsid 再 exec:认证完成后 sshpass 退出、
        # 其终端销毁,未脱离终端的代理子进程会随终端一起被杀(实测 setsid
        # 可避免;macOS 没有 setsid 命令,故借 Python 完成)。
        cmd += [
            "-o",
            f"ProxyCommand={shlex.quote(sys.executable)} -c "
            f"'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "
            f"ssh -o ControlPath={shlex.quote(via_cpath)} "
            f"-W %h:%p {shlex.quote(f'{via.user}@{via.host}')}",
        ]
    cmd += ["-fN", f"{h.user}@{h.host}"]
    env = ssh_env()
    if h.password:
        if not shutil.which("sshpass"):
            die(f"[{h.alias}] 需要密码认证,但未找到 `sshpass`,请先安装")
        cmd = ["sshpass", "-e"] + cmd
        env["SSHPASS"] = h.password
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0 or not jump_check(cp, h):
        drop_proxy_cred_file(cred_ns)  # 建立失败后回收凭据
        die(f"连接失败: {h.alias} ({h.addr()}): {r.stderr.strip()}")
    if not quiet:
        print(f"已建立长连接: {h.alias} ({h.addr()}),空闲 {PERSIST} 秒自动关闭")


def jump_exec(cp, h, command):
    jump_connect(cp, h, quiet=True)
    # `-n` 加 DEVNULL:隔离标准输入,避免远程命令吃掉调用方的输入
    return subprocess.run(
        [
            "ssh",
            "-n",
        ]
        + jump_data_opts(cp, h)
        + [
            "-p",
            str(h.port),
            f"{h.user}@{h.host}",
            command,
        ],
        stdin=subprocess.DEVNULL,
        env=ssh_env(),
    ).returncode


_LOCAL_SCP_LEGACY = None
_REMOTE_SCP_LEGACY = {}


def scp_legacy_option(output):
    # 新版强制使用 SCP 协议；不认识 -O 的旧版默认就是该协议。
    return (
        [] if re.search(r"(?:unknown|illegal|invalid) option", output, re.I) else ["-O"]
    )


def jump_scp(cp, h, direction, src, dst, capture=False):
    global _LOCAL_SCP_LEGACY
    jump_connect(cp, h, quiet=True)
    if _LOCAL_SCP_LEGACY is None:
        env = ssh_env({"LC_ALL": "C"})
        probe = subprocess.run(
            ["scp", "-O"],
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=env,
        )
        _LOCAL_SCP_LEGACY = scp_legacy_option(probe.stdout + probe.stderr)
    remote = remote_spec(h, dst if direction == "push" else src)
    args = (
        ["scp"]
        + _LOCAL_SCP_LEGACY
        + ["-q"]
        + jump_data_opts(cp, h)
        + ["-P", str(h.port)]
    )
    args += [src, remote] if direction == "push" else [remote, dst]
    if capture:
        return subprocess.run(
            args,
            stdin=subprocess.DEVNULL,
            capture_output=True,
            text=True,
            env=ssh_env(),
        )
    return subprocess.run(args, stdin=subprocess.DEVNULL, env=ssh_env()).returncode


def jump_exit(cp, h):
    cpath = jump_sock_file(cp, h)
    if not os.path.exists(cpath):
        # ControlPersist 空闲退出后套接字会消失；凭据目录仍要回收
        drop_proxy_cred_file(_jump_cred_ns(cpath))
        return False
    # `-O exit` 只使用控制套接字，不执行代理握手，也不读取凭据文件
    subprocess.run(
        [
            "ssh",
            "-o",
            f"ControlPath={cpath}",
            "-p",
            str(h.port),
            "-O",
            "exit",
            f"{h.user}@{h.host}",
        ],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        env=ssh_env(),
    )
    try:
        os.unlink(cpath)
    except FileNotFoundError:
        pass
    drop_proxy_cred_file(_jump_cred_ns(cpath))  # 连接停止后回收凭据
    return True


# ---------- `shell` 模式的命令行操作 ----------


def shell_exec(alias, session, command, timeout, password=None):
    ensure_daemon(alias, session)
    r = rpc(
        alias,
        session,
        {"cmd": "exec", "command": command, "timeout": timeout, "password": password},
        timeout=timeout + 30,
    )
    if r is None:
        die("无法连接会话守护进程")
    if r.get("status") != "ok":
        die(r.get("error", "未知错误"))
    return r


def remote_spec(h, path):
    """转义远程 shell 特殊字符，同时保留 SCP 对返回文件名的校验。"""
    return _transfer_module.remote_spec(h.user, h.host, path)


def scp_spec(h, path):
    """分别为中转主机与目标主机的 shell 添加引号。"""
    return shlex.quote(remote_spec(h, path))


def xfer_leg(hop, session, command, password, timeout, note=None):
    """在中转主机 `hop` 的会话里执行一条 `scp`,失败即报错退出。
    优先用 `sshpass` 填写密码，减少识别终端提示造成的错误。
    中转主机没有 `sshpass` 时，识别终端中的密码提示并自动填写"""
    key = (hop.alias, session)
    if key not in _REMOTE_SCP_LEGACY:
        probe = shell_exec(hop.alias, session, "LC_ALL=C scp -O 2>&1", timeout)
        _REMOTE_SCP_LEGACY[key] = scp_legacy_option(probe["output"])
    if _REMOTE_SCP_LEGACY[key]:
        command = "scp -O " + command[len("scp ") :]
    # 密码通过环境变量传给 `sshpass -e`,避免出现在 `ps` 里;命令前加空格,
    # 配合 `HISTCONTROL=ignorespace` 时不会写入中转机的 shell 历史
    r = shell_exec(
        hop.alias,
        session,
        f" SSHPASS={shlex.quote(password)} sshpass -e {command}",
        timeout,
    )
    if r["exit"] == 127 and "sshpass" in r["output"]:
        r = shell_exec(hop.alias, session, command, timeout, password=password)
    if r["exit"] != 0:
        hint = f"（{note}）" if note else ""
        die(
            f"传输失败(在 {hop.alias} 上执行){hint},退出码 {r['exit']}: {r['output'][-300:]}"
        )


def reverse_leg_note(cp, hops):
    """存在代理配置时，回传连接失败要说明该连接保持直连、不支持代理。"""
    if os.environ.get("SSH_MUX_PROXY", "").strip():
        return "回传连接保持直连，不读取 SSH_MUX_PROXY，也不支持代理"
    for h in hops:
        if h.has_proxy_fields():
            return "回传连接保持直连，不使用任何正向代理字段"
    try:
        if cp.has_section("local"):
            sec = cp["local"]
            if any(
                sec.get(k, "")
                for k in (
                    "proxy",
                    "proxy_host",
                    "proxy_port",
                    "proxy_user",
                    "proxy_password",
                )
            ):
                return "回传连接保持直连，不使用 [local] 的代理字段"
    except Exception:
        pass
    return None


def xfer_leg_proxy_opt(cp, hop, nxt, session, holder, prepared):
    """为 `hop → nxt` 这段正向复制准备代理，返回拼入 `scp` 命令的选项文本。

    经起点的已有会话准备程序和凭据，不假定登录计划已包含下一跳；
    即使 `nxt` 配置 `via_mode=jump`，也在实际执行节点 `hop` 检查运行条件。
    """
    seg_proxy = effective_proxy(nxt, hop.alias)
    if seg_proxy is None:
        return ""
    r = rpc(
        hop.alias,
        session,
        {
            "cmd": "prepare_proxy",
            "holder": holder,
            "proxy": seg_proxy.to_dict(),
            "target": {"host": nxt.host, "port": nxt.port},
        },
        timeout=120,
    )
    if r is None:
        die(f"无法连接 {hop.alias} 的会话守护进程，无法准备代理")
    if r.get("status") != "ok":
        die(f"在 {hop.alias} 准备到 {nxt.alias} 的代理失败: {r.get('error')}")
    prepared.add(hop.alias)
    return "-o " + shlex.quote("ProxyCommand=" + r["proxy_command"]) + " "


def xfer_cleanup_proxies(session, holder, prepared):
    """传统传输持有的代理资源在 `finally` 中清理；失败报告残留路径。"""
    for alias in prepared:
        try:
            r = rpc(
                alias, session, {"cmd": "cleanup_proxy", "holder": holder}, timeout=45
            )
            leftovers = (r or {}).get("leftovers") or []
            if r is None or r.get("status") != "ok":
                leftovers = [
                    {"node": alias, "path": "（清理请求未确认）", "error": "rpc"}
                ]
            warning = (r or {}).get("warning")
            if warning:
                # 守护进程重启后持有者未登记：提示远端可能残留
                print(f"ssh-mux: {warning}", file=sys.stderr)
            for item in leftovers:
                print(
                    "ssh-mux: 代理临时资源未能清理 {node}:{path}；恢复连接后请删除".format(
                        **item
                    ),
                    file=sys.stderr,
                )
        except (Exception, SystemExit):
            print(f"ssh-mux: 无法确认 {alias} 上的代理资源已清理", file=sys.stderr)


def get_staging(cp):
    """读取 [local] 的 `staging`，返回暂存主机 `Host` 或 `None`。
    本机未运行 SSH 服务时，通过这台主机暂存文件。
    本机和连接路径上的第一台中转主机都需要能通过 SSH 登录暂存主机。
    """
    if not cp.has_section("local"):
        return None
    alias = cp["local"].get("staging", "").strip()
    if not alias:
        return None
    if alias == "local":
        die("[local] 的 `staging` 不能指向 `local` 自己")
    h = get_host(cp, alias)
    if host_mode(h) != "jump":
        die(f"暂存主机 [{alias}] 必须能用 `jump` 模式直连,堡垒机链路上的主机不行")
    if not h.password:
        die(f"暂存主机 [{alias}] 需要配置 `password`(中转机应答密码用)")
    return h


def xfer_endpoint(cp):
    """选择文件传输方式：使用暂存主机，或让中转主机直接访问本机。
    返回 (暂存主机或 `None`, [local] 主机或 `None`)。
    """
    staging = get_staging(cp)
    if staging is not None:
        return staging, None
    local = get_host(cp, "local")
    if not local.password:
        die(
            "文件传输需要 [local] 段配置 `host`/`user`/`password`,"
            "本机没开 `sshd` 时改用 `staging` 指定暂存主机"
        )
    return None, local


def shell_push(cp, target, session, local_path, remote_path, timeout):
    """上传文件：沿登录路径，在各台中转主机上运行复制命令，直到目标主机。
    配置了 `staging` 时，本机先上传到暂存主机，中转主机再从那里下载。
    """
    staging, local = xfer_endpoint(cp)
    src = os.path.abspath(local_path)
    if not os.path.exists(src):
        die(f"本地路径不存在: {src}")
    hops = shell_hops(build_chain(cp, target.alias))
    tmp_dir = f"/tmp/.ssh_mux_xfer_{rand_token()}"
    tmp = f"{tmp_dir}/{os.path.basename(src)}"
    stage_dir = f"/tmp/.ssh_mux_xfer_{rand_token()}" if staging else None
    stage_tmp = f"{stage_dir}/{os.path.basename(src)}" if staging else None
    created_hops = []
    stage_created = False
    holder = "xfer-" + rand_token()  # 本次传输持有的远端代理资源
    prepared = set()
    note = reverse_leg_note(cp, hops)
    try:
        for hop in hops[:-1]:
            result = shell_exec(
                hop.alias, session, f"mkdir -m 700 -- {shlex.quote(tmp_dir)}", timeout
            )
            if result["exit"] != 0:
                die(f"无法在 {hop.alias} 创建传输目录: {result['output'][-300:]}")
            created_hops.append(hop)
        if staging:
            if jump_exec(cp, staging, f"mkdir -m 700 -- {shlex.quote(stage_dir)}") != 0:
                die(f"无法在暂存主机 {staging.alias} 创建传输目录")
            stage_created = True
            if jump_scp(cp, staging, "push", src, stage_tmp) != 0:
                die(f"传输失败(本机 -> 暂存主机 {staging.alias})")
            endpoint, epath, epw = staging, stage_tmp, staging.password
        else:
            endpoint, epath, epw = local, src, local.password
        first_dst = tmp if len(hops) > 1 else remote_path
        # 首台远端回连本机或暂存机取文件：回传连接保持直连，不支持代理
        xfer_leg(
            hops[0],
            session,
            f"scp -q -o StrictHostKeyChecking=no -P {endpoint.port} "
            f"{scp_spec(endpoint, epath)} {shlex.quote(first_dst)}",
            epw,
            timeout,
            note=note,
        )
        for i in range(len(hops) - 1):
            dst = remote_path if i == len(hops) - 2 else tmp
            # 正向段 hop[i] → hop[i+1]：上传和登录使用同一有效代理
            opt = xfer_leg_proxy_opt(
                cp, hops[i], hops[i + 1], session, holder, prepared
            )
            xfer_leg(
                hops[i],
                session,
                f"scp -q -o StrictHostKeyChecking=no {opt}-P {hops[i + 1].port} "
                f"{shlex.quote(tmp)} {scp_spec(hops[i + 1], dst)}",
                hops[i + 1].password,
                timeout,
            )
    finally:
        # 无论传输成功与否,清理代理资源、暂存主机和各中转主机上的临时文件
        xfer_cleanup_proxies(session, holder, prepared)
        if stage_created:
            try:
                jump_exec(cp, staging, f"rm -rf -- {shlex.quote(stage_dir)}")
            except (Exception, SystemExit):
                pass
        for h in created_hops:
            try:
                shell_exec(h.alias, session, f"rm -rf -- {shlex.quote(tmp_dir)}", 30)
            except (Exception, SystemExit):
                pass
    print(f"已上传 {local_path} -> {target.alias}:{remote_path}")


def shell_pull(cp, target, session, remote_path, local_path, timeout):
    """下载文件：从目标主机开始，按登录路径的相反顺序逐台复制到本机。
    配置了 `staging` 时，中转主机先上传到暂存主机，本机再从那里下载。
    """
    # 相对路径在本机解析;不转绝对路径的话,末段 scp 在中转主机上执行,
    # 会把相对路径解析到 [local] 账号在 sshd 上的家目录
    local_path = os.path.abspath(local_path)
    staging, local = xfer_endpoint(cp)
    hops = shell_hops(build_chain(cp, target.alias))
    filename = remote_path.rstrip("/").rsplit("/", 1)[-1]
    tmp_dir = f"/tmp/.ssh_mux_xfer_{rand_token()}"
    tmp = f"{tmp_dir}/{filename}"
    n = len(hops)
    stage_dir = f"/tmp/.ssh_mux_xfer_{rand_token()}" if staging else None
    stage_tmp = f"{stage_dir}/{filename}" if staging else None
    created_hops = []
    stage_created = False
    holder = "xfer-" + rand_token()  # 本次传输持有的远端代理资源
    prepared = set()
    note = reverse_leg_note(cp, hops)
    try:
        for hop in hops[:-1]:
            result = shell_exec(
                hop.alias, session, f"mkdir -m 700 -- {shlex.quote(tmp_dir)}", timeout
            )
            if result["exit"] != 0:
                die(f"无法在 {hop.alias} 创建传输目录: {result['output'][-300:]}")
            created_hops.append(hop)
        if staging:
            if jump_exec(cp, staging, f"mkdir -m 700 -- {shlex.quote(stage_dir)}") != 0:
                die(f"无法在暂存主机 {staging.alias} 创建传输目录")
            stage_created = True
        for i in range(n - 1, 0, -1):
            src = remote_path if i == n - 1 else tmp
            # 正向段 hop[i-1] → hop[i]：下载与登录使用同一有效代理
            opt = xfer_leg_proxy_opt(
                cp, hops[i - 1], hops[i], session, holder, prepared
            )
            xfer_leg(
                hops[i - 1],
                session,
                f"scp -q -o StrictHostKeyChecking=no {opt}-P {hops[i].port} "
                f"{scp_spec(hops[i], src)} {shlex.quote(tmp)}",
                hops[i].password,
                timeout,
            )
        src = tmp if n > 1 else remote_path
        if staging:
            # 首台远端回传暂存机：保持直连，不读取暂存机的入站代理字段
            xfer_leg(
                hops[0],
                session,
                f"scp -q -o StrictHostKeyChecking=no -P {staging.port} "
                f"{shlex.quote(src)} {scp_spec(staging, stage_tmp)}",
                staging.password,
                timeout,
                note=note,
            )
            if jump_scp(cp, staging, "pull", stage_tmp, local_path) != 0:
                die(f"传输失败(暂存主机 {staging.alias} -> 本机)")
        else:
            # 首台远端回传本机：保持直连，不支持代理
            xfer_leg(
                hops[0],
                session,
                f"scp -q -o StrictHostKeyChecking=no -P {local.port} "
                f"{shlex.quote(src)} {scp_spec(local, local_path)}",
                local.password,
                timeout,
                note=note,
            )
    finally:
        # 无论传输成功与否,清理代理资源、暂存主机和各中转主机上的临时文件
        xfer_cleanup_proxies(session, holder, prepared)
        if stage_created:
            try:
                jump_exec(cp, staging, f"rm -rf -- {shlex.quote(stage_dir)}")
            except (Exception, SystemExit):
                pass
        for h in created_hops:
            try:
                shell_exec(h.alias, session, f"rm -rf -- {shlex.quote(tmp_dir)}", 30)
            except (Exception, SystemExit):
                pass
    print(f"已下载 {target.alias}:{remote_path} -> {local_path}")


# ---------- 子命令 ----------


def check_alias(cp, alias):
    if alias == "local":
        die("[local] 是保留段,只用于文件中转,不能作为操作目标")
    return get_host(cp, alias)


def valid_session(name):
    if not re.fullmatch(r"[A-Za-z0-9_-]{1,32}", name):
        die(f"会话名只能包含字母、数字、_、-(最长 32): {name!r}")
    return name


def cmd_status(cp):
    for alias in cp.sections():
        if alias == "local":
            continue
        h = get_host(cp, alias)
        if h.routing == "username":
            # 用户名路由的堡垒机自身也可能配置了入口代理，一并显示
            print(
                f"{alias}  {h.addr()}  堡垒机(通过登录名选择目标，不提供独立终端)"
                f"{describe_proxy(cp, h)}"
            )
            continue
        if host_mode(h) == "jump":
            state = "已连接" if jump_check(cp, h) else "未连接"
            print(f"{alias}  {h.addr()}  jump  {state}{describe_proxy(cp, h)}")
        else:
            socks = glob.glob(shell_sock(alias, "*"))
            proxy_info = describe_proxy(cp, h)
            if not socks:
                print(f"{alias}  {h.addr()}  shell  无会话{proxy_info}")
            for sk in sorted(socks):
                sess = sk[len(shell_prefix(alias)) : -len(".sock")]
                # 只探测状态,无响应的守护进程不等太久
                state = (
                    "已连接"
                    if ping_session(alias, sess, timeout=2)
                    else "守护进程无响应"
                )
                print(f"{alias}  {h.addr()}  shell  会话 {sess}: {state}{proxy_info}")


def cmd_list(cp):
    for alias in cp.sections():
        if alias == "local":
            # [local] 段允许没有 host 字段（仅作暂存机或代理说明）
            h = Host(alias, cp[alias])
            addr = h.addr() if h.host else "(本机)"
            print(f"[local]  {addr}{describe_proxy(cp, h)}")
            continue
        h = get_host(cp, alias)
        via = f"  via={h.via}({h.via_mode})" if h.via else ""
        print(f"{alias}  {h.addr()}{via}{describe_proxy(cp, h)}")


def load_config_for_edit():
    """供增删主机用:配置文件不存在时创建空配置"""
    cp = configparser.ConfigParser(interpolation=None)
    if os.path.isfile(CONFIG_PATH):
        cp.read(CONFIG_PATH)
    return cp


def save_config(cp):
    os.makedirs(os.path.dirname(CONFIG_PATH), exist_ok=True)
    with open(CONFIG_PATH, "w") as f:
        cp.write(f)
    os.chmod(CONFIG_PATH, 0o600)  # 里面有明文密码,只允许属主读写


def cmd_host_add(args):
    alias = valid_alias(args.alias)
    cp = load_config_for_edit()
    if cp.has_section(alias):
        die(f"[{alias}] 已存在,先 `host remove {alias}` 再添加")
    if args.staging:
        if alias != "local":
            die("`--staging` 只能用于 `local` 段")
        if not cp.has_section(args.staging):
            die(f"`staging` 指向的 [{args.staging}] 不存在")
    if not args.host and not args.staging:
        die("`--host` 必填(仅 `local` 段配了 `--staging` 时可省)")
    if args.via and not cp.has_section(args.via):
        known = ", ".join(cp.sections()) or "(空)"
        die(f"`via` 指向的 [{args.via}] 不存在,现有: {known}")
    if args.via_mode and not args.via:
        die("`--via-mode` 需要配合 `--via` 使用(单独给出会被忽略)")
    proxy_fields = [
        args.proxy,
        args.proxy_host,
        args.proxy_port,
        args.proxy_user,
        args.proxy_password,
    ]
    if any(v is not None and v != "" for v in proxy_fields):
        # 代理与 `via` 允许共存；校验失败时不改写配置文件
        if not args.proxy:
            die(
                "`--proxy-host`/`--proxy-port`/`--proxy-user`/`--proxy-password` 需要配合 `--proxy` 使用"
            )
        if args.proxy != "direct":
            try:
                make_proxy(
                    args.proxy,
                    args.proxy_host,
                    args.proxy_port,
                    args.proxy_user or None,
                    args.proxy_password,
                )
            except ValueError as exc:
                die(f"代理配置无效: {exc}")
        elif any(v is not None and v != "" for v in proxy_fields[1:]):
            die("`--proxy direct` 与其余代理字段互斥（direct 表示忽略它们）")
    cp.add_section(alias)
    sec = cp[alias]
    if args.host:
        sec["host"] = args.host
    if args.staging:
        sec["staging"] = args.staging
    if args.port:
        sec["port"] = str(args.port)
    if args.user:
        sec["user"] = args.user
    if args.password is not None:
        sec["password"] = args.password
    if args.via:
        sec["via"] = args.via
        sec["via_mode"] = args.via_mode or "jump"
    if args.routing:
        sec["routing"] = args.routing
    if args.proxy:
        sec["proxy"] = args.proxy
    if args.proxy_host:
        sec["proxy_host"] = args.proxy_host
    if args.proxy_port is not None:
        sec["proxy_port"] = str(args.proxy_port)
    if args.proxy_user:
        sec["proxy_user"] = args.proxy_user
    if args.proxy_password is not None:
        sec["proxy_password"] = args.proxy_password
    save_config(cp)
    print(f"已添加: [{alias}] {args.host}")


def cmd_host_remove(alias):
    cp = load_config_for_edit()
    if not cp.has_section(alias):
        die(f"配置中没有 [{alias}]")
    deps = [s for s in cp.sections() if cp[s].get("via", "").strip() == alias]
    if deps:
        die(f"无法删除: {', '.join(deps)} 的 `via` 指向 [{alias}],先删除它们")
    cp.remove_section(alias)
    save_config(cp)
    print(f"已删除: [{alias}]")


def cmd_exit(cp, alias, session):
    h = check_alias(cp, alias)
    if host_mode(h) == "jump":
        if jump_exit(cp, h):
            print(f"已断开: {alias}")
        else:
            print(f"没有活跃连接: {alias}")
        return
    socks = glob.glob(shell_sock(alias, session if session else "*"))
    if not socks:
        print(f"没有活跃连接: {alias}" + (f"(会话 {session})" if session else ""))
        return
    for sk in sorted(socks):
        sess = sk[len(shell_prefix(alias)) : -len(".sock")]
        r = rpc(alias, sess, {"cmd": "stop"}, timeout=5)
        if r and r.get("status") == "ok":
            print(f"已断开: {alias}(会话 {sess})")
        else:
            # 只清理已经退出的会话；活动会话由控制接口停止。
            kill_stale_daemon(alias, sess)
            try:
                os.unlink(sk)
            except FileNotFoundError:
                pass
            print(f"已清理退出进程的残留会话: {alias}(会话 {sess})")


EXEC_USAGE = (
    "用法: ssh-mux exec <别名> [--session S] [--timeout N] "
    "<命令...> 或 --file <本地文件>（-f 同义，- 表示标准输入）"
)


def read_command_file(path):
    """读取本地 UTF-8 命令文件，兼容 BOM 和 Windows 换行。"""
    try:
        if path == "-":
            text = sys.stdin.buffer.read().decode("utf-8-sig")
            text = text.replace("\r\n", "\n").replace("\r", "\n")
        else:
            with open(path, encoding="utf-8-sig") as source:
                text = source.read()
    except (OSError, UnicodeError) as exc:
        die(f"无法读取命令文件 {path!r}: {exc}")
    if not text.strip():
        die(f"命令文件为空: {path!r}")
    if "\x00" in text:
        die(f"命令文件不能包含 NUL 字符: {path!r}")
    # 独立执行环境允许脚本使用 exit，不会关闭已有终端会话。
    return "(\n" + text + "\n)"


def run_exec_cli(argv):
    """只解析命令开始前的选项，其后的内容全部交给远端 shell。"""
    session, timeout, alias = "default", 120, None
    command_file = None
    cmd = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            cmd = argv[i + 1 :]
            break
        if a in ("--file", "-f") or a.startswith("--file="):
            if command_file is not None:
                die("`--file` 只能指定一次")
            if a.startswith("--file="):
                command_file = a.split("=", 1)[1]
                i += 1
            else:
                if i + 1 >= len(argv):
                    die(f"{a} 需要本地文件路径")
                command_file = argv[i + 1]
                i += 2
            if not command_file:
                die("`--file` 需要本地文件路径")
            continue
        if a == "--session" and i + 1 < len(argv):
            session = argv[i + 1]
            i += 2
            continue
        if a.startswith("--session="):
            session = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--timeout" and i + 1 < len(argv):
            timeout = parse_int(argv[i + 1], "`--timeout`")
            i += 2
            continue
        if a.startswith("--timeout="):
            timeout = parse_int(a.split("=", 1)[1], "`--timeout`")
            i += 1
            continue
        if a in ("-h", "--help") and alias is None:
            print(EXEC_USAGE)
            return
        if alias is None:
            alias = a
            i += 1
            continue
        cmd = argv[i:]
        break
    if not alias or (not cmd and command_file is None):
        die(EXEC_USAGE)
    if command_file is not None and cmd:
        die("`--file` 不能与命令文本同时使用")
    command = (
        read_command_file(command_file)
        if command_file is not None
        else " ".join(cmd).strip()
    )
    cp = load_config()
    h = check_alias(cp, alias)
    if host_mode(h) == "jump":
        sys.exit(jump_exec(cp, h, command))
    r = shell_exec(alias, valid_session(session), command, timeout)
    out = r["output"]
    sys.stdout.write(out)
    if out and not out.endswith("\n"):
        sys.stdout.write("\n")
    sys.exit(r["exit"])


def transfer_file(cp, h, direction, src, dst, session, timeout, transport="scp"):
    """选择传输方式，编码和文件校验由独立模块处理。"""
    mode = host_mode(h)
    if transport == "scp":
        if mode == "jump":
            return jump_scp(cp, h, direction, src, dst)
        method = shell_push if direction == "push" else shell_pull
        method(cp, h, valid_session(session), src, dst, timeout)
        return 0
    if transport == "stream" and mode != "jump":
        die("stream 需要 jump 模式；堡垒机终端请使用 auto、base64 或 octal")
    if mode == "shell":
        session = valid_session(session)
    elif transport == "auto":
        transport = "stream"

    spec = importlib.util.spec_from_file_location(
        "ssh_mux_file_transfer",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_transfer.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    def ssh_args(command):
        jump_connect(cp, h, quiet=True)
        # 强制禁用终端和新的交互认证，数据不能混入认证提示。
        # 连接选项与 jump_exec/jump_scp 共用，有代理时不会直连回退。
        return (
            ["ssh", "-T", "-o", "BatchMode=yes"]
            + jump_data_opts(cp, h)
            + ["-p", str(h.port), f"{h.user}@{h.host}", command]
        )

    def execute(command, limit):
        if mode == "shell":
            return shell_exec(h.alias, session, command, limit)
        result = subprocess.run(
            ssh_args(command),
            stdin=subprocess.DEVNULL,
            capture_output=True,
            timeout=limit,
            env=ssh_env(),
        )
        return {
            "exit": result.returncode,
            "output": (result.stdout + result.stderr)
            .decode("utf-8", "replace")
            .replace("\r", ""),
        }

    def stream(action, path, file, limit):
        quoted = shlex.quote(path)
        if action == "push":
            command = f"umask 077; cat > {quoted}"
            stdin, stdout = file, subprocess.DEVNULL
        else:
            command = f"test -f {quoted} && test ! -L {quoted} && cat < {quoted}"
            stdin, stdout = subprocess.DEVNULL, file
        result = subprocess.run(
            ssh_args(command),
            stdin=stdin,
            stdout=stdout,
            stderr=subprocess.PIPE,
            timeout=limit,
            env=ssh_env(),
        )
        if result.returncode != 0:
            detail = result.stderr.decode("utf-8", "replace").strip()[-300:]
            raise module.TransferError(
                f"SSH 文件流传输失败（退出码 {result.returncode}）: {detail}"
            )

    try:
        worker = module.Transfer(execute, stream, timeout)
        method = worker.push if direction == "push" else worker.pull
        path = method(src, dst, transport)
    except (module.TransferError, OSError, subprocess.TimeoutExpired) as exc:
        die(str(exc))
    print(
        f"{'已上传' if direction == 'push' else '已下载'}: {path}（长度和 SHA-256 校验通过）"
    )
    return 0


def run_hybrid(cp, host, args):
    spec = importlib.util.spec_from_file_location(
        "ssh_mux_hybrid",
        os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_hybrid.py"),
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    src, dst = (
        (args.local_path, args.remote_path)
        if args.cmd == "push"
        else (args.remote_path, args.local_path)
    )
    try:
        # 直接传递当前模块对象，支持脚本执行和 importlib 加载两种入口。
        import types

        facade = types.SimpleNamespace(**globals())
        return module.Coordinator(
            facade, cp, host, args.cmd, src, dst, args.timeout, args.leg, args.plan
        ).run()
    except (
        module.TransferError,
        OSError,
        ValueError,
        subprocess.TimeoutExpired,
    ) as exc:
        die(str(exc))
    except KeyboardInterrupt:
        die("混合传输已取消；请检查上方的残留任务提示")


def main():
    # `_proxy` 在普通参数解析和加载主机配置之前分发到共用代理模块
    if len(sys.argv) >= 2 and sys.argv[1] == "_proxy":
        spec = importlib.util.spec_from_file_location(
            "ssh_mux_proxy",
            os.path.join(os.path.dirname(os.path.abspath(__file__)), "ssh_proxy.py"),
        )
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        sys.exit(module.main(sys.argv[1:]))
    if len(sys.argv) >= 4 and sys.argv[1] == "_daemon":
        daemon_main(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "exec":
        run_exec_cli(sys.argv[2:])
        return

    # allow_abbrev=False:包装脚本 ssh-mux.sh 靠位置参数计数做路径转换,
    # 选项缩写(如 `--sess`)会打乱计数,必须禁用
    ap = argparse.ArgumentParser(
        prog="ssh-mux",
        allow_abbrev=False,
        description="SSH 长连接管理(配置文件: " + CONFIG_PATH + ")",
    )
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_session(p):
        p.add_argument(
            "--session",
            default="default",
            help="shell 模式的会话名；多个任务使用不同名称以免相互影响，默认 default",
        )

    p = sub.add_parser("connect", allow_abbrev=False, help="建立长连接(已连接则跳过)")
    p.add_argument("alias")
    add_session(p)

    p = sub.add_parser(
        "exec",
        allow_abbrev=False,
        help="执行命令或 --file 本地文件(选项放在命令文本之前)",
    )
    p.add_argument("alias")
    add_session(p)
    p.add_argument("--timeout", type=int, default=120, help="命令超时秒数(默认 120)")
    p.add_argument("--file", "-f", help="从本地 UTF-8 文件读取命令，- 表示标准输入")
    p.add_argument("command", nargs="*")

    # 注意:ssh-mux.sh 按位置参数计数做路径转换,push/pull 新增带值选项时
    # 必须同步修改 ssh-mux.sh 里的选项清单
    p = sub.add_parser("push", allow_abbrev=False, help="上传文件到远程主机")
    p.add_argument("alias")
    add_session(p)
    p.add_argument("--timeout", type=int, default=XFER_TIMEOUT)
    p.add_argument("local_path")
    p.add_argument("remote_path")
    p.add_argument(
        "--transport",
        choices=["auto", "scp", "stream", "base64", "octal", "hybrid"],
        default="scp",
        help="默认 scp：保留原有方式；auto 在 jump 使用 SSH 文件流，在 shell 自动选择编码",
    )
    p.add_argument(
        "--leg",
        action="append",
        default=[],
        help="hybrid 分段协议，例如 @local:A=base64 或 A:B=scp",
    )
    p.add_argument(
        "--plan", action="store_true", help="探测并显示 hybrid 计划，不传输用户文件"
    )

    p = sub.add_parser("pull", allow_abbrev=False, help="从远程主机下载文件")
    p.add_argument("alias")
    add_session(p)
    p.add_argument("--timeout", type=int, default=XFER_TIMEOUT)
    p.add_argument("remote_path")
    p.add_argument("local_path")
    p.add_argument(
        "--transport",
        choices=["auto", "scp", "stream", "base64", "octal", "hybrid"],
        default="scp",
        help="默认 scp：保留原有方式；auto 在 jump 使用 SSH 文件流，在 shell 自动选择编码",
    )
    p.add_argument(
        "--leg",
        action="append",
        default=[],
        help="hybrid 分段协议，例如 @local:A=base64 或 A:B=scp",
    )
    p.add_argument(
        "--plan", action="store_true", help="探测并显示 hybrid 计划，不传输用户文件"
    )

    sub.add_parser("status", allow_abbrev=False, help="查看所有主机的连接状态")
    sub.add_parser("list", allow_abbrev=False, help="列出配置中的所有主机")

    hp = sub.add_parser("host", allow_abbrev=False, help="管理配置里的主机(增/删)")
    hsub = hp.add_subparsers(dest="host_cmd", required=True)
    p = hsub.add_parser(
        "add", allow_abbrev=False, help="添加主机配置，这一步不会连接服务器"
    )
    p.add_argument("alias", help="主机别名;`local` 是文件中转用的保留段")
    p.add_argument(
        "--host",
        default=None,
        help="主机地址(IP 或域名);`local` 段配了 `--staging` 时可省",
    )
    p.add_argument("--port", type=int, default=None, help="SSH 端口(默认 22)")
    p.add_argument("--user", default=None, help="登录用户名(默认当前本机用户)")
    p.add_argument(
        "--password", default=None, help="登录密码,明文保存;不配置时使用密钥认证"
    )
    p.add_argument("--via", default=None, help="跳板/堡垒机别名")
    p.add_argument(
        "--via-mode",
        dest="via_mode",
        choices=["jump", "shell"],
        default=None,
        help="配合 --via:jump=标准 SSH 跳板(默认),shell=堡垒机",
    )
    p.add_argument(
        "--routing",
        choices=["username"],
        default=None,
        help="username：通过 <user>/<目标IP>/any 格式的登录名选择目标主机",
    )
    p.add_argument(
        "--proxy",
        choices=["direct", "http", "socks5"],
        default=None,
        help="该主机入站段的代理：direct 直连（忽略其余代理字段），http/socks5 经代理连接",
    )
    p.add_argument("--proxy-host", dest="proxy_host", default=None, help="代理地址")
    p.add_argument(
        "--proxy-port",
        dest="proxy_port",
        type=int,
        default=None,
        help="代理端口(1-65535)",
    )
    p.add_argument("--proxy-user", dest="proxy_user", default=None, help="代理用户名")
    p.add_argument(
        "--proxy-password",
        dest="proxy_password",
        default=None,
        help="代理密码,明文保存",
    )
    p.add_argument(
        "--staging",
        default=None,
        help="仅用于 local：本机未运行 SSH 服务时，通过指定主机暂存文件",
    )
    p = hsub.add_parser(
        "remove", allow_abbrev=False, help="删除主机(不影响已建立的会话)"
    )
    p.add_argument("alias")

    p = sub.add_parser("exit", allow_abbrev=False, help="断开长连接")
    p.add_argument("alias", nargs="?", help="主机别名;配合 `--all` 断开全部")
    p.add_argument("--all", action="store_true")
    p.add_argument(
        "--session", default=None, help="只断开指定会话;不带则断开该主机的所有会话"
    )

    args = ap.parse_args()

    if (
        args.cmd in ("push", "pull")
        and (args.leg or args.plan)
        and args.transport != "hybrid"
    ):
        ap.error("--leg 和 --plan 需要 --transport hybrid")

    if args.cmd == "host":
        # 增删主机只动配置文件;文件可能还不存在,不走 `load_config`
        if args.host_cmd == "add":
            cmd_host_add(args)
        else:
            cmd_host_remove(args.alias)
        return

    cp = load_config()

    if args.cmd == "connect":
        h = check_alias(cp, args.alias)
        if host_mode(h) == "jump":
            jump_connect(cp, h)
        else:
            ensure_daemon(args.alias, valid_session(args.session))
            print(f"已建立终端会话: {args.alias}(会话 {args.session})")

    elif args.cmd == "push":
        h = check_alias(cp, args.alias)
        if args.transport == "hybrid":
            sys.exit(run_hybrid(cp, h, args))
        sys.exit(
            transfer_file(
                cp,
                h,
                "push",
                args.local_path,
                args.remote_path,
                args.session,
                args.timeout,
                args.transport,
            )
        )

    elif args.cmd == "pull":
        h = check_alias(cp, args.alias)
        if args.transport == "hybrid":
            sys.exit(run_hybrid(cp, h, args))
        sys.exit(
            transfer_file(
                cp,
                h,
                "pull",
                args.remote_path,
                args.local_path,
                args.session,
                args.timeout,
                args.transport,
            )
        )

    elif args.cmd == "status":
        cmd_status(cp)

    elif args.cmd == "list":
        cmd_list(cp)

    elif args.cmd == "exit":
        if args.all:
            if args.alias:
                die("`--all` 会断开所有主机,不要再给别名")
            for alias in cp.sections():
                if alias != "local":
                    cmd_exit(cp, alias, None)
        elif args.alias:
            cmd_exit(
                cp, args.alias, valid_session(args.session) if args.session else None
            )
        else:
            die("用法: `ssh-mux exit <别名> [--session S]` 或 `ssh-mux exit --all`")


if __name__ == "__main__":
    main()
