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

CONFIG_PATH = os.environ.get("SSH_MUX_CONFIG", os.path.expanduser("~/.config/ssh-mux/hosts.conf"))
SOCKET_DIR = os.environ.get("SSH_MUX_SOCKET_DIR", "/tmp")
try:
    PERSIST = int(os.environ.get("SSH_MUX_PERSIST", "600"))  # 空闲自动退出秒数
except ValueError:
    print(f"ssh-mux: SSH_MUX_PERSIST 必须是整数秒数: {os.environ.get('SSH_MUX_PERSIST')!r}",
          file=sys.stderr)
    sys.exit(1)
AUTH_STEP_TIMEOUT = 30    # 每一步登录提示的最长等待
DAEMON_BOOT_TIMEOUT = 90  # 等待后台进程依次登录到目标主机
XFER_TIMEOUT = 3600       # 每两台主机之间传输文件的超时秒数
DEBUG_PTY = bool(os.environ.get("SSH_MUX_DEBUG"))  # 设为非空值后，将终端收到的数据写入后台进程日志

# 识别 `pty` 输出里的各类提示
PW_RX = re.compile(rb"(?i)password[^:\n]{0,40}:\s*$")
LOGIN_RX = re.compile(rb"(?i)login(\s+as)?:\s*$")
YESNO_RX = re.compile(rb"\(yes/no[^)]*\)\s*\??\s*$")
FAIL_RX = re.compile(rb"Permission denied|HOST IDENTIFICATION HAS CHANGED|Connection refused|Connection timed out")
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
    if (not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
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

    def addr(self):
        return f"{self.user}@{self.host}:{self.port}"


def load_config():
    if not os.path.isfile(CONFIG_PATH):
        die(f"配置文件不存在: {CONFIG_PATH}(格式参考同目录的 `hosts.conf.example`)")
    cp = configparser.ConfigParser(interpolation=None)  # 禁用变量替换，保留密码中的 % 字符
    cp.read(CONFIG_PATH)
    return cp


def valid_alias(alias):
    """别名会拼进 socket/日志/pid 文件名，禁止路径相关字符"""
    if not re.fullmatch(r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,31}", alias) or ".." in alias:
        die(f"别名只能包含字母、数字、_、-、.(最长 32,不能以 . 开头,不能含 ..): {alias!r}")
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
    """`shell` 模式的登录步骤：本机发起首次登录，后续在上一台主机的终端中执行"""
    chain = build_chain(cp, alias)
    hops = shell_hops(chain)
    if not hops:
        die(f"[{alias}] 连接链为空")
    return [ssh_step(cp, h) for h in hops]


# ---------- `shell` 模式:`pty` 会话 ----------

class PtySession:
    """保持从本机到目标的终端连接，支持登录、执行命令和重新连接"""

    def __init__(self, plan, log):
        self.plan = plan
        self.log = log
        self.master = None
        self.proc = None
        self.buf = b""
        self.control_socket = None
        self.on_control = None

    def _write(self, data):
        while data:
            n = os.write(self.master, data)
            data = data[n:]

    def _send_line(self, text):
        self._write(text.encode() + b"\n")

    def _pump(self, timeout):
        readers = [self.master]
        if self.control_socket is not None:
            readers.append(self.control_socket)
        r, _, _ = select.select(readers, [], [], timeout)
        if self.control_socket is not None and self.control_socket in r:
            self.on_control()
        if self.master not in r:
            return
        try:
            data = os.read(self.master, 65536)
        except OSError:
            data = b""
        if not data:
            raise ConnectionError("通道已关闭(对端退出或网络断开)")
        if DEBUG_PTY:
            self.log("pty>> " + repr(data[-2000:]))
        self.buf += data
        if len(self.buf) > 2_000_000:
            # 标注必须保留:调用方只能看到末尾,不标注会误以为输出完整
            note = "[ssh-mux: 输出超过 2MB,前面部分已丢弃,仅保留末尾]\n"
            self.buf = b"\n" + note.encode() + b"\n" + self.buf[-1_000_000:]

    def _wait_for(self, rx, timeout, extra=()):
        """等待 `rx` 匹配输出末尾;`extra` 里的提示见到就自动应答"""
        deadline = time.time() + timeout
        while True:
            if FAIL_RX.search(self.buf):
                raise ConnectionError("登录失败,输出尾部: " + tail(self.buf))
            if rx.search(self.buf):
                return
            for erx, ans in extra:
                if erx.search(self.buf):
                    self.buf = b""
                    self._send_line(ans)
                    break
            remain = deadline - time.time()
            if remain <= 0:
                raise TimeoutError("等待登录提示超时,输出尾部: " + tail(self.buf))
            try:
                self._pump(min(remain, 1.0))
            except ConnectionError as exc:
                raise ConnectionError(f"通道关闭,输出尾部: {tail(self.buf)}") from exc

    def _authenticate(self, auth):
        for rx, secret in auth:
            if not secret:
                continue  # 无密码(如密钥认证),不等待该提示
            self._wait_for(rx, AUTH_STEP_TIMEOUT, extra=[(YESNO_RX, "yes")])
            self.buf = b""
            self._send_line(secret)

    def _settle(self):
        """确认远程终端可以执行命令，然后关闭回显、提示符和颜色。
        登录后远程主机可能清空输入缓冲，因此反复发送打印标记的命令，
        直到收到标记。标记由 `printf` 拼接生成，输入命令中没有完整标记，
        避免把终端回显误认为命令执行结果。
        """
        tok = rand_token()
        rx = re.compile(rb"__RD_" + tok.encode() + rb"__")
        deadline = time.time() + AUTH_STEP_TIMEOUT
        self.buf = b""
        while True:
            self._send_line("stty -echo")
            self._send_line(f"printf '__RD_%s__\\n' {tok}")
            try:
                self._wait_for(rx, 3)
                break
            except TimeoutError:
                if time.time() > deadline:
                    raise
        self._send_line("PS1=''")
        self._send_line("export TERM=dumb")
        time.sleep(0.2)
        self.buf = b""

    def start(self):
        args, auth = self.plan[0]
        m, s = pty.openpty()
        # 窗口调大,减少折行对输出解析的干扰
        fcntl.ioctl(s, termios.TIOCSWINSZ, struct.pack("HHHH", 50, 220, 0, 0))
        # 创建新会话，并将伪终端设为控制终端。SSH 通过 /dev/tty 读取密码。
        # 没有控制终端时，SSH 会尝试调用 `ssh-askpass`，无法读取脚本发送的密码。
        def _preexec():
            os.setsid()
            fcntl.ioctl(0, termios.TIOCSCTTY, 0)
        self.proc = subprocess.Popen(args, stdin=s, stdout=s, stderr=s,
                                     preexec_fn=_preexec, close_fds=True)
        os.close(s)
        self.master = m
        try:
            self._authenticate(auth)
            self._settle()
            for args, auth in self.plan[1:]:
                # 替换中转 shell；内层 SSH 退出时整条终端链关闭，不能退回上一跳。
                self._send_line("exec " + " ".join(shlex.quote(a) for a in args))
                self._authenticate(auth)
                self._settle()
        except Exception:
            self.close()
            raise
        self.log("已登录到目标主机")

    def _stage_command(self, command, token, deadline):
        """用短行传送命令文本，避开终端补全、输入缓冲和堡垒机多行处理。"""
        name = "__ssh_mux_" + token
        data = command.encode("utf-8")
        for index, offset in enumerate(range(0, len(data), 256)):
            # `printf %b` 识别八进制字节；末尾字符防止命令替换删除换行。
            encoded = "".join("\\0%03o" % byte for byte in data[offset:offset + 256])
            previous = "" if index == 0 else '"${' + name + '}"'
            ack = f"{token}_{index}"
            self.buf = b""
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("传输命令内容超时，尚未执行命令")
            self._send_line(f" {name}={previous}$(printf '%b_' '{encoded}'); "
                            f"{name}=${{{name}%_}}; printf '__CH_%s__\\n' {ack}")
            self._wait_for(re.compile(rb"__CH_" + ack.encode() + rb"__"), remaining)
        return name

    def exec(self, command, timeout, password=None):
        """执行命令，用随机标记识别输出范围，返回 (输出, 退出码)。
        命令和结束标记在同一条 shell 语句中解析；标记不会被程序当作输入。
        `eval` 在当前 shell 执行，因此保留目录和环境变量。`password` 用于应答提示。
        """
        tok = rand_token()
        if self.master is None:
            # 上次超时后重建失败，会话不可用，先尝试重新登录
            self.rebuild()
        xs = f"__XS_{tok}__".encode()
        xe = re.compile(rb"__XE_" + tok.encode() + rb"__(\d+)\r?\n")
        deadline = time.time() + timeout
        source = shlex.quote(command)
        cleanup = ""
        if "\n" in command or "\t" in command or len(source.encode()) > 2000:
            try:
                name = self._stage_command(command, tok, deadline)
                if time.time() >= deadline:
                    raise TimeoutError("传输命令内容超时，尚未执行命令")
            except TimeoutError:
                self.close()
                raise TimeoutError("传输命令内容超时，尚未执行命令") from None
            source = '"${' + name + '}"'
            cleanup = "; unset " + name
        self.buf = b""
        self._send_line(f" printf '__XS_%s__\\n' {tok}; "
                        f"eval {source}; "
                        f"printf '__XE_%s__%s\\n' {tok} $?{cleanup}")
        started = False
        answers = 0
        while True:
            if not started:
                i = self.buf.find(xs)
                if i >= 0:
                    started = True
                    self.buf = self.buf[i + len(xs):]
            if started:
                m = xe.search(self.buf)
                if m:
                    return clean_output(self.buf[:m.start()]), int(m.group(1))
                if password and answers < 3 and PW_RX.search(self.buf):
                    # 密码提示:每次出现都要应答(最多 3 次)。ssh 每次尝试前
                    # 会清空输入缓冲，因此后续重试也需要重新填写密码
                    self.buf = b""
                    self._send_line(password)
                    answers += 1
            remain = deadline - time.time()
            if remain <= 0:
                try:
                    self._recover()
                except ConnectionError:
                    pass  # 恢复失败交给上层重建,这里统一报超时,避免误重发命令
                raise TimeoutError(f"命令超过 {timeout} 秒未结束,已发送中断")
            self._pump(min(remain, 0.5))

    def _recover(self):
        """命令超时后发送 `Ctrl-C`，再反复打印标记，确认终端恢复响应"""
        try:
            self._write(b"\x03")
            time.sleep(0.3)
            self.buf = b""
            tok = rand_token()
            rx = re.compile(rb"__RC_" + tok.encode() + rb"__")
            deadline = time.time() + 8
            while True:
                self._send_line(f"printf '__RC_%s__\\n' {tok}")
                try:
                    self._wait_for(rx, 2)
                    return
                except TimeoutError:
                    if time.time() > deadline:
                        raise
        except Exception as exc:
            raise ConnectionError("会话无法恢复,需要重建") from exc

    def rebuild(self):
        self.close()
        self.start()

    def close(self):
        try:
            if self.proc and self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait(timeout=5)
        except Exception:
            pass
        try:
            if self.master is not None:
                os.close(self.master)
        except OSError:
            pass
        self.master = None
        self.proc = None


# ---------- `shell` 模式:守护进程 ----------

def shell_prefix(alias):
    identity = json.dumps([os.path.realpath(CONFIG_PATH), valid_alias(alias)])
    key = hashlib.sha256(identity.encode()).hexdigest()[:16]
    return os.path.join(runtime_dir(), f"s_{key}_")


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
        return {"status": "error", "error": f"`timeout` 必须是整数: {req.get('timeout')!r}"}
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
    try:
        cp = load_config()
        sess = PtySession(build_shell_plan(cp, alias), log)
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
                reply = ({"status": "ok", "alias": alias, "session": session}
                         if cmd in ("ping", "stop") else
                         {"status": "error", "error": "控制接口只接受 ping 和 stop"})
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
        log("守护进程退出")


# ---------- 命令行工具与后台进程通信 ----------

def rpc(alias, session, req, timeout=30):
    """向守护进程发一条请求;连不上返回 `None`"""
    path = (shell_control_path(alias, session) if req.get("cmd") in ("ping", "stop")
            else shell_sock(alias, session))
    try:
        info = os.lstat(path)
    except FileNotFoundError:
        return None
    if (not stat.S_ISSOCK(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077):
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
        return {"status": "error", "error": "守护进程返回了无法解析的响应(可能已异常退出)"}


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


def ensure_daemon(alias, session):
    """确保后台进程已经启动，并等待完成到目标主机的登录"""
    if ping_session(alias, session):
        return
    err = shell_err_path(alias, session)
    try:
        os.unlink(err)
    except FileNotFoundError:
        pass
    if not daemon_pid_alive(alias, session):
        logf = open(shell_log_path(alias, session), "ab")
        subprocess.Popen([sys.executable, os.path.abspath(__file__), "_daemon", alias, session],
                         stdin=subprocess.DEVNULL, stdout=logf, stderr=subprocess.STDOUT,
                         start_new_session=True)
        logf.close()  # 子进程已继承副本,父进程关闭避免文件描述符泄漏
    # 后台进程可能正在登录或执行长命令，定期检查是否可以接受请求
    deadline = time.time() + DAEMON_BOOT_TIMEOUT
    while time.time() < deadline:
        if os.path.isfile(err):
            with open(err) as f:
                die(f"建立会话失败: {f.read().strip()}(日志 {shell_log_path(alias, session)})")
        if ping_session(alias, session):
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
    die(f"守护进程在 {DAEMON_BOOT_TIMEOUT} 秒内不可用(可能在执行长命令){hint},"
        f"日志: {shell_log_path(alias, session)}")


# ---------- `jump` 模式:`ControlMaster` ----------

def jump_sock_file(cp, h):
    # 相同私网地址可能属于不同网络，必须将整条登录路径计入连接身份。
    identity = [os.path.realpath(CONFIG_PATH), [
        [item.alias, item.host, item.port, item.user, item.via_mode, item.routing]
        for item in build_chain(cp, h.alias)
    ]]
    digest = hashlib.sha256(json.dumps(identity, ensure_ascii=True).encode()).hexdigest()[:32]
    return os.path.join(runtime_dir(), f"ssh_mux_j_{digest}")


def jump_check(cp, h):
    return subprocess.run(
        ["ssh", "-o", f"ControlPath={jump_sock_file(cp, h)}", "-p", str(h.port),
         "-O", "check", f"{h.user}@{h.host}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def jump_connect(cp, h, quiet=False):
    cpath = jump_sock_file(cp, h)
    via_cpath = None
    if h.via:
        via = get_host(cp, h.via)
        if via.routing or host_mode(via) == "shell":
            die(f"[{via.alias}] 是堡垒机(仅交互终端),[{h.alias}] 不能用 `via_mode=jump`")
        jump_connect(cp, via, quiet=True)
        via_cpath = jump_sock_file(cp, via)
    if jump_check(cp, h):
        if not quiet:
            print(f"已连接: {h.alias} ({h.addr()})")
        return
    try:
        os.unlink(cpath)  # 清理异常断开残留的 socket
    except FileNotFoundError:
        pass
    cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ControlMaster=yes", "-o", f"ControlPath={cpath}",
           "-o", f"ControlPersist={PERSIST}", "-o", "ConnectTimeout=10",
           "-p", str(h.port)]
    if via_cpath:
        # 不用 `-J`:ProxyJump 的内层 ssh 不继承命令行的 -o 选项,会绕开
        # 跳板机的 ControlMaster 重新认证,密码登录时必然失败。这里让内层
        # ssh 显式复用跳板机的 master 套接字,内层不再需要认证。
        # 内层先用当前 Python 执行 setsid 再 exec:认证完成后 sshpass 退出、
        # 其终端销毁,未脱离终端的代理子进程会随终端一起被杀(实测 setsid
        # 可避免;macOS 没有 setsid 命令,故借 Python 完成)。
        cmd += ["-o",
                f"ProxyCommand={shlex.quote(sys.executable)} -c "
                f"'import os,sys; os.setsid(); os.execvp(sys.argv[1], sys.argv[1:])' "
                f"ssh -o ControlPath={shlex.quote(via_cpath)} "
                f"-W %h:%p {shlex.quote(f'{via.user}@{via.host}')}"]
    cmd += ["-fN", f"{h.user}@{h.host}"]
    env = dict(os.environ)
    if h.password:
        if not shutil.which("sshpass"):
            die(f"[{h.alias}] 需要密码认证,但未找到 `sshpass`,请先安装")
        cmd = ["sshpass", "-e"] + cmd
        env["SSHPASS"] = h.password
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0 or not jump_check(cp, h):
        die(f"连接失败: {h.alias} ({h.addr()}): {r.stderr.strip()}")
    if not quiet:
        print(f"已建立长连接: {h.alias} ({h.addr()}),空闲 {PERSIST} 秒自动关闭")


def jump_exec(cp, h, command):
    jump_connect(cp, h, quiet=True)
    # `-n` 加 DEVNULL:隔离标准输入,避免远程命令吃掉调用方的输入
    return subprocess.run(
        ["ssh", "-n", "-o", f"ControlPath={jump_sock_file(cp, h)}", "-p", str(h.port),
         f"{h.user}@{h.host}", command], stdin=subprocess.DEVNULL).returncode


_LOCAL_SCP_LEGACY = None
_REMOTE_SCP_LEGACY = {}


def scp_legacy_option(output):
    # 新版强制使用 SCP 协议；不认识 -O 的旧版默认就是该协议。
    return [] if re.search(r"(?:unknown|illegal|invalid) option", output, re.I) else ["-O"]


def jump_scp(cp, h, direction, src, dst):
    global _LOCAL_SCP_LEGACY
    jump_connect(cp, h, quiet=True)
    if _LOCAL_SCP_LEGACY is None:
        env = dict(os.environ, LC_ALL="C")
        probe = subprocess.run(["scp", "-O"], stdin=subprocess.DEVNULL,
                               capture_output=True, text=True, env=env)
        _LOCAL_SCP_LEGACY = scp_legacy_option(probe.stdout + probe.stderr)
    remote = remote_spec(h, dst if direction == "push" else src)
    args = ["scp"] + _LOCAL_SCP_LEGACY + [
        "-q", "-o", f"ControlPath={jump_sock_file(cp, h)}", "-P", str(h.port)]
    args += [src, remote] if direction == "push" else [remote, dst]
    return subprocess.run(args, stdin=subprocess.DEVNULL).returncode


def jump_exit(cp, h):
    cpath = jump_sock_file(cp, h)
    if not os.path.exists(cpath):
        return False
    subprocess.run(["ssh", "-o", f"ControlPath={cpath}", "-p", str(h.port),
                    "-O", "exit", f"{h.user}@{h.host}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        os.unlink(cpath)
    except FileNotFoundError:
        pass
    return True


# ---------- `shell` 模式的命令行操作 ----------

def shell_exec(alias, session, command, timeout, password=None):
    ensure_daemon(alias, session)
    r = rpc(alias, session, {"cmd": "exec", "command": command, "timeout": timeout,
                             "password": password}, timeout=timeout + 30)
    if r is None:
        die("无法连接会话守护进程")
    if r.get("status") != "ok":
        die(r.get("error", "未知错误"))
    return r


def remote_spec(h, path):
    """转义远程 shell 特殊字符，同时保留 SCP 对返回文件名的校验。"""
    escaped = re.sub(r"([^A-Za-z0-9_@%+=:,./-])", r"\\\1", path)
    return f"{h.user}@{h.host}:{escaped}"


def scp_spec(h, path):
    """分别为中转主机与目标主机的 shell 添加引号。"""
    return shlex.quote(remote_spec(h, path))


def xfer_leg(hop, session, command, password, timeout):
    """在中转主机 `hop` 的会话里执行一条 `scp`,失败即报错退出。
    优先用 `sshpass` 填写密码，减少识别终端提示造成的错误。
    中转主机没有 `sshpass` 时，识别终端中的密码提示并自动填写"""
    key = (hop.alias, session)
    if key not in _REMOTE_SCP_LEGACY:
        probe = shell_exec(hop.alias, session, "LC_ALL=C scp -O 2>&1", timeout)
        _REMOTE_SCP_LEGACY[key] = scp_legacy_option(probe["output"])
    if _REMOTE_SCP_LEGACY[key]:
        command = "scp -O " + command[len("scp "):]
    # 密码通过环境变量传给 `sshpass -e`,避免出现在 `ps` 里;命令前加空格,
    # 配合 `HISTCONTROL=ignorespace` 时不会写入中转机的 shell 历史
    r = shell_exec(hop.alias, session,
                   f" SSHPASS={shlex.quote(password)} sshpass -e {command}", timeout)
    if r["exit"] == 127 and "sshpass" in r["output"]:
        r = shell_exec(hop.alias, session, command, timeout, password=password)
    if r["exit"] != 0:
        die(f"传输失败(在 {hop.alias} 上执行),退出码 {r['exit']}: {r['output'][-300:]}")


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
        die("文件传输需要 [local] 段配置 `host`/`user`/`password`,"
            "本机没开 `sshd` 时改用 `staging` 指定暂存主机")
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
    try:
        for hop in hops[:-1]:
            result = shell_exec(hop.alias, session,
                                f"mkdir -m 700 -- {shlex.quote(tmp_dir)}", timeout)
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
        xfer_leg(hops[0], session,
                 f"scp -q -o StrictHostKeyChecking=no -P {endpoint.port} "
                 f"{scp_spec(endpoint, epath)} {shlex.quote(first_dst)}",
                 epw, timeout)
        for i in range(len(hops) - 1):
            dst = remote_path if i == len(hops) - 2 else tmp
            xfer_leg(hops[i], session,
                     f"scp -q -o StrictHostKeyChecking=no -P {hops[i + 1].port} "
                     f"{shlex.quote(tmp)} {scp_spec(hops[i + 1], dst)}",
                     hops[i + 1].password, timeout)
    finally:
        # 无论传输成功与否,清理暂存主机和各中转主机上的临时文件(清理失败忽略)
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
    try:
        for hop in hops[:-1]:
            result = shell_exec(hop.alias, session,
                                f"mkdir -m 700 -- {shlex.quote(tmp_dir)}", timeout)
            if result["exit"] != 0:
                die(f"无法在 {hop.alias} 创建传输目录: {result['output'][-300:]}")
            created_hops.append(hop)
        if staging:
            if jump_exec(cp, staging, f"mkdir -m 700 -- {shlex.quote(stage_dir)}") != 0:
                die(f"无法在暂存主机 {staging.alias} 创建传输目录")
            stage_created = True
        for i in range(n - 1, 0, -1):
            src = remote_path if i == n - 1 else tmp
            xfer_leg(hops[i - 1], session,
                     f"scp -q -o StrictHostKeyChecking=no -P {hops[i].port} "
                     f"{scp_spec(hops[i], src)} {shlex.quote(tmp)}",
                     hops[i].password, timeout)
        src = tmp if n > 1 else remote_path
        if staging:
            xfer_leg(hops[0], session,
                     f"scp -q -o StrictHostKeyChecking=no -P {staging.port} "
                     f"{shlex.quote(src)} {scp_spec(staging, stage_tmp)}",
                     staging.password, timeout)
            if jump_scp(cp, staging, "pull", stage_tmp, local_path) != 0:
                die(f"传输失败(暂存主机 {staging.alias} -> 本机)")
        else:
            xfer_leg(hops[0], session,
                     f"scp -q -o StrictHostKeyChecking=no -P {local.port} "
                     f"{shlex.quote(src)} {scp_spec(local, local_path)}",
                     local.password, timeout)
    finally:
        # 无论传输成功与否,清理暂存主机和各中转主机上的临时文件(清理失败忽略)
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
            print(f"{alias}  {h.addr()}  堡垒机(通过登录名选择目标，不提供独立终端)")
            continue
        if host_mode(h) == "jump":
            state = "已连接" if jump_check(cp, h) else "未连接"
            print(f"{alias}  {h.addr()}  jump  {state}")
        else:
            socks = glob.glob(shell_sock(alias, "*"))
            if not socks:
                print(f"{alias}  {h.addr()}  shell  无会话")
            for sk in sorted(socks):
                sess = sk[len(shell_prefix(alias)):-len(".sock")]
                # 只探测状态,无响应的守护进程不等太久
                state = "已连接" if ping_session(alias, sess, timeout=2) else "守护进程无响应"
                print(f"{alias}  {h.addr()}  shell  会话 {sess}: {state}")


def cmd_list(cp):
    for alias in cp.sections():
        if alias == "local":
            continue
        h = get_host(cp, alias)
        via = f"  via={h.via}({h.via_mode})" if h.via else ""
        print(f"{alias}  {h.addr()}{via}")


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
        sess = sk[len(shell_prefix(alias)):-len(".sock")]
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


EXEC_USAGE = ("用法: ssh-mux exec <别名> [--session S] [--timeout N] "
              "<命令...> 或 --file <本地文件>（-f 同义，- 表示标准输入）")


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
            cmd = argv[i + 1:]
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
    command = read_command_file(command_file) if command_file is not None else " ".join(cmd).strip()
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


def main():
    if len(sys.argv) >= 4 and sys.argv[1] == "_daemon":
        daemon_main(sys.argv[2], sys.argv[3])
        return
    if len(sys.argv) >= 2 and sys.argv[1] == "exec":
        run_exec_cli(sys.argv[2:])
        return

    # allow_abbrev=False:包装脚本 ssh-mux.sh 靠位置参数计数做路径转换,
    # 选项缩写(如 `--sess`)会打乱计数,必须禁用
    ap = argparse.ArgumentParser(prog="ssh-mux", allow_abbrev=False,
                                 description="SSH 长连接管理(配置文件: " + CONFIG_PATH + ")")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_session(p):
        p.add_argument("--session", default="default",
                       help="shell 模式的会话名；多个任务使用不同名称以免相互影响，默认 default")

    p = sub.add_parser("connect", allow_abbrev=False, help="建立长连接(已连接则跳过)")
    p.add_argument("alias")
    add_session(p)

    p = sub.add_parser("exec", allow_abbrev=False,
                       help="执行命令或 --file 本地文件(选项放在命令文本之前)")
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

    p = sub.add_parser("pull", allow_abbrev=False, help="从远程主机下载文件")
    p.add_argument("alias")
    add_session(p)
    p.add_argument("--timeout", type=int, default=XFER_TIMEOUT)
    p.add_argument("remote_path")
    p.add_argument("local_path")

    sub.add_parser("status", allow_abbrev=False, help="查看所有主机的连接状态")
    sub.add_parser("list", allow_abbrev=False, help="列出配置中的所有主机")

    hp = sub.add_parser("host", allow_abbrev=False, help="管理配置里的主机(增/删)")
    hsub = hp.add_subparsers(dest="host_cmd", required=True)
    p = hsub.add_parser("add", allow_abbrev=False, help="添加主机配置，这一步不会连接服务器")
    p.add_argument("alias", help="主机别名;`local` 是文件中转用的保留段")
    p.add_argument("--host", default=None,
                   help="主机地址(IP 或域名);`local` 段配了 `--staging` 时可省")
    p.add_argument("--port", type=int, default=None, help="SSH 端口(默认 22)")
    p.add_argument("--user", default=None, help="登录用户名(默认当前本机用户)")
    p.add_argument("--password", default=None, help="登录密码,明文保存;不配置时使用密钥认证")
    p.add_argument("--via", default=None, help="跳板/堡垒机别名")
    p.add_argument("--via-mode", dest="via_mode", choices=["jump", "shell"], default=None,
                   help="配合 --via:jump=标准 SSH 跳板(默认),shell=堡垒机")
    p.add_argument("--routing", choices=["username"], default=None,
                   help="username：通过 <user>/<目标IP>/any 格式的登录名选择目标主机")
    p.add_argument("--staging", default=None,
                   help="仅用于 local：本机未运行 SSH 服务时，通过指定主机暂存文件")
    p = hsub.add_parser("remove", allow_abbrev=False, help="删除主机(不影响已建立的会话)")
    p.add_argument("alias")

    p = sub.add_parser("exit", allow_abbrev=False, help="断开长连接")
    p.add_argument("alias", nargs="?", help="主机别名;配合 `--all` 断开全部")
    p.add_argument("--all", action="store_true")
    p.add_argument("--session", default=None,
                   help="只断开指定会话;不带则断开该主机的所有会话")

    args = ap.parse_args()

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
        if host_mode(h) == "jump":
            sys.exit(jump_scp(cp, h, "push", args.local_path, args.remote_path))
        shell_push(cp, h, valid_session(args.session), args.local_path, args.remote_path, args.timeout)

    elif args.cmd == "pull":
        h = check_alias(cp, args.alias)
        if host_mode(h) == "jump":
            sys.exit(jump_scp(cp, h, "pull", args.remote_path, args.local_path))
        shell_pull(cp, h, valid_session(args.session), args.remote_path, args.local_path, args.timeout)

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
            cmd_exit(cp, args.alias, valid_session(args.session) if args.session else None)
        else:
            die("用法: `ssh-mux exit <别名> [--session S]` 或 `ssh-mux exit --all`")


if __name__ == "__main__":
    main()
