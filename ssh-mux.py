#!/usr/bin/env python3
"""ssh-mux:SSH 长连接管理

两种连接模式:
- `jump`:直连主机或标准 SSH 跳板(支持 `-J`),走 `ControlMaster` 多路复用
- `shell`:堡垒机只给交互终端,由守护进程持有 `pty` 会话链,CLI 经 Unix socket 发命令

主机信息在配置文件里(INI),命令行只引用别名。
"""

import argparse
import configparser
import fcntl
import glob
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
import string
import struct
import subprocess
import sys
import termios
import time

CONFIG_PATH = os.environ.get("SSH_MUX_CONFIG", os.path.expanduser("~/.config/ssh-mux/hosts.conf"))
SOCKET_DIR = os.environ.get("SSH_MUX_SOCKET_DIR", "/tmp")
PERSIST = int(os.environ.get("SSH_MUX_PERSIST", "600"))  # 空闲自动退出秒数
AUTH_STEP_TIMEOUT = 30    # 每一步登录提示的最长等待
DAEMON_BOOT_TIMEOUT = 90  # 等待守护进程完成登录链
XFER_TIMEOUT = 3600       # 文件传输单棒最长时长
DEBUG_PTY = bool(os.environ.get("SSH_MUX_DEBUG"))  # 置 1 后把 `pty` 流量写进守护进程日志

# 识别 `pty` 输出里的各类提示
PW_RX = re.compile(rb"(?i)password[^:\n]{0,40}:\s*$")
LOGIN_RX = re.compile(rb"(?i)login(\s+as)?:\s*$")
YESNO_RX = re.compile(rb"\(yes/no[^)]*\)\s*\??\s*$")
FAIL_RX = re.compile(rb"Permission denied|HOST IDENTIFICATION HAS CHANGED|Connection refused|Connection timed out")
ANSI_RX = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def die(msg):
    print(f"ssh-mux: {msg}", file=sys.stderr)
    sys.exit(1)


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


# ---------- 配置 ----------

class Host:
    def __init__(self, alias, sec):
        self.alias = alias
        self.host = sec.get("host", "").strip()
        self.port = int(sec.get("port", "22"))
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
    cp = configparser.ConfigParser(interpolation=None)  # 关掉插值,密码里可能有 %
    cp.read(CONFIG_PATH)
    return cp


def get_host(cp, alias):
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
    """去掉 `routing=username` 的堡垒机:它们只做接力,不产生独立 shell"""
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
            # 先过堡垒机密码,落地后再过目标机自己的 `login`/`password`
            args = base + ["-p", str(via.port), f"{via.user}/{h.host}/any@{via.host}"]
            auth = [(PW_RX, via.password), (LOGIN_RX, h.user), (PW_RX, h.password)]
            return args, auth
    args = base + ["-p", str(h.port), f"{h.user}@{h.host}"]
    auth = [(PW_RX, h.password)]
    return args, auth


def build_shell_plan(cp, alias):
    """`shell` 模式的完整登录计划:第 0 步是本地启动,其余在上一层 shell 里敲"""
    chain = build_chain(cp, alias)
    hops = shell_hops(chain)
    if not hops:
        die(f"[{alias}] 连接链为空")
    return [ssh_step(cp, h) for h in hops]


# ---------- `shell` 模式:`pty` 会话 ----------

class PtySession:
    """持有 '本机 -> ... -> 目标' 的 `pty` 会话链,支持建链、发命令、重建"""

    def __init__(self, plan, log):
        self.plan = plan
        self.log = log
        self.master = None
        self.proc = None
        self.buf = b""

    def _write(self, data):
        while data:
            n = os.write(self.master, data)
            data = data[n:]

    def _send_line(self, text):
        self._write(text.encode() + b"\n")

    def _pump(self, timeout):
        r, _, _ = select.select([self.master], [], [], timeout)
        if not r:
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
            self.buf = self.buf[-1_000_000:]

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
        """shell 就绪确认:关回显、清提示符和颜色。
        登录刚结束时对端可能清空输入缓冲(排队输入被丢弃),探针要反复发,
        直到看到标记回来为止。探针用 `printf` 拼接,使敲入的命令回显里
        不会出现完整标记,避免误判"""
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
        # 新会话 + 把 `pty` 设为控制终端:ssh 读密码要走 /dev/tty,
        # 没有控制终端它会去找 `ssh-askpass` 而不是等我们的输入
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
                self._send_line(" ".join(shlex.quote(a) for a in args))
                self._authenticate(auth)
                self._settle()
        except Exception:
            self.close()
            raise
        self.log("会话链就绪")

    def exec(self, command, timeout, password=None):
        """发命令并用随机标记截取输出。结束探针不能提前排队:读 stdin 的命令
        (如 `scp` 等密码提示)会把排队的探针行当成输入吃掉,所以等输出停顿后
        再发,并定期补发。`password` 用于执行期间自动应答密码提示;
        返回 (输出, 退出码)"""
        tok = rand_token()
        xs = f"__XS_{tok}__".encode()
        xe = re.compile(rb"__XE_" + tok.encode() + rb"__(\d+)")
        probe = f"printf '__XE_%s__%s\\n' {tok} $?"
        self.buf = b""
        self._send_line(f"printf '__XS_%s__\\n' {tok}")
        for line in command.split("\n"):
            self._send_line(line)
        deadline = time.time() + timeout
        started = False
        answers = 0
        probed = False
        last_output = time.time()
        while True:
            if not started:
                i = self.buf.find(xs)
                if i >= 0:
                    started = True
                    self.buf = self.buf[i + len(xs):]
            else:
                m = xe.search(self.buf)
                if m:
                    return clean_output(self.buf[:m.start()]), int(m.group(1))
                if password and answers < 3 and PW_RX.search(self.buf):
                    # 密码提示:每次出现都要应答(最多 3 次)。ssh 每次尝试前
                    # 会清空输入缓冲,只答一次会被后续尝试卡住
                    self.buf = b""
                    self._send_line(password)
                    answers += 1
                    last_output = time.time()
                elif password is None:
                    # 带密码应答时不发探针:两次密码提示之间的空窗期无法可靠
                    # 识别,探针可能被当成密码吃掉
                    quiet = time.time() - last_output
                    if not probed and quiet > 1.0:
                        self._send_line(probe)
                        probed = True
                    elif probed and quiet > 3.0:
                        # 探针可能被 stdin 吃掉或命令仍在跑,定期补发
                        self._send_line(probe)
                        last_output = time.time()
            remain = deadline - time.time()
            if remain <= 0:
                try:
                    self._recover()
                except ConnectionError:
                    pass  # 恢复失败交给上层重建,这里统一报超时,避免误重发命令
                raise TimeoutError(f"命令超过 {timeout} 秒未结束,已发送中断")
            before = len(self.buf)
            self._pump(min(remain, 0.5))
            if len(self.buf) > before:
                last_output = time.time()

    def _recover(self):
        """命令超时后把会话同步回来:先发 `Ctrl-C`,再反复发探针确认"""
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

def shell_sock(alias, session):
    return os.path.join(SOCKET_DIR, f"ssh_mux_s_{alias}_{session}.sock")


def shell_log_path(alias, session):
    return os.path.join(SOCKET_DIR, f"ssh_mux_s_{alias}_{session}.log")


def shell_err_path(alias, session):
    return os.path.join(SOCKET_DIR, f"ssh_mux_s_{alias}_{session}.err")


def do_exec(sess, req, log):
    command = req.get("command", "")
    timeout = min(int(req.get("timeout", 120)), 7200)
    password = req.get("password") or None
    try:
        out, code = sess.exec(command, timeout, password)
        return {"status": "ok", "exit": code, "output": out}
    except TimeoutError as exc:
        # 命令已发出且超时,不能重发(可能重复执行);会话若已乱则重建备用
        try:
            sess.rebuild()
            log("命令超时后会话已重建")
        except Exception:
            pass
        return {"status": "error", "error": str(exc)}
    except ConnectionError as exc:
        # 会话断了:重建一次再执行(命令可能未发出,重发是安全的;已发出的情况
        # 无法区分,调用方需注意命令幂等性)
        log(f"会话断开({exc}),尝试重建")
        try:
            sess.rebuild()
            out, code = sess.exec(command, timeout, password)
            return {"status": "ok", "exit": code, "output": out, "reconnected": True}
        except Exception as exc2:
            return {"status": "error", "error": f"会话重建失败: {exc2}"}


def daemon_main(alias, session):
    logf = open(shell_log_path(alias, session), "a", buffering=1)

    def log(msg):
        print(time.strftime("[%H:%M:%S]"), msg, file=logf)

    with open(shell_pid_path(alias, session), "w") as f:
        f.write(str(os.getpid()))
    try:
        os.unlink(shell_err_path(alias, session))
    except FileNotFoundError:
        pass
    try:
        cp = load_config()
        sess = PtySession(build_shell_plan(cp, alias), log)
        sess.start()
    except Exception as exc:
        # 建链失败写 `.err` 文件,CLI 轮询时读到就能报出原因
        with open(shell_err_path(alias, session), "w") as f:
            f.write(str(exc))
        log(f"建立会话失败: {exc}")
        sys.exit(1)

    sock = shell_sock(alias, session)
    srv = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        os.unlink(sock)
    except FileNotFoundError:
        pass
    try:
        srv.bind(sock)
    except OSError as exc:
        log(f"socket 绑定失败(可能已有同名守护进程): {exc}")
        sys.exit(1)
    srv.listen(4)
    log(f"守护进程就绪,socket {sock}")
    last_active = time.time()
    signal.signal(signal.SIGTERM, lambda *a: sys.exit(0))
    signal.signal(signal.SIGINT, lambda *a: sys.exit(0))

    try:
        while True:
            r, _, _ = select.select([srv], [], [], 5)
            if not r:
                if time.time() - last_active > PERSIST:
                    log(f"空闲超过 {PERSIST} 秒,退出")
                    break
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
                req = json.loads(req_first.decode())
                if req.get("cmd") == "stop":
                    conn.sendall(b'{"status":"ok"}\n')
                    log("收到 `stop`,退出")
                    break
                if req.get("cmd") == "ping":
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


# ---------- CLI 与守护进程通信 ----------

def rpc(alias, session, req, timeout=30):
    """向守护进程发一条请求;连不上返回 `None`"""
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(timeout)
    try:
        s.connect(shell_sock(alias, session))
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
    return json.loads(b"".join(chunks).decode())


def shell_pid_path(alias, session):
    return os.path.join(SOCKET_DIR, f"ssh_mux_s_{alias}_{session}.pid")


def daemon_pid_alive(alias, session):
    """pid 文件里的进程还在不在(用于区分"守护进程忙"和"守护进程不在")"""
    try:
        with open(shell_pid_path(alias, session)) as f:
            pid = int(f.read().strip())
    except (FileNotFoundError, ValueError):
        return False
    try:
        os.kill(pid, 0)
        return True
    except ProcessLookupError:
        return False
    except PermissionError:
        return True


def ping_session(alias, session):
    r = rpc(alias, session, {"cmd": "ping"}, timeout=5)
    return r is not None and r.get("status") == "ok"


def ensure_daemon(alias, session):
    """保证守护进程在跑;不在就启动并等它完成登录链"""
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
    # 守护进程可能正在建链或忙于长命令,轮询等它可用
    deadline = time.time() + DAEMON_BOOT_TIMEOUT
    while time.time() < deadline:
        if os.path.isfile(err):
            with open(err) as f:
                die(f"建立会话失败: {f.read().strip()}(日志 {shell_log_path(alias, session)})")
        if ping_session(alias, session):
            return
        time.sleep(0.5)
    die(f"守护进程在 {DAEMON_BOOT_TIMEOUT} 秒内不可用(可能在执行长命令),日志: {shell_log_path(alias, session)}")


# ---------- `jump` 模式:`ControlMaster` ----------

JUMP_CPATH = os.path.join(SOCKET_DIR, "ssh_mux_j_%h_%p_%r")


def jump_sock_file(h):
    return os.path.join(SOCKET_DIR, f"ssh_mux_j_{h.host}_{h.port}_{h.user}")


def jump_check(h):
    return subprocess.run(
        ["ssh", "-o", f"ControlPath={JUMP_CPATH}", "-O", "check", f"{h.user}@{h.host}"],
        stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0


def jump_connect(cp, h, quiet=False):
    jump_spec = None
    if h.via:
        via = get_host(cp, h.via)
        if via.routing or host_mode(via) == "shell":
            die(f"[{via.alias}] 是堡垒机(仅交互终端),[{h.alias}] 不能用 `via_mode=jump`")
        jump_connect(cp, via, quiet=True)
        jump_spec = f"{via.user}@{via.host}:{via.port}"
    if jump_check(h):
        if not quiet:
            print(f"已连接: {h.alias} ({h.addr()})")
        return
    try:
        os.unlink(jump_sock_file(h))  # 清理异常断开残留的 socket
    except FileNotFoundError:
        pass
    cmd = ["ssh", "-o", "StrictHostKeyChecking=accept-new",
           "-o", "ControlMaster=yes", "-o", f"ControlPath={JUMP_CPATH}",
           "-o", f"ControlPersist={PERSIST}", "-o", "ConnectTimeout=10",
           "-p", str(h.port)]
    if jump_spec:
        cmd += ["-J", jump_spec]
    cmd += ["-fN", f"{h.user}@{h.host}"]
    env = dict(os.environ)
    if h.password:
        if not shutil.which("sshpass"):
            die(f"[{h.alias}] 需要密码认证,但未找到 `sshpass`,请先安装")
        cmd = ["sshpass", "-e"] + cmd
        env["SSHPASS"] = h.password
    r = subprocess.run(cmd, env=env, capture_output=True, text=True)
    if r.returncode != 0 or not jump_check(h):
        die(f"连接失败: {h.alias} ({h.addr()}): {r.stderr.strip()}")
    if not quiet:
        print(f"已建立长连接: {h.alias} ({h.addr()}),空闲 {PERSIST} 秒自动关闭")


def jump_exec(cp, h, command):
    jump_connect(cp, h, quiet=True)
    return subprocess.run(
        ["ssh", "-o", f"ControlPath={JUMP_CPATH}", "-p", str(h.port),
         f"{h.user}@{h.host}", command]).returncode


def jump_scp(cp, h, direction, src, dst):
    jump_connect(cp, h, quiet=True)
    remote = f"{h.user}@{h.host}:{dst if direction == 'push' else src}"
    args = ["scp", "-q", "-o", f"ControlPath={JUMP_CPATH}", "-P", str(h.port)]
    args += [src, remote] if direction == "push" else [remote, dst]
    return subprocess.run(args).returncode


def jump_exit(h):
    if not os.path.exists(jump_sock_file(h)):
        return False
    subprocess.run(["ssh", "-o", f"ControlPath={JUMP_CPATH}", "-O", "exit", f"{h.user}@{h.host}"],
                   stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        os.unlink(jump_sock_file(h))
    except FileNotFoundError:
        pass
    return True


# ---------- `shell` 模式的 CLI 操作 ----------

def shell_exec(alias, session, command, timeout, password=None):
    ensure_daemon(alias, session)
    r = rpc(alias, session, {"cmd": "exec", "command": command, "timeout": timeout,
                             "password": password}, timeout=timeout + 30)
    if r is None:
        die("无法连接会话守护进程")
    if r.get("status") != "ok":
        die(r.get("error", "未知错误"))
    return r


def scp_spec(h, path):
    """拼 `scp` 的远程路径参数:远端 shell 和本地 shell 各引一次"""
    return shlex.quote(f"{h.user}@{h.host}:{shlex.quote(path)}")


def xfer_leg(hop, session, command, password, timeout):
    """在中转主机 `hop` 的会话里执行一条 `scp`,失败即报错退出。
    优先用 `sshpass` 喂密码,比 `pty` 应答稳定;中转机没有 `sshpass` 时
    回退到 `pty` 密码应答"""
    r = shell_exec(hop.alias, session,
                   f"sshpass -p {shlex.quote(password)} {command}", timeout)
    if r["exit"] == 127 and "sshpass" in r["output"]:
        r = shell_exec(hop.alias, session, command, timeout, password=password)
    if r["exit"] != 0:
        die(f"传输失败(在 {hop.alias} 上执行),退出码 {r['exit']}: {r['output'][-300:]}")


def shell_push(cp, target, session, local_path, remote_path, timeout):
    """上传:本机 -> 最外层中转 -> 逐跳 -> 目标,全部在中转主机的会话里编排"""
    local = get_host(cp, "local")
    if not local.password:
        die("文件传输需要 [local] 段配置 `host`/`user`/`password`")
    src = os.path.abspath(local_path)
    if not os.path.exists(src):
        die(f"本地路径不存在: {src}")
    hops = shell_hops(build_chain(cp, target.alias))
    tmp = f"/tmp/.ssh_mux_xfer_{rand_token()}"
    first_dst = tmp if len(hops) > 1 else remote_path
    xfer_leg(hops[0], session,
             f"scp -q -o StrictHostKeyChecking=no -P {local.port} "
             f"{scp_spec(local, src)} {shlex.quote(first_dst)}",
             local.password, timeout)
    for i in range(len(hops) - 1):
        dst = remote_path if i == len(hops) - 2 else tmp
        xfer_leg(hops[i], session,
                 f"scp -q -o StrictHostKeyChecking=no -P {hops[i + 1].port} "
                 f"{shlex.quote(tmp)} {scp_spec(hops[i + 1], dst)}",
                 hops[i + 1].password, timeout)
    if len(hops) > 1:
        for h in hops[:-1]:
            shell_exec(h.alias, session, f"rm -f {shlex.quote(tmp)}", 30)
    print(f"已上传 {local_path} -> {target.alias}:{remote_path}")


def shell_pull(cp, target, session, remote_path, local_path, timeout):
    """下载:目标 -> 逐跳 -> 最外层中转 -> 本机"""
    local = get_host(cp, "local")
    if not local.password:
        die("文件传输需要 [local] 段配置 `host`/`user`/`password`")
    hops = shell_hops(build_chain(cp, target.alias))
    tmp = f"/tmp/.ssh_mux_xfer_{rand_token()}"
    n = len(hops)
    for i in range(n - 1, 0, -1):
        src = remote_path if i == n - 1 else tmp
        xfer_leg(hops[i - 1], session,
                 f"scp -q -o StrictHostKeyChecking=no -P {hops[i].port} "
                 f"{scp_spec(hops[i], src)} {shlex.quote(tmp)}",
                 hops[i].password, timeout)
    src = tmp if n > 1 else remote_path
    xfer_leg(hops[0], session,
             f"scp -q -o StrictHostKeyChecking=no -P {local.port} "
             f"{shlex.quote(src)} {scp_spec(local, local_path)}",
             local.password, timeout)
    if n > 1:
        for h in hops[:-1]:
            shell_exec(h.alias, session, f"rm -f {shlex.quote(tmp)}", 30)
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
            print(f"{alias}  {h.addr()}  堡垒机(用户名路由,仅接力)")
            continue
        if host_mode(h) == "jump":
            state = "已连接" if jump_check(h) else "未连接"
            print(f"{alias}  {h.addr()}  jump  {state}")
        else:
            socks = glob.glob(shell_sock(alias, "*"))
            if not socks:
                print(f"{alias}  {h.addr()}  shell  无会话")
            for sk in sorted(socks):
                sess = os.path.basename(sk)[len(f"ssh_mux_s_{alias}_"):-len(".sock")]
                state = "已连接" if ping_session(alias, sess) else "守护进程无响应"
                print(f"{alias}  {h.addr()}  shell  会话 {sess}: {state}")


def cmd_list(cp):
    for alias in cp.sections():
        if alias == "local":
            continue
        h = get_host(cp, alias)
        via = f"  via={h.via}({h.via_mode})" if h.via else ""
        print(f"{alias}  {h.addr()}{via}")


def load_config_for_edit():
    """供增删主机用:配置文件不存在时从空配置起步"""
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
    alias = args.alias
    if not re.fullmatch(r"[A-Za-z0-9_.-]{1,32}", alias):
        die(f"别名只能包含字母、数字、_、-、.(最长 32): {alias!r}")
    cp = load_config_for_edit()
    if cp.has_section(alias):
        die(f"[{alias}] 已存在,先 `host remove {alias}` 再添加")
    if args.via and not cp.has_section(args.via):
        known = ", ".join(cp.sections()) or "(空)"
        die(f"`via` 指向的 [{args.via}] 不存在,现有: {known}")
    cp.add_section(alias)
    sec = cp[alias]
    sec["host"] = args.host
    if args.port:
        sec["port"] = str(args.port)
    if args.user:
        sec["user"] = args.user
    if args.password is not None:
        sec["password"] = args.password
    if args.via:
        sec["via"] = args.via
        sec["via_mode"] = args.via_mode
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
        if jump_exit(h):
            print(f"已断开: {alias}")
        else:
            print(f"没有活跃连接: {alias}")
        return
    socks = glob.glob(shell_sock(alias, session if session else "*"))
    if not socks:
        print(f"没有活跃连接: {alias}" + (f"(会话 {session})" if session else ""))
        return
    for sk in sorted(socks):
        sess = os.path.basename(sk)[len(f"ssh_mux_s_{alias}_"):-len(".sock")]
        r = rpc(alias, sess, {"cmd": "stop"}, timeout=5)
        if r and r.get("status") == "ok":
            print(f"已断开: {alias}(会话 {sess})")
        else:
            try:
                os.unlink(sk)
            except FileNotFoundError:
                pass
            print(f"守护进程无响应,已清理 socket: {alias}(会话 {sess})")


def run_exec_cli(argv):
    """`exec` 单独解析参数:`--session`/`--timeout` 允许出现在命令前后任意位置
    (`argparse` 的 `REMAINDER` 会把选项吞进命令,所以不用它)"""
    session, timeout, alias = "default", 120, None
    cmd = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--":
            cmd = argv[i + 1:]
            break
        if a == "--session" and i + 1 < len(argv):
            session = argv[i + 1]
            i += 2
            continue
        if a.startswith("--session="):
            session = a.split("=", 1)[1]
            i += 1
            continue
        if a == "--timeout" and i + 1 < len(argv):
            timeout = int(argv[i + 1])
            i += 2
            continue
        if a.startswith("--timeout="):
            timeout = int(a.split("=", 1)[1])
            i += 1
            continue
        if a in ("-h", "--help") and alias is None:
            print("用法: ssh-mux exec <别名> [--session S] [--timeout N] <命令...>")
            return
        if alias is None:
            alias = a
            i += 1
            continue
        cmd = argv[i:]
        break
    if not alias or not cmd:
        die("用法: ssh-mux exec <别名> [--session S] [--timeout N] <命令...>")
    cp = load_config()
    h = check_alias(cp, alias)
    command = " ".join(cmd).strip()
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

    ap = argparse.ArgumentParser(prog="ssh-mux", description="SSH 长连接管理(配置文件: " + CONFIG_PATH + ")")
    sub = ap.add_subparsers(dest="cmd", required=True)

    def add_session(p):
        p.add_argument("--session", default="default",
                       help="会话名,多 `agent` 并发时用于隔离(默认 `default`)")

    p = sub.add_parser("connect", help="建立长连接(已连接则跳过)")
    p.add_argument("alias")
    add_session(p)

    p = sub.add_parser("exec", help="复用长连接执行远程命令(未连接时自动建连;选项可放任意位置)")
    p.add_argument("alias")
    add_session(p)
    p.add_argument("--timeout", type=int, default=120, help="命令超时秒数(默认 120)")
    p.add_argument("command", nargs="*")

    p = sub.add_parser("push", help="上传文件到远程主机")
    p.add_argument("alias")
    add_session(p)
    p.add_argument("--timeout", type=int, default=XFER_TIMEOUT)
    p.add_argument("local_path")
    p.add_argument("remote_path")

    p = sub.add_parser("pull", help="从远程主机下载文件")
    p.add_argument("alias")
    add_session(p)
    p.add_argument("--timeout", type=int, default=XFER_TIMEOUT)
    p.add_argument("remote_path")
    p.add_argument("local_path")

    sub.add_parser("status", help="查看所有主机的连接状态")
    sub.add_parser("list", help="列出配置中的所有主机")

    hp = sub.add_parser("host", help="管理配置里的主机(增/删)")
    hsub = hp.add_subparsers(dest="host_cmd", required=True)
    p = hsub.add_parser("add", help="添加主机(只写配置,不建连)")
    p.add_argument("alias", help="主机别名;`local` 是文件中转用的保留段")
    p.add_argument("--host", required=True, help="主机地址(IP 或域名)")
    p.add_argument("--port", type=int, default=None, help="SSH 端口(默认 22)")
    p.add_argument("--user", default=None, help="登录用户名(默认当前本机用户)")
    p.add_argument("--password", default=None, help="登录密码,明文保存;不配则走密钥认证")
    p.add_argument("--via", default=None, help="跳板/堡垒机别名")
    p.add_argument("--via-mode", dest="via_mode", choices=["jump", "shell"], default="jump",
                   help="配合 --via:jump=标准 SSH 跳板(默认),shell=堡垒机")
    p.add_argument("--routing", choices=["username"], default=None,
                   help="username=用户名路由型堡垒机(登录名自动拼 <user>/<目标IP>/any)")
    p = hsub.add_parser("remove", help="删除主机(不影响已建立的会话)")
    p.add_argument("alias")

    p = sub.add_parser("exit", help="断开长连接")
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
            print(f"已建立会话链: {args.alias}(会话 {args.session})")

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
            for alias in cp.sections():
                if alias != "local":
                    cmd_exit(cp, alias, None)
        elif args.alias:
            cmd_exit(cp, args.alias, args.session)
        else:
            die("用法: `ssh-mux exit <别名> [--session S]` 或 `ssh-mux exit --all`")


if __name__ == "__main__":
    main()
