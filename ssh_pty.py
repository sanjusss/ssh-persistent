"""本机与远端执行器共用的终端控制模块，兼容 Python 3.4。"""

import fcntl
import os
import pty
import random
import re
import select
import shlex
import string
import struct
import subprocess
import termios
import time

AUTH_STEP_TIMEOUT = 30
DEBUG_PTY = bool(os.environ.get("SSH_MUX_DEBUG"))

PW_RX = re.compile(rb"(?i)password[^:\n]{0,40}:\s*$")
LOGIN_RX = re.compile(rb"(?i)login(\s+as)?:\s*$")
YESNO_RX = re.compile(rb"\(yes/no[^)]*\)\s*\??\s*$")
FAIL_RX = re.compile(rb"Permission denied|HOST IDENTIFICATION HAS CHANGED|Connection refused|Connection timed out")
ANSI_RX = re.compile(rb"\x1b\[[0-9;?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)")


def rand_token(n=8):
    return "".join((random.SystemRandom().choice(string.ascii_lowercase + string.digits) for _ in range(n)))


def tail(buf, n=300):
    return buf[-n:].replace(b"\r", b"").decode("utf-8", "replace").strip()


def clean_output(data):
    data = ANSI_RX.sub(b"", data)
    text = data.replace(b"\r\n", b"\n").replace(b"\r", b"").decode("utf-8", "replace")
    if text.startswith("\n"):
        text = text[1:]
    return text


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
        if len(self.buf) > 2000000:
            # 标注必须保留:调用方只能看到末尾,不标注会误以为输出完整
            note = "[ssh-mux: 输出超过 2MB,前面部分已丢弃,仅保留末尾]\n"
            self.buf = b"\n" + note.encode() + b"\n" + self.buf[-1000000:]

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
                raise ConnectionError('通道关闭,输出尾部: {}'.format(tail(self.buf))) from exc

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
            self._send_line("printf '__RD_%s__\\n' {}".format(tok))
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
            ack = '{}_{}'.format(token, index)
            self.buf = b""
            remaining = deadline - time.time()
            if remaining <= 0:
                raise TimeoutError("传输命令内容超时，尚未执行命令")
            self._send_line(" {}={}$(printf '%b_' '{}'); {}=${{{}%_}}; printf '__CH_%s__\\n' {}".format(name, previous, encoded, name, name, ack))
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
        xs = '__XS_{}__'.format(tok).encode()
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
        self._send_line(" printf '__XS_%s__\\n' {}; eval {}; printf '__XE_%s__%s\\n' {} $?{}".format(tok, source, tok, cleanup))
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
                raise TimeoutError('命令超过 {} 秒未结束,已发送中断'.format(timeout))
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
                self._send_line("printf '__RC_%s__\\n' {}".format(tok))
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
