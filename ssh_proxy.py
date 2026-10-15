"""HTTP CONNECT 与 SOCKS5 代理握手及字节转发；本机与远端共用，兼容 Python 3.4。

握手与传输通道分离，支持两种到代理的字节通道：
- 直接 TCP 通道：程序所在节点直接连接代理（本机首段或远端终端段）。
- 子进程标准输入输出通道：经 `ssh -W 代理地址:端口 跳板` 访问只有跳板可达的代理。

程序入口读取独立的 JSON 配置文件，包含该段代理、目标、转发命令和日志路径。
标准输出只传握手成功后的字节；诊断信息写入权限 600 的日志，不含凭据。
退出码：正常结束 0，配置错误 2，连接、握手或转发错误 1。
"""

import base64
import json
import os
import select
import socket
import subprocess
import sys
import time

HANDSHAKE_TIMEOUT = 10  # 代理连接和握手共用的期限（秒）

# 地址中的这些字符会改变 shell 命令或协议文本的含义，一律拒绝
_BAD_ADDR_CHARS = frozenset(" \t\r\n\x00%")


class ProxyError(Exception):
    """连接、握手或转发失败，对应退出码 1。"""


class ProxyConfigError(Exception):
    """配置错误，对应退出码 2。"""


def check_address(value, what):
    """地址作为字面量传递，拒绝空白、回车、换行、NUL、% 和非 ASCII 字符。"""
    if not isinstance(value, str) or not value:
        raise ProxyConfigError(what + " 地址为空")
    if any(c in _BAD_ADDR_CHARS for c in value):
        raise ProxyConfigError(what + " 地址含空白、回车、换行、NUL 或 % 等非法字符")
    # 请求行按 ASCII 编码；非 ASCII 地址要在这里报配置错误，而不是内部错误
    if not all(ord(c) < 128 for c in value):
        raise ProxyConfigError(
            what + " 地址含非 ASCII 字符，请改用 Punycode 或地址字面量"
        )
    return value


def check_port(value, what):
    try:
        port = int(value)
    except (TypeError, ValueError):
        raise ProxyConfigError(what + " 端口必须是整数")
    if not 1 <= port <= 65535:
        raise ProxyConfigError(what + " 端口超出 1-65535 范围")
    return port


def check_http_auth(user, password):
    """只在配置用户名时发送 Basic 认证；密码允许为空。"""
    if user is None:
        if password:
            raise ProxyConfigError("只有代理密码而没有用户名")
        return None
    if not user or any(c in user for c in (":", "\r", "\n", "\x00")):
        raise ProxyConfigError("代理用户名为空或包含冒号、回车、换行、空字节")
    return (user, password or "")


def check_socks5_auth(user, password):
    """用户名和密码各为 1 到 255 字节；只有一种认证方法，不降级。"""
    if user is None:
        if password:
            raise ProxyConfigError("只有代理密码而没有用户名")
        return None
    ulen = len(user.encode("utf-8"))
    plen = len((password or "").encode("utf-8"))
    if not 1 <= ulen <= 255 or not 1 <= plen <= 255:
        raise ProxyConfigError("SOCKS5 代理用户名和密码各须为 1-255 字节")
    return (user, password or "")


def load_config(path):
    """读取并校验 JSON 配置；错误信息不包含用户名和密码。"""
    try:
        with open(path, "r") as file:
            cfg = json.load(file)
    except (OSError, ValueError) as exc:
        raise ProxyConfigError("无法读取代理配置文件")
    if not isinstance(cfg, dict):
        raise ProxyConfigError("代理配置必须是 JSON 对象")
    proxy = cfg.get("proxy")
    if not isinstance(proxy, dict):
        raise ProxyConfigError("代理配置缺少 proxy 段")
    kind = proxy.get("type")
    if kind not in ("http", "socks5"):
        raise ProxyConfigError("未知代理类型或不支持代理链表达式")
    proxy["host"] = check_address(proxy.get("host"), "代理")
    proxy["port"] = check_port(proxy.get("port"), "代理")
    user = proxy.get("user")
    password = proxy.get("password")
    if user is not None and not isinstance(user, str):
        raise ProxyConfigError("代理用户名必须是字符串")
    if password is not None and not isinstance(password, str):
        raise ProxyConfigError("代理密码必须是字符串")
    if kind == "http":
        check_http_auth(user, password)
    else:
        check_socks5_auth(user, password)
    proxy["user"], proxy["password"] = user, password
    target = cfg.get("target")
    if not isinstance(target, dict):
        raise ProxyConfigError("代理配置缺少 target 段")
    target["host"] = check_address(target.get("host"), "目标")
    target["port"] = check_port(target.get("port"), "目标")
    relay = cfg.get("relay")
    if relay is not None:
        if (
            not isinstance(relay, list)
            or not relay
            or any(not isinstance(a, str) or not a for a in relay)
        ):
            raise ProxyConfigError("relay 转发命令必须是非空字符串列表")
    log = cfg.get("log")
    if log is not None and not isinstance(log, str):
        raise ProxyConfigError("log 必须是路径字符串")
    timeout = cfg.get("timeout", HANDSHAKE_TIMEOUT)
    try:
        timeout = float(timeout)
    except (TypeError, ValueError):
        raise ProxyConfigError("timeout 必须是数字")
    if timeout <= 0:
        raise ProxyConfigError("timeout 必须大于 0")
    pidfile = cfg.get("pidfile")
    if pidfile is not None and not isinstance(pidfile, str):
        raise ProxyConfigError("pidfile 必须是路径字符串")
    return {
        "proxy": proxy,
        "target": target,
        "relay": relay,
        "log": log,
        "timeout": timeout,
        "pidfile": pidfile,
    }


# ---------- 字节通道 ----------


class TcpChannel:
    """直接 TCP 连接到代理；代理地址由程序所在节点解析。"""

    def __init__(self, host, port, deadline):
        remaining = deadline - time.time()
        if remaining <= 0:
            raise ProxyError("连接代理超时")
        try:
            self.sock = socket.create_connection((host, port), timeout=remaining)
        except (OSError, socket.timeout):
            raise ProxyError("无法连接代理 %s:%d" % (host, port))
        self.sock.setblocking(False)

    def fileno(self):
        return self.sock.fileno()

    def read(self, size, deadline):
        timeout = None if deadline is None else max(0.0, deadline - time.time())
        r, _, _ = select.select([self.sock], [], [], timeout)
        if not r:
            raise ProxyError("代理握手超时")
        try:
            return self.sock.recv(size)
        except (BlockingIOError, InterruptedError):
            return self.read(size, deadline)
        except OSError:
            raise ProxyError("代理连接中断")

    def write(self, data, deadline):
        while data:
            timeout = None if deadline is None else max(0.0, deadline - time.time())
            _, w, _ = select.select([], [self.sock], [], timeout)
            if not w:
                raise ProxyError("代理握手超时")
            try:
                sent = self.sock.send(data)
            except OSError:
                raise ProxyError("代理连接中断")
            data = data[sent:]

    def shutdown_write(self):
        try:
            self.sock.shutdown(socket.SHUT_WR)
        except OSError:
            pass

    def close(self):
        try:
            self.sock.close()
        except OSError:
            pass


class ProcessChannel:
    """子进程的标准输入输出作为字节通道（如 `ssh -W 代理地址:端口 跳板`）。

    不再调用 setsid：本机后台连接的外层包装进程已执行一次。
    子进程退出、管道关闭和超时都视为该段失败。
    """

    def __init__(self, argv, errlog):
        self.argv = argv
        try:
            self.proc = subprocess.Popen(
                argv, stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=errlog
            )
        except (OSError, ValueError):
            raise ProxyError("无法启动转发命令 %s" % os.path.basename(argv[0]))

    def fileno(self):
        return self.proc.stdout.fileno()

    def _dead(self):
        if self.proc.poll() is None:
            return None
        return ProxyError(
            "转发进程已退出（状态 %s），转发可能被拒绝" % self.proc.returncode
        )

    def read(self, size, deadline):
        timeout = None if deadline is None else max(0.0, deadline - time.time())
        r, _, _ = select.select([self.proc.stdout], [], [], timeout)
        if not r:
            dead = self._dead()
            if dead is not None:
                raise dead
            raise ProxyError("代理握手超时")
        try:
            return os.read(self.proc.stdout.fileno(), size)
        except OSError:
            dead = self._dead()
            if dead is not None:
                raise dead
            raise ProxyError("转发通道已关闭")

    def write(self, data, deadline):
        while data:
            timeout = None if deadline is None else max(0.0, deadline - time.time())
            _, w, _ = select.select([], [self.proc.stdin], [], timeout)
            if not w:
                raise ProxyError("代理握手超时")
            try:
                sent = os.write(self.proc.stdin.fileno(), data)
            except OSError:
                dead = self._dead()
                if dead is not None:
                    raise dead
                raise ProxyError("转发通道已关闭")
            data = data[sent:]

    def shutdown_write(self):
        try:
            self.proc.stdin.close()
        except OSError:
            pass

    def close(self):
        try:
            if self.proc.poll() is None:
                self.proc.kill()
                self.proc.wait(timeout=5)
        except Exception:
            pass
        for pipe in (self.proc.stdin, self.proc.stdout):
            try:
                pipe.close()
            except Exception:
                pass


def read_exact(channel, size, deadline, what):
    """从通道读取固定长度；提前关闭视为握手失败。"""
    data = b""
    while len(data) < size:
        chunk = channel.read(size - len(data), deadline)
        if not chunk:
            raise ProxyError(what + "：通道提前关闭")
        data += chunk
    return data


# ---------- HTTP CONNECT ----------


def http_connect(channel, proxy, target, deadline, log):
    """发送一次 CONNECT；只在状态码 200 且响应头读完后转发数据。

    响应头后粘连的字节属于目标数据，原样返回给调用方转发；
    Content-Length 不用于截断；非 200（含 407）直接失败，不重试。
    """
    auth = check_http_auth(proxy.get("user"), proxy.get("password"))
    host, port = target["host"], target["port"]
    shown = "[%s]" % host if ":" in host else host
    lines = ["CONNECT %s:%d HTTP/1.1" % (shown, port), "Host: %s:%d" % (shown, port)]
    if auth is not None:
        token = base64.b64encode(("%s:%s" % auth).encode("utf-8")).decode("ascii")
        lines.append("Proxy-Authorization: Basic " + token)
    channel.write(("\r\n".join(lines) + "\r\n\r\n").encode("ascii"), deadline)
    buf = b""
    while b"\r\n\r\n" not in buf:
        if len(buf) > 65536:
            raise ProxyError("代理响应头过长")
        chunk = channel.read(4096, deadline)
        if not chunk:
            raise ProxyError("代理在握手期间关闭连接")
        buf += chunk
    head, rest = buf.split(b"\r\n\r\n", 1)
    status = head.split(b"\r\n", 1)[0]
    parts = status.split(None, 2)
    code = None
    if len(parts) >= 2 and parts[0].startswith(b"HTTP/"):
        try:
            code = int(parts[1])
        except ValueError:
            code = None
    if code != 200:
        if code == 407:
            raise ProxyError("代理要求认证或认证被拒绝（407），不自动重试")
        raise ProxyError(
            "代理拒绝连接（状态 %s）" % (code if code is not None else "未知")
        )
    log("HTTP 代理握手成功")
    return rest


# ---------- SOCKS5 ----------


def _socks5_address(host):
    """目标域名按字面交给代理解析；IP 字面量使用对应地址类型。"""
    try:
        return b"\x01" + socket.inet_pton(socket.AF_INET, host)
    except (OSError, ValueError):
        pass
    try:
        return b"\x04" + socket.inet_pton(socket.AF_INET6, host)
    except (OSError, ValueError):
        pass
    encoded = host.encode("utf-8")
    if len(encoded) > 255:
        raise ProxyConfigError("目标域名过长")
    return b"\x03" + bytes(bytearray([len(encoded)])) + encoded


def socks5_connect(channel, proxy, target, deadline, log):
    """只提供一种认证方法：无用户时无认证，有用户时用户名密码；不降级。

    成功后才转发数据；应答中的绑定地址被完整消费，不混入目标数据。
    """
    auth = check_socks5_auth(proxy.get("user"), proxy.get("password"))
    method = b"\x02" if auth is not None else b"\x00"
    channel.write(b"\x05\x01" + method, deadline)
    resp = read_exact(channel, 2, deadline, "SOCKS5 方法协商")
    if resp[0:1] != b"\x05":
        raise ProxyError("SOCKS5 应答版本不符")
    if resp[1:2] != method:
        raise ProxyError("代理未选择提供的认证方法，不降级改用其他方法")
    if auth is not None:
        user = auth[0].encode("utf-8")
        password = auth[1].encode("utf-8")
        channel.write(
            b"\x01"
            + bytes(bytearray([len(user)]))
            + user
            + bytes(bytearray([len(password)]))
            + password,
            deadline,
        )
        verdict = read_exact(channel, 2, deadline, "SOCKS5 认证应答")
        if verdict[1:2] != b"\x00":
            raise ProxyError("SOCKS5 代理认证失败")
    request = (
        b"\x05\x01\x00"
        + _socks5_address(target["host"])
        + struct_pack_port(target["port"])
    )
    channel.write(request, deadline)
    head = read_exact(channel, 4, deadline, "SOCKS5 连接应答")
    if head[0:1] != b"\x05":
        raise ProxyError("SOCKS5 连接应答版本不符")
    if head[1:2] != b"\x00":
        raise ProxyError("代理连接目标失败（应答码 %d）" % head[1])
    atyp = head[3]
    if atyp == 1:
        read_exact(channel, 4, deadline, "SOCKS5 绑定地址")
    elif atyp == 4:
        read_exact(channel, 16, deadline, "SOCKS5 绑定地址")
    elif atyp == 3:
        size = read_exact(channel, 1, deadline, "SOCKS5 绑定地址")[0]
        read_exact(channel, size, deadline, "SOCKS5 绑定地址")
    else:
        raise ProxyError("SOCKS5 绑定地址类型未知")
    read_exact(channel, 2, deadline, "SOCKS5 绑定端口")
    log("SOCKS5 代理握手成功")
    return b""


def struct_pack_port(port):
    return bytes(bytearray([(port >> 8) & 0xFF, port & 0xFF]))


# ---------- 双向转发 ----------


def _write_all(fd, data):
    while data:
        sent = os.write(fd, data)
        data = data[sent:]


def pump(channel, initial):
    """标准输入输出与通道之间双向转发；任一端正常关闭后结束。"""
    if initial:
        _write_all(1, initial)
    stdin_open = True
    channel_open = True
    while channel_open:
        readers = [channel.fileno()] + ([0] if stdin_open else [])
        try:
            readable, _, _ = select.select(readers, [], [])
        except (OSError, select.error):
            raise ProxyError("转发等待失败")
        if channel.fileno() in readable:
            data = channel.read(65536, None)
            if not data:
                channel_open = False
            else:
                try:
                    _write_all(1, data)
                except OSError:
                    return  # SSH 侧已关闭
        if stdin_open and 0 in readable:
            try:
                data = os.read(0, 65536)
            except OSError:
                data = b""
            if not data:
                stdin_open = False
                channel.shutdown_write()
            else:
                channel.write(data, None)


# ---------- 入口 ----------


def open_log(path):
    """诊断日志只允许属主读写；日志不含凭据。"""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
    os.fchmod(fd, 0o600)
    return os.fdopen(fd, "a", buffering=1)


def main(argv):
    """程序入口：`程序名 配置文件`。返回进程退出码。"""
    # 剥除经 ssh/sshpass 传入的密码变量：不留给 /proc/<pid>/environ 和子进程
    for name in ("SSHPASS", "SSH_MUX_PROXY_USER", "SSH_MUX_PROXY_PASS"):
        os.environ.pop(name, None)
    if len(argv) != 2:
        sys.stderr.write("用法: ssh_proxy <配置文件>\n")
        return 2
    try:
        cfg = load_config(argv[1])
    except ProxyConfigError as exc:
        sys.stderr.write("ssh-proxy: 配置错误: %s\n" % exc)
        return 2
    log_path = cfg["log"] or (argv[1] + ".log")
    log_file = open_log(log_path)
    os.dup2(log_file.fileno(), 2)  # 标准错误转入私有日志

    def log(msg):
        log_file.write("%s %s\n" % (time.strftime("%H:%M:%S"), msg))

    try:
        if cfg["pidfile"]:
            with open(cfg["pidfile"], "w") as file:
                file.write(str(os.getpid()))
            os.chmod(cfg["pidfile"], 0o600)
        deadline = time.time() + cfg["timeout"]
        proxy = cfg["proxy"]
        if cfg["relay"]:
            channel = ProcessChannel(cfg["relay"], log_file)
        else:
            channel = TcpChannel(proxy["host"], proxy["port"], deadline)
        try:
            if proxy["type"] == "http":
                rest = http_connect(channel, proxy, cfg["target"], deadline, log)
            else:
                rest = socks5_connect(channel, proxy, cfg["target"], deadline, log)
            pump(channel, rest)
        finally:
            channel.close()
    except ProxyConfigError as exc:
        log("配置错误: %s" % exc)
        return 2
    except ProxyError as exc:
        log("代理失败: %s" % exc)
        return 1
    except Exception as exc:
        log("内部错误: %s" % type(exc).__name__)
        return 1
    log("连接正常结束")
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv))
