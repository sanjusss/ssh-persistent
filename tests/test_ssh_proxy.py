"""ssh_proxy.py 代理协议测试；全部使用本机回环假代理，不访问外网。"""

import base64
import importlib.util
import json
import os
from pathlib import Path
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "ssh_proxy_under_test", ROOT / "ssh_proxy.py"
)
ssh_proxy = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(ssh_proxy)


class FakeProxy:
    """本机回环假代理：记录握手字节，按给定的应答脚本行动，之后回显数据。"""

    def __init__(self, handler):
        self.handler = handler
        self.connections = []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        self.thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.thread.start()

    def _accept_loop(self):
        while True:
            try:
                conn, peer = self.server.accept()
            except OSError:
                return
            self.connections.append(peer)
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        conn.settimeout(10)
        try:
            self.handler(conn)
        except (OSError, socket.timeout):
            pass
        finally:
            try:
                conn.close()
            except OSError:
                pass

    def echo_after(self, conn):
        """握手完成后回显收到的数据；对端关闭写方向后关闭连接。"""
        while True:
            try:
                data = conn.recv(65536)
            except (OSError, socket.timeout):
                break
            if not data:
                break
            conn.sendall(data)
        conn.close()

    def close(self):
        self.server.close()


def read_head(conn):
    data = b""
    while b"\r\n\r\n" not in data:
        chunk = conn.recv(4096)
        if not chunk:
            raise ConnectionError("连接提前关闭")
        data += chunk
    return data


class HelperRun:
    """以子进程方式运行 ssh_proxy.py 入口，标准输入输出用管道连接。"""

    def __init__(self, root, cfg, extra_env=None):
        self.dir = Path(tempfile.mkdtemp(prefix="ssh-proxy-test-", dir=root))
        self.cfg_path = self.dir / "proxy.json"
        self.cfg_path.write_text(json.dumps(cfg))
        env = dict(os.environ)
        if extra_env:
            env.update(extra_env)
        self.proc = subprocess.Popen(
            [sys.executable, str(ROOT / "ssh_proxy.py"), str(self.cfg_path)],
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env,
        )

    def expect_exit(self, code, timeout=15):
        try:
            self.proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            self.proc.kill()
            self.proc.wait(timeout=5)
            raise AssertionError("辅助进程未退出")
        self.out = self.proc.stdout.read() if not self.proc.stdout.closed else b""
        for pipe in (self.proc.stdin, self.proc.stdout, self.proc.stderr):
            try:
                if pipe and not pipe.closed:
                    pipe.close()
            except OSError:
                pass
        return self.proc.returncode


def base_cfg(proxy_port, kind="http", target=("target.invalid", 22), **kw):
    cfg = {
        "proxy": {"type": kind, "host": "127.0.0.1", "port": proxy_port},
        "target": {"host": target[0], "port": target[1]},
    }
    cfg.update(kw)
    return cfg


class HttpConnectTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-proxy-http-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_banner_glued_after_headers_and_echo(self):
        captured = []

        def handler(conn):
            captured.append(read_head(conn))
            conn.sendall(
                b"HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nSSH-2.0-FakeBanner\r\n"
            )
            FakeProxy.echo_after(self, conn)

        server = FakeProxy(handler)
        self.addCleanup(server.close)
        run = HelperRun(self.root, base_cfg(server.port))
        data = run.proc.stdout.readline()
        self.assertEqual(data, b"SSH-2.0-FakeBanner\r\n")  # Content-Length 不截断横幅
        run.proc.stdin.write(b"ping\n")
        run.proc.stdin.flush()
        self.assertEqual(run.proc.stdout.readline(), b"ping\n")
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(0), 0)
        self.assertTrue(
            captured[0].startswith(b"CONNECT target.invalid:22 HTTP/1.1\r\n")
        )
        self.assertNotIn(b"Proxy-Authorization", captured[0])

    def test_basic_auth_and_empty_password(self):
        captured = []

        def handler(conn):
            captured.append(read_head(conn))
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            conn.close()

        server = FakeProxy(handler)
        self.addCleanup(server.close)
        cfg = base_cfg(server.port)
        cfg["proxy"]["user"] = "alice"
        cfg["proxy"]["password"] = ""
        run = HelperRun(self.root, cfg)
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(0), 0)
        expected = base64.b64encode(b"alice:").decode()
        self.assertIn(("Proxy-Authorization: Basic " + expected).encode(), captured[0])

    def test_auth_rejected_407_is_not_retried(self):
        attempts = []

        def handler(conn):
            attempts.append(read_head(conn))
            conn.sendall(
                b"HTTP/1.1 407 Proxy Authentication Required\r\n\r\nsecret-body"
            )
            time.sleep(0.2)
            conn.close()

        server = FakeProxy(handler)
        self.addCleanup(server.close)
        cfg = base_cfg(server.port)
        cfg["proxy"]["user"] = "alice"
        cfg["proxy"]["password"] = "test-密码-407"
        log_path = self.root / "proxy.log"
        cfg["log"] = str(log_path)
        run = HelperRun(self.root, cfg)
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(1), 1)
        self.assertEqual(run.out, b"")  # 握手失败标准输出为空
        self.assertEqual(len(attempts), 1)  # 407 不重试
        time.sleep(0.3)
        run.proc.wait(timeout=5)
        log = log_path.read_text()
        self.assertNotIn("test-密码-407", log)
        self.assertNotIn(base64.b64encode("alice:test-密码-407".encode()).decode(), log)
        self.assertEqual(stat.S_IMODE(log_path.stat().st_mode), 0o600)

    def test_non_200_body_never_reaches_stdout(self):
        def handler(conn):
            read_head(conn)
            conn.sendall(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 4\r\n\r\nBODY")

        server = FakeProxy(handler)
        self.addCleanup(server.close)
        run = HelperRun(self.root, base_cfg(server.port))
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(1), 1)
        self.assertEqual(run.out, b"")

    def test_invalid_auth_config_exits_2(self):
        for update in (
            {"password": "only-pass"},
            {"user": "a:b"},
            {"user": "a\r\nb"},
            {"user": ""},
        ):
            cfg = base_cfg(1)
            cfg["proxy"].update(update)
            run = HelperRun(self.root, cfg)
            self.assertEqual(run.expect_exit(2), 2, update)
            self.assertEqual(run.out, b"")

    def test_config_errors_exit_2(self):
        bad = []
        cfg = base_cfg(1, kind="gopher")
        bad.append(cfg)
        cfg = base_cfg(1, kind="http,socks5")  # 代理链表达式
        bad.append(cfg)
        cfg = base_cfg(1)
        cfg["proxy"]["port"] = 70000
        bad.append(cfg)
        cfg = base_cfg(1)
        cfg["proxy"]["port"] = 0
        bad.append(cfg)
        cfg = base_cfg(1)
        cfg["proxy"]["host"] = "has space"
        bad.append(cfg)
        cfg = base_cfg(1)
        cfg["target"]["host"] = "100%evil"
        bad.append(cfg)
        cfg = base_cfg(1)
        del cfg["target"]
        bad.append(cfg)
        for item in bad:
            run = HelperRun(self.root, item)
            self.assertEqual(run.expect_exit(2), 2, item)

    def test_unreachable_proxy_exits_1(self):
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(("127.0.0.1", 0))
        port = server.getsockname()[1]
        server.close()  # 立即释放端口，确保连接被拒绝
        run = HelperRun(self.root, base_cfg(port))
        self.assertEqual(run.expect_exit(1), 1)
        self.assertEqual(run.out, b"")

    def test_handshake_timeout(self):
        def handler(conn):
            read_head(conn)
            time.sleep(30)  # 收到请求后不应答

        server = FakeProxy(handler)
        self.addCleanup(server.close)
        cfg = base_cfg(server.port, timeout=1)
        started = time.monotonic()
        run = HelperRun(self.root, cfg)
        self.assertEqual(run.expect_exit(1, timeout=10), 1)
        self.assertLess(time.monotonic() - started, 8)


class Socks5Tests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-proxy-socks5-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def test_no_auth_handshake_domain_literal_and_bound_address(self):
        captured = {}

        def handler(conn):
            captured["greeting"] = conn.recv(3)
            conn.sendall(b"\x05\x00")
            head = b""
            while len(head) < 4:
                head += conn.recv(4 - len(head))
            captured["request_head"] = head
            atyp = head[3]
            if atyp == 3:
                size = conn.recv(1)[0]
                captured["domain"] = conn.recv(size)
            captured["port"] = conn.recv(2)
            # 绑定地址后紧跟 SSH 横幅
            conn.sendall(b"\x05\x00\x00\x01\x7f\x00\x00\x01\x04\x00SSH-2.0-BySocks\r\n")
            FakeProxy.echo_after(self, conn)

        server = FakeProxy(handler)
        self.addCleanup(server.close)
        run = HelperRun(self.root, base_cfg(server.port, kind="socks5"))
        self.assertEqual(
            run.proc.stdout.readline(), b"SSH-2.0-BySocks\r\n"
        )  # 绑定地址不混入数据
        run.proc.stdin.write(b"via-socks\n")
        run.proc.stdin.flush()
        self.assertEqual(run.proc.stdout.readline(), b"via-socks\n")
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(0), 0)
        self.assertEqual(captured["greeting"], b"\x05\x01\x00")
        self.assertEqual(captured["request_head"][:3], b"\x05\x01\x00")
        self.assertEqual(captured["request_head"][3], 3)  # 域名按字面发送
        self.assertEqual(captured["domain"], b"target.invalid")
        self.assertEqual(captured["port"], b"\x00\x16")

    def test_user_password_auth(self):
        captured = {}

        def handler(conn):
            captured["greeting"] = conn.recv(3)
            conn.sendall(b"\x05\x02")
            auth = b""
            while len(auth) < 2:
                auth += conn.recv(2 - len(auth))
            ulen = auth[1]
            user = conn.recv(ulen)
            plen = conn.recv(1)[0]
            password = conn.recv(plen)
            captured["auth"] = (user, password)
            conn.sendall(b"\x01\x00")
            conn.recv(4)
            conn.recv(1)  # atyp 3 的长度字节在请求里按域名处理
            # 上面多读了一个字节：重新按域名请求读取
            raise RuntimeError("占位")

        # 上面的 handler 结构容易出错，改为完整读取请求
        def full_handler(conn):
            captured["greeting"] = conn.recv(3)
            conn.sendall(b"\x05\x02")
            first = conn.recv(2)
            ulen = first[1]
            user = b""
            while len(user) < ulen:
                user += conn.recv(ulen - len(user))
            plen = conn.recv(1)[0]
            password = b""
            while len(password) < plen:
                password += conn.recv(plen - len(password))
            captured["auth"] = (user, password)
            conn.sendall(b"\x01\x00")
            head = conn.recv(4)
            if head[3] == 3:
                size = conn.recv(1)[0]
                conn.recv(size)
            else:
                conn.recv(4 if head[3] == 1 else 16)
            conn.recv(2)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            conn.close()

        server = FakeProxy(full_handler)
        self.addCleanup(server.close)
        cfg = base_cfg(server.port, kind="socks5")
        cfg["proxy"]["user"] = "bob"
        cfg["proxy"]["password"] = "passw0rd"
        run = HelperRun(self.root, cfg)
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(0), 0)
        self.assertEqual(captured["greeting"], b"\x05\x01\x02")  # 只提供一种方法
        self.assertEqual(captured["auth"], (b"bob", b"passw0rd"))

    def test_method_mismatch_is_not_downgraded(self):
        state = {"requests": 0}

        def handler(conn):
            conn.recv(3)
            conn.sendall(b"\x05\x00")  # 客户端只提供用户名密码，服务端选无认证
            conn.settimeout(2)
            try:
                if conn.recv(10):
                    state["requests"] += 1  # 客户端继续发送了认证或连接数据
            except socket.timeout:
                pass

        server = FakeProxy(handler)
        self.addCleanup(server.close)
        cfg = base_cfg(server.port, kind="socks5")
        cfg["proxy"]["user"] = "bob"
        cfg["proxy"]["password"] = "passw0rd"
        run = HelperRun(self.root, cfg)
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(1), 1)
        self.assertEqual(run.out, b"")
        self.assertEqual(state["requests"], 0)  # 未继续发送认证或连接请求

    def test_auth_failure_and_connect_failure(self):
        def refuse_auth(conn):
            conn.recv(3)
            conn.sendall(b"\x05\x02")
            conn.recv(2 + 3 + 1 + 4)
            conn.sendall(b"\x01\x01")  # 认证失败
            time.sleep(0.1)

        server = FakeProxy(refuse_auth)
        self.addCleanup(server.close)
        cfg = base_cfg(server.port, kind="socks5")
        cfg["proxy"]["user"] = "bob"
        cfg["proxy"]["password"] = "bad!"
        run = HelperRun(self.root, cfg)
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(1), 1)

        def refuse_connect(conn):
            conn.recv(3)
            conn.sendall(b"\x05\x00")
            head = conn.recv(4)
            size = conn.recv(1)[0]
            conn.recv(size + 2)
            conn.sendall(b"\x05\x03\x00\x01\x00\x00\x00\x00\x00\x00")  # 网络不可达
            time.sleep(0.1)

        server2 = FakeProxy(refuse_connect)
        self.addCleanup(server2.close)
        run = HelperRun(self.root, base_cfg(server2.port, kind="socks5"))
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(1), 1)

    def test_socks5_auth_length_rules(self):
        for user, password in ((None, "x"), ("", "x"), ("u" * 256, "x"), ("u", "")):
            cfg = base_cfg(1, kind="socks5")
            cfg["proxy"]["user"] = user
            cfg["proxy"]["password"] = password
            run = HelperRun(self.root, cfg)
            self.assertEqual(run.expect_exit(2), 2, (user, password))


class RelayChannelTests(unittest.TestCase):
    """子进程标准输入输出通道：经 `ssh -W` 风格的转发命令访问代理。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-proxy-relay-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.relay = self.root / "relay.py"
        # 模拟 ssh -W：把标准输入输出桥接到目标地址（跳板视角的地址映射）
        self.relay.write_text(
            "import os,socket,select,sys\n"
            "sock = socket.create_connection((sys.argv[1], int(os.environ['RELAY_REAL_PORT'])))\n"
            "fds = [0, sock.fileno()]\n"
            "while True:\n"
            "    r, _, _ = select.select(fds, [], [])\n"
            "    for fd in r:\n"
            "        data = os.read(fd, 65536)\n"
            "        if not data:\n"
            "            sys.exit(0)\n"
            "        out = sock.fileno() if fd == 0 else 1\n"
            "        os.write(out, data)\n"
        )
        self.fail_relay = self.root / "fail_relay.py"
        self.fail_relay.write_text(
            "import sys\nsys.stderr.write('channel open failed\\n')\nsys.exit(1)\n"
        )

    def socks5_handler(self, conn):
        conn.recv(3)
        conn.sendall(b"\x05\x00")
        head = conn.recv(4)
        if head[3] == 3:
            size = conn.recv(1)[0]
            conn.recv(size)
        else:
            conn.recv(4)
        conn.recv(2)
        conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
        FakeProxy.echo_after(self, conn)

    def test_handshake_over_relay_only_reachable_through_it(self):
        server = FakeProxy(self.socks5_handler)
        self.addCleanup(server.close)
        cfg = base_cfg(9, kind="socks5")  # 端口 9 本机不可达；只有转发命令知道真实端口
        cfg["relay"] = [sys.executable, str(self.relay), "127.0.0.1", "9"]
        run = HelperRun(self.root, cfg, extra_env={"RELAY_REAL_PORT": str(server.port)})
        run.proc.stdin.write(b"through-relay\n")
        run.proc.stdin.flush()
        self.assertEqual(run.proc.stdout.readline(), b"through-relay\n")
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(0), 0)

    def test_relay_refusal_is_not_bypassed(self):
        server = FakeProxy(self.socks5_handler)
        self.addCleanup(server.close)
        cfg = base_cfg(server.port, kind="socks5")
        cfg["relay"] = [sys.executable, str(self.fail_relay)]
        run = HelperRun(self.root, cfg)
        run.proc.stdin.close()
        self.assertEqual(run.expect_exit(1), 1)
        self.assertEqual(run.out, b"")
        self.assertEqual(server.connections, [])  # 没有绕过转发直接连接

    def test_relay_process_exit_mid_handshake_fails(self):
        cfg = base_cfg(1, kind="http")
        cfg["relay"] = [sys.executable, "-c", "import sys; sys.exit(3)"]
        run = HelperRun(self.root, cfg)
        self.assertEqual(run.expect_exit(1), 1)

    def test_main_strips_secret_env_before_relay(self):
        # SSHPASS 等密码变量不经代理进程留给转发子进程和 /proc/<pid>/environ
        dump = self.root / "env.json"
        probe = self.root / "probe.py"
        probe.write_text(
            "import json, os, sys\n"
            "keys = ('SSHPASS', 'SSH_MUX_PROXY_USER', 'SSH_MUX_PROXY_PASS')\n"
            "json.dump({k: 1 for k in keys if k in os.environ}, open(sys.argv[1], 'w'))\n"
        )
        cfg = base_cfg(1, kind="socks5")
        cfg["relay"] = [sys.executable, str(probe), str(dump)]
        run = HelperRun(
            self.root,
            cfg,
            extra_env={
                "SSHPASS": "login-pw-机密",
                "SSH_MUX_PROXY_USER": "u",
                "SSH_MUX_PROXY_PASS": "p",
            },
        )
        run.proc.stdin.close()
        run.expect_exit(1)  # 探测脚本写完环境即退出，通道随之失败
        self.assertEqual(json.loads(dump.read_text()), {})


class ChannelUnitTests(unittest.TestCase):
    def test_tcp_channel_timeout_and_close(self):
        server = FakeProxy(lambda conn: time.sleep(5))
        self.addCleanup(server.close)
        deadline = time.time() + 0.3
        channel = ssh_proxy.TcpChannel("127.0.0.1", server.port, deadline)
        with self.assertRaises(ssh_proxy.ProxyError):
            channel.read(10, deadline)
        channel.close()

    def test_config_validation_unit(self):
        with self.assertRaises(ssh_proxy.ProxyConfigError):
            ssh_proxy.check_port(65536, "测试")
        with self.assertRaises(ssh_proxy.ProxyConfigError):
            ssh_proxy.check_address("a\nb", "测试")
        self.assertEqual(ssh_proxy.check_http_auth("u", None), ("u", ""))
        self.assertIsNone(ssh_proxy.check_http_auth(None, None))

    def test_non_ascii_address_rejected_as_config_error(self):
        # 非 ASCII 地址报配置错误，不是编码时的内部错误
        with self.assertRaises(ssh_proxy.ProxyConfigError):
            ssh_proxy.check_address("主机.invalid", "代理")
        with tempfile.TemporaryDirectory() as td:
            cfg = base_cfg(1)
            cfg["proxy"]["host"] = "主机.invalid"
            run = HelperRun(Path(td), cfg)
            self.assertEqual(run.expect_exit(2), 2)  # 配置错误退出码 2
            self.assertEqual(run.out, b"")

    def test_http_user_with_nul_byte_rejected(self):
        # 空字节会破坏 Basic 头的编码与头部结构
        with self.assertRaises(ssh_proxy.ProxyConfigError):
            ssh_proxy.check_http_auth("u\x00name", None)

    def test_socks5_auth_length_boundaries(self):
        # 用户名和密码各 255 字节是协议上限：接受
        self.assertEqual(
            ssh_proxy.check_socks5_auth("u" * 255, "p" * 255),
            ("u" * 255, "p" * 255),
        )
        # 256 字节超出单字节长度字段：拒绝
        with self.assertRaises(ssh_proxy.ProxyConfigError):
            ssh_proxy.check_socks5_auth("u", "p" * 256)
        with self.assertRaises(ssh_proxy.ProxyConfigError):
            ssh_proxy.check_socks5_auth("u" * 256, "p")

    def test_handshake_timeout_constant_and_config_default(self):
        # 握手期限常量与配置默认值都是 10 秒
        self.assertEqual(ssh_proxy.HANDSHAKE_TIMEOUT, 10)
        with tempfile.TemporaryDirectory() as td:
            path = Path(td) / "cfg.json"
            path.write_text(
                json.dumps(
                    {
                        "proxy": {"type": "http", "host": "127.0.0.1", "port": 8080},
                        "target": {"host": "t.invalid", "port": 22},
                    }
                )
            )
            self.assertEqual(ssh_proxy.load_config(str(path))["timeout"], 10)


if __name__ == "__main__":
    unittest.main()
