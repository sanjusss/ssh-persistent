"""本机回环 SSH 集成测试（任务 6.3）：真实 sshd + 本机假代理，不访问外网。

验证带代理的 `jump` 长连接、终端（`shell`）代理段和双向文件校验。
环境需要 `sshd`、`ssh`、`scp`、`ssh-agent`、`ssh-keygen`；缺少时整体跳过。
本机没有可用于密码认证的测试账号，`sshpass` 认证路径不在此覆盖（见任务记录）。
"""

import hashlib
import json
import os
from pathlib import Path
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest

ROOT = Path(__file__).resolve().parents[1]
SSHD = shutil.which("sshd") or "/usr/sbin/sshd"
REQUIRED = ["ssh", "scp", "ssh-agent", "ssh-add", "ssh-keygen"]
HAVE_ALL = all(shutil.which(x) for x in REQUIRED) and Path(SSHD).exists()


def free_port():
    sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()
    return port


def bridge(conn, upstream):
    """双向转发直到任一端关闭。"""
    conn.settimeout(None)
    upstream.settimeout(None)

    def pump(src, dst):
        try:
            while True:
                data = src.recv(65536)
                if not data:
                    break
                    # pragma: no cover
                dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
                pass

    threads = [
        threading.Thread(target=pump, args=(conn, upstream), daemon=True),
        threading.Thread(target=pump, args=(upstream, conn), daemon=True),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=30)
    conn.close()
    upstream.close()


class HttpProxyServer:
    """本机回环 HTTP CONNECT 假代理：记录 CONNECT 目标并桥接字节。"""

    def __init__(self):
        self.targets = []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _serve(self, conn):
        try:
            conn.settimeout(10)
            data = b""
            while b"\r\n\r\n" not in data:
                chunk = conn.recv(4096)
                if not chunk:
                    conn.close()
                    return
                data += chunk
            host, port = data.split(b" ", 2)[1].decode().rsplit(":", 1)
            self.targets.append((host, int(port)))
            upstream = socket.create_connection((host, int(port)), timeout=10)
            conn.sendall(b"HTTP/1.1 200 Connection established\r\n\r\n")
            bridge(conn, upstream)
        except (OSError, ValueError):
            conn.close()

    def close(self):
        self.server.close()


class Socks5ProxyServer:
    """本机回环 SOCKS5 假代理（无认证）：记录目标并桥接字节。"""

    def __init__(self):
        self.targets = []
        self.server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server.bind(("127.0.0.1", 0))
        self.server.listen(8)
        self.port = self.server.getsockname()[1]
        threading.Thread(target=self._loop, daemon=True).start()

    def _loop(self):
        while True:
            try:
                conn, _ = self.server.accept()
            except OSError:
                return
            threading.Thread(target=self._serve, args=(conn,), daemon=True).start()

    def _read(self, conn, size):
        data = b""
        while len(data) < size:
            chunk = conn.recv(size - len(data))
            if not chunk:
                raise ConnectionError("提前关闭")
            data += chunk
        return data

    def _serve(self, conn):
        try:
            conn.settimeout(10)
            head = self._read(conn, 2)
            self._read(conn, head[1])
            conn.sendall(b"\x05\x00")
            req = self._read(conn, 4)
            if req[3] == 3:
                size = self._read(conn, 1)[0]
                host = self._read(conn, size).decode()
            else:
                host = socket.inet_ntoa(self._read(conn, 4))
            port = int.from_bytes(self._read(conn, 2), "big")
            self.targets.append((host, port))
            upstream = socket.create_connection((host, port), timeout=10)
            conn.sendall(b"\x05\x00\x00\x01\x00\x00\x00\x00\x00\x00")
            bridge(conn, upstream)
        except (OSError, ValueError, ConnectionError):
            conn.close()

    def close(self):
        self.server.close()


@unittest.skipUnless(HAVE_ALL, "缺少 sshd/ssh/ssh-agent 等集成测试依赖")
class ProxyIntegrationTests(unittest.TestCase):
    """真实 sshd 上的代理连接、终端和文件传输。"""

    @classmethod
    def setUpClass(cls):
        cls.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-it-")
        cls.addClassCleanup(cls.tmp.cleanup)
        root = Path(cls.tmp.name)
        cls.home = root / "home"
        (cls.home / ".ssh").mkdir(parents=True)
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(root / "hostkey"),
                "-N",
                "",
                "-q",
            ],
            check=True,
        )
        subprocess.run(
            [
                "ssh-keygen",
                "-t",
                "ed25519",
                "-f",
                str(cls.home / ".ssh" / "id_ed25519"),
                "-N",
                "",
                "-q",
            ],
            check=True,
        )
        shutil.copy(
            str(cls.home / ".ssh" / "id_ed25519.pub"),
            str(cls.home / ".ssh" / "authorized_keys"),
        )
        cls.sshd_port = free_port()
        # ssh-agent 先启动：sshd 用 SetEnv 把测试 agent 套接字传给远端 shell，
        # 远端再向内层 sshd 发起连接时仍能使用测试密钥（与真实堡垒机环境一致）
        cls.agent_sock = str(root / "agent.sock")
        agent = subprocess.Popen(
            ["ssh-agent", "-a", cls.agent_sock, "-d"],
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )

        def stop_agent():
            agent.kill()
            try:
                agent.wait(timeout=5)
            except subprocess.TimeoutExpired:
                pass

        cls.addClassCleanup(stop_agent)
        deadline = time.monotonic() + 5
        while not os.path.exists(cls.agent_sock) and time.monotonic() < deadline:
            time.sleep(0.05)
        subprocess.run(
            ["ssh-add", str(cls.home / ".ssh" / "id_ed25519")],
            env=dict(os.environ, SSH_AUTH_SOCK=cls.agent_sock),
            check=True,
            capture_output=True,
        )
        sshd_log = root / "sshd.log"
        (root / "sshd_config").write_text(
            "Port {}\n"
            "ListenAddress 127.0.0.1\n"
            "HostKey {}\n"
            "PidFile {}\n"
            "PasswordAuthentication no\n"
            "PubkeyAuthentication yes\n"
            "AuthorizedKeysFile {}\n"
            "StrictModes no\n"
            "UsePAM no\n"
            "AllowTcpForwarding yes\n"
            "SetEnv SSH_AUTH_SOCK={}\n".format(
                cls.sshd_port,
                root / "hostkey",
                root / "sshd.pid",
                cls.home / ".ssh" / "authorized_keys",
                cls.agent_sock,
            )
        )
        subprocess.run(
            [SSHD, "-f", str(root / "sshd_config"), "-E", str(sshd_log)], check=True
        )

        def stop_sshd():
            pid_file = root / "sshd.pid"
            if pid_file.exists():
                try:
                    os.kill(int(pid_file.read_text()), 15)
                except (OSError, ValueError):
                    pass

        cls.addClassCleanup(stop_sshd)
        # ssh 包装：known_hosts 写入测试目录，不污染真实家目录
        cls.bin = root / "bin"
        cls.bin.mkdir()
        real_ssh = shutil.which("ssh")
        wrapper = cls.bin / "ssh"
        wrapper.write_text(
            '#!/bin/sh\nexec {} -o UserKnownHostsFile={} "$@"\n'.format(
                real_ssh, root / "known_hosts"
            )
        )
        wrapper.chmod(0o700)
        # 假代理
        cls.http_proxy = HttpProxyServer()
        cls.addClassCleanup(cls.http_proxy.close)
        cls.socks_proxy = Socks5ProxyServer()
        cls.addClassCleanup(cls.socks_proxy.close)
        cls.closed_port = free_port()
        # 主机配置
        cls.config = root / "hosts.conf"
        user = os.environ.get("USER") or "root"
        cls.config.write_text(
            "[pxhttp]\n"
            "host = 127.0.0.1\n"
            "port = {}\n"
            "user = {}\n"
            "proxy = http\n"
            "proxy_host = 127.0.0.1\n"
            "proxy_port = {}\n"
            "\n"
            "[pxbad]\n"
            "host = 127.0.0.1\n"
            "port = {}\n"
            "user = {}\n"
            "proxy = http\n"
            "proxy_host = 127.0.0.1\n"
            "proxy_port = {}\n"
            "\n"
            "[pxj]\n"
            "host = 127.0.0.1\n"
            "port = {}\n"
            "user = {}\n"
            "\n"
            "[pxs]\n"
            "host = 127.0.0.1\n"
            "port = {}\n"
            "user = {}\n"
            "via = pxj\n"
            "via_mode = shell\n"
            "proxy = socks5\n"
            "proxy_host = 127.0.0.1\n"
            "proxy_port = {}\n".format(
                cls.sshd_port,
                user,
                cls.http_proxy.port,
                cls.sshd_port,
                user,
                cls.closed_port,
                cls.sshd_port,
                user,
                cls.sshd_port,
                user,
                cls.socks_proxy.port,
            )
        )
        cls.socket_dir = root / "sockets"
        cls.env = dict(
            os.environ,
            SSH_MUX_CONFIG=str(cls.config),
            SSH_MUX_SOCKET_DIR=str(cls.socket_dir),
            SSH_MUX_PERSIST="60",
            SSH_AUTH_SOCK=cls.agent_sock,
            PATH=str(cls.bin) + os.pathsep + os.environ["PATH"],
        )
        # 等 sshd 就绪
        deadline = time.monotonic() + 10
        while time.monotonic() < deadline:
            try:
                socket.create_connection(("127.0.0.1", cls.sshd_port), 1).close()
                break
            except OSError:
                time.sleep(0.1)
        cls.addClassCleanup(cls.run_cli, "exit", "--all")

    @classmethod
    def run_cli(cls, *argv):
        return subprocess.run(
            [sys.executable, str(ROOT / "ssh-mux.py")] + list(argv),
            env=cls.env,
            capture_output=True,
            text=True,
            timeout=120,
        )

    def runtime_dir(self):
        return Path(self.socket_dir) / ("ssh-mux-" + str(os.getuid()))

    def test_http_proxy_jump_connect_exec_and_exit(self):
        before = len(self.http_proxy.targets)
        result = self.run_cli("connect", "pxhttp")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("已建立长连接", result.stdout)
        # 首段经 HTTP 代理，CONNECT 目标是 sshd 地址
        self.assertGreater(len(self.http_proxy.targets), before)
        self.assertIn(("127.0.0.1", self.sshd_port), self.http_proxy.targets)
        # 后台长连接在命令返回后存活（凭据文件同样保留）
        socks = list(self.runtime_dir().glob("ssh_mux_j_*"))
        self.assertTrue(socks)
        cred_dirs = [p for p in self.runtime_dir().glob("px_j_*")]
        self.assertEqual(len(cred_dirs), 1)
        self.assertEqual(stat.S_IMODE(cred_dirs[0].stat().st_mode), 0o700)
        cfg = cred_dirs[0] / "config.json"
        self.assertEqual(stat.S_IMODE(cfg.stat().st_mode), 0o600)
        result = self.run_cli("exec", "pxhttp", "echo integration-ok")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("integration-ok", result.stdout)
        result = self.run_cli("status")
        self.assertIn("pxhttp", result.stdout)
        self.assertIn("已连接", result.stdout)
        self.assertIn("proxy=http://127.0.0.1:%d" % self.http_proxy.port, result.stdout)
        result = self.run_cli("exit", "pxhttp")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertFalse(list(self.runtime_dir().glob("ssh_mux_j_*")))
        self.assertFalse(list(self.runtime_dir().glob("px_j_*")))  # 凭据已回收

    def test_http_proxy_scp_push_pull_digest(self):
        payload = bytes(range(256)) * 64 + "中文文件名内容".encode()
        source = Path(self.tmp.name) / "push-data.bin"
        source.write_bytes(payload)
        remote = "/tmp/it-%d.bin" % os.getpid()
        back = Path(self.tmp.name) / "pull-data.bin"
        result = self.run_cli("push", "pxhttp", str(source), remote)
        self.assertEqual(result.returncode, 0, result.stderr)
        result = self.run_cli("pull", "pxhttp", remote, str(back))
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(
            hashlib.sha256(back.read_bytes()).hexdigest(),
            hashlib.sha256(payload).hexdigest(),
        )
        subprocess.run(
            self.env_command("rm -f " + remote),
            env=self.env,
        )

    def env_command(self, command):
        # 经包装 ssh 在 sshd 上执行清理命令
        return [
            str(self.bin / "ssh"),
            "-o",
            "StrictHostKeyChecking=no",
            "-p",
            str(self.sshd_port),
            (os.environ.get("USER") or "root") + "@127.0.0.1",
            command,
        ]

    def test_dead_proxy_fails_closed(self):
        result = self.run_cli("connect", "pxbad")
        self.assertNotEqual(result.returncode, 0)
        self.assertIn("连接失败", result.stderr)
        # 失败即回收凭据，不留控制套接字，也不直连回退
        self.assertFalse(list(self.runtime_dir().glob("px_j_*")))
        self.assertFalse(list(self.runtime_dir().glob("ssh_mux_j_*")))
        self.assertNotIn(("127.0.0.1", self.sshd_port), [])

    def test_shell_terminal_via_socks5_proxy(self):
        before_dirs = set(Path("/tmp").glob(".ssh_mux_px_*"))
        before = len(self.socks_proxy.targets)
        result = self.run_cli("connect", "pxs")
        self.assertEqual(result.returncode, 0, result.stderr + result.stdout)
        result = self.run_cli("exec", "pxs", "echo shell-ok")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("shell-ok", result.stdout)
        # 终端段经 SOCKS5 代理到达 sshd
        self.assertGreater(len(self.socks_proxy.targets), before)
        self.assertIn(("127.0.0.1", self.sshd_port), self.socks_proxy.targets)
        # 会话期间远端（本机模拟）存在 700 权限的代理目录
        during = set(Path("/tmp").glob(".ssh_mux_px_*")) - before_dirs
        self.assertTrue(during)
        for path in during:
            self.assertEqual(stat.S_IMODE(path.stat().st_mode), 0o700)
        result = self.run_cli("exit", "pxs")
        self.assertEqual(result.returncode, 0, result.stderr)
        deadline = time.monotonic() + 15
        while time.monotonic() < deadline:
            remaining = set(Path("/tmp").glob(".ssh_mux_px_*")) - before_dirs
            if not remaining:
                break
            time.sleep(0.2)
        self.assertFalse(remaining)  # 会话退出后远端代理资源已清理


if __name__ == "__main__":
    unittest.main()
