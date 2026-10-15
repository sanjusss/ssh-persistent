"""SSH 会话与本地进程通信的回归测试；不连接外部主机。"""

import configparser
import importlib.util
import io
import json
import os
from pathlib import Path
import shutil
import shlex
import signal
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest import mock


SCRIPT = Path(__file__).resolve().parents[1] / "ssh-mux.py"
SPEC = importlib.util.spec_from_file_location("ssh_mux_core_tests", SCRIPT)
mux = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mux)


class IsolatedRuntimeTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ssh-mux-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.socket_patch = mock.patch.object(mux, "SOCKET_DIR", str(self.root))
        self.config_patch = mock.patch.object(
            mux, "CONFIG_PATH", str(self.root / "hosts.conf")
        )
        self.socket_patch.start()
        self.config_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.addCleanup(self.config_patch.stop)

    @staticmethod
    def config():
        config = configparser.ConfigParser(interpolation=None)
        config.read_dict(
            {
                "hop": {"host": "hop.invalid"},
                "a": {"host": "a.invalid", "via": "hop", "via_mode": "shell"},
                "a_b": {"host": "ab.invalid", "via": "hop", "via_mode": "shell"},
            }
        )
        return config

    def test_alias_and_session_have_unambiguous_paths(self):
        for path_function in (
            mux.shell_sock,
            mux.shell_log_path,
            mux.shell_err_path,
            mux.shell_pid_path,
        ):
            with self.subTest(path_function=path_function.__name__):
                self.assertNotEqual(
                    path_function("a_b", "c"), path_function("a", "b_c")
                )

    def test_configuration_files_have_separate_sessions(self):
        first = mux.shell_sock("a", "default")
        with mock.patch.object(mux, "CONFIG_PATH", str(self.root / "other.conf")):
            second = mux.shell_sock("a", "default")
        self.assertNotEqual(first, second)

    def test_runtime_directory_is_private(self):
        directory = Path(mux.runtime_dir())
        self.assertEqual(directory.parent, self.root)
        self.assertEqual(directory.stat().st_uid, os.getuid())
        self.assertEqual(stat.S_IMODE(directory.stat().st_mode), 0o700)

    def test_runtime_directory_rejects_symlink(self):
        destination = self.root / "attacker-directory"
        destination.mkdir()
        directory = self.root / ("ssh-mux-" + str(os.getuid()))
        directory.symlink_to(destination, target_is_directory=True)
        with self.assertRaises((SystemExit, OSError, RuntimeError)):
            mux.runtime_dir()

    def test_runtime_directory_rejects_group_or_public_access(self):
        directory = self.root / ("ssh-mux-" + str(os.getuid()))
        directory.mkdir(mode=0o755)
        directory.chmod(0o755)
        with self.assertRaises((SystemExit, OSError, RuntimeError)):
            mux.runtime_dir()

    def test_runtime_directory_rejects_foreign_owner(self):
        with mock.patch.object(mux.os, "getuid", return_value=os.getuid() + 1):
            with self.assertRaises((SystemExit, OSError, RuntimeError)):
                mux.runtime_dir()

    def test_legacy_shared_socket_cannot_impersonate_daemon(self):
        # 模拟另一用户预先占用旧版可预测路径，并伪造成功回复。
        server = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.addCleanup(server.close)
        legacy_path = self.root / "ssh_mux_s_a_default.sock"
        server.bind(str(legacy_path))
        legacy_path.chmod(0o777)
        server.listen(1)
        server.settimeout(0.3)
        captured = []

        def impersonate():
            try:
                connection, _ = server.accept()
            except socket.timeout:
                return
            with connection:
                connection.settimeout(1)
                data = b""
                while b"\n" not in data:
                    chunk = connection.recv(65536)
                    if not chunk:
                        return
                    data += chunk
                captured.append(json.loads(data))
                connection.sendall(b'{"status":"ok"}\n')

        thread = threading.Thread(target=impersonate)
        thread.start()
        try:
            accepted = mux.ping_session("a", "default", timeout=1)
        finally:
            thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertFalse(accepted)
        self.assertEqual(captured, [])

    def test_exit_alias_does_not_stop_alias_with_same_prefix(self):
        Path(mux.shell_sock("a", "default")).touch()
        Path(mux.shell_sock("a_b", "default")).touch()
        with mock.patch.object(mux, "rpc", return_value={"status": "ok"}) as rpc:
            mux.cmd_exit(self.config(), "a", None)
        stopped = [
            (call[0][0], call[0][1])
            for call in rpc.call_args_list
            if call[0][2].get("cmd") == "stop"
        ]
        self.assertEqual(stopped, [("a", "default")])

    def test_exit_routing_bastion_is_skipped(self):
        # `exit --all` 会遍历到用户名路由堡垒机；它不提供独立终端，应跳过而不是报错
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_dict(
            {
                "bastion": {"host": "b.invalid", "routing": "username"},
                "a": {"host": "a.invalid", "via": "bastion", "via_mode": "shell"},
            }
        )
        with (
            mock.patch.object(mux, "jump_exit") as jump_exit,
            mock.patch.object(mux, "rpc") as rpc,
            mock.patch("sys.stdout", new_callable=io.StringIO) as out,
        ):
            mux.cmd_exit(cp, "bastion", None)
        jump_exit.assert_not_called()
        rpc.assert_not_called()
        self.assertIn("跳过", out.getvalue())

    def test_stale_pid_never_signals_unrelated_process(self):
        Path(mux.shell_sock("a", "default")).touch()
        Path(mux.shell_pid_path("a", "default")).write_text("424242")
        with (
            mock.patch.object(mux, "rpc", return_value=None),
            mock.patch.object(mux.os, "kill") as kill,
            mock.patch.object(mux.time, "sleep"),
        ):
            mux.cmd_exit(self.config(), "a", "default")
        destructive_calls = [
            call
            for call in kill.call_args_list
            if call[0][1] in (signal.SIGTERM, signal.SIGKILL)
        ]
        self.assertEqual(destructive_calls, [])

    def start_local_daemon(self):
        # 子进程只把登录计划换成本地 Bash，保留真实守护进程和套接字实现。
        Path(mux.CONFIG_PATH).write_text("[a]\nhost = example.invalid\n")
        source = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('local_daemon_test', sys.argv[1])
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)
mux.build_shell_plan = lambda config, alias: [(['bash', '--noprofile', '--norc', '-i'], [])]
mux.daemon_main('a', 'default')
"""
        environment = dict(
            os.environ,
            SSH_MUX_CONFIG=mux.CONFIG_PATH,
            SSH_MUX_SOCKET_DIR=mux.SOCKET_DIR,
            SSH_MUX_PERSIST="30",
        )
        process = subprocess.Popen(
            [sys.executable, "-c", source, str(SCRIPT)],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        def cleanup():
            if process.poll() is None:
                mux.rpc("a", "default", {"cmd": "stop"}, timeout=0.5)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.terminate()
                try:
                    process.wait(timeout=3)
                except subprocess.TimeoutExpired:
                    process.kill()
                    process.wait(timeout=3)
            process.stderr.close()

        self.addCleanup(cleanup)
        return process

    def wait_for_local_daemon(self):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            if mux.ping_session("a", "default", timeout=0.2):
                return
            time.sleep(0.02)
        log_path = Path(mux.shell_log_path("a", "default"))
        self.fail(
            "本地守护进程未就绪："
            + (log_path.read_text() if log_path.exists() else "无日志")
        )

    def assert_daemon_resources_released(self):
        self.assertFalse(mux.daemon_pid_alive("a", "default"))
        for path_function in (
            mux.shell_sock,
            mux.shell_control_path,
            mux.shell_pid_path,
        ):
            self.assertFalse(Path(path_function("a", "default")).exists())

    @unittest.skipUnless(shutil.which("bash"), "需要本地 Bash")
    def test_daemon_exec_and_stop_release_lock_and_sockets(self):
        process = self.start_local_daemon()
        self.wait_for_local_daemon()
        self.assertTrue(mux.daemon_pid_alive("a", "default"))
        reply = mux.rpc(
            "a",
            "default",
            {"cmd": "exec", "command": "printf 'ok\\n'; false", "timeout": 3},
            timeout=4,
        )
        self.assertEqual(reply, {"status": "ok", "exit": 1, "output": "ok\n"})
        self.assertEqual(
            mux.rpc("a", "default", {"cmd": "stop"}, timeout=1)["status"], "ok"
        )
        self.assertEqual(process.wait(timeout=3), 0)
        self.assert_daemon_resources_released()

    @unittest.skipUnless(shutil.which("bash"), "需要本地 Bash")
    def test_daemon_can_ping_and_stop_while_command_is_running(self):
        process = self.start_local_daemon()
        self.wait_for_local_daemon()
        started = self.root / "command-started"
        command = "printf ready > " + shlex.quote(str(started)) + "; sleep 30"
        result = []

        def execute():
            result.append(
                mux.rpc(
                    "a",
                    "default",
                    {"cmd": "exec", "command": command, "timeout": 40},
                    timeout=5,
                )
            )

        thread = threading.Thread(target=execute)
        thread.start()
        self.addCleanup(thread.join, 6)
        deadline = time.monotonic() + 3
        while not started.exists() and time.monotonic() < deadline:
            time.sleep(0.02)
        self.assertTrue(started.exists(), "长命令没有开始")
        self.assertTrue(mux.ping_session("a", "default", timeout=1))
        self.assertEqual(
            mux.rpc("a", "default", {"cmd": "stop"}, timeout=1)["status"], "ok"
        )
        self.assertEqual(process.wait(timeout=3), 0)
        thread.join(timeout=2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(len(result), 1)
        self.assert_daemon_resources_released()

    @unittest.skipUnless(shutil.which("bash"), "需要本地 Bash")
    def test_concurrent_daemons_keep_one_owner(self):
        processes = [self.start_local_daemon(), self.start_local_daemon()]
        self.wait_for_local_daemon()
        deadline = time.monotonic() + 3
        while (
            all(process.poll() is None for process in processes)
            and time.monotonic() < deadline
        ):
            time.sleep(0.02)
        active = [process for process in processes if process.poll() is None]
        self.assertEqual(len(active), 1)
        stopped = [process for process in processes if process.poll() is not None]
        self.assertEqual(stopped[0].returncode, 0)
        self.assertEqual(
            int(Path(mux.shell_pid_path("a", "default")).read_text()), active[0].pid
        )
        reply = mux.rpc(
            "a",
            "default",
            {"cmd": "exec", "command": "printf owner", "timeout": 3},
            timeout=4,
        )
        self.assertEqual(reply, {"status": "ok", "exit": 0, "output": "owner"})
        self.assertEqual(
            mux.rpc("a", "default", {"cmd": "stop"}, timeout=1)["status"], "ok"
        )
        self.assertEqual(active[0].wait(timeout=3), 0)
        self.assert_daemon_resources_released()


class DaemonBootTimeoutTest(unittest.TestCase):
    """启动期限按链路长度估算：基准 90，每跳 45，每个远端代理准备 60，外加基准 30。"""

    @staticmethod
    def config(entries):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_dict(entries)
        return cp

    def setUp(self):
        # 估算会读取本机默认代理变量；测试时固定为空
        patcher = mock.patch.dict(os.environ, {"SSH_MUX_PROXY": ""})
        patcher.start()
        self.addCleanup(patcher.stop)

    def test_single_hop_keeps_base_timeout(self):
        cp = self.config(
            {
                "bastion": {"host": "b.invalid", "routing": "username"},
                "a": {"host": "a.invalid", "via": "bastion", "via_mode": "shell"},
            }
        )
        self.assertEqual(mux.daemon_boot_timeout(cp, "a"), 90)

    def test_two_hop_shell_chain_scales(self):
        cp = self.config(
            {
                "bastion": {"host": "b.invalid", "routing": "username"},
                "a": {"host": "a.invalid", "via": "bastion", "via_mode": "shell"},
                "b": {"host": "b2.invalid", "via": "a", "via_mode": "shell"},
            }
        )
        self.assertEqual(mux.daemon_boot_timeout(cp, "b"), 30 + 45 * 2)

    def test_remote_proxy_prepare_adds_time(self):
        cp = self.config(
            {
                "bastion": {"host": "b.invalid", "routing": "username"},
                "a": {"host": "a.invalid", "via": "bastion", "via_mode": "shell"},
                "b": {
                    "host": "b2.invalid",
                    "via": "a",
                    "via_mode": "shell",
                    "proxy": "socks5",
                    "proxy_host": "10.0.0.1",
                    "proxy_port": "1080",
                },
            }
        )
        self.assertEqual(mux.daemon_boot_timeout(cp, "b"), 30 + 45 * 2 + 60)

    def test_local_first_hop_proxy_adds_no_prepare_time(self):
        cp = self.config(
            {
                "a": {
                    "host": "a.invalid",
                    "proxy": "http",
                    "proxy_host": "10.0.0.1",
                    "proxy_port": "8080",
                },
            }
        )
        self.assertEqual(mux.daemon_boot_timeout(cp, "a"), 90)

    def test_mixed_chain_counts_jump_prefix_hops(self):
        cp = self.config(
            {
                "a": {"host": "a.invalid"},
                "b": {
                    "host": "b.invalid",
                    "via": "a",
                    "via_mode": "jump",
                    "proxy": "http",
                    "proxy_host": "10.0.0.1",
                    "proxy_port": "8080",
                },
                "c": {"host": "c.invalid", "via": "b", "via_mode": "shell"},
            }
        )
        # 开头两个标准跳板段在本机建立（各计一跳），B → C 无代理不准备远端程序
        self.assertEqual(mux.daemon_boot_timeout(cp, "c"), 30 + 45 * 3)

    def test_invalid_config_falls_back_to_base(self):
        cp = self.config(
            {"a": {"host": "a.invalid", "via": "missing", "via_mode": "shell"}}
        )
        self.assertEqual(mux.daemon_boot_timeout(cp, "a"), 90)


@unittest.skipUnless(shutil.which("bash"), "需要本地 Bash 模拟交互式 SSH 会话")
class PtySessionTest(unittest.TestCase):
    def make_session(self, nested=False):
        plan = [
            (["env", "MUX_TEST_HOP=outer", "bash", "--noprofile", "--norc", "-i"], [])
        ]
        if nested:
            plan.append(
                (
                    [
                        "env",
                        "MUX_TEST_HOP=target",
                        "bash",
                        "--noprofile",
                        "--norc",
                        "-i",
                    ],
                    [],
                )
            )
        session = mux.PtySession(plan, lambda message: None)
        self.addCleanup(session.close)
        session.start()
        return session

    def test_target_exit_cannot_return_to_parent_shell(self):
        session = self.make_session(nested=True)
        output, code = session.exec('printf "%s\\n" "$MUX_TEST_HOP"', 6)
        self.assertEqual((output, code), ("target\n", 0))
        with self.assertRaises(ConnectionError):
            session.exec("kill -HUP $$", 6)

    def test_command_finishes_when_password_prompt_is_absent(self):
        session = self.make_session()
        output, code = session.exec(
            "printf 'copied\\n'", 6, password="unused-test-password"
        )
        self.assertEqual((output, code), ("copied\n", 0))

    def test_multiline_command_keeps_exit_code_and_session_state(self):
        session = self.make_session()
        command = (
            "MUX_TEST_VALUE='hello world'\nprintf '%s\\n' \"$MUX_TEST_VALUE\"\nfalse"
        )
        output, code = session.exec(command, 6)
        self.assertEqual((output, code), ("hello world\n", 1))
        output, code = session.exec('printf "%s\\n" "$MUX_TEST_VALUE"', 6)
        self.assertEqual((output, code), ("hello world\n", 0))


if __name__ == "__main__":
    unittest.main()
