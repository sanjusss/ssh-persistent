"""文件传输与连接身份回归；所有传输只在本机临时目录内运行。"""

import configparser
import contextlib
import importlib.util
import io
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock


def load_mux():
    path = Path(__file__).resolve().parents[1] / "ssh-mux.py"
    spec = importlib.util.spec_from_file_location("ssh_mux_transfer_tests", path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def config():
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_dict({
        "local": {"host": "local.invalid", "user": "review", "password": "demo"},
        "gateA": {"host": "gate-a.invalid", "user": "review"},
        "gateB": {"host": "gate-b.invalid", "user": "review"},
        "prod": {"host": "10.0.0.5", "user": "root", "via": "gateA"},
        "test": {"host": "10.0.0.5", "user": "root", "via": "gateB"},
        "first": {"host": "first.invalid", "user": "review"},
        "last": {"host": "last.invalid", "user": "review", "via": "first", "via_mode": "shell"},
        "relay": {"host": "relay.invalid", "user": "review", "password": "demo"},
    })
    return cp


class ConnectionIdentityTests(unittest.TestCase):
    def setUp(self):
        self.mux = load_mux()
        self.cp = config()

    def test_private_addresses_behind_different_gateways_have_separate_connections(self):
        active = set()
        established = []

        def fake_run(args, **kwargs):
            cpath = next(arg for arg in args if arg.startswith("ControlPath="))
            if "-O" in args:
                return subprocess.CompletedProcess(args, 0 if cpath in active else 1)
            active.add(cpath)
            established.append(args)
            return subprocess.CompletedProcess(args, 0, "", "")

        with tempfile.TemporaryDirectory() as td, \
                mock.patch.object(self.mux, "runtime_dir", return_value=td), \
                mock.patch.object(self.mux.subprocess, "run", side_effect=fake_run):
            for alias in ("prod", "test"):
                self.mux.jump_connect(self.cp, self.mux.get_host(self.cp, alias), quiet=True)
            target_connections = [args for args in established if args[-1] == "root@10.0.0.5"]
            self.assertEqual(len(target_connections), 2)
            paths = [next(arg for arg in args if arg.startswith("ControlPath="))
                     for args in target_connections]
            self.assertNotEqual(*paths)

    def test_gateway_and_config_path_changes_invalidate_socket(self):
        h = self.mux.get_host(self.cp, "prod")
        with mock.patch.object(self.mux, "runtime_dir", return_value="/tmp/review"), \
                mock.patch.object(self.mux, "CONFIG_PATH", "/tmp/config-a"):
            first = self.mux.jump_sock_file(self.cp, h)
            self.cp["gateA"]["host"] = "replacement.invalid"
            self.assertNotEqual(first, self.mux.jump_sock_file(self.cp, h))
            second = self.mux.jump_sock_file(self.cp, h)
            self.mux.CONFIG_PATH = "/tmp/config-b"
            self.assertNotEqual(second, self.mux.jump_sock_file(self.cp, h))

    def test_old_scp_option_errors_keep_default_legacy_protocol(self):
        for output in ("scp: unknown option -- O", "scp: illegal option -- O", "invalid option -- O"):
            self.assertEqual(self.mux.scp_legacy_option(output), [])
        self.assertEqual(self.mux.scp_legacy_option("usage: scp [-O] source target"), ["-O"])


@unittest.skipUnless(shutil.which("scp"), "需要本机 scp")
class LocalTransferTests(unittest.TestCase):
    def setUp(self):
        self.mux = load_mux()
        self.cp = config()
        self.temp = tempfile.TemporaryDirectory(prefix="ssh-transfer-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.transport = self.root / "local-ssh"
        self.transport.write_text('#!/bin/sh\nfor arg do :; done\nexec /bin/sh -c "$arg"\n')
        self.transport.chmod(0o700)
        self.real_run = subprocess.run
        self.created_dirs = []
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(mock.patch.object(self.mux, "runtime_dir", return_value=str(self.root)))
        self.stack.enter_context(mock.patch.object(self.mux, "jump_connect"))
        self.stack.enter_context(mock.patch.object(self.mux.subprocess, "run", side_effect=self.scp_run))
        self.stack.enter_context(mock.patch.object(self.mux, "shell_exec", side_effect=self.local_shell))
        self.stack.enter_context(mock.patch.object(self.mux, "jump_exec", side_effect=self.local_jump_exec))
        self.stack.enter_context(contextlib.redirect_stdout(io.StringIO()))

    def scp_run(self, args, **kwargs):
        self.assertEqual(args[0], "scp")
        if args != ["scp", "-O"]:
            args = args[:1] + ["-S", str(self.transport)] + args[1:]
        if not kwargs.get("capture_output"):
            kwargs.setdefault("stdout", subprocess.PIPE)
            kwargs.setdefault("stderr", subprocess.PIPE)
        return self.real_run(args, **kwargs)

    def local_shell(self, alias, session, command, timeout, password=None):
        # 强制覆盖没有 sshpass 时的回退分支，真实 scp 通过本地进程通信。
        if " sshpass -e " in command:
            return {"exit": 127, "output": "sshpass: command not found"}
        if command.startswith("scp "):
            result = self.scp_run(shlex.split(command), text=True)
        else:
            result = self.real_run(command, shell=True, capture_output=True, text=True)
        if command.startswith("mkdir ") and result.returncode == 0:
            self.created_dirs.append(Path(shlex.split(command)[-1]))
        return {"exit": result.returncode, "output": result.stdout + result.stderr}

    def local_jump_exec(self, cp, host, command):
        return self.local_shell(host.alias, "review", command, 10)["exit"]

    def test_jump_paths_with_spaces_quotes_and_shell_metacharacters(self):
        source = self.root / "source file.txt"
        source.write_bytes(b"transfer contents\x00\xff")
        remote = self.root / "remote ' file; $literal.txt"
        local = self.root / "download file.txt"
        h = self.mux.get_host(self.cp, "relay")
        self.assertEqual(self.mux.jump_scp(self.cp, h, "push", str(source), str(remote)), 0)
        self.assertEqual(remote.read_bytes(), source.read_bytes())
        self.assertEqual(self.mux.jump_scp(self.cp, h, "pull", str(remote), str(local)), 0)
        self.assertEqual(local.read_bytes(), source.read_bytes())

    def check_directory_transfer(self, staging):
        if staging:
            self.cp["local"] = {"staging": "relay"}
        source = self.root / "original ' file.txt"
        source.write_text("original contents")
        remote_dir = self.root / "remote directory"
        remote_dir.mkdir()
        local_dir = self.root / "local directory"
        local_dir.mkdir()
        h = self.mux.get_host(self.cp, "last")
        self.mux.shell_push(self.cp, h, "review", str(source), str(remote_dir) + "/", 10)
        self.assertEqual([p.name for p in remote_dir.iterdir()], [source.name])
        remote = remote_dir / source.name
        self.assertEqual(remote.read_text(), source.read_text())
        self.mux.shell_pull(self.cp, h, "review", str(remote), str(local_dir) + "/", 10)
        self.assertEqual([p.name for p in local_dir.iterdir()], [source.name])
        self.assertEqual((local_dir / source.name).read_text(), source.read_text())
        self.assertTrue(self.created_dirs)
        self.assertTrue(all(not path.exists() for path in self.created_dirs))

    def test_multi_hop_directory_destinations_preserve_filename(self):
        self.check_directory_transfer(staging=False)

    def test_staging_directory_destinations_preserve_filename(self):
        self.check_directory_transfer(staging=True)


if __name__ == "__main__":
    unittest.main()
