"""无 scp 传输测试；仅在本地临时目录中执行，不读取服务器配置。"""

import contextlib
import importlib.util
import io
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import tempfile
import unittest
from unittest import mock

from test_transfer import config, load_mux

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("transfer_under_test", ROOT / "ssh_transfer.py")
transfer = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(transfer)


class NoScpTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-no-scp-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        # 白名单中没有 scp、openssl 和 python；可移除 base64 来验证回退。
        for name in ("wc", "cat", "mkdir", "mv", "rm", "dd", "sha256sum", "od", "base64"):
            path = shutil.which(name)
            if path:
                (self.bin / name).symlink_to(path)
        self.env = dict(os.environ, PATH=str(self.bin))
        self.work_dirs = []

    def execute(self, command, limit):
        result = subprocess.run(["/bin/sh", "-c", command], cwd=self.root, env=self.env,
                                capture_output=True, timeout=limit, text=True)
        return {"exit": result.returncode, "output": result.stdout + result.stderr}

    def stream(self, action, path, file, limit):
        if action == "push":
            with open(path, "wb") as target:
                shutil.copyfileobj(file, target)
        else:
            with open(path, "rb") as source:
                shutil.copyfileobj(source, file)

    def worker(self, execute=None):
        worker = transfer.Transfer(execute or self.execute, self.stream, 30)
        original = worker.make_work

        def make_work(parent):
            # pull 的远端 /tmp 同样放到本测试临时目录内。
            original(str(self.root) if parent == "/tmp" else parent)
            self.work_dirs.append(worker.work)

        worker.make_work = make_work
        return worker

    def roundtrip(self, mode, data):
        source = self.root / "源 '文件; $literal"
        source.write_bytes(data)
        remote = self.root / "remote"
        remote.mkdir(exist_ok=True)
        destination = self.worker().push(str(source), str(remote), mode)
        self.assertEqual(Path(destination).read_bytes(), data)
        local = self.root / "download"
        local.mkdir(exist_ok=True)
        result = self.worker().pull(destination, str(local), mode)
        self.assertEqual(Path(result).read_bytes(), data)
        self.assertEqual(Path(result).stat().st_mode & 0o777, 0o600)
        self.assertTrue(all(not Path(path).exists() for path in self.work_dirs))

    def test_binary_and_empty_roundtrip_without_scp(self):
        for mode in ("stream", "auto", "base64", "octal"):
            for data in (b"", b"a", b"ab", bytes(range(256)) * 5 + b"\r\n\x1b[31m"):
                with self.subTest(mode=mode, size=len(data)):
                    self.roundtrip(mode, data)

    def test_auto_falls_back_without_base64(self):
        (self.bin / "base64").unlink()
        self.roundtrip("auto", bytes(range(256)))
        with self.assertRaisesRegex(transfer.TransferError, "base64"):
            self.worker().codec("pull", "base64")

    def test_duplicate_commands_do_not_duplicate_data(self):
        def twice(command, limit):
            self.execute(command, limit)
            return self.execute(command, limit)

        source, destination = self.root / "source", self.root / "destination"
        source.write_bytes(bytes(range(256)) * 9)
        for mode in ("base64", "octal"):
            self.worker(twice).push(str(source), str(destination), mode)
            self.assertEqual(destination.read_bytes(), source.read_bytes())
        self.assertTrue(all(not Path(path).exists() for path in self.work_dirs))

    def test_openssl_and_python_backends_without_native_base64_or_sha256sum(self):
        (self.bin / "base64").unlink()
        (self.bin / "sha256sum").unlink()
        for name in ("openssl", "python3"):
            executable = shutil.which(name)
            if not executable:
                continue
            with self.subTest(backend=name):
                link = self.bin / name
                link.symlink_to(executable)
                try:
                    self.roundtrip("base64", bytes(range(256)) * 5)
                finally:
                    link.unlink()

    def test_corrupt_upload_preserves_old_target(self):
        source, destination = self.root / "source", self.root / "destination"
        source.write_bytes(b"new contents")
        destination.write_bytes(b"old contents")
        worker = self.worker()
        original = worker.chunk_command
        worker.chunk_command = lambda data, offset, codec, decoder: original(
            b"X" + data[1:], offset, codec, decoder)
        with self.assertRaisesRegex(transfer.TransferError, "SHA-256"):
            worker.push(str(source), str(destination), "base64")
        self.assertEqual(destination.read_bytes(), b"old contents")
        self.assertFalse(Path(worker.work).exists())

    def test_corrupt_download_preserves_old_target_and_cleans(self):
        source, destination = self.root / "source", self.root / "destination"
        source.write_bytes(bytes(range(256)))
        destination.write_bytes(b"old")

        def corrupt(command, limit):
            result = self.execute(command, limit)
            if "count=1" in command:
                result["output"] = "invalid!"
            return result

        worker = self.worker(corrupt)
        with self.assertRaises(transfer.TransferError):
            worker.pull(str(source), str(destination), "base64")
        self.assertEqual(destination.read_bytes(), b"old")
        self.assertFalse(Path(worker.work).exists())
        self.assertEqual(list(self.root.glob(".ssh-mux-*")), [])

    def test_partial_stream_does_not_replace_target(self):
        source, destination = self.root / "source", self.root / "destination"
        source.write_bytes(b"new contents")
        destination.write_bytes(b"old")
        worker = self.worker()

        def partial(action, path, file, limit):
            if action == "push":
                Path(path).write_bytes(b"partial")
            else:
                file.write(b"partial")
            raise transfer.TransferError("interrupted")

        worker.stream = partial
        for action in (worker.push, worker.pull):
            with self.assertRaisesRegex(transfer.TransferError, "interrupted"):
                action(str(source), str(destination), "stream")
            self.assertEqual(destination.read_bytes(), b"old")
        self.assertTrue(all(not Path(path).exists() for path in self.work_dirs))

    def test_download_multiple_blocks_and_source_change(self):
        self.roundtrip("base64", bytes(range(256)) * 140)
        source, destination = self.root / "source", self.root / "destination"
        source.write_bytes(b"new")
        destination.write_bytes(b"old")
        worker = self.worker()
        original = worker.metadata
        calls = []

        def changed(path):
            calls.append(path)
            if len(calls) == 2:
                source.write_bytes(b"changed")
            return original(path)

        worker.metadata = changed
        with self.assertRaisesRegex(transfer.TransferError, "源文件"):
            worker.pull(str(source), str(destination), "base64")
        self.assertEqual(destination.read_bytes(), b"old")

    def test_reject_links_fifos_and_control_characters(self):
        source = self.root / "source"
        source.write_bytes(b"safe")
        link = self.root / "link"
        link.symlink_to(source)
        fifo = self.root / "fifo"
        os.mkfifo(fifo)
        for path in (link, fifo):
            with self.assertRaises(transfer.TransferError):
                self.worker().push(str(path), "dest", "auto")
        for method, src, dst in (("push", source, link), ("pull", link, source)):
            with self.assertRaises(transfer.TransferError):
                getattr(self.worker(), method)(str(src), str(dst), "auto")
        with self.assertRaises(transfer.TransferError):
            transfer.checked_path("file\nname")
        with self.assertRaisesRegex(transfer.TransferError, "目录不存在"):
            self.worker().pull(str(source), str(self.root / "missing") + "/", "auto")

    def test_missing_checksum_tool_and_timeout(self):
        (self.bin / "sha256sum").unlink()
        with self.assertRaisesRegex(transfer.TransferError, "SHA-256"):
            self.worker().probe()
        with self.assertRaises(transfer.TransferError):
            transfer.Transfer(self.execute, timeout=0)
        worker = self.worker()
        worker.deadline = 0
        with self.assertRaisesRegex(transfer.TransferError, "超时"):
            worker.run("true")

    def test_command_size_stays_under_terminal_staging_threshold(self):
        worker = self.worker()
        worker.work = "/tmp/" + "文件 'x" * 15
        for codec, decoder in (("base64", "base64 -d"), ("octal", None)):
            size = worker.chunk_size(codec, decoder, 10 ** 12)
            command = "(" + worker.chunk_command(b"x" * size, 10 ** 12, codec, decoder) + ")"
            self.assertLessEqual(len(shlex.quote(command).encode()), 1900)
        worker.work = "/tmp/" + "文件 'x" * 100
        with self.assertRaisesRegex(transfer.TransferError, "路径过长"):
            worker.chunk_size("base64", "base64 -d", 1000)


class TransferRoutingTests(unittest.TestCase):
    def test_cli_passes_transport_and_paths(self):
        mux, cp = load_mux(), config()
        for action, mode in (("push", "base64"), ("pull", "octal"), ("push", None), ("pull", None)):
            options = ["--transport", mode] if mode else []
            with mock.patch.object(mux.sys, "argv", ["ssh-mux", action, *options,
                                                     "first", "source", "destination"]), \
                    mock.patch.object(mux, "load_config", return_value=cp), \
                    mock.patch.object(mux, "transfer_file", return_value=0) as call, \
                    self.assertRaises(SystemExit) as raised:
                mux.main()
            self.assertEqual(raised.exception.code, 0)
            self.assertEqual(call.call_args[0][2:],
                             (action, "source", "destination", "default", 3600, mode or "scp"))

    def test_default_uses_scp_and_stream_rejects_shell(self):
        mux, cp = load_mux(), config()
        with mock.patch.object(mux, "jump_scp", return_value=0) as scp:
            mux.transfer_file(cp, mux.get_host(cp, "first"), "push", "a", "b", "test", 30)
            scp.assert_called_once()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            mux.transfer_file(cp, mux.get_host(cp, "last"), "push", "a", "b", "test", 30, "stream")

    def test_jump_explicit_auto_uses_binary_ssh_and_no_scp(self):
        mux, cp = load_mux(), config()
        real_run = subprocess.run

        def local_ssh(args, **kwargs):
            self.assertEqual(args[0], "ssh")
            self.assertIn("-T", args)
            return real_run(["/bin/sh", "-c", args[-1]], **kwargs)

        with tempfile.TemporaryDirectory() as directory, \
                mock.patch.object(mux, "jump_connect"), \
                mock.patch.object(mux, "jump_sock_file", return_value="unused"), \
                mock.patch.object(mux.subprocess, "run", side_effect=local_ssh), \
                contextlib.redirect_stdout(io.StringIO()):
            source, remote, local = [Path(directory) / name for name in ("source", "remote", "local")]
            source.write_bytes(bytes(range(256)) * 100)
            host = mux.get_host(cp, "first")
            mux.transfer_file(cp, host, "push", str(source), str(remote), "test", 30, "auto")
            mux.transfer_file(cp, host, "pull", str(remote), str(local), "test", 30, "auto")
            self.assertEqual(source.read_bytes(), local.read_bytes())


if __name__ == "__main__":
    unittest.main()
