"""混合传输回归；远端由本地 shell 和模拟 SSH 进程代替。"""

import configparser
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import shlex
import shutil
import subprocess
import sys
import tempfile
import unittest
from unittest import mock

from test_transfer import load_mux

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("hybrid_tests_module", ROOT / "ssh_hybrid.py")
hybrid = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hybrid)


def config():
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_dict({"gate": {"host": "gate.invalid", "routing": "username", "user": "demo"},
                  "A": {"host": "a.invalid", "via": "gate", "via_mode": "shell", "user": "demo"},
                  "B": {"host": "b.invalid", "via": "A", "via_mode": "shell", "user": "demo"},
                  "T": {"host": "t.invalid", "via": "B", "via_mode": "shell", "user": "demo"}})
    return cp


class RouteTests(unittest.TestCase):
    def test_routing_gate_is_not_a_file_endpoint(self):
        mux, cp = load_mux(), config()
        legs = hybrid.plan_route(mux, cp, mux.get_host(cp, "T"), ["A:B=base64", "B:T=stream"])
        self.assertEqual([(x["outer"], x["inner"], x["transport"]) for x in legs],
                         [("@local", "A", "auto"), ("A", "B", "base64"), ("B", "T", "stream")])

    def test_standard_jumps_collapse_unless_explicitly_split(self):
        mux, cp = load_mux(), config()
        cp["A"].pop("via")
        cp["B"]["via_mode"] = cp["T"]["via_mode"] = "jump"
        host = mux.get_host(cp, "T")
        self.assertEqual(len(hybrid.plan_route(mux, cp, host, [])), 1)
        self.assertEqual(len(hybrid.plan_route(mux, cp, host, ["A:B=scp"])), 3)

    def test_invalid_or_duplicate_leg_rejected(self):
        mux, cp = load_mux(), config()
        for legs in (["A:T=scp"], ["A:B=scp", "A:B=base64"], ["gate:A=auto"], ["A:B=bad"]):
            with self.assertRaises(hybrid.TransferError):
                hybrid.plan_route(mux, cp, mux.get_host(cp, "T"), legs)


class WorkerIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="hybrid-tests-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        ssh = self.bin / "ssh"
        ssh.write_text("#!" + sys.executable + "\n" + r'''
import os,sys
args=sys.argv[1:]
if '-tt' in args:
    os.execv('/bin/bash',['bash','--noprofile','--norc','-i'])
if os.environ.get('TEST_TTY_ONLY'):
    print('exec request failed on channel 0',file=sys.stderr);sys.exit(1)
os.execv('/bin/sh',['sh','-c',args[-1]])
''')
        ssh.chmod(0o700)
        scp = self.bin / "scp"
        actual_scp = shutil.which("scp")
        if actual_scp:
            scp.write_text("#!" + sys.executable + "\nimport os,sys\nos.execv(" + repr(actual_scp) +
                           ",['scp','-S'," + repr(str(ssh)) + "]+sys.argv[1:])\n")
            scp.chmod(0o700)
        self.env = dict(os.environ, PATH=str(self.bin) + os.pathsep + os.environ["PATH"])
        self.bundle = self.root / "worker.pyz"
        self.bundle.write_bytes(hybrid.worker_bundle())
        self.source = self.root / "源 '文件;$literal"
        self.source.write_bytes(bytes(range(256)) * 5)
        self.destination = self.root / "target"

    def request(self, mode, action="push", op="transfer", timeout=30):
        directory = Path(tempfile.mkdtemp(dir=self.root, prefix="job-"))
        request = {"id": directory.name, "target": {"host": "target.invalid", "port": 22,
                   "user": "demo", "password": ""}, "timeout": timeout, "transport": mode,
                   "action": action, "op": op, "src": str(self.source), "dst": str(self.destination),
                   "expected": [len(self.source.read_bytes()), hashlib.sha256(self.source.read_bytes()).hexdigest()]}
        (directory / "request.json").write_text(json.dumps(request))
        return directory

    def run_worker(self, directory):
        result = subprocess.run([sys.executable, str(self.bundle), str(directory)], env=self.env,
                                capture_output=True, text=True, timeout=45)
        self.assertEqual(result.returncode, 0, (result.stdout, result.stderr,
                                               (directory / "result.json").read_text()))
        return json.loads((directory / "result.json").read_text())

    def test_remote_worker_all_transports_push_and_pull(self):
        for mode in ("stream", "base64", "octal", "scp"):
            if mode == "scp" and not shutil.which("scp"):
                continue
            for action in ("push", "pull"):
                with self.subTest(mode=mode, action=action):
                    directory = self.request(mode, action)
                    self.run_worker(directory)
                    self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
                    self.assertFalse((directory / "request.json").exists())

    def test_terminal_only_connection_transfers_without_local_relay(self):
        self.env["TEST_TTY_ONLY"] = "1"
        for action in ("push", "pull"):
            directory = self.request("base64", action)
            self.run_worker(directory)
            self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        result = self.run_worker(self.request("auto"))
        self.assertEqual(result["transport"], "base64")

    def test_empty_file_and_source_hash_mismatch(self):
        self.source.write_bytes(b"")
        self.run_worker(self.request("octal"))
        self.assertEqual(self.destination.read_bytes(), b"")
        directory = self.request("base64")
        self.source.write_bytes(b"changed")
        self.destination.write_bytes(b"old target")
        result = subprocess.run([sys.executable, str(self.bundle), str(directory)], env=self.env,
                                capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(self.destination.read_bytes(), b"old target")
        self.assertEqual(json.loads((directory / "result.json").read_text())["status"], "error")

    def test_duplicate_launch_executes_once_and_returns_saved_result(self):
        directory = self.request("base64")
        processes = [subprocess.Popen([sys.executable, str(self.bundle), str(directory)], env=self.env,
                                       stdout=subprocess.PIPE, stderr=subprocess.PIPE) for _ in range(2)]
        for process in processes:
            process.communicate(timeout=45)
            self.assertEqual(process.returncode, 0)
        original = (directory / "result.json").read_bytes()
        self.destination.write_bytes(b"changed after completion")
        self.run_worker(directory)
        self.assertEqual((directory / "result.json").read_bytes(), original)
        self.assertEqual(self.destination.read_bytes(), b"changed after completion")

    def test_cancel_and_missing_request_produce_structured_failure(self):
        directory = self.request("base64")
        (directory / "cancel").touch()
        result = subprocess.run([sys.executable, str(self.bundle), str(directory)], env=self.env,
                                capture_output=True, timeout=45)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads((directory / "result.json").read_text())["status"], "error")
        self.assertFalse(self.destination.exists())

    def test_worker_timeout_stops_before_destination_write(self):
        directory = self.request("base64", timeout=0.05)
        result = subprocess.run([sys.executable, str(self.bundle), str(directory)], env=self.env,
                                capture_output=True, timeout=10)
        self.assertEqual(result.returncode, 1)
        self.assertEqual(json.loads((directory / "result.json").read_text())["status"], "error")
        self.assertFalse(self.destination.exists())

    def test_expired_encoded_download_cleans_next_hop_directory(self):
        log = self.root / "dd-args"
        dd = self.bin / "dd"
        dd.write_text("#!/bin/sh\nprintf '%s\\n' \"$@\" > " + shlex.quote(str(log)) +
                      "\nsleep 3\nexec " + shlex.quote(shutil.which("dd")) + ' "$@"\n')
        dd.chmod(0o700)
        directory = self.request("base64", action="pull", timeout=2)
        result = subprocess.run([sys.executable, str(self.bundle), str(directory)], env=self.env,
                                capture_output=True, timeout=25)
        self.assertEqual(result.returncode, 1)
        self.assertTrue(log.exists(), "必须在实际下载块期间触发超时")
        part = next(arg[3:] for arg in log.read_text().splitlines() if arg.startswith("of="))
        remote_temp = Path(part).parent
        self.addCleanup(shutil.rmtree, remote_temp, True)
        payload = json.loads((directory / "result.json").read_text())
        self.assertEqual(payload["status"], "error")
        self.assertEqual(payload["leftovers"], [])
        self.assertFalse(remote_temp.exists())

    def test_failed_next_hop_cleanup_is_returned_in_result(self):
        rm = self.bin / "rm"
        rm.write_text("#!/bin/sh\ncase \"$*\" in *ssh_mux_transfer_*) exit 1;; esac\nexec " +
                      shlex.quote(shutil.which("rm")) + ' "$@"\n')
        rm.chmod(0o700)
        directory = self.request("stream", op="probe")
        payload = self.run_worker(directory)
        self.assertTrue(payload["leftovers"])
        for path in payload["leftovers"]:
            self.assertTrue(Path(path).is_dir())
            self.assertTrue(Path(path).name.startswith(".ssh_mux_transfer_"))
            self.addCleanup(shutil.rmtree, path, True)

    def test_late_cleanup_result_is_reported_before_logs_are_removed(self):
        mux, cp = load_mux(), config()
        owner = hybrid.Coordinator(mux, cp, mux.get_host(cp, "T"), "push",
                                   str(self.source), str(self.destination), 30, [])
        endpoint = owner.endpoint("B")
        directory = str(self.root / "job-test")
        endpoint.work = str(self.root / "work")
        endpoint.job_dirs = [directory]
        endpoint.job_targets[directory] = "T"
        path = "/tmp/.ssh_mux_transfer_test_leftover"
        payload = {"status": "error", "leftovers": [path]}
        error = io.StringIO()

        def execute(command, limit):
            if command.startswith("rm -rf"):
                self.assertIn("T:" + path, error.getvalue())
            return {"exit": 0, "output": json.dumps(payload) + "\n" if command.startswith("cat ") else ""}

        endpoint.execute = execute
        with contextlib.redirect_stderr(error):
            self.assertTrue(endpoint.stop_jobs())
            endpoint.cleanup()
        self.assertIn("T:" + path, error.getvalue())

    def test_first_leg_auto_probes_protocol_and_only_falls_back_when_unsupported(self):
        mux = load_mux()
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_dict({"T": {"host": "target.invalid", "user": "demo"}})
        root, env = self.root, self.env
        stream_calls = []

        class LocalEndpoint(hybrid.Endpoint):
            def execute(self, command, limit):
                result = subprocess.run(["/bin/sh", "-c", command], env=env, cwd=root,
                                        capture_output=True, text=True, timeout=limit)
                return {"exit": result.returncode, "output": result.stdout + result.stderr}

            def stream(self, action, path, file, limit):
                stream_calls.append(action)
                with open(path, "wb" if action == "push" else "rb") as remote:
                    shutil.copyfileobj(file, remote) if action == "push" else shutil.copyfileobj(remote, file)

        rejected = subprocess.CompletedProcess([], 1, "", "exec request failed on channel 0")
        with mock.patch.object(hybrid, "Endpoint", LocalEndpoint), \
                mock.patch.object(mux, "jump_connect", side_effect=AssertionError("不能连接真实服务器")), \
                mock.patch.object(mux, "jump_scp", return_value=rejected) as scp, \
                contextlib.redirect_stdout(io.StringIO()) as output:
            for plan_only in (True, False):
                owner = hybrid.Coordinator(mux, cp, mux.get_host(cp, "T"), "push",
                                           str(self.source), str(self.destination), 30, [], plan_only)
                self.assertEqual(owner.run(), 0)
                self.assertEqual(owner.legs[0]["transport"], "stream")
            self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
            self.assertGreaterEqual(len(stream_calls), 4)
            scp.return_value = subprocess.CompletedProcess([], 1, "", "Permission denied")
            stream_calls.clear()
            with self.assertRaisesRegex(hybrid.TransferError, "未切换协议"):
                hybrid.Coordinator(mux, cp, mux.get_host(cp, "T"), "push",
                                   str(self.source), str(self.destination), 30, [], True).run()
            self.assertEqual(stream_calls, [])

    def test_ipv6_scp_arguments_for_old_and_remote_paths(self):
        if not shutil.which("scp"):
            self.skipTest("需要本机 scp")
        directory = self.request("scp")
        request = json.loads((directory / "request.json").read_text())
        request["target"]["host"] = "2001:db8::1"
        (directory / "request.json").write_text(json.dumps(request))
        self.run_worker(directory)
        self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
        mux, cp = load_mux(), config()
        cp["T"]["host"] = "2001:db8::1"
        host = mux.get_host(cp, "T")
        actual = mux.remote_spec(host, "/tmp/file")
        self.assertEqual(actual, "demo@[2001:db8::1]:/tmp/file")
        for address in ("2001:db8::1", "[2001:db8::1]", "fe80::1%eth0"):
            spec = hybrid.transfer_module.remote_spec("demo", address, "/tmp/file")
            self.assertEqual(spec.count("["), 1)
            log = self.root / "ssh-args"
            fake_ssh = self.root / "capture-ssh"
            fake_ssh.write_text("#!" + sys.executable + "\nimport json,sys\nopen(" + repr(str(log)) +
                                ",'w').write(json.dumps(sys.argv[1:]))\nsys.exit(1)\n")
            fake_ssh.chmod(0o700)
            for operands in ((str(self.source), spec), (spec, str(self.destination))):
                subprocess.run([shutil.which("scp"), "-O", "-S", str(fake_ssh), *operands],
                               capture_output=True, timeout=5)
                args = json.loads(log.read_text())
                self.assertIn(address.strip("[]"), args)

    def test_unknown_running_job_preserves_all_staging_directories(self):
        mux, cp = load_mux(), config()
        coordinator = hybrid.Coordinator(mux, cp, mux.get_host(cp, "T"), "push",
                                         str(self.source), str(self.destination), 30, [])
        first, second = mock.Mock(), mock.Mock()
        first.stop_jobs.return_value = False
        second.stop_jobs.return_value = True
        first.used = second.used = False
        coordinator.endpoints = {"A": first, "B": second}
        coordinator.perform = mock.Mock(side_effect=hybrid.TransferError("连接中断"))
        with self.assertRaises(hybrid.TransferError):
            coordinator.run()
        first.cleanup.assert_called_once_with(False)
        second.cleanup.assert_called_once_with(False)

    def test_mixed_chain_roundtrip_and_plan_do_not_use_real_ssh(self):
        mux, cp = load_mux(), config()
        root, env = self.root, self.env
        endpoints = []

        class LocalEndpoint(hybrid.Endpoint):
            def execute(self, command, limit):
                self.used = True
                result = subprocess.run(["/bin/sh", "-c", command], env=env, cwd=root,
                                        capture_output=True, text=True, timeout=limit)
                return {"exit": result.returncode, "output": result.stdout + result.stderr}

            def prepare(self, parent="/tmp"):
                super().prepare(str(root) if parent == "/tmp" else parent)
                endpoints.append(self)

        with mock.patch.object(hybrid, "Endpoint", LocalEndpoint), \
                mock.patch.object(mux, "cmd_exit"), contextlib.redirect_stdout(io.StringIO()):
            legs = ["@local:A=base64", "A:B=base64", "B:T=stream"]
            host = mux.get_host(cp, "T")
            plan = hybrid.Coordinator(mux, cp, host, "push", str(self.source), str(self.destination), 120, legs, True)
            self.assertEqual(plan.run(), 0)
            self.assertFalse(self.destination.exists())
            push = hybrid.Coordinator(mux, cp, host, "push", str(self.source), str(self.destination), 120, legs)
            self.assertEqual(push.run(), 0)
            self.assertEqual(self.destination.read_bytes(), self.source.read_bytes())
            download = self.root / "download"
            pull = hybrid.Coordinator(mux, cp, host, "pull", str(self.destination), str(download), 120, legs)
            self.assertEqual(pull.run(), 0)
            self.assertEqual(download.read_bytes(), self.source.read_bytes())
            original_job = LocalEndpoint.job

            def fail_transfer(endpoint, *args, **kwargs):
                if len(args) > 3 and args[3] == "transfer":
                    raise hybrid.TransferError("模拟第二段失败")
                return original_job(endpoint, *args, **kwargs)

            self.destination.write_bytes(b"old target")
            with mock.patch.object(LocalEndpoint, "job", fail_transfer), self.assertRaises(hybrid.TransferError):
                hybrid.Coordinator(mux, cp, host, "push", str(self.source), str(self.destination), 120, legs).run()
            self.assertEqual(self.destination.read_bytes(), b"old target")
        self.assertTrue(all(not Path(endpoint.work).exists() for endpoint in endpoints))


if __name__ == "__main__":
    unittest.main()
