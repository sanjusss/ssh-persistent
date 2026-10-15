"""远端代理准备、私有输入、生命周期与传输接入测试；远端用本机 bash 或假对象模拟。"""

import configparser
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_transfer import load_mux

ROOT = Path(__file__).resolve().parents[1]


def load_module(name, filename):
    spec = importlib.util.spec_from_file_location(name, ROOT / filename)
    module = importlib.util.module_from_spec(spec)
    sys.path.insert(0, str(ROOT))
    try:
        spec.loader.exec_module(module)
    finally:
        sys.path.remove(str(ROOT))
    return module


hybrid = load_module("proxy_remote_hybrid", "ssh_hybrid.py")
worker = load_module("proxy_remote_worker", "ssh_worker.py")

PROXY_DICT = {
    "type": "socks5",
    "host": "10.1.1.1",
    "port": 1080,
    "user": "px-user",
    "password": "px-pass-机密",
}
TARGET = {"host": "b.invalid", "port": 22}


class FakeSess:
    """模拟远端终端：按命令内容返回预设结果，记录私有输入。"""

    def __init__(self, probe_code=0, mkdir_code=0, verify_code=0):
        self.probe_code = probe_code
        self.mkdir_code = mkdir_code
        self.verify_code = verify_code
        self.commands = []
        self.private = []

    def exec(self, command, timeout, password=None):
        self.commands.append(command)
        if "command -v python3" in command:
            return "", self.probe_code
        if "mkdir -m 700" in command:
            return "", self.mkdir_code
        if "S_IMODE" in command:
            return "", self.verify_code
        return "", 0

    def send_private(self, content, remote_path, timeout=60):
        self.private.append((bytes(content), remote_path))


class PrepareRemoteProxyTests(unittest.TestCase):
    """远端准备接口与运行条件探测（任务 4.1、4.2）。"""

    def setUp(self):
        self.mux = load_mux()

    def prepare(self, sess, holder="h1"):
        janitor = self.mux.RemoteJanitor()
        logs = []
        info = self.mux.prepare_remote_proxy(
            sess, "A", dict(PROXY_DICT), TARGET, holder, janitor, logs.append
        )
        return info, janitor, logs

    def test_success_returns_remote_paths_and_registers_holder(self):
        sess = FakeSess()
        info, janitor, logs = self.prepare(sess)
        # 返回路径均为远端路径
        self.assertTrue(info["dir"].startswith(self.mux.REMOTE_PROXY_DIR))
        self.assertEqual(
            info["command"],
            "python3 {} {}".format(
                shlex.quote(info["dir"] + "/ssh_proxy.py"),
                shlex.quote(info["dir"] + "/px.json"),
            ),
        )
        entries = janitor.pop("h1")
        self.assertEqual([(n, d) for n, d, _ in entries], [("A", info["dir"])])
        # 登记含断线重建材料：该段的 proxy 字典与目标 host/port
        self.assertEqual(entries[0][2], {"proxy": PROXY_DICT, "target": TARGET})
        # 接收校验用 python3（兼容 BSD/macOS，远端本就要求 python3），不用 stat -c
        verify_cmd = sess.commands[-1]
        self.assertIn("S_IMODE", verify_cmd)
        self.assertNotIn("stat -c", verify_cmd)
        # 程序与配置都经私有输入通道发送，命令行不包含秘密
        self.assertEqual(len(sess.private), 2)
        script, script_path = sess.private[0]
        self.assertEqual(script, (ROOT / "ssh_proxy.py").read_bytes())
        config, config_path = sess.private[1]
        self.assertEqual(config_path, info["dir"] + "/px.json")
        data = json.loads(config.decode())
        self.assertEqual(data["proxy"], PROXY_DICT)  # 远端只收到自身段配置
        self.assertEqual(data["target"], TARGET)
        self.assertTrue(data["log"].startswith(info["dir"]))
        for command in sess.commands:
            self.assertNotIn("px-pass-机密", command)
        self.assertNotIn("px-pass-机密", json.dumps(logs, ensure_ascii=False))

    def test_probe_failure_reports_node_without_install(self):
        sess = FakeSess(probe_code=1)
        with self.assertRaises(self.mux.ProxySetupError) as ctx:
            self.prepare(sess)
        self.assertIn("A", str(ctx.exception))
        self.assertIn("不会自动安装软件", str(ctx.exception))
        # 探测失败后不创建目录、不发送任何内容
        self.assertEqual(len(sess.commands), 1)
        self.assertEqual(sess.private, [])

    def test_dir_and_verify_failure_report_node(self):
        sess = FakeSess(mkdir_code=1)
        with self.assertRaises(self.mux.ProxySetupError) as ctx:
            self.prepare(sess)
        self.assertIn("A", str(ctx.exception))
        self.assertEqual(sess.private, [])
        sess = FakeSess(verify_code=1)
        with self.assertRaises(self.mux.ProxySetupError):
            self.prepare(sess)

    def test_holders_on_same_node_are_isolated(self):
        janitor = self.mux.RemoteJanitor()
        janitor.register("h1", "A", "/tmp/.ssh_mux_px_one")
        janitor.register("h2", "A", "/tmp/.ssh_mux_px_two")
        self.assertEqual(janitor.pop("h1"), [("A", "/tmp/.ssh_mux_px_one", None)])
        self.assertEqual(janitor.pop("h1"), [])
        self.assertEqual(janitor.pop("h2"), [("A", "/tmp/.ssh_mux_px_two", None)])

    def test_fixed_dir_rebuild_is_idempotent(self):
        """断线重建到原目录：目录可能因仅网络闪断而已存在，幂等覆盖不报错。"""
        sess = FakeSess()
        janitor = self.mux.RemoteJanitor()
        info = self.mux.prepare_remote_proxy(
            sess,
            "A",
            dict(PROXY_DICT),
            TARGET,
            "xfer-1",
            janitor,
            lambda m: None,
            fixed_dir="/tmp/.ssh_mux_px_fixed",
        )
        # 重发的命令可继续引用原路径
        self.assertEqual(info["dir"], "/tmp/.ssh_mux_px_fixed")
        mkdir_cmd = next(c for c in sess.commands if "mkdir -m 700" in c)
        self.assertIn("test -d", mkdir_cmd)  # 同名目录已存在时幂等
        self.assertIn("test ! -L", mkdir_cmd)  # 拒绝预置的符号链接
        self.assertIn("chmod 700", mkdir_cmd)
        sent = sorted(p for _, p in sess.private)
        self.assertEqual(
            sent,
            ["/tmp/.ssh_mux_px_fixed/px.json", "/tmp/.ssh_mux_px_fixed/ssh_proxy.py"],
        )
        self.assertEqual(
            janitor.pop("xfer-1"),
            [("A", "/tmp/.ssh_mux_px_fixed", {"proxy": PROXY_DICT, "target": TARGET})],
        )
        # 再次闪断后的重复重建也不报错中断
        self.mux.prepare_remote_proxy(
            sess,
            "A",
            dict(PROXY_DICT),
            TARGET,
            "xfer-1",
            self.mux.RemoteJanitor(),
            lambda m: None,
            fixed_dir="/tmp/.ssh_mux_px_fixed",
        )

    @unittest.skipUnless(shutil.which("bash"), "需要本地 Bash")
    def test_fixed_dir_rebuild_rejects_symlink(self):
        """重建命令在本机 bash 下实测：符号链接被拒绝，真实目录幂等通过。"""
        sess = FakeSess()
        self.mux.prepare_remote_proxy(
            sess,
            "A",
            dict(PROXY_DICT),
            TARGET,
            "xfer-1",
            self.mux.RemoteJanitor(),
            lambda m: None,
            fixed_dir="/tmp/.ssh_mux_px_LINK",
        )
        mkdir_cmd = next(c for c in sess.commands if "mkdir -m 700" in c)
        tmp = tempfile.mkdtemp(prefix="ssh-mux-link-")
        self.addCleanup(shutil.rmtree, tmp, ignore_errors=True)
        target = os.path.join(tmp, ".ssh_mux_px_LINK")
        # 命令引用的是固定远端路径；换到本机临时路径执行同一命令模板
        local_cmd = mkdir_cmd.replace("/tmp/.ssh_mux_px_LINK", shlex.quote(target))
        # 目录被替换为符号链接（指向合法目录也不行）时准备失败
        real = os.path.join(tmp, "real")
        os.mkdir(real)
        os.symlink(real, target)
        r = subprocess.run(["bash", "-c", local_cmd], capture_output=True)
        self.assertNotEqual(r.returncode, 0)
        # 真实目录存在时幂等通过
        os.unlink(target)
        os.mkdir(target, 0o700)
        r = subprocess.run(["bash", "-c", local_cmd], capture_output=True)
        self.assertEqual(r.returncode, 0, r.stderr)
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o700)


class AttachSupportTests(unittest.TestCase):
    """登录步骤钩子：远端准备、未使用提示与重建重备（任务 4.1、4.5）。"""

    def setUp(self):
        self.mux = load_mux()
        self.cp = configparser.ConfigParser(interpolation=None)
        self.cp.read_dict(
            {
                "A": {"host": "a.invalid", "user": "u"},
                "B": {
                    "host": "b.invalid",
                    "user": "u",
                    "via": "A",
                    "via_mode": "shell",
                },
                "C": {
                    "host": "c.invalid",
                    "user": "u",
                    "via": "B",
                    "via_mode": "shell",
                    "proxy": "http",
                    "proxy_host": "10.2.2.2",
                    "proxy_port": "8080",
                },
            }
        )

    def test_on_step_prepares_and_reprepares_after_rebuild(self):
        plan = self.mux.build_shell_plan(self.cp, "C")
        sess = self.mux.PtySession(plan, lambda msg: None)
        janitor = self.mux.RemoteJanitor()
        with mock.patch.object(self.mux, "jump_connect", return_value=None):
            self.mux.attach_proxy_support(
                sess, self.cp, plan, janitor, "session", "s_t", lambda m: None, set()
            )
            sess.before_start()
            prep_meta = plan[2][2]
            self.assertIn("prepare", prep_meta)
            remote = FakeSess()
            opts = sess.on_step(remote, prep_meta)
            self.assertTrue(opts[1].startswith("ProxyCommand=python3 "))
            # 程序或配置丢失后的重建会重新准备（再次登记新目录）
            opts2 = sess.on_step(remote, prep_meta)
            self.assertNotEqual(opts, opts2)
            self.assertEqual(len(janitor.pop("session")), 2)

    def test_unused_hint_logged_once(self):
        logs = []
        hinted = set()
        sess = self.mux.PtySession([(["true"], [], {})], lambda msg: None)
        plan = [(["true"], [], {"unused_hint": "提示甲"})]
        self.mux.attach_proxy_support(
            sess,
            self.cp,
            plan,
            self.mux.RemoteJanitor(),
            "session",
            "s_t",
            logs.append,
            hinted,
        )
        meta = {"unused_hint": "提示甲"}
        sess.on_step(FakeSess(), meta)
        sess.on_step(FakeSess(), meta)
        self.assertEqual(logs, ["提示: 提示甲"])  # 复用不重复提示

    def attach(self, sess, janitor, logs):
        self.mux.attach_proxy_support(
            sess,
            self.cp,
            [(["true"], [], {})],
            janitor,
            "session",
            "s_t",
            logs.append,
            set(),
        )

    def test_after_start_reprepares_xfer_holders_to_original_dir(self):
        """断线重建：xfer-* 持有者重建到原目录；session 持有者不重复准备。"""
        logs = []
        sess = self.mux.PtySession([(["true"], [], {})], lambda msg: None)
        janitor = self.mux.RemoteJanitor()
        self.attach(sess, janitor, logs)
        # start() 期间 on_step 已用新随机目录为 session 准备好登录段
        # （旧登记保留供清理）；传输经 rpc 为 xfer-1 准备过资源（含重建材料）
        materials = {"proxy": dict(PROXY_DICT), "target": dict(TARGET)}
        janitor.register("session", "B", "/tmp/.ssh_mux_px_oldlogin", dict(materials))
        janitor.register("xfer-1", "C", "/tmp/.ssh_mux_px_xfer", materials)
        calls = []

        def fake_prepare(s, node, proxy_dict, target, holder, j, log, fixed_dir=None):
            calls.append((node, proxy_dict, target, holder, fixed_dir))
            j.register(holder, node, fixed_dir, {"proxy": proxy_dict, "target": target})
            return {"dir": fixed_dir, "command": "python3 x"}

        with mock.patch.object(self.mux, "prepare_remote_proxy", fake_prepare):
            sess.after_start()
        # xfer-1 重建到原目录，重发的命令可继续引用原路径；重建材料一致
        self.assertEqual(len(calls), 1)
        node, proxy_dict, target, holder, fixed_dir = calls[0]
        self.assertEqual(
            (node, holder, fixed_dir), ("C", "xfer-1", "/tmp/.ssh_mux_px_xfer")
        )
        self.assertEqual(proxy_dict, PROXY_DICT)
        self.assertEqual(target, TARGET)
        self.assertEqual(
            janitor.by_holder.get("xfer-1"),
            [("C", "/tmp/.ssh_mux_px_xfer", {"proxy": PROXY_DICT, "target": TARGET})],
        )
        # session 持有者的旧目录不被重复准备：登记原样保留，仅供事后清理
        self.assertEqual(
            [(n, d) for n, d, _ in janitor.by_holder["session"]],
            [("B", "/tmp/.ssh_mux_px_oldlogin")],
        )
        # 初始启动时 janitor 里没有其他持有者，自然是无操作
        janitor2 = self.mux.RemoteJanitor()
        sess2 = self.mux.PtySession([(["true"], [], {})], lambda msg: None)
        self.attach(sess2, janitor2, logs)
        with mock.patch.object(self.mux, "prepare_remote_proxy", fake_prepare):
            sess2.after_start()
        self.assertEqual(len(calls), 1)

    def test_after_start_reprepare_failure_logged_not_fatal(self):
        """重建代理资源失败不中断会话恢复：记录日志，该段重试随后报错。"""
        logs = []
        sess = self.mux.PtySession([(["true"], [], {})], lambda msg: None)
        janitor = self.mux.RemoteJanitor()
        self.attach(sess, janitor, logs)
        materials = {"proxy": dict(PROXY_DICT), "target": dict(TARGET)}
        janitor.register("xfer-9", "C", "/tmp/.ssh_mux_px_lost", materials)

        def failing_prepare(*a, **k):
            raise ConnectionError("通道仍不可达")

        with mock.patch.object(self.mux, "prepare_remote_proxy", failing_prepare):
            sess.after_start()  # 不抛出，会话重建本身不崩溃
        text = "\n".join(logs)
        self.assertIn("重建", text)
        self.assertIn("/tmp/.ssh_mux_px_lost", text)
        self.assertNotIn("px-pass-机密", text)  # 日志不含秘密
        # 登记保留，供事后清理
        self.assertEqual(
            janitor.by_holder.get("xfer-9"),
            [("C", "/tmp/.ssh_mux_px_lost", materials)],
        )


class PtyPrivateChannelTests(unittest.TestCase):
    """私有输入通道的字节、权限与中断恢复（任务 4.3、4.5）。"""

    @unittest.skipUnless(shutil.which("bash"), "需要本地 Bash")
    def make_session(self):
        plan = [(["bash", "--noprofile", "--norc", "-i"], [])]
        logs = []
        sess = load_mux().PtySession(plan, logs.append)
        self.addCleanup(sess.close)
        sess.start()
        return sess, logs

    def test_send_private_roundtrip_permissions_and_log_silence(self):
        sess, logs = self.make_session()
        directory = "/tmp/.ssh_mux_px_test" + next(tempfile._get_candidate_names())
        out, code = sess.exec(
            "umask 077; mkdir -m 700 -- " + shlex.quote(directory), 10
        )
        self.assertEqual(code, 0)
        secret = "凭据-内容-π-" + "x" * 3000  # 多段分块发送
        target = directory + "/px.json"
        sess.send_private(secret.encode(), target)
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        self.assertEqual(Path(target).read_bytes(), secret.encode())
        # 凭据及其编码不进入日志；终端会话仍可用
        self.assertNotIn(secret, "".join(logs))
        out, code = sess.exec("printf 'still-alive'", 6)
        self.assertEqual((out, code), ("still-alive", 0))

    def test_interrupted_send_recovers_and_drops_body(self):
        sess, logs = self.make_session()
        directory = "/tmp/.ssh_mux_px_test" + next(tempfile._get_candidate_names())
        sess.exec("umask 077; mkdir -m 700 -- " + shlex.quote(directory), 10)
        target = directory + "/px.json"
        original = sess._wait_for
        state = {"calls": 0}

        def flaky(rx, timeout, extra=()):
            # 只让分段确认等待失败；就绪确认与恢复流程仍走真实等待
            if b"__PX_ACK_" in rx.pattern:
                raise TimeoutError("模拟私有输入中断")
            return original(rx, timeout, extra)

        with mock.patch.object(sess, "_wait_for", side_effect=flaky):
            with self.assertRaises(TimeoutError):
                sess.send_private(b"body-must-not-run", target)
        # 停止接收并恢复终端：剩余正文不得由 shell 执行，临时文件被丢弃
        out, code = sess.exec("printf 'recovered'", 6)
        self.assertEqual((out, code), ("recovered", 0))
        out, code = sess.exec(
            "ls -a {} | grep -c recv || true".format(shlex.quote(directory)), 6
        )
        self.assertFalse(os.path.exists(target))
        out, code = sess.exec(
            "find {} -name '*.recv-*' | wc -l".format(shlex.quote(directory)), 6
        )
        self.assertEqual(out.strip(), "0")
        self.assertNotIn("body-must-not-run", "".join(logs))


class LifecycleUnitTests(unittest.TestCase):
    """资源清理时机与失败报告（任务 4.4、4.5）。"""

    def setUp(self):
        self.mux = load_mux()
        self.cp = configparser.ConfigParser(interpolation=None)
        self.cp.read_dict({"A": {"host": "a.invalid", "user": "u"}})

    def test_cleanup_on_local_node_uses_session(self):
        janitor = self.mux.RemoteJanitor()
        janitor.register("h1", "A", "/tmp/.ssh_mux_px_a")
        sess = FakeSess()
        leftovers = self.mux.cleanup_holder_resources(
            self.cp, janitor, "h1", lambda m: None, local_node="A", sess=sess
        )
        self.assertEqual(leftovers, [])
        self.assertTrue(any("rm -rf" in c for c in sess.commands))
        self.assertEqual(janitor.pop("h1"), [])

    def test_prepare_send_failure_leaves_registered_dir(self):
        """send_private 中途失败：目录已登记，随后的持有者清理会尝试删除它。"""
        janitor = self.mux.RemoteJanitor()

        class FlakySess(FakeSess):
            def send_private(self, content, remote_path, timeout=60):
                raise ConnectionError("模拟私有输入中断")

        sess = FlakySess()
        with self.assertRaises(ConnectionError):
            self.mux.prepare_remote_proxy(
                sess, "A", dict(PROXY_DICT), TARGET, "xfer-2", janitor, lambda m: None
            )
        entries = janitor.by_holder.get("xfer-2")
        self.assertEqual(len(entries), 1)  # 目录创建成功即登记
        node, directory, _ = entries[0]
        self.assertEqual(node, "A")
        # 持有者清理覆盖这个部分写入的目录
        sess2 = FakeSess()
        leftovers = self.mux.cleanup_holder_resources(
            self.cp, janitor, "xfer-2", lambda m: None, local_node="A", sess=sess2
        )
        self.assertEqual(leftovers, [])
        self.assertTrue(any("rm -rf" in c and directory in c for c in sess2.commands))

    def test_cleanup_failure_reports_node_and_path(self):
        janitor = self.mux.RemoteJanitor()
        janitor.register("h1", "A", "/tmp/.ssh_mux_px_a")
        janitor.register("h2", "A", "/tmp/.ssh_mux_px_b")

        def fake_management(cp, node, command, timeout, log, janitor=None, depth=0):
            raise SystemExit(1)  # 管理连接失败（die）

        with mock.patch.object(self.mux, "management_exec", fake_management):
            leftovers = self.mux.cleanup_holder_resources(
                self.cp, janitor, "h1", lambda m: None
            )
        # 清理失败报告节点和路径；SystemExit 不向上传播、不覆盖原错误
        self.assertEqual([x["path"] for x in leftovers], ["/tmp/.ssh_mux_px_a"])
        self.assertEqual(leftovers[0]["node"], "A")
        self.assertEqual(janitor.pop("h2"), [("A", "/tmp/.ssh_mux_px_b", None)])

    def test_cleanup_command_verifies_process_identity(self):
        """kill 前校验进程身份：PID 复用不会误杀无关进程。"""
        cmd = self.mux.remote_cleanup_command("/tmp/.ssh_mux_px_x1")
        self.assertIn("ps -p", cmd)
        self.assertIn("ssh_proxy[.]py", cmd)
        self.assertIn("rm -rf", cmd)

    @unittest.skipUnless(
        shutil.which("bash") and shutil.which("ps"), "需要本地 bash 与 ps"
    )
    def test_cleanup_command_kills_only_proxy_process(self):
        with tempfile.TemporaryDirectory(prefix="ssh-mux-cl-") as td:
            work = Path(td) / ".ssh_mux_px_x1"
            work.mkdir(mode=0o700)
            # 命令行含 ssh_proxy.py 的进程会被 kill
            fake_proxy = work / "ssh_proxy.py"
            fake_proxy.write_text("import time\ntime.sleep(60)\n")
            prox = subprocess.Popen([sys.executable, "ssh_proxy.py"], cwd=str(work))
            # 无关进程（PID 复用情形）不被 kill
            other = subprocess.Popen(["sleep", "60"])
            self.addCleanup(lambda: prox.poll() is None and prox.kill())
            self.addCleanup(lambda: other.poll() is None and other.kill())
            cmd = self.mux.remote_cleanup_command(str(work))
            (work / "proxy.pid").write_text(str(prox.pid))
            subprocess.run(["bash", "-c", cmd], check=True, timeout=30)
            self.assertEqual(prox.wait(timeout=5), -15)  # 收到 SIGTERM
            self.assertIsNone(other.poll())  # 无关进程仍在运行
            self.assertFalse(work.exists())
            # pid 文件指向无关进程时只删目录不 kill
            work2 = Path(td) / ".ssh_mux_px_x2"
            work2.mkdir(mode=0o700)
            (work2 / "proxy.pid").write_text(str(other.pid))
            subprocess.run(
                ["bash", "-c", self.mux.remote_cleanup_command(str(work2))],
                check=True,
                timeout=30,
            )
            self.assertIsNone(other.poll())
            self.assertFalse(work2.exists())

    def test_management_exec_depth_guard_and_jump_path(self):
        with self.assertRaises(self.mux.ProxySetupError):
            self.mux.management_exec(self.cp, "A", "true", 10, lambda m: None, depth=9)
        with mock.patch.object(self.mux, "jump_exec", return_value=0) as je:
            self.mux.management_exec(self.cp, "A", "true", 10, lambda m: None)
        self.assertEqual(je.call_count, 1)
        with mock.patch.object(self.mux, "jump_exec", return_value=1):
            with self.assertRaises(self.mux.ProxySetupError):
                self.mux.management_exec(self.cp, "A", "true", 10, lambda m: None)


@unittest.skipUnless(shutil.which("bash"), "需要本地 Bash 模拟远端")
class DaemonProxyRpcTests(unittest.TestCase):
    """守护进程 rpc 的准备、清理与私有输入（任务 4.1-4.4）。"""

    def setUp(self):
        self.mux = load_mux()
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-rpc-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.socket_patch = mock.patch.object(self.mux, "SOCKET_DIR", str(self.root))
        self.config_patch = mock.patch.object(
            self.mux, "CONFIG_PATH", str(self.root / "hosts.conf")
        )
        self.socket_patch.start()
        self.config_patch.start()
        self.addCleanup(self.socket_patch.stop)
        self.addCleanup(self.config_patch.stop)
        Path(self.mux.CONFIG_PATH).write_text("[a]\nhost = example.invalid\n")

    def start_daemon(self):
        source = """
import importlib.util, sys
spec = importlib.util.spec_from_file_location('local_daemon_proxy_test', sys.argv[1])
mux = importlib.util.module_from_spec(spec)
spec.loader.exec_module(mux)
mux.build_shell_plan = lambda config, alias: [(['bash', '--noprofile', '--norc', '-i'], [])]
mux.daemon_main('a', 'default')
"""
        environment = dict(
            os.environ,
            SSH_MUX_CONFIG=self.mux.CONFIG_PATH,
            SSH_MUX_SOCKET_DIR=self.mux.SOCKET_DIR,
            SSH_MUX_PERSIST="30",
        )
        process = subprocess.Popen(
            [sys.executable, "-c", source, str(ROOT / "ssh-mux.py")],
            env=environment,
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        def cleanup():
            if process.poll() is None:
                self.mux.rpc("a", "default", {"cmd": "stop"}, timeout=0.5)
            try:
                process.wait(timeout=3)
            except subprocess.TimeoutExpired:
                process.terminate()
                process.wait(timeout=3)
            process.stderr.close()

        self.addCleanup(cleanup)
        deadline = time.monotonic() + 8
        while time.monotonic() < deadline:
            if self.mux.ping_session("a", "default", timeout=0.2):
                return process
            time.sleep(0.05)
        self.fail("本地守护进程未就绪")

    def daemon_log(self):
        path = Path(self.mux.shell_log_path("a", "default"))
        return path.read_text() if path.exists() else ""

    def prepare(self, holder, **proxy_update):
        proxy = dict(PROXY_DICT)
        proxy.update(proxy_update)
        reply = self.mux.rpc(
            "a",
            "default",
            {
                "cmd": "prepare_proxy",
                "holder": holder,
                "proxy": proxy,
                "target": TARGET,
            },
            timeout=60,
        )
        self.assertIsNotNone(reply)
        return reply

    def test_prepare_and_cleanup_via_rpc(self):
        self.start_daemon()
        reply = self.prepare("h1")
        self.assertEqual(reply["status"], "ok", reply)
        directory = reply["dir"]
        # 返回路径均为远端（本机模拟）路径，命令行不含秘密
        self.assertNotIn("px-pass-机密", reply["proxy_command"])
        self.assertTrue(directory.startswith("/tmp/.ssh_mux_px_"))
        self.assertEqual(stat.S_IMODE(os.stat(directory).st_mode), 0o700)
        px = Path(directory) / "px.json"
        self.assertEqual(stat.S_IMODE(px.stat().st_mode), 0o600)
        data = json.loads(px.read_text())
        self.assertEqual(data["proxy"]["password"], "px-pass-机密")  # 秘密只在 600 文件
        self.assertTrue((Path(directory) / "ssh_proxy.py").is_file())
        self.assertNotIn("px-pass-机密", self.daemon_log())  # 日志与回显无秘密
        reply = self.mux.rpc(
            "a", "default", {"cmd": "cleanup_proxy", "holder": "h1"}, timeout=30
        )
        self.assertEqual(reply["status"], "ok")
        self.assertEqual(reply["leftovers"], [])
        self.assertFalse(os.path.exists(directory))

    def test_holders_isolated_and_bad_requests_rejected(self):
        self.start_daemon()
        r1 = self.prepare("h1")
        r2 = self.prepare("h2")
        self.assertNotEqual(r1["dir"], r2["dir"])
        reply = self.mux.rpc(
            "a", "default", {"cmd": "cleanup_proxy", "holder": "h1"}, timeout=30
        )
        self.assertEqual(reply["leftovers"], [])
        self.assertTrue(os.path.isdir(r2["dir"]))  # 同节点其他使用方不受影响
        self.mux.rpc(
            "a", "default", {"cmd": "cleanup_proxy", "holder": "h2"}, timeout=30
        )
        bad = self.mux.rpc(
            "a",
            "default",
            {
                "cmd": "prepare_proxy",
                "holder": "bad holder!",
                "proxy": PROXY_DICT,
                "target": TARGET,
            },
            timeout=10,
        )
        self.assertEqual(bad["status"], "error")

    def test_private_write_via_socket(self):
        self.start_daemon()
        prep = self.prepare("hw")
        target = prep["dir"] + "/note.txt"
        reply = self.mux.rpc(
            "a",
            "default",
            {"cmd": "private_write", "path": target, "data": "秘密-正文"},
            timeout=60,
        )
        self.assertEqual(reply["status"], "ok", reply)
        self.assertEqual(Path(target).read_text(), "秘密-正文")
        self.assertEqual(stat.S_IMODE(os.stat(target).st_mode), 0o600)
        self.assertNotIn("秘密-正文", self.daemon_log())
        for bad_path in ("/etc/passwd", "", "/tmp/other.txt"):
            reply = self.mux.rpc(
                "a",
                "default",
                {"cmd": "private_write", "path": bad_path, "data": "x"},
                timeout=10,
            )
            self.assertEqual(reply["status"], "error", bad_path)
        self.mux.rpc(
            "a", "default", {"cmd": "cleanup_proxy", "holder": "hw"}, timeout=30
        )

    def test_cleanup_unknown_holder_warns_and_repeat_is_quiet(self):
        """守护进程重启后对未知持有者返回 warning；已清理的重复清理不告警。"""
        self.start_daemon()
        reply = self.mux.rpc(
            "a",
            "default",
            {"cmd": "cleanup_proxy", "holder": "xfer-ghost"},
            timeout=30,
        )
        self.assertEqual(reply["status"], "ok")
        self.assertEqual(reply["leftovers"], [])
        self.assertIn("xfer-ghost", reply.get("warning", ""))
        self.assertIn("可能残留", reply["warning"])
        # 重复清理不再告警（持有者已标记为已清理）
        reply = self.mux.rpc(
            "a",
            "default",
            {"cmd": "cleanup_proxy", "holder": "xfer-ghost"},
            timeout=30,
        )
        self.assertNotIn("warning", reply)
        # 正常登记 → 清理不告警；之后再清理也不告警
        prep = self.prepare("h9")
        self.addCleanup(shutil.rmtree, prep["dir"], ignore_errors=True)
        reply = self.mux.rpc(
            "a", "default", {"cmd": "cleanup_proxy", "holder": "h9"}, timeout=30
        )
        self.assertEqual(reply["status"], "ok")
        self.assertNotIn("warning", reply)
        reply = self.mux.rpc(
            "a", "default", {"cmd": "cleanup_proxy", "holder": "h9"}, timeout=30
        )
        self.assertNotIn("warning", reply)

    def test_session_holder_cleanup_failure_is_reported_not_fatal(self):
        self.start_daemon()
        prep = self.prepare("session")
        self.addCleanup(shutil.rmtree, prep["dir"], ignore_errors=True)
        reply = self.mux.rpc("a", "default", {"cmd": "stop"}, timeout=5)
        self.assertEqual(reply["status"], "ok")
        deadline = time.monotonic() + 15
        while (
            time.monotonic() < deadline
            and not Path(self.mux.shell_log_path("a", "default")).exists()
        ):
            time.sleep(0.05)
        # 管理会话连不上 example.invalid：报告节点和残留路径，守护进程仍正常退出
        deadline = time.monotonic() + 15
        log = ""
        while time.monotonic() < deadline:
            log = self.daemon_log()
            if "守护进程退出" in log:
                break
            time.sleep(0.1)
        self.assertIn("守护进程退出", log)
        self.assertIn("远端残留", log)
        self.assertIn(prep["dir"], log)


class ShellTransferProxyTests(unittest.TestCase):
    """传统 `shell_push()`/`shell_pull()` 的代理接入与清理（任务 5.1-5.3）。"""

    def setUp(self):
        self.mux = load_mux()
        self.mux._REMOTE_SCP_LEGACY.clear()
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-xfer-")
        self.addCleanup(self.tmp.cleanup)
        self.source = Path(self.tmp.name) / "data.bin"
        self.source.write_bytes(bytes(range(256)))
        self.cp = configparser.ConfigParser(interpolation=None)
        self.cp.read_dict(
            {
                "local": {"host": "me.invalid", "user": "u", "password": "local-pw"},
                "A": {"host": "a.invalid", "user": "u", "password": "a-pw"},
                "B": {
                    "host": "b.invalid",
                    "user": "u",
                    "password": "b-pw",
                    "via": "A",
                    "via_mode": "shell",
                    "proxy": "socks5",
                    "proxy_host": "10.1.1.1",
                    "proxy_port": "1080",
                    "proxy_user": "px-user",
                    "proxy_password": "px-pass-机密",
                },
            }
        )
        self.exec_log = []
        self.rpc_log = []

        def fake_exec(alias, session, command, timeout, password=None):
            self.exec_log.append((alias, command, password))
            if "SSHPASS" in command and "b.invalid" in command and self.fail_forward:
                return {"status": "ok", "exit": 1, "output": "scp: broken pipe"}
            return {"status": "ok", "exit": 0, "output": ""}

        def fake_rpc(alias, session, req, timeout=30):
            self.rpc_log.append((alias, req))
            if req.get("cmd") == "prepare_proxy":
                return {
                    "status": "ok",
                    "dir": "/tmp/.ssh_mux_px_fake",
                    "proxy_command": (
                        "python3 /tmp/.ssh_mux_px_fake/ssh_proxy.py "
                        "/tmp/.ssh_mux_px_fake/px.json"
                    ),
                }
            if req.get("cmd") == "cleanup_proxy":
                return {"status": "ok", "leftovers": []}
            return {"status": "ok"}

        self.fail_forward = False
        patches = (
            mock.patch.object(self.mux, "shell_exec", fake_exec),
            mock.patch.object(self.mux, "rpc", fake_rpc),
        )
        for p in patches:
            p.start()
            self.addCleanup(p.stop)

    def target(self):
        return self.mux.get_host(self.cp, "B")

    def forward_commands(self):
        return [c for _, c, _ in self.exec_log if "SSHPASS" in c]

    def test_push_prepares_proxy_on_origin_and_cleans_up(self):
        self.mux.shell_push(
            self.cp, self.target(), "s1", str(self.source), "/tmp/dst.bin", 30
        )
        prepare = [r for _, r in self.rpc_log if r.get("cmd") == "prepare_proxy"]
        self.assertEqual(len(prepare), 1)
        # 在段起点 A 的现有会话上准备（无需到 B 的会话，也无反向连接）
        self.assertEqual(prepare[0]["target"], {"host": "b.invalid", "port": 22})
        self.assertEqual(prepare[0]["proxy"]["type"], "socks5")
        self.assertEqual(self.rpc_log[0][0], "A")
        forward = [c for c in self.forward_commands() if "b.invalid" in c]
        self.assertEqual(len(forward), 1)
        self.assertIn("ProxyCommand=python3 /tmp/.ssh_mux_px_fake", forward[0])
        reverse = [c for c in self.forward_commands() if "me.invalid" in c]
        self.assertEqual(len(reverse), 1)
        self.assertNotIn("ProxyCommand", reverse[0])  # 回传连接保持直连
        cleanup = [r for _, r in self.rpc_log if r.get("cmd") == "cleanup_proxy"]
        self.assertEqual(len(cleanup), 1)
        self.assertEqual(cleanup[0]["holder"], prepare[0]["holder"])
        self.assertTrue(cleanup[0]["holder"].startswith("xfer-"))
        # 登录会话的 holder 不被传输清理触碰
        self.assertNotIn("session", {r.get("holder") for _, r in self.rpc_log})

    def test_pull_uses_same_proxy_and_cleans_up(self):
        self.mux.shell_pull(
            self.cp, self.target(), "s1", "/tmp/src.bin", str(self.root_dst()), 30
        )
        forward = [c for c in self.forward_commands() if "b.invalid" in c]
        self.assertEqual(len(forward), 1)
        self.assertIn("ProxyCommand=", forward[0])
        cleanup = [r for _, r in self.rpc_log if r.get("cmd") == "cleanup_proxy"]
        self.assertEqual(len(cleanup), 1)

    def root_dst(self):
        return str(Path(self.tmp.name) / "downloaded.bin")

    def test_jump_via_mode_still_prepares_on_shell_origin(self):
        # 即使 B 配置 via_mode=jump，远端复制也在实际执行节点 A 准备代理
        self.cp["B"]["via_mode"] = "jump"
        self.mux.shell_push(
            self.cp, self.target(), "s1", str(self.source), "/tmp/dst.bin", 30
        )
        prepare = [(a, r) for a, r in self.rpc_log if r.get("cmd") == "prepare_proxy"]
        self.assertEqual(len(prepare), 1)
        self.assertEqual(prepare[0][0], "A")

    def test_failure_still_cleans_and_session_survives(self):
        self.fail_forward = True
        with contextlib.redirect_stderr(io.StringIO()):
            with self.assertRaises(SystemExit):
                self.mux.shell_push(
                    self.cp, self.target(), "s1", str(self.source), "/tmp/dst.bin", 30
                )
        cleanup = [r for _, r in self.rpc_log if r.get("cmd") == "cleanup_proxy"]
        self.assertEqual(len(cleanup), 1)  # 失败路径也回收凭据
        # A 的登录会话仍可用于后续命令（finally 的 rm 已执行）
        rm = [c for _, c, _ in self.exec_log if "rm -rf" in c]
        self.assertTrue(rm)

    def test_reverse_leg_note_on_failure(self):
        note = self.mux.reverse_leg_note(
            self.cp, self.mux.shell_hops(self.mux.build_chain(self.cp, "B"))
        )
        self.assertIn("直连", note)

        def fail_exec(alias, session, command, timeout, password=None):
            self.exec_log.append((alias, command, password))
            if "SSHPASS" in command and "me.invalid" in command:
                return {"status": "ok", "exit": 1, "output": "connection refused"}
            return {"status": "ok", "exit": 0, "output": ""}

        with mock.patch.object(self.mux, "shell_exec", fail_exec):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit):
                    self.mux.shell_pull(
                        self.cp,
                        self.target(),
                        "s1",
                        "/tmp/src.bin",
                        self.root_dst(),
                        30,
                    )
        # 回传失败明确说明该连接不支持代理
        self.assertIn("回传连接保持直连", err.getvalue())

    def test_cleanup_warning_printed_to_stderr(self):
        """守护进程重启后清理未知持有者：warning 提示打印到 stderr。"""

        def warn_rpc(alias, session, req, timeout=30):
            return {
                "status": "ok",
                "leftovers": [],
                "warning": "持有者 xfer-x 未登记（守护进程可能已重启）；"
                "远端 /tmp/.ssh_mux_px_* 目录可能残留，请检查并手动删除",
            }

        err = io.StringIO()
        with (
            mock.patch.object(self.mux, "rpc", warn_rpc),
            contextlib.redirect_stderr(err),
        ):
            self.mux.xfer_cleanup_proxies("s1", "xfer-x", {"A"})
        self.assertIn("未登记", err.getvalue())
        self.assertIn("可能残留", err.getvalue())

    def test_reverse_note_sources(self):
        hops = self.mux.shell_hops(self.mux.build_chain(self.cp, "B"))
        with mock.patch.dict(os.environ, {"SSH_MUX_PROXY": "http://10.0.0.1:8080"}):
            self.assertIn("SSH_MUX_PROXY", self.mux.reverse_leg_note(self.cp, hops))
        cp2 = configparser.ConfigParser(interpolation=None)
        cp2.read_dict(
            {
                "local": {
                    "host": "me.invalid",
                    "proxy": "http",
                    "proxy_host": "h",
                    "proxy_port": "1",
                },
                "A": {"host": "a.invalid"},
            }
        )
        note = self.mux.reverse_leg_note(
            cp2, self.mux.shell_hops(self.mux.build_chain(cp2, "A"))
        )
        self.assertIn("[local]", note)

    def test_staging_reverse_leg_stays_direct(self):
        self.cp["local"] = {"staging": "S"}
        self.cp["S"] = {
            "host": "s.invalid",
            "user": "u",
            "password": "s-pw",
            "proxy": "http",
            "proxy_host": "10.3.3.3",
            "proxy_port": "8080",
        }
        jump_calls = []
        with (
            mock.patch.object(
                self.mux, "jump_exec", lambda *a, **k: jump_calls.append(a) or 0
            ),
            mock.patch.object(
                self.mux, "jump_scp", lambda *a, **k: jump_calls.append(a) or 0
            ),
        ):
            self.mux.shell_push(
                self.cp, self.target(), "s1", str(self.source), "/tmp/dst.bin", 30
            )
        # 本机主动连接暂存机走暂存机自己的登录链（jump 系列）
        self.assertTrue(any(call[1].alias == "S" for call in jump_calls))
        reverse = [
            c
            for c in self.forward_commands()
            if "s.invalid" in c and "b.invalid" not in c
        ]
        self.assertTrue(reverse)
        for command in reverse:
            self.assertNotIn("ProxyCommand", command)  # 远端回传暂存机保持直连


class FakeOwner:
    def __init__(self, mux, cp, local_dir):
        self.mux = mux
        self.cp = cp
        self.task = "task-proxy-remote"
        self.deadline = time.monotonic() + 120
        self.cleanup_deadline = self.deadline
        self.cleaning = False
        self.local_dir = str(local_dir)
        self.bundle = b"fake-worker-bundle"

    def remaining(self):
        return 120.0


class EndpointJobProxyTests(unittest.TestCase):
    """`Endpoint.job()` 的含凭据请求走专用输入通道（任务 5.4）。"""

    def setUp(self):
        self.mux = load_mux()
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-job-")
        self.addCleanup(self.tmp.cleanup)
        self.cp = configparser.ConfigParser(interpolation=None)
        self.cp.read_dict(
            {
                "D": {"host": "d.invalid", "user": "u"},
                "E": {
                    "host": "e.invalid",
                    "user": "u",
                    "via": "D",
                    "via_mode": "jump",
                    "proxy": "socks5",
                    "proxy_host": "10.4.4.4",
                    "proxy_port": "1080",
                    "proxy_user": "px-user",
                    "proxy_password": "px-pass-机密",
                },
                "A": {"host": "a.invalid", "user": "u"},
                "B": {
                    "host": "b.invalid",
                    "user": "u",
                    "via": "A",
                    "via_mode": "shell",
                },
                "T": {
                    "host": "t.invalid",
                    "user": "u",
                    "via": "B",
                    "via_mode": "shell",
                    "proxy": "http",
                    "proxy_host": "10.5.5.5",
                    "proxy_port": "8080",
                    "proxy_user": "px-user",
                    "proxy_password": "px-pass-机密",
                },
            }
        )
        self.owner = FakeOwner(self.mux, self.cp, self.tmp.name)

    def run_job_flow(self, captured, commands):
        """驱动 job()：记录命令，在启动后返回匹配的结果。"""
        state = {"launched": False}

        def fake_run(command):
            commands.append(command)
            if "worker.log" in command:
                state["launched"] = True
                return ""
            if "result.json" in command and state["launched"]:
                return json.dumps(
                    {
                        "id": captured["request"]["id"],
                        "status": "ok",
                        "transport": "stream",
                    }
                )
            return ""

        return fake_run

    def test_jump_endpoint_request_via_stream_private_channel(self):
        ep = hybrid.Endpoint(self.owner, self.mux.get_host(self.cp, "D"))
        ep.work = str(Path(self.tmp.name) / "work")
        Path(ep.work).mkdir()
        captured = {}
        commands = []

        class FakeTransfer:
            def __init__(self, execute, stream, timeout):
                captured["stream"] = stream

            def push(self, local_path, remote, transport):
                captured["transport"] = transport
                captured["remote"] = remote
                captured["request"] = json.loads(Path(local_path).read_text())

        put_bytes = mock.Mock()
        with (
            mock.patch.object(hybrid, "Transfer", FakeTransfer),
            mock.patch.object(ep, "put_bytes", put_bytes),
            mock.patch.object(ep, "run", self.run_job_flow(captured, commands)),
        ):
            result = ep.job(
                self.mux.get_host(self.cp, "E"),
                "push",
                "stream",
                op="transfer",
                src="/tmp/x",
                dst="/tmp/y",
                expected=[1, "0" * 64],
            )
        self.assertEqual(result["status"], "ok")
        # 纯 jump 端点使用文件流的标准输入，不走 auto 上传
        self.assertEqual(captured["transport"], "stream")
        self.assertTrue(callable(captured["stream"]))
        self.assertEqual(put_bytes.call_count, 1)  # 只有程序包上传用普通通道
        request = captured["request"]
        self.assertEqual(request["proxy"]["password"], "px-pass-机密")
        self.assertEqual(request["proxy"]["host"], "10.4.4.4")
        # 命令中没有秘密：请求正文只经文件流标准输入
        for recorded in commands:
            self.assertNotIn("px-pass-机密", recorded)

    def test_shell_endpoint_request_via_rpc_private_write(self):
        ep = hybrid.Endpoint(self.owner, self.mux.get_host(self.cp, "B"))
        self.assertFalse(ep.jump)
        ep.work = str(Path(self.tmp.name) / "work2")
        Path(ep.work).mkdir()
        captured = {}
        rpc_calls = []

        def fake_rpc(alias, session, req, timeout=30):
            rpc_calls.append((alias, session, req))
            if req.get("cmd") == "private_write":
                captured["request"] = json.loads(req["data"])
                captured["path"] = req["path"]
                return {"status": "ok"}
            return {"status": "ok"}

        commands = []

        def fake_run(command):
            commands.append(command)
            if "result.json" in command and captured:
                return json.dumps(
                    {
                        "id": captured["request"]["id"],
                        "status": "ok",
                        "transport": "base64",
                    }
                )
            return ""

        put_bytes = mock.Mock()
        with (
            mock.patch.object(self.mux, "ensure_daemon", return_value=None),
            mock.patch.object(self.mux, "rpc", fake_rpc),
            mock.patch.object(ep, "put_bytes", put_bytes),
            mock.patch.object(ep, "run", fake_run),
        ):
            result = ep.job(
                self.mux.get_host(self.cp, "T"),
                "pull",
                "base64",
                op="transfer",
                src="/tmp/x",
                dst="/tmp/y",
                expected=[1, "0" * 64],
            )
        self.assertEqual(result["status"], "ok")
        # 终端端点经守护进程私有输入请求，不通过 put_bytes() 的 auto 上传
        self.assertEqual(put_bytes.call_count, 1)  # 仅程序包
        self.assertTrue(captured["path"].endswith("/request.json"))
        self.assertEqual(captured["request"]["proxy"]["password"], "px-pass-机密")
        self.assertEqual(captured["request"]["target"]["host"], "t.invalid")
        for command in commands:
            self.assertNotIn("px-pass-机密", command)


class WorkerProxyTests(unittest.TestCase):
    """混合传输执行器的代理入口与配置（任务 5.5、5.6）。"""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-worker-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)

    def make_request(self, directory, **update):
        request = {
            "id": "job1",
            "target": {"host": "t.invalid", "port": 22, "user": "u", "password": ""},
            "timeout": 60,
            "transport": "stream",
            "action": "push",
            "op": "probe",
            "src": None,
            "dst": None,
            "expected": None,
        }
        request.update(update)
        (directory / "request.json").write_text(json.dumps(request))
        return request

    def make_dir(self):
        directory = self.root / ("job-" + next(tempfile._get_candidate_names()))
        directory.mkdir(mode=0o700)
        return directory

    class FakeChannel:
        instances = []

        def __init__(self, target, directory, timeout):
            self.target = target
            self.directory = directory
            self.proxy_config = None
            self.pending_cleanup = set()
            self.closed = False
            type(self).instances.append(self)

        def start(self):
            pass

        def select(self, transport, action):
            return "stream"

        def cleanup_pending(self, recover=False):
            return []

        def close(self):
            self.closed = True

    def test_bundle_contains_ssh_proxy(self):
        import io as _io
        import zipfile

        bundle = hybrid.worker_bundle()
        names = zipfile.ZipFile(_io.BytesIO(bundle)).namelist()
        self.assertIn("ssh_proxy.py", names)
        self.assertIn("__main__.py", names)  # ssh_worker.py 作为程序包入口

    def test_run_job_writes_private_proxy_config(self):
        FakeChannel = self.FakeChannel
        FakeChannel.instances = []
        directory = self.make_dir()
        self.make_request(
            directory,
            proxy=dict(PROXY_DICT),
            target={
                "host": "t.invalid",
                "port": 22,
                "user": "u",
                "password": "job-pass-机密",
            },
        )
        self.assertEqual(worker.run_job(str(directory), channel_type=FakeChannel), 0)
        channel = FakeChannel.instances[0]
        proxy_json = directory / "proxy.json"
        # 任务请求删除后仍可凭独立配置重连；权限 600
        self.assertFalse((directory / "request.json").exists())
        self.assertEqual(channel.proxy_config, str(proxy_json))
        self.assertEqual(stat.S_IMODE(proxy_json.stat().st_mode), 0o600)
        text = proxy_json.read_text()
        data = json.loads(text)
        self.assertEqual(data["proxy"], PROXY_DICT)
        # ssh_proxy 只读 host/port：SSH 登录密码不写入这个长期留存的文件
        self.assertEqual(data["target"], {"host": "t.invalid", "port": 22})
        self.assertNotIn("job-pass-机密", text)
        self.assertNotIn("password", json.dumps(data["target"]))
        self.assertTrue(channel.closed)  # 任务退出时完整清理

    def test_run_job_proxy_timeout_follows_remaining_deadline(self):
        """proxy.json 的握手期限服从外层剩余期限：min(10, 剩余)，下限 1 秒。"""
        FakeChannel = self.FakeChannel
        FakeChannel.instances = []
        directory = self.make_dir()
        self.make_request(directory, proxy=dict(PROXY_DICT), timeout=5)
        self.assertEqual(worker.run_job(str(directory), channel_type=FakeChannel), 0)
        data = json.loads((directory / "proxy.json").read_text())
        self.assertGreaterEqual(data["timeout"], 1)
        self.assertLessEqual(data["timeout"], 5)  # 不超过外层剩余期限
        # 剩余期限充足时保持默认的 10 秒握手期限
        directory2 = self.make_dir()
        self.make_request(directory2, proxy=dict(PROXY_DICT), timeout=60)
        self.assertEqual(worker.run_job(str(directory2), channel_type=FakeChannel), 0)
        data2 = json.loads((directory2 / "proxy.json").read_text())
        self.assertEqual(data2["timeout"], 10)

    def test_run_job_without_proxy_writes_nothing(self):
        FakeChannel = self.FakeChannel
        FakeChannel.instances = []
        directory = self.make_dir()
        self.make_request(directory)
        self.assertEqual(worker.run_job(str(directory), channel_type=FakeChannel), 0)
        self.assertIsNone(FakeChannel.instances[0].proxy_config)
        self.assertFalse((directory / "proxy.json").exists())

    def test_channel_base_shares_proxy_for_all_operations(self):
        directory = self.make_dir()
        channel = worker.Channel(
            {"host": "t.invalid", "port": 22, "user": "u", "password": ""},
            str(directory),
            60,
        )
        plain = channel.base()
        self.assertFalse(any("ProxyCommand" in a for a in plain))
        channel.proxy_config = str(directory / "proxy.json")
        proxied = channel.base()
        opt = next(a for a in proxied if a.startswith("ProxyCommand="))
        self.assertIn("__proxy__", opt)
        self.assertIn("proxy.json", opt)
        # 登录、文件流、重连探测都经 base() 共用该段代理；套接字消失也不直连回退
        self.assertEqual(channel.base(), proxied)
        # scp 手工拼接参数，也必须携带同一代理选项：控制套接字失效时 OpenSSH
        # 会用当前参数另建连接，密钥认证目标不得静默直连
        captured = []

        def fake_run(args, limit, **kw):
            captured.append(args)
            return 0, b"", b""

        channel.run = fake_run
        channel.scp_options = ["-O"]  # 正常运行时由 select() 探测后赋值
        channel.scp("push", "/tmp/local.bin", "/tmp/remote.bin", 30)
        scp_args = captured[0]
        self.assertEqual(scp_args[0], "scp")
        scp_opt = next((a for a in scp_args if a.startswith("ProxyCommand=")), None)
        self.assertIsNotNone(scp_opt)
        self.assertEqual(scp_opt, opt)  # 与 base() 逐字节一致
        # 无代理时 scp 不含 ProxyCommand
        channel.proxy_config = None
        captured.clear()
        channel.scp("push", "/tmp/local.bin", "/tmp/remote.bin", 30)
        self.assertFalse(any("ProxyCommand" in a for a in captured[0]))

    def test_proxy_entrypoint_reads_standalone_config(self):
        bundle = self.root / "worker.pyz"
        bundle.write_bytes(hybrid.worker_bundle())
        # 配置错误退出 2，不消费任务请求
        bad = self.root / "bad.json"
        bad.write_text(json.dumps({"proxy": {"type": "http", "host": "h", "port": 0}}))
        r = subprocess.run(
            [sys.executable, str(bundle), "__proxy__", str(bad)],
            capture_output=True,
        )
        self.assertEqual(r.returncode, 2)
        self.assertEqual(r.stdout, b"")
        # 连接失败退出 1，标准输出为空
        good = self.root / "ok.json"
        good.write_text(
            json.dumps(
                {
                    "proxy": {"type": "http", "host": "127.0.0.1", "port": 1},
                    "target": {"host": "t.invalid", "port": 22},
                    "timeout": 2,
                }
            )
        )
        r = subprocess.run(
            [sys.executable, str(bundle), "__proxy__", str(good)],
            capture_output=True,
            timeout=15,
        )
        self.assertEqual(r.returncode, 1)
        self.assertEqual(r.stdout, b"")


if __name__ == "__main__":
    unittest.main()
