"""本机与标准跳板代理接入测试；用假 ssh/sshpass 捕获参数与环境，不连接外部主机。"""

import configparser
import contextlib
import importlib.util
import io
import json
import os
from pathlib import Path
import stat
import sys
import tempfile
import time
import unittest
from unittest import mock

from test_transfer import load_mux

ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location(
    "proxy_local_hybrid_module", ROOT / "ssh_hybrid.py"
)
hybrid = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(hybrid)

FAKE_SSH = (
    "#!"
    + sys.executable
    + "\n"
    + r"""
import json, os, sys
args = sys.argv[1:]
cap = os.environ.get("TEST_CAPTURE")
if cap:
    rec = {
        "args": args,
        "env": {k: v for k, v in os.environ.items()
                if k.startswith("SSH_MUX") or k == "SSHPASS"},
    }
    with open(cap, "a") as f:
        f.write(json.dumps(rec) + "\n")

def opt(name):
    for i, a in enumerate(args):
        if a == "-o" and i + 1 < len(args) and args[i + 1].startswith(name + "="):
            return args[i + 1].split("=", 1)[1]
    return None

cpath = opt("ControlPath")
if "-O" in args:
    op = args[args.index("-O") + 1]
    if op == "check":
        sys.exit(0 if cpath and os.path.exists(cpath) else 1)
    if op == "exit":
        if cpath and os.path.exists(cpath):
            os.unlink(cpath)
        sys.exit(0)
if "-fN" in args:
    if os.environ.get("TEST_SSH_FAIL"):
        sys.stderr.write("mock connect failure\n")
        sys.exit(1)
    if cpath:
        os.makedirs(os.path.dirname(cpath), exist_ok=True)
        open(cpath, "w").close()
    sys.exit(0)
sys.exit(0)
"""
)

FAKE_SSHPASS = (
    "#!"
    + sys.executable
    + "\n"
    + r"""
import json, os, sys
cap = os.environ.get("TEST_CAPTURE")
if cap:
    rec = {
        "args": ["sshpass"] + sys.argv[1:],
        "env": {k: v for k, v in os.environ.items()
                if k.startswith("SSH_MUX") or k == "SSHPASS"},
    }
    with open(cap, "a") as f:
        f.write(json.dumps(rec) + "\n")
os.execvp(sys.argv[2], sys.argv[2:])
"""
)


def write_exe(path, content):
    path.write_text(content)
    path.chmod(0o700)


class FakeSshBase(unittest.TestCase):
    """安装假 ssh/sshpass 到 PATH 最前，并把运行目录隔离到临时目录。"""

    def setUp(self):
        self.mux = load_mux()
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-local-")
        self.addCleanup(self.tmp.cleanup)
        self.root = Path(self.tmp.name)
        self.bin = self.root / "bin"
        self.bin.mkdir()
        write_exe(self.bin / "ssh", FAKE_SSH)
        write_exe(self.bin / "sshpass", FAKE_SSHPASS)
        self.capture = self.root / "capture.jsonl"
        self.runtime = self.root / "runtime"
        env_patch = mock.patch.dict(
            os.environ,
            {
                "PATH": str(self.bin) + os.pathsep + os.environ["PATH"],
                "TEST_CAPTURE": str(self.capture),
            },
        )
        env_patch.start()
        self.addCleanup(env_patch.stop)
        rt_patch = mock.patch.object(
            self.mux, "runtime_dir", return_value=str(self.runtime)
        )
        rt_patch.start()
        self.addCleanup(rt_patch.stop)

    def records(self):
        if not self.capture.exists():
            return []
        return [json.loads(line) for line in self.capture.read_text().splitlines()]

    def connect_records(self, alias_host):
        """找出建立主连接（-fN）且目标是 alias_host 的 ssh 记录。"""
        return [
            r
            for r in self.records()
            if r["args"][0] != "sshpass"
            and "-fN" in r["args"]
            and r["args"][-1].endswith("@" + alias_host)
        ]

    def make_config(self):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_dict(
            {
                "A": {
                    "host": "a.invalid",
                    "user": "u",
                    "password": "host-pw-a",
                    "proxy": "http",
                    "proxy_host": "10.0.0.9",
                    "proxy_port": "8080",
                    "proxy_user": "proxy-user-a",
                    "proxy_password": "proxy-pass-a",
                },
                "B": {
                    "host": "b.invalid",
                    "user": "u",
                    "via": "A",
                    "via_mode": "jump",
                    "proxy": "socks5",
                    "proxy_host": "10.9.9.9",
                    "proxy_port": "1080",
                },
                "D": {"host": "d.invalid", "user": "u"},
            }
        )
        return cp


class ProxyCommandShapeTests(unittest.TestCase):
    """本机代理命令的形状与转义（任务 3.1、3.3）。"""

    def setUp(self):
        self.mux = load_mux()

    def test_command_shape_single_setsid_and_percent_escaped(self):
        cmd = self.mux.local_proxy_command("/tmp/px_100%/config.json")
        self.assertTrue(cmd.startswith("ProxyCommand="))
        self.assertIn("_proxy", cmd)
        # 包装进程只执行一次 setsid，避免 sshpass 退出后辅助进程被挂断
        self.assertEqual(cmd.count("setsid"), 1)
        # % 全部按字面转义，ProxyCommand 的令牌展开不会改变路径
        self.assertNotIn("%", cmd.replace("%%", ""))
        self.assertIn("%%", cmd)

    def test_addr_and_port_literal_validation(self):
        for bad in ("has space", "line\nbreak", "100%evil", "a\rb", "x\x00y", "", None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.mux.proxy_addr_ok(bad, "测试")
        # 非 ASCII 地址（如中文域名）拒绝：请求行按 ASCII 编码，不报内部错误
        with self.assertRaises(ValueError):
            self.mux.proxy_addr_ok("主机.invalid", "测试")
        self.assertEqual(self.mux.proxy_addr_ok("2001:db8::1", "测试"), "2001:db8::1")
        for bad in ("x", 0, 65536, None):
            with self.assertRaises(ValueError, msg=repr(bad)):
                self.mux.proxy_port_ok(bad, "测试")
        self.assertEqual(self.mux.proxy_port_ok("22", "测试"), 22)


class CredFileTests(unittest.TestCase):
    """本机私有凭据文件的生命周期（任务 3.3、3.4）。"""

    def setUp(self):
        self.mux = load_mux()
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-cred-")
        self.addCleanup(self.tmp.cleanup)
        patcher = mock.patch.object(self.mux, "runtime_dir", return_value=self.tmp.name)
        patcher.start()
        self.addCleanup(patcher.stop)
        self.proxy = self.mux.ProxySpec("http", "10.0.0.9", 8080, "u", "p")

    def mode(self, path):
        return stat.S_IMODE(os.stat(path).st_mode)

    def test_prepare_permissions_and_isolation(self):
        p1 = self.mux.prepare_proxy_cred_file("j_aa", self.proxy, "t.invalid", 22)
        p2 = self.mux.prepare_proxy_cred_file("j_bb", self.proxy, "t.invalid", 22)
        self.assertNotEqual(p1, p2)  # 连接实例隔离
        self.assertEqual(self.mode(os.path.dirname(p1)), 0o700)
        self.assertEqual(self.mode(p1), 0o600)
        data = json.loads(Path(p1).read_text())
        # 秘密只出现在 600 凭据文件里
        self.assertEqual(data["proxy"]["user"], "u")
        self.assertEqual(data["proxy"]["password"], "p")
        self.assertEqual(data["target"], {"host": "t.invalid", "port": 22})
        self.mux.drop_proxy_cred_file("j_aa")
        self.assertFalse(os.path.exists(os.path.dirname(p1)))
        self.assertTrue(os.path.isfile(p2))  # 其他实例不受影响
        self.mux.drop_proxy_cred_file("j_aa")  # 重复清理不报错

    def test_ensure_keeps_running_instance_and_reprepares_after_loss(self):
        p1 = self.mux.prepare_proxy_cred_file("j_cc", self.proxy, "t.invalid", 22)
        Path(p1).write_text('{"marker": 1}')  # 运行中的实例不被覆写
        self.assertEqual(
            self.mux.ensure_proxy_cred_file("j_cc", self.proxy, "t.invalid", 22), p1
        )
        self.assertEqual(json.loads(Path(p1).read_text()), {"marker": 1})
        self.mux.drop_proxy_cred_file("j_cc")
        p2 = self.mux.ensure_proxy_cred_file("j_cc", self.proxy, "t.invalid", 22)
        self.assertEqual(p2, p1)
        self.assertEqual(
            json.loads(Path(p2).read_text())["proxy"]["password"], "p"
        )  # 丢失后按当前配置重新准备

    def test_illegal_namespace_rejected(self):
        with self.assertRaises(SystemExit):
            self.mux.proxy_cred_dir("../escape")

    def test_drop_reports_leftover_path_on_cleanup_failure(self):
        path = self.mux.prepare_proxy_cred_file("j_fail", self.proxy, "t.invalid", 22)
        directory = os.path.dirname(path)
        err = io.StringIO()
        with (
            # 模拟清理失败：rmtree 不生效，目录残留
            mock.patch.object(self.mux.shutil, "rmtree", lambda *a, **k: None),
            contextlib.redirect_stderr(err),
        ):
            self.mux.drop_proxy_cred_file("j_fail")
        self.assertIn(directory, err.getvalue())  # 向 stderr 报告残留路径
        self.assertTrue(os.path.isdir(directory))

    def test_strip_proxy_env(self):
        env = {
            "SSH_MUX_PROXY_USER": "leak",
            "SSH_MUX_PROXY_PASS": "leak2",
            "SSH_MUX_PROXY": "http://127.0.0.1:8080",
            "HOME": "/home/x",
        }
        out = self.mux.strip_proxy_env(dict(env))
        self.assertNotIn("SSH_MUX_PROXY_USER", out)
        self.assertNotIn("SSH_MUX_PROXY_PASS", out)
        # 连接规划仍要读取本机默认代理，只有凭据变量被移除
        self.assertEqual(out["SSH_MUX_PROXY"], "http://127.0.0.1:8080")
        self.assertEqual(out["HOME"], "/home/x")


class JumpConnectTests(FakeSshBase):
    """`jump_connect()`/`jump_data_opts()` 的代理接入（任务 3.1-3.4）。"""

    def test_first_hop_proxy_command_env_and_cred_lifecycle(self):
        cp = self.make_config()
        # 父环境残留的同名凭据变量必须被剥除，SendEnv 再宽松也无秘密可发
        with mock.patch.dict(
            os.environ,
            {"SSH_MUX_PROXY_USER": "leak", "SSH_MUX_PROXY_PASS": "leak2"},
        ):
            self.mux.jump_connect(cp, self.mux.get_host(cp, "A"))
        rec = self.connect_records("a.invalid")
        self.assertEqual(len(rec), 1)
        args = rec[0]["args"]
        proxy_opt = next(a for a in args if a.startswith("ProxyCommand="))
        self.assertIn("_proxy", proxy_opt)
        self.assertNotIn("proxy-user-a", proxy_opt)
        self.assertNotIn("proxy-pass-a", proxy_opt)
        # 外层 ssh 与 sshpass 的环境都没有代理秘密
        for r in self.records():
            self.assertNotIn("SSH_MUX_PROXY_USER", r["env"])
            self.assertNotIn("SSH_MUX_PROXY_PASS", r["env"])
        sshpass = [r for r in self.records() if r["args"][0] == "sshpass"]
        self.assertEqual(sshpass[0]["env"].get("SSHPASS"), "host-pw-a")
        self.assertNotIn("proxy-pass-a", json.dumps(rec[0]["args"]))
        # 启动命令返回后凭据文件保留（供后续数据连接复用）
        ns = (
            "j_"
            + os.path.basename(
                self.mux.jump_sock_file(cp, self.mux.get_host(cp, "A"))
            ).rsplit("ssh_mux_j_", 1)[-1]
        )
        cred = Path(self.mux.proxy_cred_dir(ns)) / "config.json"
        self.assertTrue(cred.is_file())
        self.assertEqual(stat.S_IMODE(cred.stat().st_mode), 0o600)
        data = json.loads(cred.read_text())
        self.assertEqual(data["proxy"]["password"], "proxy-pass-a")
        self.assertIsNone(data["relay"])  # 本机首段直连代理，不经转发
        self.assertEqual(data["target"]["host"], "a.invalid")

    def test_jump_segment_relay_uses_ssh_w_without_remote_python(self):
        cp = self.make_config()
        self.mux.jump_connect(cp, self.mux.get_host(cp, "B"))
        rec = self.connect_records("b.invalid")
        self.assertEqual(len(rec), 1)
        proxy_opt = next(a for a in rec[0]["args"] if a.startswith("ProxyCommand="))
        # 握手程序是本机脚本路径，不在跳板上执行 Python
        self.assertIn("ssh-mux.py", proxy_opt.replace("%%", "%"))
        ns = (
            "j_"
            + os.path.basename(
                self.mux.jump_sock_file(cp, self.mux.get_host(cp, "B"))
            ).rsplit("ssh_mux_j_", 1)[-1]
        )
        cfg = json.loads(
            (Path(self.mux.proxy_cred_dir(ns)) / "config.json").read_text()
        )
        relay = cfg["relay"]
        self.assertEqual(relay[0], "ssh")
        self.assertNotIn("python", " ".join(relay).lower())
        w_index = relay.index("-W")
        # 代理只能从跳板经 `ssh -W 代理地址:端口` 访问
        self.assertEqual(relay[w_index + 1], "10.9.9.9:1080")
        a_sock = self.mux.jump_sock_file(cp, self.mux.get_host(cp, "A"))
        self.assertIn(f"ControlPath={a_sock}", relay)
        self.assertEqual(relay[-1], "u@a.invalid")
        self.assertEqual(cfg["target"]["host"], "b.invalid")

    def test_jump_segment_relay_brackets_ipv6_proxy(self):
        # IPv6 字面量代理地址含冒号，拼 `-W` 参数时必须加方括号
        cp = self.make_config()
        cp["B"]["proxy_host"] = "2001:db8::9"
        self.mux.jump_connect(cp, self.mux.get_host(cp, "B"))
        ns = (
            "j_"
            + os.path.basename(
                self.mux.jump_sock_file(cp, self.mux.get_host(cp, "B"))
            ).rsplit("ssh_mux_j_", 1)[-1]
        )
        cfg = json.loads(
            (Path(self.mux.proxy_cred_dir(ns)) / "config.json").read_text()
        )
        relay = cfg["relay"]
        self.assertEqual(relay[relay.index("-W") + 1], "[2001:db8::9]:1080")

    def test_exit_with_new_identity_leaves_old_socket(self):
        # 配置代理建立连接标识后改代理地址：按新标识断开不影响旧标识的套接字
        cp = self.make_config()
        self.mux.jump_connect(cp, self.mux.get_host(cp, "A"))
        old_sock = self.mux.jump_sock_file(cp, self.mux.get_host(cp, "A"))
        self.assertTrue(os.path.exists(old_sock))
        cp["A"]["proxy_host"] = "10.0.0.10"  # 代理地址变化 → 新连接标识
        h_new = self.mux.get_host(cp, "A")
        new_sock = self.mux.jump_sock_file(cp, h_new)
        self.assertNotEqual(old_sock, new_sock)
        self.assertFalse(self.mux.jump_exit(cp, h_new))  # 新标识本未连接，幂等
        self.assertTrue(os.path.exists(old_sock))  # 旧连接不受影响
        # 旧连接仍可按旧标识检查与断开
        cp["A"]["proxy_host"] = "10.0.0.9"
        h_old = self.mux.get_host(cp, "A")
        self.assertTrue(self.mux.jump_check(cp, h_old))
        self.assertTrue(self.mux.jump_exit(cp, h_old))
        self.assertFalse(os.path.exists(old_sock))

    def test_connect_failure_reclaims_cred(self):
        cp = self.make_config()
        h = self.mux.get_host(cp, "A")
        ns = (
            "j_"
            + os.path.basename(self.mux.jump_sock_file(cp, h)).rsplit("ssh_mux_j_", 1)[
                -1
            ]
        )
        with mock.patch.dict(os.environ, {"TEST_SSH_FAIL": "1"}):
            with self.assertRaises(SystemExit):
                self.mux.jump_connect(cp, h)
        self.assertFalse(os.path.exists(self.mux.proxy_cred_dir(ns)))

    def test_exit_and_check_never_touch_proxy(self):
        cp = self.make_config()
        h = self.mux.get_host(cp, "A")
        self.mux.jump_connect(cp, h)
        ns = (
            "j_"
            + os.path.basename(self.mux.jump_sock_file(cp, h)).rsplit("ssh_mux_j_", 1)[
                -1
            ]
        )
        cred_dir = self.mux.proxy_cred_dir(ns)
        marker = Path(cred_dir) / "config.json"
        marker.write_text('{"unreadable": true')  # 查看/断开不读取凭据内容
        self.capture.write_text("")
        self.assertTrue(self.mux.jump_check(cp, h))
        self.assertTrue(marker.exists())  # 检查连接不触碰凭据
        self.assertTrue(self.mux.jump_exit(cp, h))
        for r in self.records():
            self.assertFalse(
                any(a.startswith("ProxyCommand=") for a in r["args"]), r["args"]
            )
        self.assertFalse(os.path.exists(cred_dir))  # 断开即回收
        self.assertFalse(self.mux.jump_exit(cp, h))  # 已断开时幂等

    def test_exit_without_socket_still_reclaims_cred(self):
        # ControlPersist 空闲退出后套接字消失：exit 返回 False 但仍回收凭据
        cp = self.make_config()
        h = self.mux.get_host(cp, "A")
        self.mux.jump_connect(cp, h)
        ns = (
            "j_"
            + os.path.basename(self.mux.jump_sock_file(cp, h)).rsplit("ssh_mux_j_", 1)[
                -1
            ]
        )
        cred_dir = Path(self.mux.proxy_cred_dir(ns))
        self.assertTrue(cred_dir.is_dir())
        os.unlink(self.mux.jump_sock_file(cp, h))  # 模拟空闲自动退出
        self.assertFalse(self.mux.jump_exit(cp, h))
        self.assertFalse(cred_dir.exists())

    def test_data_opts_keep_full_proxy_path_after_socket_loss(self):
        cp = self.make_config()
        h_b = self.mux.get_host(cp, "B")
        opts = self.mux.jump_data_opts(cp, h_b)
        self.assertTrue(any(a.startswith("ControlPath=") for a in opts))
        self.assertTrue(any(a.startswith("ProxyCommand=") for a in opts))
        # 控制套接字不存在时选项不变：数据连接不会直连回退
        sock = self.mux.jump_sock_file(cp, h_b)
        self.assertFalse(os.path.exists(sock))
        self.assertEqual(opts, self.mux.jump_data_opts(cp, h_b))
        # 直连且无代理时不新增代理命令
        opts_d = self.mux.jump_data_opts(cp, self.mux.get_host(cp, "D"))
        self.assertFalse(any(a.startswith("ProxyCommand=") for a in opts_d))

    def test_data_opts_fall_back_to_via_relay_when_socket_lost(self):
        # B 经 A 直连（A 可有代理）：末段无代理但有跳板时，附带经 A 套接字的
        # `-W` 转发命令兜底，套接字失效也不会从本机直连 B
        cp = self.make_config()
        for key in ("proxy", "proxy_host", "proxy_port"):
            cp["B"].pop(key)
        opts = self.mux.jump_data_opts(cp, self.mux.get_host(cp, "B"))
        proxy_opt = next(a for a in opts if a.startswith("ProxyCommand="))
        a_sock = self.mux.jump_sock_file(cp, self.mux.get_host(cp, "A"))
        self.assertIn(f"ControlPath={a_sock}", proxy_opt)
        self.assertIn("-W %h:%p", proxy_opt)
        self.assertIn("u@a.invalid", proxy_opt)
        self.assertNotIn("_proxy", proxy_opt)  # 不是本机握手命令
        # 直连无 via 主机不含 ProxyCommand
        opts_d = self.mux.jump_data_opts(cp, self.mux.get_host(cp, "D"))
        self.assertFalse(any(a.startswith("ProxyCommand=") for a in opts_d))

    def test_connect_rejects_invalid_proxy_before_reuse(self):
        cp = self.make_config()
        h = self.mux.get_host(cp, "A")
        self.mux.jump_connect(cp, h)  # 建立连接
        self.assertTrue(self.mux.jump_check(cp, h))
        # 配置改坏（proxy=http 缺端口）：即使已有连接可复用也拒绝
        del cp["A"]["proxy_port"]
        h_bad = self.mux.get_host(cp, "A")
        out = io.StringIO()
        with (
            contextlib.redirect_stdout(out),
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                self.mux.jump_connect(cp, h_bad)
        self.assertNotIn("已连接", out.getvalue())
        # 合法配置 + 已有连接仍正常复用：不重复准备、不另起连接
        cp2 = self.make_config()
        h2 = self.mux.get_host(cp2, "A")
        self.capture.write_text("")
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.mux.jump_connect(cp2, h2)
        self.assertIn("已连接", out.getvalue())
        # 复用路径只跑 jump_check（-O check），不发起新连接
        self.assertEqual(self.connect_records("a.invalid"), [])

    def test_legacy_jump_without_proxy_keeps_ssh_w(self):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_dict(
            {
                "E": {"host": "e.invalid", "user": "u"},
                "F": {"host": "f.invalid", "user": "u", "via": "E", "via_mode": "jump"},
            }
        )
        self.mux.jump_connect(cp, self.mux.get_host(cp, "F"))
        rec = self.connect_records("f.invalid")
        proxy_opt = next(a for a in rec[0]["args"] if a.startswith("ProxyCommand="))
        # 无代理跳板保留原 `ssh -W %h:%p` 复用方式
        self.assertIn("-W %h:%p", proxy_opt)
        self.assertNotIn("_proxy", proxy_opt)
        rec_e = self.connect_records("e.invalid")
        self.assertFalse(
            any(a.startswith("ProxyCommand=") for a in rec_e[0]["args"])
        )  # 直连且无代理


class EndpointSshArgsTests(FakeSshBase):
    """`Endpoint.ssh_args()` 与 jump 系列共用连接参数（任务 3.2）。"""

    class FakeOwner:
        def __init__(self, mux, cp):
            self.mux = mux
            self.cp = cp
            self.task = "task-proxy-local"
            self.deadline = time.monotonic() + 60
            self.cleanup_deadline = self.deadline
            self.cleaning = False

        def remaining(self):
            return 60.0

    def ssh_args(self, cp, alias):
        owner = self.FakeOwner(self.mux, cp)
        ep = hybrid.Endpoint(owner, self.mux.get_host(cp, alias))
        with mock.patch.object(self.mux, "jump_connect", return_value=None):
            return ep.ssh_args("true")

    def test_endpoint_uses_shared_proxy_options(self):
        cp = self.make_config()
        args = self.ssh_args(cp, "A")
        self.assertTrue(any(a.startswith("ProxyCommand=") for a in args))
        self.assertTrue(any(a.startswith("ControlPath=") for a in args))
        self.assertNotIn(
            "proxy-pass-a", json.dumps(args)
        )  # 参数不含秘密，秘密只在 600 凭据文件
        args_d = self.ssh_args(cp, "D")
        self.assertFalse(any(a.startswith("ProxyCommand=") for a in args_d))


class ShellPlanProxyTests(FakeSshBase):
    """使用代理的混合登录链规划（任务 3.5）。"""

    def mixed_config(self):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_dict(
            {
                "A": {"host": "a.invalid", "user": "u"},
                "B": {
                    "host": "b.invalid",
                    "user": "u",
                    "via": "A",
                    "via_mode": "jump",
                    "proxy": "http",
                    "proxy_host": "10.0.0.9",
                    "proxy_port": "8080",
                },
                "C": {
                    "host": "c.invalid",
                    "user": "u",
                    "via": "B",
                    "via_mode": "shell",
                },
            }
        )
        return cp

    def test_mixed_chain_keeps_jump_prefix_then_terminal(self):
        cp = self.mixed_config()
        plan = self.mux.build_shell_plan(cp, "C")
        self.assertEqual(len(plan), 2)
        args, auth, meta = plan[0]
        # 开头连续的标准跳板路径在本机建立，再在路径末端打开终端
        self.assertEqual(meta.get("jump_socket"), "B")
        h_b = self.mux.get_host(cp, "B")
        self.assertIn(f"ControlPath={self.mux.jump_sock_file(cp, h_b)}", args)
        self.assertEqual(args[-1], "u@b.invalid")
        self.assertEqual(auth, [])
        # A → B 的代理由本机经 `ssh -W` 完成，A 上无需远端准备（A 无 Python 也可登录 C）
        self.assertNotIn("prepare", meta)
        args_c, auth_c, meta_c = plan[1]
        self.assertEqual(meta_c, {})
        self.assertEqual(args_c[-1], "u@c.invalid")

    def test_shell_segment_proxy_marks_prepare(self):
        cp = self.mixed_config()
        cp["C"]["proxy"] = "socks5"
        cp["C"]["proxy_host"] = "10.1.1.1"
        cp["C"]["proxy_port"] = "1080"
        plan = self.mux.build_shell_plan(cp, "C")
        prep = plan[1][2].get("prepare")
        self.assertIsNotNone(prep)
        self.assertEqual(prep["origin"], "B")
        self.assertEqual(prep["proxy"]["type"], "socks5")
        self.assertEqual(prep["target"], {"host": "c.invalid", "port": 22})

    def test_no_proxy_chain_keeps_legacy_plan(self):
        cp = self.mixed_config()
        for key in ("proxy", "proxy_host", "proxy_port"):
            cp["B"].pop(key)
        plan = self.mux.build_shell_plan(cp, "C")
        self.assertEqual(len(plan), 3)
        for step, alias in zip(plan, ("A", "B", "C")):
            args, auth = self.mux.ssh_step(cp, self.mux.get_host(cp, alias))
            self.assertEqual(step[0], args)
            self.assertEqual(step[1], auth)
            self.assertEqual(step[2], {})  # 无代理链保持原计划

    def test_before_start_rebuilds_socket_on_original_path(self):
        cp = self.mixed_config()
        plan = self.mux.build_shell_plan(cp, "C")
        calls = []
        sess = self.mux.PtySession(plan, lambda msg: None)
        with mock.patch.object(
            self.mux,
            "jump_connect",
            lambda cp_, h, quiet=False: calls.append(h.alias),
        ):
            self.mux.attach_proxy_support(
                sess,
                cp,
                plan,
                self.mux.RemoteJanitor(),
                "session",
                "s_test",
                lambda m: None,
                set(),
            )
            # 前序套接字失效后按原路径重建（jump_connect 内部递归建立 A 再建 B）
            self.assertEqual(sess.before_start(), [])
        self.assertEqual(calls, ["B"])

    def test_before_start_prepares_local_cred_and_recovers_after_loss(self):
        # 首个终端段带代理（用户名路由堡垒机入口）：prefix 为 0，凭据由守护进程准备
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_dict(
            {
                "bastion": {
                    "host": "gate.invalid",
                    "user": "T",
                    "routing": "username",
                    "proxy": "http",
                    "proxy_host": "10.0.0.9",
                    "proxy_port": "8080",
                    "proxy_user": "proxy-user-a",
                    "proxy_password": "proxy-pass-a",
                },
                "A": {"host": "a.invalid", "user": "u", "via": "bastion"},
            }
        )
        plan = self.mux.build_shell_plan(cp, "A")
        self.assertIn("local_proxy", plan[0][2])
        sess = self.mux.PtySession(plan, lambda msg: None)
        self.mux.attach_proxy_support(
            sess,
            cp,
            plan,
            self.mux.RemoteJanitor(),
            "session",
            "s_demo",
            lambda m: None,
            set(),
        )
        opts = sess.before_start()
        self.assertEqual(len(opts), 2)
        self.assertTrue(opts[1].startswith("ProxyCommand="))
        self.assertNotIn("proxy-pass-a", opts[1])  # 终端首步参数无代理秘密
        cred = Path(self.mux.proxy_cred_dir("s_demo")) / "config.json"
        self.assertTrue(cred.is_file())
        self.assertEqual(stat.S_IMODE(cred.stat().st_mode), 0o600)
        self.mux.drop_proxy_cred_file("s_demo")
        sess.before_start()  # 旧文件丢失后重连重新准备
        self.assertTrue(cred.is_file())
        data = json.loads(cred.read_text())
        self.assertEqual(data["proxy"]["password"], "proxy-pass-a")


if __name__ == "__main__":
    unittest.main()
