"""逐段代理规划、连接标识、host 子命令测试；不连接外部主机。"""

import configparser
import contextlib
import hashlib
import importlib.util
import io
import json
import os
from pathlib import Path
import tempfile
import types
import unittest
from unittest import mock

from test_transfer import load_mux


def load_fresh():
    return load_mux()


def base_config():
    cp = configparser.ConfigParser(interpolation=None)
    cp.read_dict(
        {
            "A": {"host": "a.invalid", "user": "u"},
            "B": {"host": "b.invalid", "user": "u", "via": "A", "via_mode": "jump"},
            "C": {"host": "c.invalid", "user": "u", "via": "B", "via_mode": "shell"},
        }
    )
    return cp


class EffectiveProxyTests(unittest.TestCase):
    """逐段优先级与配置校验（任务 1.1、1.2）。"""

    def setUp(self):
        self.mux = load_fresh()
        self.cp = base_config()

    def host(self, alias):
        return self.mux.get_host(self.cp, alias)

    def test_direct_ignores_remaining_fields_and_env(self):
        self.cp["B"]["proxy"] = "direct"
        self.cp["B"]["proxy_host"] = "leftover.invalid"
        env = {"SSH_MUX_PROXY": "http://10.0.0.1:8080"}
        self.assertIsNone(self.mux.effective_proxy(self.host("B"), "A", env=env))
        # @local 段的条目配了 direct 后，本机默认代理同样被忽略
        self.cp["A"]["proxy"] = "direct"
        self.assertIsNone(self.mux.effective_proxy(self.host("A"), "@local", env=env))

    def test_explicit_config_beats_env(self):
        self.cp["A"]["proxy"] = "socks5"
        self.cp["A"]["proxy_host"] = "127.0.0.2"
        self.cp["A"]["proxy_port"] = "1080"
        env = {"SSH_MUX_PROXY": "http://10.0.0.1:8080"}
        seg = self.mux.effective_proxy(self.host("A"), "@local", env=env)
        self.assertEqual((seg.kind, seg.host, seg.port), ("socks5", "127.0.0.2", 1080))

    def test_env_only_applies_to_local_origin(self):
        env = {"SSH_MUX_PROXY": "socks5://127.0.0.1:1080"}
        seg = self.mux.effective_proxy(self.host("A"), "@local", env=env)
        self.assertEqual((seg.kind, seg.host, seg.port), ("socks5", "127.0.0.1", 1080))
        self.assertIsNone(seg.user)
        # 远端段默认直连，不读取本机默认代理
        self.assertIsNone(self.mux.effective_proxy(self.host("B"), "A", env=env))

    def test_env_with_userinfo_or_missing_port_rejected(self):
        for raw in (
            "http://user@127.0.0.1:8080",
            "http://user:pass@127.0.0.1:8080",
            "http://127.0.0.1",
            "socks5://127.0.0.1/",
            "ftp://127.0.0.1:21",
            "http://127.0.0.1:99999",
            "http://127.0.0.1:8080/extra",
        ):
            env = {"SSH_MUX_PROXY": raw}
            with self.assertRaises(SystemExit, msg=raw):
                self.mux.effective_proxy(self.host("A"), "@local", env=env)

    def test_env_error_never_echoes_secret(self):
        # 非法变量可能混入密码：错误文本只说原因，不回显原始值
        for raw in (
            "ftp://user:px-pass-机密@10.0.0.9:21",  # 协议不受支持
            "http://10.0.0.9:8080/p?token=px-pass-机密",  # 只接受 协议://主机:端口
        ):
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                with self.assertRaises(SystemExit, msg=raw):
                    self.mux.effective_proxy(
                        self.host("A"), "@local", env={"SSH_MUX_PROXY": raw}
                    )
            self.assertNotIn("px-pass-机密", err.getvalue(), raw)
            self.assertNotIn(raw, err.getvalue(), raw)

    def test_empty_env_means_direct(self):
        for raw in (None, "", "   "):
            env = {} if raw is None else {"SSH_MUX_PROXY": raw}
            self.assertIsNone(
                self.mux.effective_proxy(self.host("A"), "@local", env=env)
            )

    def test_proxy_fields_without_type_rejected(self):
        self.cp["B"]["proxy_host"] = "10.0.0.9"
        with self.assertRaises(SystemExit):
            self.mux.effective_proxy(self.host("B"), "A")

    def test_port_range_and_unknown_type_and_chain_rejected(self):
        for proxy, port in (
            ("http", "0"),
            ("http", "65536"),
            ("socks5", "abc"),
            ("socks4", "1080"),
            ("http,socks5", "1080"),
            ("http+socks5", "1"),
        ):
            self.cp["B"]["proxy"] = proxy
            self.cp["B"]["proxy_host"] = "10.0.0.9"
            self.cp["B"]["proxy_port"] = port
            with self.assertRaises(SystemExit, msg=f"{proxy}:{port}"):
                self.mux.effective_proxy(self.host("B"), "A")

    def test_inner_segment_config_error_never_direct(self):
        # B 配置 proxy=http 但没有端口：报告 A → B 的配置错误
        self.cp["B"]["proxy"] = "http"
        self.cp["B"]["proxy_host"] = "10.0.0.9"
        with self.assertRaises(SystemExit):
            self.mux.plan_segments(self.cp, "C")

    def test_http_auth_rules(self):
        self.cp["A"]["proxy"] = "http"
        self.cp["A"]["proxy_host"] = "127.0.0.2"
        self.cp["A"]["proxy_port"] = "8080"
        self.cp["A"]["proxy_user"] = "alice"
        seg = self.mux.effective_proxy(self.host("A"), "@local")
        self.assertEqual((seg.user, seg.password), ("alice", None))
        self.cp["A"]["proxy_user"] = "ali:ce"
        with self.assertRaises(SystemExit):
            self.mux.effective_proxy(self.host("A"), "@local")

    def test_http_user_with_nul_byte_rejected(self):
        # 空字节会破坏 Basic 头的编码与头部结构，配置层直接拒绝
        with self.assertRaises(ValueError):
            self.mux.make_proxy("http", "10.0.0.9", 8080, "u\x00name", None)

    def test_socks5_auth_length_boundaries(self):
        # 用户名和密码各 255 字节是协议上限：接受
        seg = self.mux.make_proxy("socks5", "10.0.0.9", 1080, "u" * 255, "p" * 255)
        self.assertEqual((seg.user, seg.password), ("u" * 255, "p" * 255))
        # 256 字节超出单字节长度字段：拒绝
        with self.assertRaises(ValueError):
            self.mux.make_proxy("socks5", "10.0.0.9", 1080, "u", "p" * 256)
        with self.assertRaises(ValueError):
            self.mux.make_proxy("socks5", "10.0.0.9", 1080, "u" * 256, "p")

    def test_non_ascii_proxy_host_rejected(self):
        # 非 ASCII 地址在配置层拒绝，报配置错误而不是编码时的内部错误
        with self.assertRaises(ValueError):
            self.mux.make_proxy("http", "主机.invalid", 8080, None, None)

    def test_segments_of_mixed_chain(self):
        # 本机 → A（P1），A → B（显式直连），B → C（P2）；代理不串联也不继承
        self.cp["A"]["proxy"] = "socks5"
        self.cp["A"]["proxy_host"] = "127.0.0.2"
        self.cp["A"]["proxy_port"] = "1080"
        self.cp["B"]["proxy"] = "direct"
        self.cp["C"]["proxy"] = "http"
        self.cp["C"]["proxy_host"] = "10.9.0.1"
        self.cp["C"]["proxy_port"] = "3128"
        env = {"SSH_MUX_PROXY": "http://10.0.0.1:8080"}
        segments = self.mux.plan_segments(self.cp, "C", env=env)
        self.assertEqual([s.origin for s in segments], ["@local", "A", "B"])
        self.assertEqual(segments[0].proxy.kind, "socks5")  # 显式配置覆盖环境变量
        self.assertIsNone(segments[1].proxy)
        self.assertEqual(segments[2].proxy.kind, "http")
        self.assertEqual([s.entry.alias for s in segments], ["A", "B", "C"])


class UsernameRoutingTests(unittest.TestCase):
    """用户名路由只控制堡垒机入口（任务 1.3）。"""

    def setUp(self):
        self.mux = load_fresh()
        self.cp = configparser.ConfigParser(interpolation=None)
        self.cp.read_dict(
            {
                "bastion": {
                    "host": "gate.invalid",
                    "user": "T1",
                    "routing": "username",
                },
                "A": {"host": "a.invalid", "via": "bastion", "via_mode": "shell"},
                "B": {"host": "b.invalid", "via": "A", "via_mode": "shell"},
            }
        )

    def test_entry_segment_uses_bastion_proxy(self):
        self.cp["bastion"]["proxy"] = "http"
        self.cp["bastion"]["proxy_host"] = "127.0.0.3"
        self.cp["bastion"]["proxy_port"] = "8080"
        self.cp["A"]["proxy"] = "socks5"
        self.cp["A"]["proxy_host"] = "10.1.1.1"
        self.cp["A"]["proxy_port"] = "1080"
        segments = self.mux.plan_segments(self.cp, "A")
        self.assertEqual(len(segments), 1)
        seg = segments[0]
        self.assertEqual(seg.entry.alias, "bastion")  # 实际入口是堡垒机
        self.assertEqual((seg.proxy.kind, seg.proxy.host), ("http", "127.0.0.3"))
        self.assertIn("bastion", seg.unused)  # A 的代理标为未使用并提示入口别名

    def test_direct_on_internal_target_has_no_hint(self):
        self.cp["A"]["proxy"] = "direct"
        segments = self.mux.plan_segments(self.cp, "A")
        self.assertIsNone(segments[0].proxy)
        self.assertIsNone(segments[0].unused)

    def test_next_segment_after_routing_still_applies_proxy(self):
        # 登录 A 后，A 到 B 使用 B 的代理
        self.cp["B"]["proxy"] = "socks5"
        self.cp["B"]["proxy_host"] = "10.2.2.2"
        self.cp["B"]["proxy_port"] = "1080"
        segments = self.mux.plan_segments(self.cp, "B")
        self.assertEqual(len(segments), 2)
        self.assertEqual(segments[1].origin, "A")
        self.assertEqual(segments[1].proxy.host, "10.2.2.2")

    def test_local_section_proxy_never_controls_egress(self):
        cp = base_config()
        cp["local"] = {
            "host": "me.invalid",
            "proxy": "http",
            "proxy_host": "10.0.0.1",
            "proxy_port": "8080",
        }
        text = self.mux.describe_proxy(cp, self.mux.get_host(cp, "local"))
        self.assertIn("未使用", text)


class IdentityTests(unittest.TestCase):
    """连接标识覆盖路径上的有效代理（任务 1.4）。"""

    def setUp(self):
        self.mux = load_fresh()
        self.cp = base_config()

    def test_no_proxy_identity_byte_identical(self):
        h = self.mux.get_host(self.cp, "C")
        with (
            mock.patch.object(self.mux, "runtime_dir", return_value="/tmp/review"),
            mock.patch.object(self.mux, "CONFIG_PATH", "/tmp/hosts.conf"),
        ):
            identity = [
                os.path.realpath("/tmp/hosts.conf"),
                [
                    [i.alias, i.host, i.port, i.user, i.via_mode, i.routing]
                    for i in self.mux.build_chain(self.cp, "C")
                ],
            ]
            expected = hashlib.sha256(
                json.dumps(identity, ensure_ascii=True).encode()
            ).hexdigest()[:32]
            self.assertEqual(
                self.mux.jump_sock_file(self.cp, h), f"/tmp/review/ssh_mux_j_{expected}"
            )
            legacy = hashlib.sha256(
                json.dumps([os.path.realpath("/tmp/hosts.conf"), "C"]).encode()
            ).hexdigest()[:16]
            self.assertEqual(self.mux.shell_prefix("C"), f"/tmp/review/s_{legacy}_")

    def test_proxy_change_on_affects_dependents(self):
        # shell_prefix 从磁盘配置容错读取，这里把配置写到临时文件
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "hosts.conf")

            def save():
                with open(cfg, "w") as f:
                    self.cp.write(f)

            save()
            with (
                mock.patch.object(self.mux, "runtime_dir", return_value=td),
                mock.patch.object(self.mux, "CONFIG_PATH", cfg),
            ):
                h_c = self.mux.get_host(self.cp, "C")
                h_b = self.mux.get_host(self.cp, "B")
                before_b = self.mux.jump_sock_file(self.cp, h_b)
                before_c = self.mux.jump_sock_file(self.cp, h_c)
                before_prefix = self.mux.shell_prefix("C")
                self.cp["A"]["proxy"] = "http"
                self.cp["A"]["proxy_host"] = "127.0.0.2"
                self.cp["A"]["proxy_port"] = "8080"
                save()
                self.assertNotEqual(before_b, self.mux.jump_sock_file(self.cp, h_b))
                self.assertNotEqual(before_c, self.mux.jump_sock_file(self.cp, h_c))
                self.assertNotEqual(before_prefix, self.mux.shell_prefix("C"))
                # 只改凭据标识不变
                with_creds = self.mux.jump_sock_file(self.cp, h_b)
                self.cp["A"]["proxy_user"] = "u1"
                self.cp["A"]["proxy_password"] = "p1"
                save()
                self.assertEqual(with_creds, self.mux.jump_sock_file(self.cp, h_b))
                self.assertTrue(self.mux.shell_prefix("C"))

    def test_env_and_config_same_endpoint_share_identity(self):
        with (
            mock.patch.object(self.mux, "runtime_dir", return_value="/tmp/review"),
            mock.patch.object(self.mux, "CONFIG_PATH", "/tmp/hosts.conf"),
        ):
            env = {"SSH_MUX_PROXY": "socks5://127.0.0.5:1080"}
            with mock.patch.dict(os.environ, env, clear=False):
                from_env = self.mux.jump_sock_file(
                    self.cp, self.mux.get_host(self.cp, "A")
                )
            self.cp["A"]["proxy"] = "socks5"
            self.cp["A"]["proxy_host"] = "127.0.0.5"
            self.cp["A"]["proxy_port"] = "1080"
            with mock.patch.dict(os.environ, {}, clear=False):
                os.environ.pop("SSH_MUX_PROXY", None)
                from_cfg = self.mux.jump_sock_file(
                    self.cp, self.mux.get_host(self.cp, "A")
                )
            self.assertEqual(from_env, from_cfg)

    def test_shell_prefix_env_and_config_same_endpoint_identical(self):
        # 镜像 jump 侧：shell_prefix 对同端点的两来源（环境变量/显式配置）标识相同
        with tempfile.TemporaryDirectory() as td:
            cfg = os.path.join(td, "hosts.conf")

            def save():
                with open(cfg, "w") as f:
                    self.cp.write(f)

            save()
            with (
                mock.patch.object(self.mux, "runtime_dir", return_value=td),
                mock.patch.object(self.mux, "CONFIG_PATH", cfg),
            ):
                with mock.patch.dict(
                    os.environ, {"SSH_MUX_PROXY": "socks5://127.0.0.5:1080"}
                ):
                    from_env = self.mux.shell_prefix("A")
                self.cp["A"]["proxy"] = "socks5"
                self.cp["A"]["proxy_host"] = "127.0.0.5"
                self.cp["A"]["proxy_port"] = "1080"
                save()
                with mock.patch.dict(os.environ, {}, clear=False):
                    os.environ.pop("SSH_MUX_PROXY", None)
                    from_cfg = self.mux.shell_prefix("A")
                self.assertEqual(from_env, from_cfg)
                # 代理确实进入了标识：去掉代理配置后前缀改变
                for key in ("proxy", "proxy_host", "proxy_port"):
                    self.cp["A"].pop(key)
                save()
                self.assertNotEqual(from_cfg, self.mux.shell_prefix("A"))

    def test_unrelated_path_unaffected(self):
        cp = base_config()
        cp["other"] = {"host": "other.invalid"}
        with (
            mock.patch.object(self.mux, "runtime_dir", return_value="/tmp/review"),
            mock.patch.object(self.mux, "CONFIG_PATH", "/tmp/hosts.conf"),
        ):
            before = self.mux.jump_sock_file(cp, self.mux.get_host(cp, "other"))
            cp["A"]["proxy"] = "http"
            cp["A"]["proxy_host"] = "127.0.0.2"
            cp["A"]["proxy_port"] = "8080"
            self.assertEqual(
                before, self.mux.jump_sock_file(cp, self.mux.get_host(cp, "other"))
            )

    def test_invalid_env_does_not_break_identity(self):
        with (
            mock.patch.object(self.mux, "runtime_dir", return_value="/tmp/review"),
            mock.patch.object(self.mux, "CONFIG_PATH", "/tmp/hosts.conf"),
            mock.patch.dict(os.environ, {"SSH_MUX_PROXY": "http://user@bad:1"}),
        ):
            # 标识计算不解析失败而崩溃（连接建立时会拒绝）
            self.assertTrue(
                self.mux.jump_sock_file(self.cp, self.mux.get_host(self.cp, "A"))
            )
            self.assertTrue(self.mux.shell_prefix("A"))

    def test_shell_cred_ns_isolated_per_session(self):
        # 守护进程按会话隔离，凭据命名空间也按会话隔离：一个会话退出不影响另一个
        with (
            mock.patch.object(self.mux, "runtime_dir", return_value="/tmp/review"),
            mock.patch.object(self.mux, "CONFIG_PATH", "/tmp/hosts.conf"),
        ):
            ns1 = self.mux.shell_cred_ns("A", "default")
            ns2 = self.mux.shell_cred_ns("A", "other-session")
        self.assertNotEqual(ns1, ns2)
        self.assertTrue(ns1.startswith("s_"))
        # 会话名合法字符含 `-`，凭据目录命名校验要允许
        with mock.patch.object(self.mux, "runtime_dir", return_value="/tmp/review"):
            self.assertIn("px_s_", self.mux.proxy_cred_dir(ns2))
            # management_exec 的 m_ 前缀不受影响
            self.assertTrue(self.mux.proxy_cred_dir("m_abc123"))


class HostCommandTests(unittest.TestCase):
    """host add/list/status 的代理支持（任务 1.5）。"""

    def setUp(self):
        self.mux = load_fresh()
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-host-")
        self.addCleanup(self.tmp.cleanup)
        self.cfg = str(Path(self.tmp.name) / "hosts.conf")
        patcher = mock.patch.object(self.mux, "CONFIG_PATH", self.cfg)
        patcher.start()
        self.addCleanup(patcher.stop)

    def add_args(self, alias, **kw):
        defaults = dict(
            alias=alias,
            host=None,
            port=None,
            user=None,
            password=None,
            via=None,
            via_mode=None,
            routing=None,
            staging=None,
            proxy=None,
            proxy_host=None,
            proxy_port=None,
            proxy_user=None,
            proxy_password=None,
        )
        defaults.update(kw)
        return types.SimpleNamespace(**defaults)

    def test_add_with_via_and_proxy(self):
        self.mux.cmd_host_add(self.add_args("A", host="a.invalid"))
        self.mux.cmd_host_add(
            self.add_args(
                "B",
                host="b.invalid",
                via="A",
                via_mode="jump",
                proxy="socks5",
                proxy_host="10.0.0.9",
                proxy_port=1080,
                proxy_user="u",
                proxy_password="p",
            )
        )
        cp = self.mux.load_config()
        self.assertEqual(cp["B"]["via"], "A")
        self.assertEqual(cp["B"]["proxy"], "socks5")
        self.assertEqual(cp["B"]["proxy_port"], "1080")

    def test_invalid_proxy_config_does_not_rewrite_file(self):
        self.mux.cmd_host_add(self.add_args("A", host="a.invalid"))
        before = Path(self.cfg).read_text()
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.mux.cmd_host_add(
                self.add_args(
                    "B", host="b.invalid", proxy="http", proxy_host="10.0.0.9"
                )
            )  # 缺端口
        self.assertEqual(Path(self.cfg).read_text(), before)
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.mux.cmd_host_add(
                self.add_args("B", host="b.invalid", proxy_host="10.0.0.9")
            )
        self.assertEqual(Path(self.cfg).read_text(), before)
        # 已有别名处理不变
        with contextlib.redirect_stderr(io.StringIO()), self.assertRaises(SystemExit):
            self.mux.cmd_host_add(self.add_args("A", host="x.invalid"))
        self.assertEqual(Path(self.cfg).read_text(), before)

    def test_list_hides_secrets_and_shows_segment(self):
        self.mux.cmd_host_add(self.add_args("A", host="a.invalid"))
        self.mux.cmd_host_add(
            self.add_args(
                "B",
                host="b.invalid",
                via="A",
                proxy="http",
                proxy_host="10.0.0.9",
                proxy_port=8080,
                proxy_user="secretuser",
                proxy_password="secretpass",
            )
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.mux.cmd_list(self.mux.load_config())
        text = out.getvalue()
        self.assertIn("proxy=http://10.0.0.9:8080", text)
        self.assertIn("A → B", text)
        self.assertNotIn("secretuser", text)
        self.assertNotIn("secretpass", text)

    def test_list_shows_unused_reasons(self):
        self.mux.cmd_host_add(
            self.add_args("bastion", host="gate.invalid", routing="username", user="T")
        )
        self.mux.cmd_host_add(
            self.add_args(
                "A",
                host="a.invalid",
                via="bastion",
                via_mode="shell",
                proxy="http",
                proxy_host="10.0.0.9",
                proxy_port=8080,
            )
        )
        cp = self.mux.load_config()
        cp.add_section("local")
        cp["local"]["proxy"] = "http"
        cp["local"]["proxy_host"] = "10.0.0.1"
        cp["local"]["proxy_port"] = "8080"
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.mux.cmd_list(cp)
        text = out.getvalue()
        self.assertIn("未使用", text)
        self.assertIn("bastion", text)
        self.assertIn("[local]", text)

    def test_invalid_env_does_not_block_list(self):
        self.mux.cmd_host_add(self.add_args("A", host="a.invalid"))
        out = io.StringIO()
        with (
            mock.patch.dict(os.environ, {"SSH_MUX_PROXY": "http://user@bad"}),
            contextlib.redirect_stdout(out),
        ):
            self.mux.cmd_list(self.mux.load_config())
        self.assertIn("A", out.getvalue())

    def test_status_shows_proxy_without_secrets(self):
        self.mux.cmd_host_add(
            self.add_args(
                "A",
                host="a.invalid",
                proxy="socks5",
                proxy_host="10.0.0.9",
                proxy_port=1080,
                proxy_user="secret_user_x",
                proxy_password="secret_pass_x",
            )
        )
        out = io.StringIO()
        with (
            mock.patch.object(self.mux, "jump_check", return_value=False),
            contextlib.redirect_stdout(out),
        ):
            self.mux.cmd_status(self.mux.load_config())
        text = out.getvalue()
        self.assertIn("proxy=socks5://10.0.0.9:1080", text)
        self.assertNotIn("secret_user_x", text)
        self.assertNotIn("secret_pass_x", text)

    def test_status_shows_routing_bastion_own_proxy(self):
        # 用户名路由的堡垒机自身也可能配置了入口代理，status 一并显示
        self.mux.cmd_host_add(
            self.add_args(
                "gate",
                host="gate.invalid",
                routing="username",
                proxy="http",
                proxy_host="10.0.0.7",
                proxy_port=8080,
            )
        )
        out = io.StringIO()
        with contextlib.redirect_stdout(out):
            self.mux.cmd_status(self.mux.load_config())
        text = out.getvalue()
        self.assertIn("堡垒机", text)
        self.assertIn("proxy=http://10.0.0.7:8080", text)

    def test_hint_unused_proxies_goes_to_stderr(self):
        # 用户名路由内部目标上的代理字段未使用：首次提示输出到 stderr
        self.mux.cmd_host_add(
            self.add_args("bastion", host="gate.invalid", routing="username")
        )
        self.mux.cmd_host_add(
            self.add_args(
                "A",
                host="a.invalid",
                via="bastion",
                proxy="http",
                proxy_host="10.0.0.9",
                proxy_port=8080,
            )
        )
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            self.mux.hint_unused_proxies("A")
        text = err.getvalue()
        self.assertIn("提示", text)
        self.assertIn("bastion", text)

    def test_ensure_daemon_rejects_invalid_proxy_before_reuse(self):
        # 配置改坏（proxy=http 缺端口）：即使已有会话可复用也拒绝，不启动进程
        Path(self.cfg).write_text(
            "[A]\nhost = a.invalid\nproxy = http\nproxy_host = 10.0.0.9\n"
        )
        with (
            mock.patch.object(self.mux, "ping_session", return_value=True),
            mock.patch.object(self.mux.subprocess, "Popen") as popen,
            contextlib.redirect_stderr(io.StringIO()),
        ):
            with self.assertRaises(SystemExit):
                self.mux.ensure_daemon("A", "default")
        popen.assert_not_called()

    def test_ensure_daemon_reuses_session_with_valid_proxy(self):
        # 合法配置 + 已有会话正常复用：不重复启动守护进程
        self.mux.cmd_host_add(
            self.add_args(
                "A",
                host="a.invalid",
                proxy="http",
                proxy_host="10.0.0.9",
                proxy_port=8080,
            )
        )
        with (
            mock.patch.object(self.mux, "ping_session", return_value=True),
            mock.patch.object(self.mux.subprocess, "Popen") as popen,
        ):
            self.mux.ensure_daemon("A", "default")
        popen.assert_not_called()


class ExampleConfigTests(unittest.TestCase):
    """用配置解析核对 `hosts.conf.example` 与逐段规则一致（任务 1.6）。"""

    def setUp(self):
        self.mux = load_fresh()
        self.path = Path(__file__).resolve().parents[1] / "hosts.conf.example"

    def parse(self, text):
        cp = configparser.ConfigParser(interpolation=None)
        cp.read_string(text)
        return cp

    def test_example_parses_and_all_fields_valid(self):
        text = self.path.read_text()
        cp = self.parse(text)
        self.assertIn("local", cp.sections())
        for alias in cp.sections():
            h = self.mux.get_host(cp, alias)
            # 示例中的代理行都是注释，各段按规则得到直连或显式配置
            origin = h.via or "@local"
            with mock.patch.dict(os.environ, {}, clear=True):
                self.mux.effective_proxy(h, origin, env={})

    def test_uncommented_proxy_examples_follow_segment_rules(self):
        text = self.path.read_text()
        # 取消示例中代理行的注释：堡垒机 HTTP、B 段 SOCKS5、web 段 HTTP、db 直连
        lines = []
        for line in text.splitlines():
            if line.startswith("# proxy") or line.startswith("#proxy"):
                lines.append(line.lstrip("# "))
            else:
                lines.append(line)
        cp = self.parse("\n".join(lines))
        self.assertEqual(cp["bastion"]["proxy"], "http")
        self.assertEqual(cp["B"]["proxy"], "socks5")
        self.assertEqual(cp["web"]["proxy"], "http")
        self.assertEqual(cp["db"]["proxy"], "direct")
        # 用户名路由入口段取堡垒机代理
        segments = self.mux.plan_segments(cp, "A")
        self.assertEqual(segments[0].entry.alias, "bastion")
        self.assertEqual(segments[0].proxy.kind, "http")
        # B 段在 A 上使用 SOCKS5；与入口段类型不同，互不继承
        segments_b = self.mux.plan_segments(cp, "B")
        self.assertEqual(segments_b[-1].origin, "A")
        self.assertEqual(segments_b[-1].proxy.kind, "socks5")
        # web 段使用显式 HTTP；db 显式直连并忽略本机默认代理
        segments_web = self.mux.plan_segments(cp, "web")
        self.assertEqual(segments_web[-1].proxy.kind, "http")
        env = {"SSH_MUX_PROXY": "http://10.0.0.1:8080"}
        self.assertIsNone(
            self.mux.effective_proxy(self.mux.get_host(cp, "db"), "@local", env=env)
        )


if __name__ == "__main__":
    unittest.main()
