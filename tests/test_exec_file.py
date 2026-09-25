"""从本地文件读取远程命令的回归测试，使用本地 shell 模拟执行。"""

import configparser
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


ROOT = Path(__file__).resolve().parents[1]
SPEC = importlib.util.spec_from_file_location("mux_file_tests", ROOT / "ssh-mux.py")
mux = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(mux)


class FileCommandTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory(prefix="ssh-mux-file-test-")
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.file = self.root / "复杂 command.sh"
        self.cp = configparser.ConfigParser(interpolation=None)
        self.cp.read_dict({"direct": {"host": "test.invalid"},
                           "terminal": {"host": "target.invalid", "via": "direct",
                                        "via_mode": "shell"}})
        patch = mock.patch.object(mux, "load_config", return_value=self.cp)
        self.load_config = patch.start()
        self.addCleanup(patch.stop)

    def invoke(self, args):
        output, error = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(output), contextlib.redirect_stderr(error):
            with self.assertRaises(SystemExit) as stopped:
                mux.run_exec_cli(args)
        return stopped.exception.code, output.getvalue(), error.getvalue()

    @staticmethod
    def local_jump(config, host, command):
        result = subprocess.run(["bash", "-c", command], capture_output=True, text=True)
        print(result.stdout, end="")
        return result.returncode

    @unittest.skipUnless(shutil.which("bash") and shutil.which("awk"), "需要 Bash 和 awk")
    def test_complex_awk_script_through_both_modes(self):
        # 文件中的引号按正常 shell 语法书写，不需要为命令行再转义一次。
        script = '''label="O'Reilly $ literal"
awk -v label="$label" '
    { sum += $2 }
    END { printf "%s:%d\\n", label, sum }
' <<'DATA'
alice 10
bob 20
DATA
# 末尾注释'''
        self.file.write_text(script, encoding="utf-8")
        expected = (0, "O'Reilly $ literal:30\n", "")
        with mock.patch.object(mux, "jump_exec", side_effect=self.local_jump):
            self.assertEqual(self.invoke(["direct", "--file", str(self.file)]), expected)
        session = mux.PtySession([(["bash", "--noprofile", "--norc", "-i"], [])], lambda _: None)
        self.addCleanup(session.close)
        session.start()

        def terminal(alias, name, command, timeout):
            output, code = session.exec(command, timeout)
            return {"status": "ok", "exit": code, "output": output}

        with mock.patch.object(mux, "shell_exec", side_effect=terminal):
            self.assertEqual(self.invoke(["terminal", "--file", str(self.file)]), expected)

    @unittest.skipUnless(shutil.which("bash"), "需要 Bash")
    def test_file_options_and_relative_paths(self):
        self.file.write_text("printf 'ok\\n'", encoding="utf-8")
        relative = os.path.relpath(str(self.file))
        variations = [
            ["direct", "--file", relative],
            ["-f", relative, "direct", "--timeout", "4"],
            ["--session", "case1", "direct", "--file=" + relative],
            ["direct", "--timeout=4", "--file", relative, "--session=case1"],
        ]
        with mock.patch.object(mux, "jump_exec", side_effect=self.local_jump):
            for args in variations:
                with self.subTest(args=args):
                    self.assertEqual(self.invoke(args), (0, "ok\n", ""))

    @unittest.skipUnless(shutil.which("bash"), "需要 Bash")
    def test_utf8_bom_and_windows_newlines(self):
        self.file.write_bytes(b"\xef\xbb\xbf# comment\r\nprintf '" +
                              "中文".encode() + b"\\n'\r\n")
        with mock.patch.object(mux, "jump_exec", side_effect=self.local_jump):
            self.assertEqual(self.invoke(["direct", "-f", str(self.file)]), (0, "中文\n", ""))

    @unittest.skipUnless(shutil.which("bash"), "需要 Bash")
    def test_standard_input(self):
        source = io.TextIOWrapper(io.BytesIO(b"printf '$1 \\\\ literal\\n'\n"), encoding="utf-8")
        self.addCleanup(source.close)
        with mock.patch.object(mux.sys, "stdin", source), \
                mock.patch.object(mux, "jump_exec", side_effect=self.local_jump):
            self.assertEqual(self.invoke(["direct", "--file", "-"]), (0, "$1 \\ literal\n", ""))

    def test_unreadable_or_invalid_files_fail_before_connecting(self):
        for data in (None, b"", b" \n\t", b"\xff", b"echo a\x00b"):
            with self.subTest(data=data):
                self.load_config.reset_mock()
                if data is not None:
                    self.file.write_bytes(data)
                result = self.invoke(["direct", "--file", str(self.file)])
                self.assertEqual(result[0], 1)
                self.assertTrue(result[2])
                self.load_config.assert_not_called()
        self.load_config.reset_mock()
        self.assertEqual(self.invoke(["direct", "--file", str(self.root)])[0], 1)
        self.load_config.assert_not_called()

    def test_conflicts_and_missing_file_values_fail_before_connecting(self):
        for args in (["direct", "--file"], ["direct", "--file="],
                     ["direct", "--file", "a", "--file", "b"],
                     ["direct", "--file", "a", "echo hi"],
                     ["direct", "-f", "a", "--", "echo", "hi"]):
            with self.subTest(args=args):
                self.load_config.reset_mock()
                self.assertEqual(self.invoke(args)[0], 1)
                self.load_config.assert_not_called()

    @unittest.skipUnless(shutil.which("bash"), "需要 Bash")
    def test_file_option_inside_inline_command_is_not_parsed(self):
        with mock.patch.object(mux, "jump_exec", side_effect=self.local_jump):
            self.assertEqual(self.invoke(["direct", "printf '%s\\n'", "--file", "example"]),
                             (0, "--file\nexample\n", ""))

    @unittest.skipUnless(shutil.which("bash"), "需要 Bash")
    def test_exit_and_directory_changes_do_not_close_or_change_session(self):
        session = mux.PtySession([(["bash", "--noprofile", "--norc", "-i"], [])], lambda _: None)
        self.addCleanup(session.close)
        session.start()
        original = session.exec("pwd", 3)
        self.file.write_text("cd " + shlex.quote(str(self.root)) +
                             "\nMUX_FILE_TEST=changed\nprintf 'done\\n'\nexit 7\n", encoding="utf-8")
        self.assertEqual(session.exec(mux.read_command_file(str(self.file)), 3), ("done\n", 7))
        self.assertEqual(session.exec("pwd", 3), original)
        self.assertEqual(session.exec("printf '%s\\n' \"${MUX_FILE_TEST-unset}\"", 3), ("unset\n", 0))

    @unittest.skipUnless(shutil.which("bash") and shutil.which("awk"), "需要 Bash 和 awk")
    def test_multiline_file_preserves_literal_tabs(self):
        self.file.write_text("# comment\n" * 1000 +
                             "awk '{print $2}' <<'DATA'\nx\t42\nDATA\n", encoding="utf-8")
        session = mux.PtySession([(["bash", "--noprofile", "--norc", "-i"], [])], lambda _: None)
        self.addCleanup(session.close)
        session.start()
        self.assertEqual(session.exec(mux.read_command_file(str(self.file)), 5), ("42\n", 0))

    @unittest.skipUnless(shutil.which("bash"), "需要 Bash")
    def test_long_unicode_line_survives_terminal_transport(self):
        value = "文字 ' $ \\ end_" * 400
        self.file.write_text("printf '%s\\n' " + shlex.quote(value), encoding="utf-8")
        session = mux.PtySession([(["bash", "--noprofile", "--norc", "-i"], [])], lambda _: None)
        self.addCleanup(session.close)
        session.start()
        self.assertEqual(session.exec(mux.read_command_file(str(self.file)), 5), (value + "\n", 0))

    @unittest.skipUnless(shutil.which("bash"), "需要 Bash")
    def test_transport_timeout_does_not_execute_script(self):
        marker = self.root / "should-not-exist"
        self.file.write_text("printf executed > " + shlex.quote(str(marker)), encoding="utf-8")
        session = mux.PtySession([(["bash", "--noprofile", "--norc", "-i"], [])], lambda _: None)
        self.addCleanup(session.close)
        session.start()
        with mock.patch.object(session, "_wait_for", side_effect=TimeoutError("missing acknowledgement")):
            with self.assertRaisesRegex(TimeoutError, "尚未执行"):
                session.exec(mux.read_command_file(str(self.file)), 3)
        self.assertFalse(marker.exists())
        self.assertIsNone(session.master)


if __name__ == "__main__":
    unittest.main()
