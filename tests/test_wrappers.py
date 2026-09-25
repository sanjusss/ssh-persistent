"""Exercise the POSIX launcher with simulated Windows and WSL commands."""

import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).resolve().parents[1]


class WindowsWrapperTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory(prefix="ssh-mux-wrapper-test-")
        self.addCleanup(self.tmp.cleanup)
        self.bin = Path(self.tmp.name)
        self.env = dict(os.environ)
        self.env["PATH"] = str(self.bin) + os.pathsep + self.env["PATH"]
        self.env["TEST_WINDOWS_CWD"] = r"C:\work area"
        self.env["TEST_WSL_ROOT"] = "/drives"
        self.write_command("uname", "print('MINGW64_NT-10.0')\n")
        self.write_command("cygpath", r'''
import ntpath
import os
import sys

path = sys.argv[-1]
if not path:
    sys.exit(1)
if path.startswith('/'):
    path = 'C:/msys64' + path
if not ntpath.isabs(path):
    path = ntpath.join(os.environ['TEST_WINDOWS_CWD'], path)
print(ntpath.normpath(path))
''')
        self.write_command("wsl.exe", r'''
import json
import os
import sys

args = sys.argv[1:]
if args[:3] == ['-e', 'wslpath', '-a']:
    path = args[3]
    if path.endswith('/fail-mapping'):
        sys.exit(1)
    assert os.environ['MSYS_NO_PATHCONV'] == '1'
    assert os.environ['MSYS2_ARG_CONV_EXCL'] == '*'
    assert path[1:3] == ':/'
    print(os.environ['TEST_WSL_ROOT'] + '/' + path[0].lower() + path[2:])
elif len(args) > 2 and args[:2] == ['-e', 'python3'] and args[2] != '-c':
    assert os.environ['MSYS_NO_PATHCONV'] == '1'
    assert os.environ['MSYS2_ARG_CONV_EXCL'] == '*'
    print(json.dumps(args[3:]))
''')

    def write_command(self, name, source):
        path = self.bin / name
        path.write_text("#!" + sys.executable + "\n" + source)
        path.chmod(0o755)

    def launch(self, *args):
        return subprocess.run(
            ["/bin/sh", str(ROOT / "ssh-mux.sh"), *args],
            env=self.env, text=True, capture_output=True, timeout=10,
        )

    def forwarded(self, *args):
        result = self.launch(*args)
        self.assertEqual(result.returncode, 0, result.stderr)
        return json.loads(result.stdout)

    def test_push_resolves_relative_windows_and_posix_paths(self):
        for path in (r".\app.tar.gz", "./app.tar.gz", "app.tar.gz"):
            with self.subTest(path=path):
                self.assertEqual(
                    self.forwarded("push", "db", path, "/tmp/"),
                    ["push", "db", "/drives/c/work area/app.tar.gz", "/tmp/"],
                )

    def test_pull_resolves_relative_directory_and_preserves_remote_path(self):
        self.assertEqual(
            self.forwarded("pull", "db", "C:/remote/path", ".\\logs\\"),
            ["pull", "db", "C:/remote/path", "/drives/c/work area/logs"],
        )

    def test_absolute_paths_use_wsl_mount_mapping(self):
        for path, expected in (
            (r"D:\file with spaces.txt", "/drives/d/file with spaces.txt"),
            ("/tmp/file.txt", "/drives/c/msys64/tmp/file.txt"),
            ("C:\\", "/drives/c/"),
        ):
            with self.subTest(path=path):
                self.assertEqual(
                    self.forwarded("push", "db", path, "/tmp/")[2], expected,
                )

    def test_options_do_not_shift_local_path_position(self):
        self.assertEqual(
            self.forwarded(
                "push", "--session", "case-1", "db", "--timeout=30",
                r".\input.txt", r"/tmp/remote\path",
            ),
            ["push", "--session", "case-1", "db", "--timeout=30",
             "/drives/c/work area/input.txt", r"/tmp/remote\path"],
        )
        self.assertEqual(
            self.forwarded(
                "pull", "--timeout", "30", "db", "/tmp/input",
                "--session=case-1", r".\output.txt",
            ),
            ["pull", "--timeout", "30", "db", "/tmp/input",
             "--session=case-1", "/drives/c/work area/output.txt"],
        )

    def test_end_of_options_allows_local_path_starting_with_dash(self):
        self.assertEqual(
            self.forwarded("push", "db", "--", "-input.txt", "--timeout"),
            ["push", "db", "--", "/drives/c/work area/-input.txt", "--timeout"],
        )

    def test_transport_option_preserves_path_positions(self):
        self.assertEqual(
            self.forwarded("push", "--transport", "base64", "db", r".\file", "/tmp/"),
            ["push", "--transport", "base64", "db", "/drives/c/work area/file", "/tmp/"],
        )
        self.assertEqual(
            self.forwarded("push", "--transport", "hybrid", "--leg", "A:B=base64", "db", r".\file", "/tmp/", "--plan"),
            ["push", "--transport", "hybrid", "--leg", "A:B=base64", "db", "/drives/c/work area/file", "/tmp/", "--plan"],
        )
        self.assertEqual(
            self.forwarded("pull", "db", "--transport=octal", "/tmp/file", r".\file"),
            ["pull", "db", "--transport=octal", "/tmp/file", "/drives/c/work area/file"],
        )

    def test_mapping_failure_stops_before_python(self):
        result = self.launch("push", "db", "fail-mapping", "/tmp/")
        self.assertNotEqual(result.returncode, 0)
        self.assertEqual(result.stdout, "")

    def test_unc_paths_are_rejected(self):
        for path in (r"\\server\share\file", "//server/share/file"):
            with self.subTest(path=path):
                result = self.launch("push", "db", path, "/tmp/")
                self.assertNotEqual(result.returncode, 0)
                self.assertEqual(result.stdout, "")

    def test_non_transfer_arguments_are_unchanged(self):
        command = r"printf '%s' C:\remote\file"
        self.assertEqual(
            self.forwarded("exec", "db", command), ["exec", "db", command],
        )

    def test_exec_file_maps_relative_absolute_and_equals_paths(self):
        for flag in ("--file", "-f"):
            self.assertEqual(
                self.forwarded("exec", "db", flag, r".\awk script.sh"),
                ["exec", "db", flag, "/drives/c/work area/awk script.sh"],
            )
        self.assertEqual(
            self.forwarded("exec", "db", r"--file=D:\scripts\check.sh"),
            ["exec", "db", "--file=/drives/d/scripts/check.sh"],
        )

    def test_exec_file_options_can_precede_alias(self):
        self.assertEqual(
            self.forwarded("exec", "--file", r".\check.sh", "--session", "case1",
                           "db", "--timeout=30"),
            ["exec", "--file", "/drives/c/work area/check.sh", "--session", "case1",
             "db", "--timeout=30"],
        )

    def test_exec_standard_input_is_not_a_path(self):
        self.assertEqual(self.forwarded("exec", "db", "--file", "-"),
                         ["exec", "db", "--file", "-"])
        self.assertEqual(self.forwarded("exec", "db", "--file=-"),
                         ["exec", "db", "--file=-"])

    def test_exec_inline_file_arguments_are_not_mapped(self):
        for args in (("exec", "db", "awk", "--file", r"C:\remote\a.awk"),
                     ("exec", "db", "--", "--file", r".\remote.sh")):
            self.assertEqual(self.forwarded(*args), list(args))

    def test_exec_file_mapping_errors_and_missing_values(self):
        for args in (("exec", "db", "--file"), ("exec", "db", "--file="),
                     ("exec", "db", "--file", "fail-mapping")):
            result = self.launch(*args)
            self.assertNotEqual(result.returncode, 0)
            self.assertEqual(result.stdout, "")


if __name__ == "__main__":
    unittest.main()
