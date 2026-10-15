"""语法兼容性守卫：发布的五个文件必须能用 Python 3.7 的语法规则解析。

括号式多上下文 `with (...)`、海象赋值等 3.8+ 语法会在目标平台上直接
SyntaxError；本测试在开发机上用 ast 的 feature_version 提前拦截。
"""

import ast
from pathlib import Path
import unittest

ROOT = Path(__file__).resolve().parents[1]

SHIPPED = ["ssh-mux.py", "ssh_hybrid.py", "ssh_pty.py", "ssh_worker.py", "ssh_proxy.py"]


class Py37GrammarTests(unittest.TestCase):
    def test_shipped_files_parse_with_37_grammar(self):
        for name in SHIPPED:
            source = (ROOT / name).read_text(encoding="utf-8")
            try:
                ast.parse(source, filename=name, feature_version=(3, 7))
            except SyntaxError as exc:
                self.fail(f"{name} 含 Python 3.8+ 语法: {exc}")


if __name__ == "__main__":
    unittest.main()
