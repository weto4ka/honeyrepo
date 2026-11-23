"""Package-level checks: packaging, supported Python versions and claims the docs make."""

import ast
import os
import subprocess
import sys
import tomllib
import unittest

import support

import honeyrepo


class PackagingTests(unittest.TestCase):
    def pyproject(self):
        return tomllib.loads((support.ROOT / "pyproject.toml").read_text(encoding="utf-8"))

    def test_version_matches_pyproject(self):
        self.assertEqual(self.pyproject()["project"]["version"], honeyrepo.__version__)

    def test_there_are_no_dependencies(self):
        self.assertEqual(self.pyproject()["project"]["dependencies"], [])

    def test_the_minimum_python_matches_the_guard(self):
        needed = self.pyproject()["project"]["requires-python"]
        self.assertEqual(needed, ">=" + ".".join(map(str, honeyrepo.MIN_PYTHON)))

    def test_only_the_standard_library_is_imported(self):
        # Backs the README's "no dependencies" claim, and keeps attacker.py runnable inside a sandbox.
        for path in sorted(support.SRC.glob("*.py")):
            tree = ast.parse(path.read_text(encoding="utf-8"))
            for node in ast.walk(tree):
                names = []
                if isinstance(node, ast.Import):
                    names = [alias.name for alias in node.names]
                elif isinstance(node, ast.ImportFrom) and node.level == 0 and node.module:
                    names = [node.module]
                for name in names:
                    top = name.split(".")[0]
                    self.assertTrue(
                        top in sys.stdlib_module_names or top == "honeyrepo",
                        f"{path.name} imports {name}, which is not in the standard library",
                    )

    def test_the_attacker_imports_nothing_from_honeyrepo(self):
        tree = ast.parse((support.SRC / "attacker.py").read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            if isinstance(node, (ast.Import, ast.ImportFrom)):
                module = getattr(node, "module", None) or ""
                names = [alias.name for alias in node.names] + [module]
                self.assertFalse(any(name.split(".")[0] == "honeyrepo" for name in names))

    def test_scenarios_are_shipped_as_package_data(self):
        package_data = self.pyproject()["tool"]["setuptools"]["package-data"]["honeyrepo"]
        self.assertIn("scenarios/*.toml", package_data)


class PythonVersionTests(unittest.TestCase):
    def test_old_pythons_get_a_clear_message(self):
        for old in ((3, 10, 14), (3, 9, 0), (2, 7, 18)):
            with self.subTest(old):
                with self.assertRaises(SystemExit) as caught:
                    honeyrepo.check_python(old)
                self.assertIn("needs Python 3.11", str(caught.exception))
                self.assertIn(".".join(map(str, old)), str(caught.exception))

    def test_supported_pythons_pass(self):
        for fine in ((3, 11, 0), (3, 12, 4), (3, 13, 1), (4, 0, 0)):
            honeyrepo.check_python(fine)

    def test_running_as_a_module_works(self):
        env = dict(os.environ, PYTHONPATH=str(support.SRC.parent))
        done = subprocess.run(
            [sys.executable, "-m", "honeyrepo", "--version"], capture_output=True, text=True, env=env, timeout=30
        )
        self.assertEqual(done.returncode, 0, done.stderr)
        self.assertIn(honeyrepo.__version__, done.stdout)


class DocumentationTests(unittest.TestCase):
    """The docs must describe the code that exists, not an earlier version."""

    def read(self, *parts):
        return (support.ROOT.joinpath(*parts)).read_text(encoding="utf-8")

    def test_readme_documents_every_exit_code(self):
        from honeyrepo.cli import EXIT_CODES

        readme = self.read("README.md")
        for verdict, code in EXIT_CODES.items():
            self.assertIn(f"| {verdict} | {code} |", readme)

    def test_documented_scenarios_exist(self):
        from honeyrepo.scenario import list_builtin

        self.assertIn("readme-exfil", list_builtin())
        self.assertIn("readme-exfil", self.read("README.md"))


if __name__ == "__main__":
    unittest.main()
