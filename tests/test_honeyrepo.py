import contextlib
import io
import os
import sys
import unittest
from pathlib import Path
from unittest import mock

import honeyrepo
from honeyrepo.cli import main
from honeyrepo.runner import attack_env, run_scripted
from honeyrepo.scenario import ScenarioError, list_builtin, load, parse

DEMO_WRAPPER = Path(honeyrepo.__file__).with_name("demo_block_network.py")

UNSAFE_SCENARIO = '''
id = "x"
title = "x"
[bait.files]
"../evil.txt" = "x"
[canary]
path = ".env"
template = "{canary}"
[attack]
command = ["{python}", "-c", "pass"]
'''


class ScenarioTests(unittest.TestCase):
    def test_builtin_scenarios_load(self):
        names = list_builtin()
        self.assertIn("readme-exfil", names)
        for name in names:
            self.assertEqual(load(name).id, name)

    def test_paths_that_escape_the_temp_directory_are_rejected(self):
        with self.assertRaises(ScenarioError):
            parse(UNSAFE_SCENARIO)

    def test_unknown_scenario_is_an_error(self):
        with self.assertRaises(ScenarioError):
            load("does-not-exist")


class RunnerTests(unittest.TestCase):
    def test_unprotected_attack_leaks_the_canary(self):
        result = run_scripted(load("readme-exfil"))
        self.assertEqual(result.verdict, "LEAKED")
        self.assertGreaterEqual(result.hits, 1)

    def test_blocking_wrapper_holds(self):
        result = run_scripted(load("readme-exfil"), wrap=[sys.executable, str(DEMO_WRAPPER)])
        self.assertEqual(result.verdict, "HELD")

    def test_wrapper_that_never_starts_the_attack_is_inconclusive_not_held(self):
        result = run_scripted(
            load("readme-exfil"), wrap=[sys.executable, "-c", "import sys; sys.exit(3)"]
        )
        self.assertEqual(result.verdict, "INCONCLUSIVE")

    def test_real_environment_variables_do_not_reach_the_attack(self):
        with mock.patch.dict(os.environ, {"MY_API_KEY": "do-not-leak", "HTTPS_PROXY": "http://x"}):
            env = attack_env(Path("home"), "http://127.0.0.1:1")
        self.assertNotIn("MY_API_KEY", env)
        self.assertNotIn("HTTPS_PROXY", env)
        self.assertEqual(env["HONEYREPO_LISTENER"], "http://127.0.0.1:1")


class CliTests(unittest.TestCase):
    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = main(list(args))
        return code, out.getvalue(), err.getvalue()

    def test_list(self):
        code, out, _ = self.run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("readme-exfil", out)

    def test_leak_exits_with_1(self):
        code, out, _ = self.run_cli("run", "readme-exfil")
        self.assertEqual(code, 1)
        self.assertIn("LEAKED", out)

    def test_unknown_scenario_exits_with_2(self):
        code, _, err = self.run_cli("run", "does-not-exist")
        self.assertEqual(code, 2)
        self.assertIn("unknown scenario", err)


if __name__ == "__main__":
    unittest.main()
