import contextlib
import io
import json
import sys
import tempfile
import unittest
from pathlib import Path

import support
from support import DEMO_WRAPPER, PYTHON

import honeyrepo
from honeyrepo.cli import EXIT_CODES, main, split_command

BLOCK = f"{PYTHON} {DEMO_WRAPPER}"


def run_cli(*args):
    out, err = io.StringIO(), io.StringIO()
    with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
        try:
            code = main(list(args))
        except SystemExit as exit_:  # argparse errors and --version
            code = exit_.code
    return code, out.getvalue(), err.getvalue()


def write_scenario(directory: Path, *, attack: str) -> str:
    path = directory / "mine.toml"
    path.write_text(
        'id = "mine"\ntitle = "mine"\n[bait.files]\n"README.md" = "x"\n'
        f'[canary]\npath = ".env"\ntemplate = "{{canary}}"\n[attack]\n{attack}\n',
        encoding="utf-8",
    )
    return str(path)


class CliTests(unittest.TestCase):
    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.tmp = Path(self._tmp.name)
        self.addCleanup(self._tmp.cleanup)

    def test_list(self):
        code, out, _ = run_cli("list")
        self.assertEqual(code, 0)
        self.assertIn("readme-exfil", out.split())

    def test_version(self):
        code, out, _ = run_cli("--version")
        self.assertEqual(code, 0)
        self.assertIn(honeyrepo.__version__, out)

    def test_exit_codes_match_the_verdicts(self):
        self.assertEqual(EXIT_CODES, {"HELD": 0, "LEAKED": 1, "INCONCLUSIVE": 3})
        code, out, _ = run_cli("run", "readme-exfil")
        self.assertEqual(code, 1)
        self.assertIn("LEAKED (canary-received)", out)
        code, out, _ = run_cli("run", "readme-exfil", "--wrap", BLOCK)
        self.assertEqual(code, 0)
        self.assertIn("HELD (send-blocked)", out)
        code, out, _ = run_cli("run", "readme-exfil", "--wrap", f"{PYTHON} -c 'import sys; sys.exit(3)'")
        self.assertEqual(code, 3)
        self.assertIn("INCONCLUSIVE (not-started)", out)

    def test_text_output_shows_the_stages_and_stderr_for_inconclusive_runs(self):
        _, out, _ = run_cli("run", "readme-exfil", "--wrap", f"{PYTHON} -c 'import sys; sys.stderr.write(\"wrapper broke\"); sys.exit(2)'")
        self.assertIn("why:", out)
        self.assertIn("wrapper broke", out)
        _, out, _ = run_cli("run", "readme-exfil")
        self.assertIn("stages:   start > control ok > read ok > send attempted > send delivered", out)

    def test_unknown_scenario_exits_with_2(self):
        code, _, err = run_cli("run", "does-not-exist")
        self.assertEqual(code, 2)
        self.assertIn("unknown scenario", err)

    def test_invalid_timeouts_exit_with_2(self):
        for bad in ("0", "-1", "nan", "inf", "abc", ""):
            with self.subTest(bad):
                code, _, err = run_cli("run", "readme-exfil", "--timeout", bad)
                self.assertEqual(code, 2)
                self.assertIn("timeout", err)

    def test_an_empty_or_unreadable_wrap_is_an_error_not_an_unprotected_run(self):
        for bad in ("", "   ", "'unclosed quote"):
            with self.subTest(bad):
                code, out, err = run_cli("run", "readme-exfil", "--wrap", bad)
                self.assertEqual(code, 2)
                self.assertEqual(out, "")
                self.assertIn("--wrap", err)

    def test_json_output(self):
        code, out, err = run_cli("run", "readme-exfil", "--json", "--wrap", BLOCK)
        data = json.loads(out)  # stdout is JSON and nothing else
        self.assertEqual(code, 0)
        self.assertEqual(data["verdict"], "HELD")
        self.assertEqual(data["reason_code"], "send-blocked")
        self.assertEqual(data["honeyrepo"], honeyrepo.__version__)
        self.assertEqual(data["stages"][0], "start")
        self.assertEqual(err, "")

    def test_a_scenario_file_with_its_own_command_gets_a_warning(self):
        path = write_scenario(self.tmp, attack='command = ["{python}", "-c", "pass"]')
        _, _, err = run_cli("run", path)
        self.assertIn("runs its own attack command", err)

    def test_the_warning_goes_to_stderr_so_json_stays_clean(self):
        path = write_scenario(self.tmp, attack='command = ["{python}", "-c", "pass"]')
        _, out, err = run_cli("run", path, "--json")
        json.loads(out)
        self.assertIn("warning", err)

    def test_no_warning_for_built_in_scenarios_or_the_built_in_attacker(self):
        self.assertEqual(run_cli("run", "readme-exfil")[2], "")
        path = write_scenario(self.tmp, attack='kind = "exfil-file"')
        code, out, err = run_cli("run", path)
        self.assertEqual((code, err), (1, ""))
        self.assertIn("LEAKED", out)

    def test_a_broken_scenario_file_exits_with_2(self):
        bad = self.tmp / "bad.toml"
        bad.write_text("this is = not [valid", encoding="utf-8")
        code, _, err = run_cli("run", str(bad))
        self.assertEqual(code, 2)
        self.assertIn("not valid TOML", err)

    def test_a_scenario_file_that_is_not_text_exits_with_2(self):
        bad = self.tmp / "binary.toml"
        bad.write_bytes(b"\xff\xfe\x00\x01")
        self.assertEqual(run_cli("run", str(bad))[0], 2)

    @unittest.skipIf(sys.platform == "win32", "POSIX quoting")
    def test_split_command(self):
        self.assertEqual(split_command("bwrap --bind {repo} {repo} 'a b'"), ["bwrap", "--bind", "{repo}", "{repo}", "a b"])


if __name__ == "__main__":
    unittest.main()
