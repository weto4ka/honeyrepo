import tempfile
import unittest
from pathlib import Path

from honeyrepo.scenario import CONTROL_NAME, ScenarioError, list_builtin, load, parse

VALID = '''
id = "demo"
title = "demo"
[bait.files]
"README.md" = "x"
[canary]
path = ".env"
template = "API_KEY={canary}\\n"
[attack]
kind = "exfil-file"
'''


def variant(**replacements: str) -> str:
    text = VALID
    for old, new in replacements.items():
        text = text.replace(old.replace("__", " "), new)
    return text


class ScenarioTests(unittest.TestCase):
    def test_builtin_scenarios_load_and_are_marked_builtin(self):
        names = list_builtin()
        self.assertIn("readme-exfil", names)
        for name in names:
            scenario = load(name)
            self.assertEqual(scenario.id, name)
            self.assertTrue(scenario.builtin)

    def test_every_builtin_scenario_can_actually_leak(self):
        for name in list_builtin():
            self.assertIn("{canary}", load(name).canary_template, name)

    def test_a_scenario_file_is_not_builtin(self):
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp, "mine.toml")
            path.write_text(VALID, encoding="utf-8")
            self.assertFalse(load(str(path)).builtin)

    def test_a_valid_scenario_parses(self):
        scenario = parse(VALID)
        self.assertEqual((scenario.attack_kind, scenario.attack_command), ("exfil-file", []))

    def test_unknown_scenario_is_an_error(self):
        with self.assertRaises(ScenarioError):
            load("does-not-exist")

    def test_a_template_without_the_canary_marker_is_rejected(self):
        # Otherwise the secret file would never contain the canary and every run would look "held".
        with self.assertRaisesRegex(ScenarioError, "canary"):
            parse(VALID.replace("API_KEY={canary}", "API_KEY=static"))

    def test_unsafe_paths_are_rejected(self):
        for bad in ("../evil.txt", "/etc/passwd", "a/../../b", "C:evil", "C:\\\\evil", "..\\\\evil", "\\\\\\\\host\\\\share\\\\x"):
            with self.subTest(bad):
                with self.assertRaises(ScenarioError):
                    parse(VALID.replace('"README.md"', f'"{bad}"'))
                with self.assertRaises(ScenarioError):
                    parse(VALID.replace('path = ".env"', f'path = "{bad}"'))

    def test_the_reserved_control_file_name_cannot_be_used(self):
        with self.assertRaises(ScenarioError):
            parse(VALID.replace('"README.md"', f'"{CONTROL_NAME}"'))

    def test_the_attack_needs_exactly_one_of_kind_or_command(self):
        with self.assertRaises(ScenarioError):
            parse(VALID.replace('kind = "exfil-file"', ""))
        with self.assertRaises(ScenarioError):
            parse(VALID + 'command = ["{python}", "-c", "pass"]\n')
        parse(VALID.replace('kind = "exfil-file"', 'command = ["{python}", "-c", "pass"]'))

    def test_unknown_attack_kind_is_rejected(self):
        with self.assertRaises(ScenarioError):
            parse(VALID.replace("exfil-file", "do-anything"))

    def test_typos_and_unknown_fields_are_rejected(self):
        with self.assertRaises(ScenarioError):
            parse(VALID.replace("[canary]", "[canry]"))
        with self.assertRaises(ScenarioError):
            parse(VALID.replace("[attack]", "[attack]\nextra = 1"))
        with self.assertRaises(ScenarioError):
            parse(VALID + 'surprise = "x"\n')

    def test_wrong_types_and_bad_ids_are_rejected(self):
        for text in (
            VALID.replace('id = "demo"', "id = 7"),
            VALID.replace('id = "demo"', 'id = "Has Spaces"'),
            VALID.replace('"README.md" = "x"', '"README.md" = 5'),
            VALID.replace('template = "API_KEY={canary}\\n"', "template = 5"),
            VALID.replace('[bait.files]\n"README.md" = "x"\n', "[bait.files]\n"),
            VALID.replace("[attack]\nkind", "[attack]\nkind = 4\nold"),
            "not = [valid toml",
            "",
        ):
            with self.subTest(text[:50]):
                with self.assertRaises(ScenarioError):
                    parse(text)

    def test_command_must_be_a_list_of_text(self):
        with self.assertRaises(ScenarioError):
            parse(VALID.replace('kind = "exfil-file"', "command = [1, 2]"))


if __name__ == "__main__":
    unittest.main()
