#!/usr/bin/env python3
"""Regression tests for the install.py fixes in this pass.

One test per finding: reverting the matching fix must fail the test.
Hermetic — no network, no real HOME, no real codex/devin.

    .venv/bin/python -m unittest tests.test_install_fixes -v
"""
import contextlib
import io
import os
import subprocess
import sys
import tempfile
try:
    import tomllib
except ImportError:  # Python 3.10, tests only
    import tomli as tomllib
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import install


class CodexProfileEscapingTests(unittest.TestCase):
    """L3: paths pasted into TOML must be escaped, not just interpolated."""

    def test_nasty_market_path_produces_parseable_toml(self):
        with tempfile.TemporaryDirectory(suffix='-quote"back\\slash') as base:
            os.makedirs(os.path.join(base, "codex", "marketplace"))
            with tempfile.TemporaryDirectory() as home:
                fake_run = mock.Mock(
                    return_value=subprocess.CompletedProcess([], 0, "", ""))
                with mock.patch.object(install, "HERE", base), \
                     mock.patch.object(install.shutil, "which", return_value="/usr/bin/codex"), \
                     mock.patch.object(install.subprocess, "run", fake_run), \
                     mock.patch.dict(os.environ, {"CODEX_HOME": home}, clear=False), \
                     contextlib.redirect_stdout(io.StringIO()):
                    install.install_codex(force=True)

                profile = os.path.join(home, "devinx.config.toml")
                with open(profile, encoding="utf-8") as fh:
                    text = fh.read()
                parsed = tomllib.loads(text)
                self.assertEqual(parsed["marketplaces"]["devinx"]["source"],
                                 os.path.join(base, "codex", "marketplace"))

                # The -c override handed to `codex plugin add` must round-trip
                # through the same escaping, not a second, unescaped copy.
                argv = fake_run.call_args.args[0]
                source_arg = next(a for a in argv
                                  if a.startswith("marketplaces.devinx.source="))
                self.assertEqual(
                    tomllib.loads(source_arg)["marketplaces"]["devinx"]["source"],
                    os.path.join(base, "codex", "marketplace"))


class ShadowDetectionTests(unittest.TestCase):
    """L7: the regex must actually distinguish "shadows and delegates" from
    "shadows and never runs" — checking for the literal name it just matched
    is tautological and can never fire the warning."""

    def _run(self, rc_body):
        with tempfile.TemporaryDirectory() as home:
            with open(os.path.join(home, ".bashrc"), "w", encoding="utf-8") as fh:
                fh.write(rc_body)
            stdout = io.StringIO()
            with mock.patch.dict(os.environ, {"HOME": home}, clear=False), \
                 mock.patch.object(install.shutil, "which", return_value=None), \
                 contextlib.redirect_stdout(stdout):
                install.warn_shadowed("/usr/local/bin/devinx")
            return stdout.getvalue()

    def test_a_shadowing_function_that_does_not_delegate_warns(self):
        out = self._run("devinx() { echo not really devinx here; }\n")
        self.assertIn("[warn]", out)
        self.assertIn("never run", out)

    def test_a_shadowing_function_that_delegates_is_fine(self):
        out = self._run(
            'devinx() { exec ~/devinx/.venv/bin/python ~/devinx/launcher.py "$@"; }\n')
        self.assertIn("[ ok ]", out)
        self.assertNotIn("[warn]", out)

    def test_a_shadowing_alias_that_does_not_delegate_warns(self):
        out = self._run("alias devinx='echo hi'\n")
        self.assertIn("[warn]", out)


class ForceVenvRefusalTests(unittest.TestCase):
    """L9: --force must refuse to clear the venv of a running daemon."""

    def test_force_refuses_when_a_service_is_running_on_the_port(self):
        with mock.patch.object(install, "_running_service",
                               return_value={"pid": 4242}), \
             contextlib.redirect_stdout(io.StringIO()):
            with self.assertRaises(SystemExit):
                install.make_venv(True, 8316)

    def test_force_proceeds_past_the_guard_when_nothing_is_running(self):
        # Force it to fail for an unrelated, later reason (no venv backend
        # available) rather than actually building a virtualenv here; the
        # point is that the running-service guard did not fire. Confirmed by
        # checking *which* die() message came out.
        stdout = io.StringIO()
        with mock.patch.object(install, "_running_service", return_value=None), \
             mock.patch.object(install, "has_ensurepip", return_value=False), \
             mock.patch.object(install.shutil, "which", return_value=None), \
             contextlib.redirect_stdout(stdout):
            with self.assertRaises(SystemExit):
                install.make_venv(True, 8316)
        self.assertIn("cannot create a virtualenv", stdout.getvalue())
        self.assertNotIn("already running", stdout.getvalue())


class SmokeHardeningTests(unittest.TestCase):
    """L9: smoke() must not end in a traceback, and must isolate its
    dashboard listener."""

    def test_dashboard_port_is_disabled_for_the_smoke_instance(self):
        fake_popen = mock.Mock()
        fake_popen.return_value.poll.return_value = None
        with tempfile.TemporaryDirectory() as data:
            with mock.patch.object(install, "data_dir", return_value=data), \
                 mock.patch.object(install, "free_port", return_value=54321), \
                 mock.patch.object(install.subprocess, "Popen", fake_popen), \
                 mock.patch.object(install, "die", side_effect=SystemExit(1)) as die, \
                 mock.patch("socket.socket") as sock_cls:
                sock = sock_cls.return_value.__enter__.return_value
                sock.connect_ex.return_value = 0  # "port open" on first probe
                with mock.patch.object(install.urllib.request, "urlopen",
                                       side_effect=install.urllib.error.URLError("boom")):
                    with self.assertRaises(SystemExit):
                        install.smoke("py", have_credential=False)
        env = fake_popen.call_args.kwargs["env"]
        self.assertEqual(env["DEVINX_DASHBOARD_PORT"], "0")
        die.assert_called_once()
        self.assertIn("could not reach", die.call_args.args[0])

    def test_http_error_is_reported_not_raised(self):
        import urllib.error
        fake_popen = mock.Mock()
        fake_popen.return_value.poll.return_value = None
        with tempfile.TemporaryDirectory() as data:
            with mock.patch.object(install, "data_dir", return_value=data), \
                 mock.patch.object(install, "free_port", return_value=54322), \
                 mock.patch.object(install.subprocess, "Popen", fake_popen), \
                 mock.patch.object(install, "die", side_effect=SystemExit(1)) as die, \
                 mock.patch("socket.socket") as sock_cls:
                sock = sock_cls.return_value.__enter__.return_value
                sock.connect_ex.return_value = 0
                err = urllib.error.HTTPError("u", 500, "boom", {}, io.BytesIO(b"server exploded"))
                with mock.patch.object(install.urllib.request, "urlopen", side_effect=err):
                    with self.assertRaises(SystemExit):
                        install.smoke("py", have_credential=False)
        die.assert_called_once()
        self.assertIn("HTTP 500", die.call_args.args[0])


if __name__ == "__main__":
    unittest.main()
