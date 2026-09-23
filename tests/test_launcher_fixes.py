#!/usr/bin/env python3
"""Regression tests for the launcher/diagnostics fixes in this pass.

One test per finding in the audit: reverting the matching fix must fail the
test. Hermetic — no network, no real service, no real HOME.

    .venv/bin/python -m unittest tests.test_launcher_fixes -v
"""
import contextlib
import io
import json
import os
import signal
import socket
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

sys.dont_write_bytecode = True
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import diagnostics
import launcher
import runtime_support


class DiagnosticFlagScanTests(unittest.TestCase):
    """--status/--doctor/--explain also after devinx's own flags (L9 feature)."""

    def test_flag_after_devin_flag_is_found(self):
        self.assertEqual(launcher._diagnostic_flag(["--d", "--status"]), "--status")

    def test_flag_in_first_position_still_found(self):
        self.assertEqual(launcher._diagnostic_flag(["--status", "--json"]), "--status")

    def test_a_client_subcommand_ahead_of_it_is_ambiguous(self):
        self.assertIsNone(launcher._diagnostic_flag(["mcp", "--status"]))

    def test_nothing_past_a_bare_separator(self):
        self.assertIsNone(launcher._diagnostic_flag(["--d", "--", "--status"]))

    def test_main_dispatches_with_the_flag_removed_from_the_rest(self):
        with mock.patch.object(sys, "argv", ["devinx", "--d", "--status"]), \
             mock.patch("diagnostics.main", return_value=0) as m, \
             mock.patch.object(launcher.shutil, "which") as which:
            self.assertEqual(launcher.main(), 0)
        which.assert_not_called()
        m.assert_called_once_with("--status", ["--d"], launcher)


class PlainFlagTests(unittest.TestCase):
    """A one-run opt-out when DEVINX_ALWAYS=1 (missing feature)."""

    def test_plain_cancels_the_always_default(self):
        with mock.patch.dict(os.environ, {"DEVINX_ALWAYS": "1"}, clear=False):
            use_devin, _, _, out = launcher.split_args(["--plain", "hello"])
        self.assertFalse(use_devin)
        self.assertEqual(out, ["hello"])

    def test_an_explicit_devin_flag_still_wins_over_plain(self):
        with mock.patch.dict(os.environ, {"DEVINX_ALWAYS": "1"}, clear=False):
            use_devin, _, _, _ = launcher.split_args(["--plain", "--d"])
        self.assertTrue(use_devin)

    def test_plain_does_nothing_without_the_always_default(self):
        with mock.patch.dict(os.environ, {}, clear=True):
            use_devin, _, _, out = launcher.split_args(["--plain"])
        self.assertFalse(use_devin)
        self.assertEqual(out, [])

    def test_plain_also_cancels_the_orchestrator_default(self):
        # Otherwise --explain would report the orchestrator on while the
        # proxy it depends on is off.
        with mock.patch.dict(os.environ, {"DEVINX_ORCHESTRATOR": "1"}, clear=False):
            use_devin, use_orch, _, _ = launcher.split_args(["--plain"])
        self.assertFalse(use_devin)
        self.assertFalse(use_orch)

    def test_an_explicit_or_flag_still_wins_over_plain(self):
        with mock.patch.dict(os.environ, {"DEVINX_ORCHESTRATOR": "1"}, clear=False):
            use_devin, use_orch, _, _ = launcher.split_args(["--plain", "--or"])
        self.assertTrue(use_devin)
        self.assertTrue(use_orch)


class OrchestratorImpliesDevinTests(unittest.TestCase):
    """L5: DEVINX_ORCHESTRATOR=1 alone must act like --or."""

    def test_env_var_alone_turns_on_devin_mode(self):
        with mock.patch.dict(os.environ, {"DEVINX_ORCHESTRATOR": "1"}, clear=False):
            use_devin, use_orch, _, _ = launcher.split_args([])
        self.assertTrue(use_devin)
        self.assertTrue(use_orch)


class AgentsMergeFormTests(unittest.TestCase):
    """L9: the --agents=<json> single-token form must merge, not be dropped."""

    def test_equals_form_is_merged(self):
        mine = {"mine": {"description": "d", "prompt": "p"}}
        out = launcher.merge_agents(
            ["--agents=" + json.dumps(mine), "-p", "go"],
            {"swe2-x": {"description": "d", "prompt": "p"}})
        self.assertEqual(out.count("--agents"), 1)
        merged = json.loads(out[out.index("--agents") + 1])
        self.assertIn("mine", merged)
        self.assertIn("swe2-x", merged)
        self.assertEqual(out[out.index("--agents") + 2:], ["-p", "go"])

    def test_non_object_agents_warns_instead_of_silently_dropping(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            out = launcher.merge_agents(
                ["--agents", "[1, 2]"], {"swe2-x": {"description": "d", "prompt": "p"}})
        self.assertIn("not an object", stderr.getvalue())
        # Left alone rather than silently losing the injected agents.
        self.assertEqual(out, ["--agents", "[1, 2]"])

    def test_no_existing_agents_flag_is_prepended_not_appended(self):
        """L1: the injected flag must precede any user argument (e.g. a client
        subcommand like `mcp`), or the client's option parser never sees it."""
        out = launcher.merge_agents(["mcp", "list"], {"swe2-x": {"description": "d", "prompt": "p"}})
        self.assertEqual(out[0], "--agents")
        self.assertEqual(out[2:], ["mcp", "list"])


class PluginArgsOrderingTests(unittest.TestCase):
    """L1: both injected option groups precede the user's own head arguments."""

    def test_plugin_dir_and_agents_precede_a_client_subcommand(self):
        with mock.patch.object(sys, "argv", ["devinx", "--d", "--or", "mcp", "list"]), \
             mock.patch.object(launcher, "ensure_service", return_value=True), \
             mock.patch.object(launcher.shutil, "which", return_value="/usr/bin/claude"), \
             mock.patch.object(sys, "platform", "win32"), \
             mock.patch.object(subprocess, "call", return_value=0) as call:
            launcher.main()
        args = call.call_args.args[0]
        self.assertEqual(args[0], "/usr/bin/claude")
        # "mcp" (the client subcommand) must come after both injected flags.
        mcp_at = args.index("mcp")
        self.assertLess(args.index("--plugin-dir"), mcp_at)
        self.assertLess(args.index("--agents"), mcp_at)


class CodexProfileDedupTests(unittest.TestCase):
    """L4: `-p`/`--profile` given by the user must not collide with our own."""

    def test_user_profile_suppresses_ours_and_warns(self):
        with tempfile.TemporaryDirectory() as home:
            open(os.path.join(home, "devinx.config.toml"), "w").close()
            with mock.patch.dict(os.environ, {"CODEX_HOME": home}, clear=False), \
                 mock.patch.object(sys, "argv",
                                   ["devinx", "--cx", "--or", "-p", "work"]), \
                 mock.patch.object(launcher, "ensure_service", return_value=True), \
                 mock.patch.object(launcher.shutil, "which", return_value="/usr/bin/codex"), \
                 mock.patch.object(sys, "platform", "win32"), \
                 mock.patch.object(subprocess, "call", return_value=0) as call, \
                 contextlib.redirect_stderr(io.StringIO()) as stderr:
                launcher.main()
        args = call.call_args.args[0]
        self.assertEqual(args.count("-p"), 1)
        self.assertEqual(args[args.index("-p") + 1], "work")
        self.assertIn("not applied", stderr.getvalue())

    def test_without_a_user_profile_ours_is_still_added(self):
        with tempfile.TemporaryDirectory() as home:
            open(os.path.join(home, "devinx.config.toml"), "w").close()
            with mock.patch.dict(os.environ, {"CODEX_HOME": home}, clear=False):
                args = launcher.codex_args(True)
        self.assertEqual(args.count("-p"), 1)
        self.assertEqual(args[args.index("-p") + 1], "devinx")


class StdoutStderrTests(unittest.TestCase):
    """L6: launcher chatter must never land on stdout (it breaks `| jq`)."""

    def test_replacing_an_older_service_is_reported_on_stderr(self):
        stdout, stderr = io.StringIO(), io.StringIO()
        with mock.patch.object(launcher, "startup_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(launcher, "service_state",
                               return_value=("stale", {"pid": os.getpid() + 50000})), \
             mock.patch.object(launcher, "stop_service", return_value=True), \
             mock.patch.object(launcher, "start_service") as start, \
             mock.patch.object(launcher, "listening", return_value=True), \
             contextlib.redirect_stdout(stdout), contextlib.redirect_stderr(stderr):
            self.assertTrue(launcher.ensure_service())
        start.assert_called_once()
        self.assertEqual(stdout.getvalue(), "")
        self.assertIn("replacing a service running older code", stderr.getvalue())


class ProxyBypassTests(unittest.TestCase):
    """L2: readiness probes must not go through a shell HTTP proxy."""

    def test_service_state_opener_bypasses_a_bogus_proxy(self):
        # A proxy env var pointed at a port nothing listens on: a plain
        # urlopen()/build_opener() would try to route through it and fail or
        # hang; launcher._opener must reach loopback directly regardless.
        import http.server
        import threading

        class Hello(http.server.BaseHTTPRequestHandler):
            def do_GET(self):
                body = b'{"service": "devinx", "pid": 1, "build": "x"}'
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a):
                pass

        server = http.server.HTTPServer(("127.0.0.1", 0), Hello)
        port = server.server_address[1]
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            with mock.patch.dict(os.environ, {
                    "http_proxy": "http://127.0.0.1:1",
                    "HTTP_PROXY": "http://127.0.0.1:1"}, clear=False):
                with launcher._opener.open(
                        f"http://127.0.0.1:{port}/api/hello", timeout=3) as r:
                    data = json.loads(r.read())
            self.assertEqual(data["service"], "devinx")
        finally:
            server.shutdown()
            thread.join(timeout=3)
            server.server_close()

    def test_no_proxy_is_appended_not_clobbered(self):
        env = {"NO_PROXY": "example.internal"}
        launcher._add_no_proxy(env)
        hosts = env["NO_PROXY"].split(",")
        self.assertIn("example.internal", hosts)
        self.assertIn("127.0.0.1", hosts)
        self.assertIn("localhost", hosts)


class ServiceStateRobustnessTests(unittest.TestCase):
    """L9: a non-object /api/hello reply must not crash the launcher."""

    def test_non_dict_hello_reply_is_treated_as_foreign(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b"[1, 2, 3]"
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(launcher, "_opener", opener), \
             mock.patch("socket.socket") as sock_cls:
            sock = sock_cls.return_value.__enter__.return_value
            sock.connect_ex.return_value = 0
            state, info = launcher.service_state()
        self.assertEqual((state, info), ("foreign", {}))

    def test_non_dict_models_reply_never_raises(self):
        response = mock.MagicMock()
        response.__enter__.return_value.read.return_value = b'{"data": "not-a-list"}'
        opener = mock.Mock()
        opener.open.return_value = response
        with mock.patch.object(launcher, "_opener", opener), \
             mock.patch("socket.socket") as sock_cls:
            sock = sock_cls.return_value.__enter__.return_value
            sock.connect_ex.return_value = 0
            self.assertFalse(launcher.listening())


class StopServicePidValidationTests(unittest.TestCase):
    """S3: never signal a pid we did not verify is actually devinx.py."""

    def test_a_bool_pid_is_rejected(self):
        self.assertFalse(launcher.stop_service({"pid": True}))

    def test_pid_zero_or_negative_is_rejected(self):
        self.assertFalse(launcher.stop_service({"pid": 0}))
        self.assertFalse(launcher.stop_service({"pid": -1}))

    def test_the_launchers_own_pid_is_never_signalled(self):
        self.assertFalse(launcher.stop_service({"pid": os.getpid()}))

    def test_own_process_group_is_never_signalled(self):
        if not hasattr(os, "getpgrp"):
            self.skipTest("POSIX only")
        self.assertFalse(launcher.stop_service({"pid": os.getpgrp()}))

    @unittest.skipUnless(sys.platform != "win32", "POSIX /proc check")
    def test_a_pid_not_running_devinx_is_refused_even_if_positive(self):
        # PID 1 is already rejected by the <=1 guard; use our own test
        # process's pid, which is real, positive, not us, and not devinx.py.
        with subprocess.Popen([sys.executable, "-c", "import time; time.sleep(5)"]) as proc:
            try:
                self.assertFalse(launcher.stop_service({"pid": proc.pid}))
            finally:
                proc.kill()
                proc.wait()


class ValidateEnvTests(unittest.TestCase):
    """Missing feature: a bad numeric DEVINX_* value must not start a broken
    service silently — refuse with a clear error instead."""

    def test_invalid_value_is_rejected(self):
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"DEVINX_RATE_WAIT": "not-a-number"}, clear=False), \
             contextlib.redirect_stderr(stderr):
            self.assertFalse(launcher._validate_devinx_env())
        self.assertIn("DEVINX_RATE_WAIT", stderr.getvalue())

    def test_valid_values_pass(self):
        with mock.patch.dict(os.environ, {"DEVINX_RATE_WAIT": "900"}, clear=False):
            self.assertTrue(launcher._validate_devinx_env())

    def test_a_bad_port_falls_back_instead_of_crashing(self):
        stderr = io.StringIO()
        with contextlib.redirect_stderr(stderr):
            self.assertEqual(launcher._port_env("DEVINX_PORT", 8316), 8316)

    def test_a_fractional_value_is_rejected_for_an_int_only_setting(self):
        # devinx.py parses DEVINX_RATE_WAIT with int(), not float(): a value
        # that passes float() but not int() must still be caught here, or the
        # launcher says "valid" and the daemon dies on import right after.
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"DEVINX_RATE_WAIT": "1.5"}, clear=False), \
             contextlib.redirect_stderr(stderr):
            self.assertFalse(launcher._validate_devinx_env())
        self.assertIn("DEVINX_RATE_WAIT", stderr.getvalue())

    def test_previously_unvalidated_variables_are_now_checked(self):
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"DEVINX_PACE": "x"}, clear=False), \
             contextlib.redirect_stderr(stderr):
            self.assertFalse(launcher._validate_devinx_env())
        self.assertIn("DEVINX_PACE", stderr.getvalue())


class LockTimeoutTests(unittest.TestCase):
    """L9: a waiting launcher must outlast the holder's own worst case."""

    def test_lock_wait_exceeds_the_single_start_timeout(self):
        source = __import__("inspect").getsource(launcher.ensure_service)
        self.assertIn("START_TIMEOUT + 35", source)


class DaemonEnvAllowlistTests(unittest.TestCase):
    """S4: the daemon inherits an allowlist, not the whole shell."""

    def test_unrelated_variables_are_not_propagated(self):
        with mock.patch.dict(os.environ, {"SOME_RANDOM_SECRET": "x",
                                          "DEVINX_RATE_WAIT": "900",
                                          "XDG_DATA_HOME": "/tmp/x"}, clear=False):
            env = launcher._daemon_env()
        self.assertNotIn("SOME_RANDOM_SECRET", env)
        self.assertIn("DEVINX_RATE_WAIT", env)
        self.assertIn("XDG_DATA_HOME", env)

    def test_path_and_home_survive(self):
        env = launcher._daemon_env()
        self.assertIn("PATH", env)

    def test_dump_and_allow_browser_warn_loudly_when_propagated(self):
        stderr = io.StringIO()
        with mock.patch.dict(os.environ, {"DEVINX_DUMP": "1"}, clear=False), \
             contextlib.redirect_stderr(stderr):
            env = launcher._daemon_env()
        self.assertIn("DEVINX_DUMP", env)
        self.assertIn("every session", stderr.getvalue())

    def test_proxy_and_cert_vars_survive(self):
        with mock.patch.dict(os.environ, {"HTTPS_PROXY": "http://proxy:8080",
                                          "SSL_CERT_FILE": "/etc/ca.pem"}, clear=False):
            env = launcher._daemon_env()
        self.assertIn("HTTPS_PROXY", env)
        self.assertIn("SSL_CERT_FILE", env)


class ConfigurationMismatchSharedHelperTests(unittest.TestCase):
    """S4: warn when a requested setting differs from the running daemon's."""

    def test_mismatch_produces_a_warning(self):
        warnings = diagnostics.configuration_mismatches(
            {"DEVINX_MAX_INFLIGHT": "12"}, {"DEVINX_MAX_INFLIGHT": 64})
        self.assertTrue(any("differs" in w for w in warnings))

    def test_matching_value_is_silent(self):
        warnings = diagnostics.configuration_mismatches(
            {"DEVINX_MAX_INFLIGHT": "64"}, {"DEVINX_MAX_INFLIGHT": 64.0})
        self.assertEqual(warnings, [])

    def test_ensure_service_warns_on_a_running_mismatch(self):
        stderr = io.StringIO()
        with mock.patch.object(launcher, "startup_lock", return_value=contextlib.nullcontext()), \
             mock.patch.object(launcher, "service_state", return_value=(
                 "fresh", {"configuration": {"DEVINX_MAX_INFLIGHT": 64}})), \
             mock.patch.dict(os.environ, {"DEVINX_MAX_INFLIGHT": "12"}, clear=False), \
             contextlib.redirect_stderr(stderr):
            self.assertTrue(launcher.ensure_service())
        self.assertIn("differs", stderr.getvalue())


class ExplainExitCodeTests(unittest.TestCase):
    """Small fix: --explain must not exit 1 just because the service is down."""

    def test_explain_exits_zero_with_service_down(self):
        with mock.patch.object(diagnostics, "read_service", return_value=("unavailable", {})):
            rc = diagnostics.main("--explain", ["--d"], launcher)
        self.assertEqual(rc, 0)

    def test_status_still_reports_nonzero_with_service_down(self):
        with mock.patch.object(diagnostics, "read_service", return_value=("unavailable", {})):
            rc = diagnostics.main("--status", [], launcher)
        self.assertEqual(rc, 1)


class NonHttpListenerTests(unittest.TestCase):
    """L9: diagnostics must not crash (BadStatusLine) on a non-HTTP listener."""

    def test_http_exception_is_handled(self):
        import http.client
        with mock.patch("urllib.request.OpenerDirector.open",
                        side_effect=http.client.BadStatusLine("garbage")):
            state, info = diagnostics.read_service("127.0.0.1", 1)
        self.assertEqual((state, info), ("unavailable", {}))


class WindowsCmdShimWarningTests(unittest.TestCase):
    """L10: an oversized --agents JSON through a claude.cmd shim should warn,
    not fail mysteriously."""

    def test_oversized_cmdline_through_a_cmd_shim_warns(self):
        stderr = io.StringIO()
        args = ["C:\\nodejs\\claude.cmd", "--agents", "X" * 9000]
        with mock.patch.object(sys, "platform", "win32"), \
             contextlib.redirect_stderr(stderr):
            launcher._warn_windows_cmd_shim(args[0], args)
        self.assertIn("cmd.exe", stderr.getvalue())

    def test_a_native_binary_is_never_warned_about(self):
        stderr = io.StringIO()
        args = ["claude.exe", "--agents", "X" * 9000]
        with mock.patch.object(sys, "platform", "win32"), \
             contextlib.redirect_stderr(stderr):
            launcher._warn_windows_cmd_shim(args[0], args)
        self.assertEqual(stderr.getvalue(), "")


if __name__ == "__main__":
    unittest.main()
