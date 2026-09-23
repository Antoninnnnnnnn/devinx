"""Per-agent file ownership and the daemon's inherited risky switches."""
import json
import os
import subprocess
import sys
import tempfile
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
sys.path.insert(0, ROOT)
HOOK = os.path.join(ROOT, "plugin", "hooks", "ownership_guard.py")

import diagnostics  # noqa: E402
import runtime_support  # noqa: E402


def run_hook(event, env_paths=None):
    env = dict(os.environ)
    env.pop("DEVINX_OWNED_PATHS", None)
    if env_paths is not None:
        env["DEVINX_OWNED_PATHS"] = env_paths
    r = subprocess.run([sys.executable, HOOK], input=json.dumps(event),
                       capture_output=True, text=True, env=env)
    return r.returncode, r.stderr


class PerAgentOwnershipTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.repo = os.path.join(self.tmp.name, "repo")
        os.makedirs(os.path.join(self.repo, "src", "api"))
        os.makedirs(os.path.join(self.repo, "apps"))
        self.transcript = os.path.join(self.tmp.name, "sess.jsonl")
        open(self.transcript, "w").close()
        self.subagents = os.path.join(self.tmp.name, "sess", "subagents")
        os.makedirs(self.subagents)

    def brief(self, agent_id, text, as_blocks=False):
        content = [{"type": "text", "text": text}] if as_blocks else text
        with open(os.path.join(self.subagents, f"agent-{agent_id}.jsonl"), "w") as fh:
            fh.write(json.dumps({"type": "user", "agentId": agent_id,
                                 "message": {"role": "user", "content": content}}) + "\n")

    def event(self, path, agent_id=None):
        e = {"tool_name": "Edit", "cwd": self.repo,
             "transcript_path": self.transcript,
             "tool_input": {"file_path": os.path.join(self.repo, path)}}
        if agent_id:
            e["agent_id"] = agent_id
        return e

    def test_two_workers_each_get_their_own_boundary(self):
        self.brief("a1", "Do it.\n<owned-paths>\nsrc/api/**\n</owned-paths>")
        self.brief("b2", "Other.\n<owned-paths>\n- apps/x.py\n</owned-paths>", as_blocks=True)
        self.assertEqual(run_hook(self.event("src/api/v.py", "a1"))[0], 0)
        self.assertEqual(run_hook(self.event("apps/x.py", "a1"))[0], 2)
        self.assertEqual(run_hook(self.event("apps/x.py", "b2"))[0], 0)
        self.assertEqual(run_hook(self.event("src/api/v.py", "b2"))[0], 2)

    def test_brief_without_block_falls_back_to_the_session_setting(self):
        self.brief("c3", "No declaration here.")
        self.assertEqual(run_hook(self.event("apps/x.py", "c3"))[0], 0)
        self.assertEqual(run_hook(self.event("apps/x.py", "c3"), "src")[0], 2)

    def test_main_thread_ignores_subagent_declarations(self):
        self.brief("a1", "<owned-paths>src/api/**</owned-paths>")
        self.assertEqual(run_hook(self.event("apps/x.py"))[0], 0)

    def test_unreadable_or_hostile_agent_id_fails_open(self):
        self.assertEqual(run_hook(self.event("apps/x.py", "missing"))[0], 0)
        self.assertEqual(run_hook(self.event("apps/x.py", "../../etc"))[0], 0)


class RiskySwitchTests(unittest.TestCase):
    def test_inherited_dump_is_reported(self):
        warnings = diagnostics.configuration_mismatches(
            {}, {"DEVINX_DUMP": True, "DEVINX_ALLOW_BROWSER": False})
        self.assertTrue(any("DEVINX_DUMP is active" in w for w in warnings))
        self.assertFalse(any("ALLOW_BROWSER" in w for w in warnings))

    def test_requested_but_missing_is_reported(self):
        warnings = diagnostics.configuration_mismatches(
            {"DEVINX_ALLOW_BROWSER": "1"}, {"DEVINX_ALLOW_BROWSER": False})
        self.assertTrue(any("requested" in w for w in warnings))

    def test_old_service_without_the_fields_says_nothing(self):
        self.assertEqual(diagnostics.configuration_mismatches({}, {}), [])


class PortLockTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self._orig = runtime_support._lock_dir
        runtime_support._lock_dir = lambda: self.tmp.name
        self.addCleanup(lambda: setattr(runtime_support, "_lock_dir", self._orig))

    def test_second_service_on_the_same_port_is_refused_until_release(self):
        program = ("import sys, runtime_support as r\n"
                   f"r._lock_dir = lambda: {self.tmp.name!r}\n"
                   "sys.exit(0 if r.PortLock(18555).acquire(wait=0.3) else 3)\n")
        first = runtime_support.PortLock(18555)
        self.assertTrue(first.acquire(wait=0))
        other = subprocess.run([sys.executable, "-c", program], cwd=ROOT)
        self.assertEqual(other.returncode, 3)
        first.release()
        other = subprocess.run([sys.executable, "-c", program], cwd=ROOT)
        self.assertEqual(other.returncode, 0)

    def test_server_no_longer_shares_its_port(self):
        import devinx
        a = devinx.Server(("127.0.0.1", 0), devinx.Handler)
        self.addCleanup(a.server_close)
        with self.assertRaises(OSError):
            devinx.Server(("127.0.0.1", a.server_port), devinx.Handler)


class HelloProofTests(unittest.TestCase):
    def test_proof_matches_only_with_the_same_secret(self):
        with tempfile.TemporaryDirectory() as d1, tempfile.TemporaryDirectory() as d2:
            s1 = runtime_support.service_secret(d1)
            self.assertEqual(runtime_support.service_secret(d1), s1)
            self.assertEqual(os.stat(os.path.join(d1, "service-secret")).st_mode & 0o777, 0o600)
            s2 = runtime_support.service_secret(d2)
            nonce = "ab" * 16
            self.assertEqual(runtime_support.hello_proof(s1, nonce),
                             runtime_support.hello_proof(s1, nonce))
            self.assertNotEqual(runtime_support.hello_proof(s1, nonce),
                                runtime_support.hello_proof(s2, nonce))

    def test_launcher_rejects_a_wrong_proof_and_accepts_the_right_one(self):
        import threading
        from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
        from urllib.parse import parse_qs, urlsplit
        import launcher
        with tempfile.TemporaryDirectory() as data:
            secret = runtime_support.service_secret(data)
            mode = {"good": True}

            class Fake(BaseHTTPRequestHandler):
                def do_GET(self):
                    nonce = parse_qs(urlsplit(self.path).query).get("nonce", [""])[0]
                    proof = runtime_support.hello_proof(secret if mode["good"] else "x" * 64, nonce)
                    body = json.dumps({"service": "devinx", "build": launcher.local_build(),
                                       "pid": 1, "inflight": 0, "proof": proof}).encode()
                    self.send_response(200)
                    self.send_header("content-length", str(len(body)))
                    self.end_headers()
                    self.wfile.write(body)

                def log_message(self, *a):
                    pass

            srv = ThreadingHTTPServer(("127.0.0.1", 0), Fake)
            threading.Thread(target=srv.serve_forever, daemon=True).start()
            self.addCleanup(srv.shutdown)
            old_port, old_dd = launcher.PORT, launcher.data_dir
            launcher.PORT, launcher.data_dir = srv.server_port, (lambda: data)
            self.addCleanup(lambda: (setattr(launcher, "PORT", old_port),
                                     setattr(launcher, "data_dir", old_dd)))
            self.assertEqual(launcher.service_state()[0], "fresh")
            mode["good"] = False
            self.assertEqual(launcher.service_state()[0], "foreign")


if __name__ == "__main__":
    unittest.main()
