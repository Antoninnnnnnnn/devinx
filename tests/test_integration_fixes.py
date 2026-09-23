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


if __name__ == "__main__":
    unittest.main()
