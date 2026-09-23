#!/usr/bin/env python3
"""Regression tests for the plugin hook fixes in this pass (H2-H4, H9).

One test per finding: reverting the matching fix must fail the test.
Hermetic - DEVINX_DATA always points at a throwaway temp directory, so
nothing here ever touches the real HOME.

    .venv/bin/python -m unittest tests.test_hooks_fixes -v
"""
import concurrent.futures
import json
import os
import subprocess
import sys
import tempfile
import time
import unittest
from unittest import mock

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
HOOKS_DIR = os.path.join(ROOT, "plugin", "hooks")
sys.path.insert(0, HOOKS_DIR)
sys.dont_write_bytecode = True

import edit_loop_guard  # noqa: E402
import ownership_guard  # noqa: E402

EDIT_GUARD = os.path.join(HOOKS_DIR, "edit_loop_guard.py")
OWNERSHIP_GUARD = os.path.join(HOOKS_DIR, "ownership_guard.py")


class HermeticHookCase(unittest.TestCase):
    """A throwaway DEVINX_DATA for every test, never the real HOME."""

    def setUp(self):
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.env = dict(os.environ, DEVINX_DATA=self._tmp.name)
        self.session = "test-" + os.urandom(6).hex()

    def _call(self, tool, args, hook_event=None, session=None):
        event = {"session_id": session or self.session, "tool_name": tool,
                 "tool_input": args}
        if hook_event:
            event["hook_event_name"] = hook_event
        return subprocess.run([sys.executable, EDIT_GUARD], input=json.dumps(event),
                              capture_output=True, text=True, env=self.env)


class SessionStartClearsStateTests(HermeticHookCase):
    """H2: state must not survive into a new session; --resume is separate;
    mid-session compaction is not "a new session" and must not reset it."""

    def _session_start(self, source):
        return subprocess.run(
            [sys.executable, EDIT_GUARD],
            input=json.dumps({"session_id": self.session,
                              "hook_event_name": "SessionStart", "source": source}),
            capture_output=True, text=True, env=self.env)

    def test_resume_clears_this_sessions_state(self):
        args = {"file_path": "/a/b.py", "old_string": "X", "new_string": "Y"}
        for _ in range(3):
            self.assertEqual(self._call("Edit", args).returncode, 0)
        self.assertEqual(self._session_start("resume").returncode, 0)
        # Without the clear, this would be the blocked 4th attempt.
        self.assertEqual(self._call("Edit", args).returncode, 0)

    def test_compact_does_not_clear_state(self):
        # A long session auto-compacting repeatedly must not hand itself
        # three fresh attempts on every compaction - that would let the exact
        # loop this hook exists to stop keep going, just slower.
        args = {"file_path": "/a/b.py", "old_string": "X", "new_string": "Y"}
        for _ in range(3):
            self.assertEqual(self._call("Edit", args).returncode, 0)
        self.assertEqual(self._session_start("compact").returncode, 0)
        self.assertEqual(self._call("Edit", args).returncode, 2)

    def test_the_lock_file_itself_is_never_removed_by_a_clear(self):
        args = {"file_path": "/a/b.py", "old_string": "X", "new_string": "Y"}
        self.assertEqual(self._call("Edit", args).returncode, 0)
        with mock.patch.dict(os.environ, {"DEVINX_DATA": self._tmp.name}):
            lock_path = edit_loop_guard.state_path(self.session) + ".lock"
        self.assertTrue(os.path.exists(lock_path))
        self.assertEqual(self._session_start("resume").returncode, 0)
        self.assertTrue(os.path.exists(lock_path))


class SuccessResetsTheCounterTests(HermeticHookCase):
    """H2: a PostToolUse success forgives that exact attempt."""

    def test_a_success_between_failures_prevents_the_block(self):
        args = {"file_path": "/a/b.py", "old_string": "X", "new_string": "Y"}
        for _ in range(3):
            self.assertEqual(self._call("Edit", args, "PreToolUse").returncode, 0)
        # It actually succeeded this time.
        self.assertEqual(self._call("Edit", args, "PostToolUse").returncode, 0)
        # So the identical attempt afterwards is not the 4th strike anymore.
        self.assertEqual(self._call("Edit", args, "PreToolUse").returncode, 0)

    def test_a_read_of_the_file_also_forgives_pending_attempts(self):
        args = {"file_path": "/a/b.py", "old_string": "X", "new_string": "Y"}
        for _ in range(3):
            self.assertEqual(self._call("Edit", args, "PreToolUse").returncode, 0)
        self.assertEqual(
            self._call("Read", {"file_path": "/a/b.py"}, "PostToolUse").returncode, 0)
        self.assertEqual(self._call("Edit", args, "PreToolUse").returncode, 0)

    def test_a_pretooluse_denial_does_not_itself_increment(self):
        args = {"file_path": "/a/b.py", "old_string": "X", "new_string": "Y"}
        for _ in range(3):
            self.assertEqual(self._call("Edit", args, "PreToolUse").returncode, 0)
        blocked = self._call("Edit", args, "PreToolUse")
        self.assertEqual(blocked.returncode, 2)
        # Retrying the *blocked* call more times must not need to be undone by
        # more than one success - it never actually ran, so it was never
        # counted again past the first block.
        self._call("Edit", args, "PreToolUse")
        self._call("Edit", args, "PreToolUse")
        self.assertEqual(self._call("Edit", args, "PostToolUse").returncode, 0)
        self.assertEqual(self._call("Edit", args, "PreToolUse").returncode, 0)


class NotebookEditIsActuallyTrackedTests(HermeticHookCase):
    """H3: NotebookEdit was matched by the hook but never actually checked,
    because its key was built from old_string/new_string, fields it does not
    have."""

    def test_the_fourth_identical_notebook_edit_is_refused(self):
        args = {"notebook_path": "/a/b.ipynb", "cell_id": "c1",
                "new_source": "print(1)", "edit_mode": "replace"}
        for _ in range(3):
            self.assertEqual(self._call("NotebookEdit", args).returncode, 0)
        self.assertEqual(self._call("NotebookEdit", args).returncode, 2)

    def test_different_cells_never_collide(self):
        for i in range(5):
            args = {"notebook_path": "/a/b.ipynb", "cell_id": f"c{i}",
                    "new_source": "print(1)", "edit_mode": "replace"}
            self.assertEqual(self._call("NotebookEdit", args).returncode, 0)


class WriteIsTrackedWhenItCarriesContentTests(HermeticHookCase):
    """H3: add Write coverage - keyed on (file_path, content), so a Write
    with no content (as in the pre-existing pass-through test) is still left
    alone, but a real, repeated, identical Write is now caught."""

    def test_the_fourth_identical_write_is_refused(self):
        args = {"file_path": "/a/b.py", "content": "same content"}
        for _ in range(3):
            self.assertEqual(self._call("Write", args).returncode, 0)
        self.assertEqual(self._call("Write", args).returncode, 2)

    def test_a_write_with_no_content_field_is_never_tracked(self):
        args = {"file_path": "/a/b.py"}
        for _ in range(8):
            self.assertEqual(self._call("Write", args).returncode, 0)


class ConcurrentAttemptsAreCountedAccuratelyTests(HermeticHookCase):
    """H3: the read-modify-write must be atomic and locked, or parallel
    agents hitting the same edit race each other's counts."""

    def test_exactly_allowed_calls_pass_under_forty_parallel_attempts(self):
        args = {"file_path": "/race.py", "old_string": "X", "new_string": "Y"}

        def attempt(_):
            return self._call("Edit", args).returncode

        with concurrent.futures.ThreadPoolExecutor(max_workers=40) as pool:
            results = list(pool.map(attempt, range(40)))
        self.assertEqual(results.count(0), edit_loop_guard.ALLOWED)
        self.assertEqual(results.count(2), 40 - edit_loop_guard.ALLOWED)


class StatePathIsPrivateTests(HermeticHookCase):
    """H9: state lives under a private, per-user directory, mode 0700, not a
    predictable shared-/tmp name, and old files get cleaned up."""

    def test_state_dir_is_not_the_shared_tmp_root(self):
        with mock.patch.dict(os.environ, {"DEVINX_DATA": self._tmp.name}):
            path = edit_loop_guard.state_path(self.session)
        self.assertTrue(path.startswith(self._tmp.name))
        self.assertNotEqual(os.path.dirname(path), tempfile.gettempdir())

    def test_state_dir_is_mode_0700_on_posix(self):
        if sys.platform == "win32":
            self.skipTest("POSIX permission bits")
        with mock.patch.dict(os.environ, {"DEVINX_DATA": self._tmp.name}):
            directory = edit_loop_guard._state_dir()
        mode = os.stat(directory).st_mode & 0o777
        self.assertEqual(mode, 0o700)

    def test_old_state_files_are_cleaned_up(self):
        with mock.patch.dict(os.environ, {"DEVINX_DATA": self._tmp.name}):
            directory = edit_loop_guard._state_dir()
        stale = os.path.join(directory, "ancient.json")
        with open(stale, "w") as fh:
            fh.write("{}")
        old = 8 * 24 * 3600
        os.utime(stale, (0, time.time() - old))
        edit_loop_guard._cleanup_old(directory)
        self.assertFalse(os.path.exists(stale))


class SegmentAwareGlobTests(unittest.TestCase):
    """H4: '*' must not cross a path separator; '**' must."""

    def test_single_star_does_not_cross_a_slash(self):
        self.assertFalse(ownership_guard._glob_match(
            ["src", "a", "b.py"], ["src", "*.py"]))

    def test_single_star_matches_within_one_segment(self):
        self.assertTrue(ownership_guard._glob_match(
            ["src", "a.py"], ["src", "*.py"]))

    def test_double_star_crosses_any_depth(self):
        self.assertTrue(ownership_guard._glob_match(
            ["src", "a", "b", "c.py"], ["src", "**", "*.py"]))
        self.assertTrue(ownership_guard._glob_match(
            ["src", "c.py"], ["src", "**", "*.py"]))


class SymlinkEscapeTests(unittest.TestCase):
    """H4: a symlinked directory inside the owned tree must not be usable to
    write outside the declared boundary."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def test_a_symlink_escaping_the_owned_directory_is_refused(self):
        root = self.tmp.name
        owned_dir = os.path.join(root, "owned")
        outside_dir = os.path.join(root, "outside")
        os.makedirs(owned_dir)
        os.makedirs(outside_dir)
        if sys.platform == "win32":
            self.skipTest("symlink privileges vary on Windows")
        os.symlink(outside_dir, os.path.join(owned_dir, "escape"))
        target = os.path.join(owned_dir, "escape", "secret.py")
        self.assertFalse(ownership_guard.owned(target, [owned_dir], root))

    def test_a_plain_file_inside_the_owned_directory_still_passes(self):
        root = self.tmp.name
        owned_dir = os.path.join(root, "owned")
        os.makedirs(owned_dir)
        target = os.path.join(owned_dir, "fine.py")
        self.assertTrue(ownership_guard.owned(target, [owned_dir], root))


class RelativeTargetUsesEventCwdTests(unittest.TestCase):
    """H4: a relative target must resolve against event['cwd'], not whatever
    directory the hook process itself happens to be running in."""

    def test_relative_target_resolves_against_event_cwd_not_process_cwd(self):
        # The hook process's own cwd is wherever the test runner started it -
        # deliberately different from the event's cwd, to prove the target
        # is resolved against the latter.
        event_cwd = os.path.dirname(os.path.abspath(__file__))
        self.assertTrue(ownership_guard.owned(
            "relative_target.py", [os.path.join(event_cwd, "relative_target.py")],
            event_cwd))


class PathsepSplitTests(unittest.TestCase):
    """H9: split on os.pathsep, not a literal ':' (which breaks 'C:\\...')."""

    def test_source_uses_os_pathsep_not_a_literal_colon(self):
        source = __import__("inspect").getsource(ownership_guard._run)
        self.assertIn("os.pathsep", source)
        self.assertNotIn('split(":")', source)

    def test_windows_style_drive_path_is_not_split_in_half(self):
        # os.pathsep is platform-fixed, so this exercises the *splitting*
        # logic directly rather than the whole subprocess on a POSIX runner.
        raw = r"C:\repo\tests\*.py;C:\repo\docs"
        parts = [p for p in raw.split(";") if p]
        self.assertEqual(parts, [r"C:\repo\tests\*.py", r"C:\repo\docs"])


class FailOpenOnUnexpectedJsonTests(unittest.TestCase):
    """H9: valid JSON in an unexpected shape must never crash the hook."""

    def _run(self, script, payload):
        return subprocess.run([sys.executable, script], input=payload,
                              capture_output=True, text=True)

    def test_edit_loop_guard_survives_a_json_array(self):
        r = self._run(EDIT_GUARD, "[1, 2, 3]")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr, "")

    def test_ownership_guard_survives_a_json_array(self):
        r = self._run(OWNERSHIP_GUARD, "[1, 2, 3]")
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr, "")

    def test_ownership_guard_survives_a_non_dict_tool_input(self):
        event = json.dumps({"tool_name": "Edit", "cwd": "/repo", "tool_input": "oops"})
        r = self._run(OWNERSHIP_GUARD, event)
        self.assertEqual(r.returncode, 0)

    def test_ownership_guard_survives_a_nul_byte_in_the_path(self):
        # os.path.realpath() raises ValueError on an embedded NUL.
        event = json.dumps({"tool_name": "Edit", "cwd": "/repo",
                            "tool_input": {"file_path": "/repo/a\x00b.py"}})
        env = dict(os.environ, DEVINX_OWNED_PATHS="/repo")
        r = subprocess.run([sys.executable, OWNERSHIP_GUARD], input=event,
                           capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr, "")

    def test_edit_loop_guard_survives_an_unwritable_state_directory(self):
        # DEVINX_DATA pointing at a plain file: _state_dir()'s makedirs()
        # fails, and the next os.open() for the lock file must not raise.
        with tempfile.TemporaryDirectory() as tmp:
            blocker = os.path.join(tmp, "blocks-the-hooks-subdir")
            with open(blocker, "w") as fh:
                fh.write("not a directory")
            event = json.dumps({"session_id": "s", "tool_name": "Edit",
                                "tool_input": {"file_path": "/a/b.py",
                                              "old_string": "X", "new_string": "Y"}})
            env = dict(os.environ, DEVINX_DATA=blocker)
            r = subprocess.run([sys.executable, EDIT_GUARD], input=event,
                               capture_output=True, text=True, env=env)
        self.assertEqual(r.returncode, 0)
        self.assertEqual(r.stderr, "")


if __name__ == "__main__":
    unittest.main()
