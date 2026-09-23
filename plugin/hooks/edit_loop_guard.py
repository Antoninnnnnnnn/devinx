#!/usr/bin/env python3
"""Stop an agent from retrying an edit that has already failed the same way.

Measured, on one night in this repo's own fleet: an agent issued 1 835 Edit
calls at a single file, 1 751 of them byte-identical, for 12.6 hours, one every
nine seconds. 1 176 came back "File has been modified since read ... Read it
again before attempting to write it." It never read the file. It had rewritten
it out of band — python3 heredocs, git checkout — which invalidates the read
state the tool checks, and then retried the identical call until morning.

Nothing in the model's own reasoning broke that loop, and no change to the
proxy could: the call is well formed and the refusal is correct every time.
The only thing that ends it is something outside the agent that counts.

So this counts, but only a run of the SAME attempt going nowhere:

- PreToolUse (also the default when hook_event_name is absent, for an older
  Claude Code or a direct call): refuse an attempt already at ALLOWED, without
  incrementing it — a call this hook itself denies is never counted, and a
  call something else denies never reaches PostToolUse at all, so it is never
  counted either.
- PostToolUse on a successful Edit/Write/NotebookEdit forgives that exact
  attempt: a legitimate repeat (a revert, redoing the same fix twice) is never
  penalised once it has actually worked.
- PostToolUse on a Read forgives every attempt recorded against that file: the
  refusal's own remedy ("read it again") is what un-blocks it.
- SessionStart clears this session's state on startup, --resume and --clear
  (a loop from a previous run is not evidence about this one), but not on
  compact or fork: a long session auto-compacting repeatedly must not hand
  itself three fresh attempts on every compaction, which would let the exact
  loop this hook exists to stop keep going, just slower.

One acknowledged gap: a call denied by a *different* hook (ownership_guard,
or the interactive permission prompt) still increments here, because the
increment happens at PreToolUse time, before it is known whether anything
downstream will refuse it. Undoing that would need this hook to know the
final permission outcome, which PreToolUse alone does not carry.

Threshold is deliberately loose: two or three identical failing attempts
happen for honest reasons — a racing writer, a retry after an interruption —
and none of them need help. A fourth in a row, never once successful, is a
loop.

Hook contract: stdin carries the event as JSON. Exit 0 lets a PreToolUse call
through, exit 2 blocks it and puts stderr in front of the model. A PostToolUse
or SessionStart call is always exit 0 - it never blocks anything, it only
updates state for the *next* PreToolUse call to see.
"""

import contextlib
import hashlib
import json
import os
import random
import sys
import tempfile
import time

ALLOWED = 3
TRACKED = ("Edit", "Write", "NotebookEdit")
MAX_AGE_SECONDS = 7 * 24 * 3600


def _state_dir():
    """A private, per-user directory - not a predictable name in shared /tmp.

    Mirrors launcher.py's data_dir() logic (duplicated rather than imported:
    this script is invoked standalone, by path, from a plugin whose
    CLAUDE_PLUGIN_ROOT is not the repo root, so importing across that
    boundary would be more fragile than repeating a dozen lines).
    """
    if os.environ.get("DEVINX_DATA"):
        base = os.path.normpath(os.environ["DEVINX_DATA"])
    elif sys.platform == "win32":
        base = os.path.join(
            os.environ.get("LOCALAPPDATA") or os.path.expanduser("~"), "devinx")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support/devinx")
    else:
        base = os.path.join(
            os.environ.get("XDG_STATE_HOME") or os.path.expanduser("~/.local/state"),
            "devinx")
    directory = os.path.join(base, "hooks")
    try:
        os.makedirs(directory, mode=0o700, exist_ok=True)
        os.chmod(directory, 0o700)
    except OSError:
        pass
    # Cheap and only occasionally: sweeping the directory on every one of
    # potentially thousands of hook calls a session makes is wasted work: old
    # state (a session that will never come back) only needs to go eventually.
    if random.random() < 0.02:
        _cleanup_old(directory)
    return directory


def _cleanup_old(directory, max_age=MAX_AGE_SECONDS):
    cutoff = time.time() - max_age
    try:
        names = os.listdir(directory)
    except OSError:
        return
    for name in names:
        # A lock file's mtime is set once, at creation, and flock() never
        # touches it again - judging a *lock* file's age this way would
        # remove one still guarding a long-lived session's state file, and a
        # concurrent holder would keep the old inode while a newcomer
        # creates a fresh one, landing two processes in the same critical
        # section at once.
        if name.endswith(".lock"):
            continue
        path = os.path.join(directory, name)
        try:
            if os.path.getmtime(path) < cutoff:
                os.remove(path)
        except OSError:
            pass


def state_path(session):
    safe = hashlib.sha1((session or "nosession").encode()).hexdigest()[:16]
    return os.path.join(_state_dir(), f"edit-guard-{safe}.json")


@contextlib.contextmanager
def _locked(path):
    """Hold an exclusive lock across the whole read-modify-write.

    Without this, two Edit calls in flight at once from parallel agents can
    both read the same count, both write back the same increment, and the
    loop never gets counted accurately - measured shape: 6 passages recorded
    instead of 3 with 40 agents hammering the same file.
    """
    lock_path = path + ".lock"
    flags = (os.O_RDWR | os.O_CREAT | getattr(os, "O_CLOEXEC", 0)
             | getattr(os, "O_NOFOLLOW", 0))
    fd = os.open(lock_path, flags, 0o600)
    try:
        if os.name == "nt":
            import msvcrt
            if os.fstat(fd).st_size == 0:
                os.write(fd, b"0")
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_LOCK, 1)
            try:
                yield
            finally:
                os.lseek(fd, 0, os.SEEK_SET)
                msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
        else:
            import fcntl
            fcntl.flock(fd, fcntl.LOCK_EX)
            try:
                yield
            finally:
                fcntl.flock(fd, fcntl.LOCK_UN)
    finally:
        os.close(fd)


def _load(path):
    """Never follow a symlink planted at this predictable-ish path."""
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0))
    except OSError:
        return {}
    try:
        with os.fdopen(fd, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {}
    except (OSError, ValueError):
        return {}


def _save(path, data):
    """Write via a temp file and os.replace(): a reader never sees a partial
    write, and a crash mid-write never corrupts the previous good state."""
    directory = os.path.dirname(path) or "."
    fd, tmp = tempfile.mkstemp(dir=directory, prefix=".tmp-edit-guard-")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(data, fh)
        os.replace(tmp, path)
    except OSError:
        with contextlib.suppress(OSError):
            os.remove(tmp)


def _key_and_file(tool, args):
    """Identify one specific attempt, or (None, None) if this call cannot be
    tracked at all (missing fields; a Write with no content yet)."""
    if tool == "Edit":
        target = args.get("file_path")
        old = args.get("old_string")
        if not target or old is None:
            return None, None
        payload = [target, old, args.get("new_string")]
    elif tool == "NotebookEdit":
        # NotebookEdit has no old_string/new_string at all - the original
        # code's key (built only from those two fields) meant a NotebookEdit
        # call always fell through to "cannot be tracked", even though the
        # tool was listed as matched.
        target = args.get("notebook_path")
        if not target:
            return None, None
        payload = [target, args.get("cell_id"), args.get("edit_mode"),
                  args.get("new_source")]
    elif tool == "Write":
        target = args.get("file_path")
        content = args.get("content")
        if not target or content is None:
            return None, None
        payload = [target, content]
    else:
        return None, None
    key = hashlib.sha1(json.dumps(payload, sort_keys=True)
                       .encode("utf-8", "replace")).hexdigest()[:20]
    return key, target


def _clear_file(path, target):
    with _locked(path):
        state = _load(path)
        remaining = {k: v for k, v in state.items() if v.get("file") != target}
        if len(remaining) != len(state):
            _save(path, remaining)


def _clear_session(session):
    """Empty the state, but never unlink the lock file itself.

    runtime_support.startup_lock's own comment says why: a concurrent holder
    keeps the old inode open regardless of what the directory entry now
    points to, so unlinking it lets a newcomer create a fresh inode and lock
    it while the original holder still believes it holds the only lock -
    two processes end up in the critical section at once. Clearing the
    *content* under the existing lock has none of that problem.
    """
    path = state_path(session)
    with _locked(path):
        _save(path, {})


# SessionStart fires for more than "a genuinely new run": Claude Code's own
# settings.json shows `source` distinguishing startup/resume/clear/compact/
# fork, and a long main session auto-compacting repeatedly must not hand
# itself three fresh attempts on every compaction - that would let exactly
# the loop this hook exists to stop keep going, just slower. Resuming a
# previous run, or clearing/starting fresh, are the cases state should not
# survive; mid-session compaction is not one of them.
_SESSION_CLEARING_SOURCES = frozenset({"startup", "resume", "clear"})


def main():
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0     # Never let a broken hook stand between an agent and its work.
    if not isinstance(event, dict):
        return 0     # Valid JSON, unexpected shape (e.g. a bare list): fail open.

    hook_event = event.get("hook_event_name") or "PreToolUse"
    session = event.get("session_id")

    if hook_event == "SessionStart":
        if event.get("source") in _SESSION_CLEARING_SOURCES:
            _clear_session(session)
        return 0

    tool = event.get("tool_name")
    args = event.get("tool_input")
    if not isinstance(args, dict):
        args = {}

    if tool == "Read":
        if hook_event == "PostToolUse":
            target = args.get("file_path")
            if target:
                _clear_file(state_path(session), target)
        return 0

    if tool not in TRACKED:
        return 0

    key, target = _key_and_file(tool, args)
    if key is None:
        return 0

    path = state_path(session)
    with _locked(path):
        state = _load(path)

        if hook_event == "PostToolUse":
            # It worked: this exact attempt is no longer evidence of a loop.
            if key in state:
                del state[key]
                _save(path, state)
            return 0

        entry = state.get(key, {"file": target, "n": 0})
        if entry.get("n", 0) >= ALLOWED:
            sys.stderr.write(
                f"Blocked: this is attempt {entry['n'] + 1} at the identical "
                f"edit to {target} — the same change as before, and it has not "
                f"succeeded yet.\n\n"
                f"Repeating it will fail again for the same reason. Do one of "
                f"these instead:\n"
                f"  - Read {target} now and edit from what it actually "
                f"contains. If you wrote to it outside the {tool} tool (a "
                f"heredoc, git checkout, a script), that is why the edit "
                f"keeps being rejected.\n"
                f"  - If the file is not yours to change, stop and report "
                f"that, rather than working around it.\n"
                f"  - If you have already tried both, the task is blocked. "
                f"Say so and stop; a loop is not progress.\n")
            return 2

        entry["n"] = entry.get("n", 0) + 1
        entry["file"] = target
        state[key] = entry
        if len(state) > 2000:
            state = {key: entry}
        _save(path, state)
    return 0


if __name__ == "__main__":
    sys.exit(main())
