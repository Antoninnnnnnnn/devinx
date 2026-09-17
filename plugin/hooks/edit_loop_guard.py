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

So this counts. The same edit, meaning the same file and the same old_string,
attempted more than ALLOWED times in one session is refused with the remedy
spelled out. The threshold is deliberately loose: two or three identical
attempts happen for honest reasons — a racing writer, a revert, a retry after
an interruption — and none of them need help. A fourth is a loop.

Hook contract: PreToolUse gets the call on stdin as JSON, exit 0 lets it
through, exit 2 blocks it and puts stderr in front of the model.
"""

import hashlib
import json
import os
import sys
import tempfile

ALLOWED = 3


def state_path(session):
    safe = hashlib.sha1((session or "nosession").encode()).hexdigest()[:16]
    return os.path.join(tempfile.gettempdir(), f"devinx-edit-guard-{safe}.json")


def main():
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0     # Never let a broken hook stand between an agent and its work.

    tool = event.get("tool_name")
    args = event.get("tool_input") or {}
    if tool not in ("Edit", "NotebookEdit"):
        return 0
    target = args.get("file_path") or args.get("notebook_path") or ""
    old = args.get("old_string")
    if not target or old is None:
        return 0

    key = hashlib.sha1(
        json.dumps([target, old, args.get("new_string")],
                   sort_keys=True).encode("utf-8", "replace")).hexdigest()[:20]
    path = state_path(event.get("session_id"))
    try:
        with open(path, encoding="utf-8") as fh:
            seen = json.load(fh)
    except (OSError, ValueError):
        seen = {}
    n = seen.get(key, 0) + 1
    seen[key] = n
    if len(seen) > 2000:
        seen = {key: n}
    try:
        with open(path, "w", encoding="utf-8") as fh:
            json.dump(seen, fh)
    except OSError:
        pass

    if n <= ALLOWED:
        return 0

    sys.stderr.write(
        f"Blocked: this is attempt {n} at the identical edit to {target} — "
        f"the same old_string and the same new_string as before.\n\n"
        f"Repeating it will fail again for the same reason. Do one of these "
        f"instead:\n"
        f"  - Read {target} now and edit from what it actually contains. If "
        f"you wrote to it outside the Edit tool (a heredoc, git checkout, a "
        f"script), that is why the edit keeps being rejected.\n"
        f"  - If the file is not yours to change, stop and report that, "
        f"rather than working around it.\n"
        f"  - If you have already tried both, the task is blocked. Say so and "
        f"stop; a loop is not progress.\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
