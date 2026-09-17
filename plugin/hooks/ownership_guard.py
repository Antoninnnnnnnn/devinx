#!/usr/bin/env python3
"""Hold an agent to the files its own prompt said it owns.

Prose does not hold. Measured here: an agent was told "You own exactly these
five files" and "If a fix genuinely requires changing production code under
apps/, stop and report rather than reaching for it", and then spent 12.6 hours
editing apps/backend/relay/pricing/rules.py. It read the boundary, agreed to
it, and crossed it anyway — not once, as a slip, but continuously for a night.

An instruction the model can reconsider is not a boundary. This is the same
instruction expressed where it cannot be reconsidered.

The orchestrator states ownership in the subagent's prompt. A prompt is text,
so the boundary is read back out of it: DEVINX_OWNED_PATHS, set per agent, is
a colon-separated list of paths (or glob patterns) that agent may write. With
it unset this hook does nothing at all — no fleet-wide default, because a
boundary nobody declared is not a boundary and guessing one would break every
agent that legitimately writes anywhere.

Hook contract: PreToolUse on stdin, exit 0 allows, exit 2 blocks with stderr
put in front of the model.
"""

import fnmatch
import json
import os
import sys

WRITERS = ("Edit", "Write", "NotebookEdit")


def owned(path, patterns, root):
    full = os.path.abspath(path)
    for pattern in patterns:
        pattern = os.path.expanduser(pattern.strip())
        if not pattern:
            continue
        if not os.path.isabs(pattern):
            pattern = os.path.join(root, pattern)
        pattern = os.path.normpath(pattern)
        if fnmatch.fnmatch(full, pattern) or full == pattern:
            return True
        # A directory named as owned carries what is under it.
        if full.startswith(pattern.rstrip("/") + os.sep):
            return True
    return False


def main():
    patterns = [p for p in os.environ.get("DEVINX_OWNED_PATHS", "").split(":") if p]
    if not patterns:
        return 0
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    if event.get("tool_name") not in WRITERS:
        return 0
    args = event.get("tool_input") or {}
    target = args.get("file_path") or args.get("notebook_path")
    if not target:
        return 0
    root = event.get("cwd") or os.getcwd()
    if owned(target, patterns, root):
        return 0
    sys.stderr.write(
        f"Blocked: {target} is not one of the files you own.\n\n"
        f"You own:\n" + "".join(f"  {p}\n" for p in patterns) +
        "\nThis is the boundary your task set, enforced rather than asked. If "
        "the work genuinely requires changing this file, that is a finding: "
        "stop and report what needs to change and why, and let whoever owns "
        "it decide. Do not work around this by writing the file through a "
        "shell command — that is the same boundary crossed less visibly.\n")
    return 2


if __name__ == "__main__":
    sys.exit(main())
