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
so the boundary is read back out of it: DEVINX_OWNED_PATHS is a
os.pathsep-separated list of paths (or glob patterns - '*' stays inside one
path segment, '**' crosses any number of them) that may be written. With it
unset this hook does nothing at all — no fleet-wide default, because a
boundary nobody declared is not a boundary and guessing one would break every
agent that legitimately writes anywhere.

It is a session-wide setting, not a per-agent one: the Agent tool has no
environment parameter, and the launcher does not set this variable itself, so
today every subagent in a session sees the same DEVINX_OWNED_PATHS the root
happened to have when it started. A real per-agent boundary needs an
agent_id in the hook's own event plus a SubagentStart hook, which this pass
does not add.

Hook contract: PreToolUse on stdin, exit 0 allows, exit 2 blocks with stderr
put in front of the model.
"""

import fnmatch
import json
import os
import sys

WRITERS = ("Edit", "Write", "NotebookEdit")


def _segments(path):
    """The path split into its non-empty, non-'.' components, for a glob
    match that walks segment by segment instead of treating the whole path
    as one string."""
    return [s for s in path.split(os.sep) if s and s != "."]


def _glob_match(path_segs, pattern_segs):
    """fnmatch, but '*' never crosses a path separator and '**' always does.

    Plain fnmatch.fnmatch("src/a/b.py", "src/*.py") is True - a single '*'
    matches the slash in "a/b.py" too, so a pattern meant to own the files
    directly under src/ silently also owns everything under src/ no matter
    how deep. Matching one path segment against one pattern segment at a
    time is what keeps '*' inside its own directory level; '**' opts back
    into crossing any number of segments (including zero) when that is
    actually wanted.
    """
    if not pattern_segs:
        return not path_segs
    head = pattern_segs[0]
    if head == "**":
        if _glob_match(path_segs, pattern_segs[1:]):
            return True
        return bool(path_segs) and _glob_match(path_segs[1:], pattern_segs)
    if not path_segs:
        return False
    return (fnmatch.fnmatch(path_segs[0], head)
            and _glob_match(path_segs[1:], pattern_segs[1:]))


def owned(path, patterns, root):
    # A relative target is resolved against the event's own cwd, the same
    # root a relative pattern is resolved against below - os.path.abspath()
    # here used the *process's* cwd instead, which need not be the same
    # directory the tool call actually happened in.
    target = path if os.path.isabs(path) else os.path.join(root, path)
    # realpath on both sides: a symlink inside the target path (or inside an
    # owned pattern's own directory) that points outside the declared
    # boundary must not be able to walk around it.
    full = os.path.realpath(target)
    for pattern in patterns:
        pattern = os.path.expanduser(pattern.strip())
        if not pattern:
            continue
        if not os.path.isabs(pattern):
            pattern = os.path.join(root, pattern)
        pattern = os.path.realpath(os.path.normpath(pattern))
        if full == pattern:
            return True
        # A directory named as owned carries what is under it, no globbing
        # needed - and no risk of '*' crossing anything, since there isn't one.
        if full.startswith(pattern.rstrip(os.sep) + os.sep):
            return True
        if _glob_match(_segments(full), _segments(pattern)):
            return True
    return False


def main():
    # os.pathsep, not a literal ':': on Windows that splits "C:\..." in half.
    patterns = [p for p in os.environ.get("DEVINX_OWNED_PATHS", "").split(os.pathsep) if p]
    if not patterns:
        return 0
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    if not isinstance(event, dict):
        return 0     # Valid JSON, unexpected shape (e.g. a bare list): fail open.
    if event.get("tool_name") not in WRITERS:
        return 0
    args = event.get("tool_input")
    if not isinstance(args, dict):
        return 0
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
