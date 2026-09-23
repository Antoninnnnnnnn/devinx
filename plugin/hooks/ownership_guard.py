#!/usr/bin/env python3
"""Hold an agent to the files its own prompt said it owns.

Prose does not hold. Measured here: an agent was told "You own exactly these
five files" and "If a fix genuinely requires changing production code under
apps/, stop and report rather than reaching for it", and then spent 12.6 hours
editing apps/backend/relay/pricing/rules.py. It read the boundary, agreed to
it, and crossed it anyway — not once, as a slip, but continuously for a night.

An instruction the model can reconsider is not a boundary. This is the same
instruction expressed where it cannot be reconsidered.

The orchestrator states ownership in the subagent's prompt, and the
boundary is read back out of that prompt: a block

    <owned-paths>
    src/api/**
    tests/api/test_limits.py
    </owned-paths>

anywhere in the brief lists the paths (or glob patterns - '*' stays inside
one path segment, '**' crosses any number of them) that agent may write.
A call made inside a subagent carries its agent_id, and Claude Code keeps
that agent's transcript at <session>/subagents/agent-<agent_id>.jsonl beside
the session's own, its first record being the brief exactly as the root
wrote it. So the declaration is found from the agent itself, with nothing
to correlate and nothing for the root to configure: two parallel workers of
the same type each get their own boundary.

DEVINX_OWNED_PATHS (os.pathsep-separated) is the session-wide fallback: it
applies to the main thread and to any subagent whose brief declares nothing.
With neither, this hook does nothing at all — no fleet-wide default, because
a boundary nobody declared is not a boundary and guessing one would break
every agent that legitimately writes anywhere.

Hook contract: PreToolUse on stdin, exit 0 allows, exit 2 blocks with stderr
put in front of the model.
"""

import fnmatch
import json
import os
import re
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
    """Fail open on literally anything unexpected, not just malformed JSON:
    os.path.realpath() can raise ValueError on a path with an embedded NUL,
    for one. None of that is the model's fault, so none of it may become a
    traceback (or an uncaught exception's exit code, which is not exit 2 and
    would not put a useful message in front of it either)."""
    try:
        return _run()
    except Exception:
        return 0


_DECLARED = re.compile(r"<owned-paths>(.*?)</owned-paths>", re.S)


def declared_patterns(event):
    """The paths the subagent's own brief declared, or None if it declared none
    (or this is the main thread, or its transcript cannot be read)."""
    agent_id, transcript = event.get("agent_id"), event.get("transcript_path")
    if not isinstance(agent_id, str) or not isinstance(transcript, str) or not transcript:
        return None
    if not re.fullmatch(r"[A-Za-z0-9_-]+", agent_id):
        return None
    path = os.path.join(os.path.splitext(transcript)[0], "subagents",
                        f"agent-{agent_id}.jsonl")
    try:
        with open(path, encoding="utf-8") as fh:
            first = json.loads(fh.readline())
    except (OSError, ValueError):
        return None
    content = (first.get("message") or {}).get("content") if isinstance(first, dict) else None
    if isinstance(content, list):
        content = "\n".join(b.get("text", "") for b in content
                            if isinstance(b, dict) and b.get("type") == "text")
    if not isinstance(content, str):
        return None
    found = _DECLARED.findall(content)
    if not found:
        return None
    out = []
    for block in found:
        for item in re.split(r"[\n,]", block):
            item = item.strip().lstrip("-*").strip().strip("`")
            if item:
                out.append(item)
    return out


def _run():
    try:
        event = json.load(sys.stdin)
    except (ValueError, OSError):
        return 0
    if not isinstance(event, dict):
        return 0     # Valid JSON, unexpected shape (e.g. a bare list): fail open.
    patterns = declared_patterns(event)
    if patterns is None:
        # os.pathsep, not a literal ':': on Windows that splits "C:\..." in half.
        patterns = [p for p in os.environ.get("DEVINX_OWNED_PATHS", "").split(os.pathsep) if p]
    if not patterns:
        return 0
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
