#!/usr/bin/env python3
"""Launch Claude Code, optionally through the local devinx service.

Without --devin (or --d) this is a passthrough: plain claude, no service started,
no environment injected, no extra flags. With it, devinx.py is started if its
port is not already answering, and claude is pointed at it.

Keeping this in Python rather than in a .sh and a .cmd means one implementation
instead of two that drift apart; the shell wrappers installed on PATH do nothing
but call this file.
"""
import glob
import json
import os
import shutil
import socket
import subprocess
import sys
import time
import urllib.request

HERE = os.path.dirname(os.path.abspath(__file__))
PORT = int(os.environ.get("DEVINX_PORT", "8316"))
HOST = "127.0.0.1"
START_TIMEOUT = 40
# Must match devinx.SWE_ALIAS: the id the service advertises and the launcher
# selects, and the one the readiness probe identifies devinx by.
SWE_ALIAS = "swe-2"

# Cleared so Claude Code falls back to its own claude.ai login. A leftover API key
# or OAuth token in the environment would make it authenticate as something else.
SCRUB = (
    "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL", "CLAUDE_CODE_OAUTH_TOKEN",
)

ENV = {
    "ANTHROPIC_BASE_URL": f"http://{HOST}:{PORT}",
    # The alias, not a tier: this is the entry shown in /model, and the effort
    # slider next to it is what selects medium / high / max.
    "ANTHROPIC_CUSTOM_MODEL_OPTION": SWE_ALIAS,
    "ANTHROPIC_CUSTOM_MODEL_OPTION_SUPPORTED_CAPABILITIES":
        "effort,max_effort,xhigh_effort,per_turn_effort",
    "CLAUDE_CODE_ENABLE_GATEWAY_MODEL_DISCOVERY": "1",
    # Claude Code has no catalog entry for a custom model, so it assumes a 200k
    # window and auto-compacts there, printing a warning at startup. This states
    # the real one. The value is inherited from the previous working setup rather
    # than measured here; override with DEVINX_CONTEXT_TOKENS if it is wrong.
    # Too low only compacts earlier than needed; too high pushes the failure
    # upstream instead, so err downward if unsure.
    "CLAUDE_CODE_MAX_CONTEXT_TOKENS": os.environ.get(
        "DEVINX_CONTEXT_TOKENS", "305000"),
}

# Opt-in. Without one of these, nothing is started and nothing is injected: the
# launcher is a passthrough to plain Claude Code. `-d` is deliberately not
# accepted, it is Claude Code's own --debug short flag.
DEVIN_FLAGS = {"--devin", "--d"}


def split_args(argv):
    """Return (use_devin, args_for_claude).

    Everything after a bare `--` is passed through untouched, so a prompt that
    happens to contain the flag is never swallowed.
    """
    use_devin = os.environ.get("DEVINX_ALWAYS") == "1"
    out = []
    for i, a in enumerate(argv):
        if a == "--":
            out.extend(argv[i:])
            break
        if a in DEVIN_FLAGS:
            use_devin = True
            continue
        out.append(a)
    return use_devin, out


def packaged_agents():
    """Parse agents/*.md into the JSON shape `claude --agents` expects.

    Injecting them per session rather than installing them into ~/.claude/agents
    is what makes --devin genuinely opt-in: without the flag a plain session
    shows no swe2-* agent at all, instead of listing agents that would fail if
    invoked, since nothing routes swe-2 models outside devin mode. It also stops
    the installer writing into a config directory the user may have moved with
    CLAUDE_CONFIG_DIR.
    """
    out = {}
    for path in sorted(glob.glob(os.path.join(HERE, "agents", "*.md"))):
        try:
            with open(path, encoding="utf-8") as fh:
                text = fh.read()
        except OSError:
            continue
        if not text.startswith("---"):
            continue
        _, _, rest = text.partition("---")
        front, sep, prompt = rest.partition("\n---")
        if not sep:
            continue
        meta = {}
        for line in front.splitlines():
            key, colon, value = line.partition(":")
            if colon:
                meta[key.strip()] = value.strip()
        name = meta.get("name")
        if not name:
            continue
        agent = {"description": meta.get("description", ""),
                 "prompt": prompt.lstrip("-\n").strip()}
        if meta.get("model"):
            agent["model"] = meta["model"]
        out[name] = agent
    return out


def merge_agents(passthrough, agents):
    """Add --agents, merging with one the user already passed rather than
    fighting over the flag. Their definitions win on a name clash."""
    if not agents:
        return passthrough
    existing = {}
    for i, a in enumerate(passthrough):
        if a == "--agents" and i + 1 < len(passthrough):
            try:
                existing = json.loads(passthrough[i + 1])
            except ValueError:
                sys.stderr.write("devinx: --agents is not valid JSON, "
                                 "leaving it alone\n")
                return passthrough
            merged = dict(agents)
            merged.update(existing if isinstance(existing, dict) else {})
            return (passthrough[:i + 1] + [json.dumps(merged)]
                    + passthrough[i + 2:])
    return passthrough + ["--agents", json.dumps(agents)]


def listening():
    """True only if *devinx* answers on the port.

    A bare TCP connect would also succeed for an unrelated process holding the
    port, and Claude Code would then be pointed at it and fail in confusing ways.
    Checking that the model list contains a swe-2 entry makes a port conflict
    deterministic instead of silent. This guards against accidents, not against a
    hostile local process.
    """
    with socket.socket() as s:
        s.settimeout(0.5)
        if s.connect_ex((HOST, PORT)) != 0:
            return False
    try:
        with urllib.request.urlopen(
                f"http://{HOST}:{PORT}/v1/models", timeout=3) as r:
            data = json.loads(r.read()).get("data") or []
        # The exact alias, not a swe-2* prefix: an older gateway sharing this
        # port advertises swe-2-max and friends without knowing `swe-2`, so a
        # prefix match accepted it as devinx and Claude Code was pointed at a
        # service that would then refuse the model this launcher selects.
        return any(m.get("id") == SWE_ALIAS for m in data)
    except Exception:
        return False


def data_dir():
    if os.environ.get("DEVINX_DATA"):
        return os.path.normpath(os.environ["DEVINX_DATA"])
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.normpath(os.path.join(base, "devinx"))


def start_service():
    """Spawn devinx.py detached so it outlives this launcher and the claude run."""
    log_dir = data_dir()
    os.makedirs(log_dir, exist_ok=True)
    log = open(os.path.join(log_dir, "devinx.log"), "ab")
    kwargs = {"stdout": log, "stderr": log, "stdin": subprocess.DEVNULL,
              "cwd": HERE}
    if sys.platform == "win32":
        # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no console window, and the
        # service is not killed when the launching terminal closes.
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    subprocess.Popen([sys.executable, os.path.join(HERE, "devinx.py")], **kwargs)


def main():
    use_devin, passthrough = split_args(sys.argv[1:])

    claude = shutil.which("claude")
    if not claude:
        sys.stderr.write("claude not found on PATH - install Claude Code first\n")
        return 1

    env = dict(os.environ)

    if not use_devin:
        # Plain Claude Code: no service, no injected configuration, no extra
        # flags. The one thing removed is a base URL pointing at devinx itself,
        # inherited from a parent devin-mode session — leaving it would silently
        # route "plain" through the proxy, which is the opposite of the intent.
        if env.get("ANTHROPIC_BASE_URL", "").rstrip("/") == f"http://{HOST}:{PORT}":
            for name in ENV:
                env.pop(name, None)
        args = [claude] + passthrough
        if sys.platform == "win32":
            return subprocess.call(args, env=env)
        os.execvpe(claude, args, env)

    if not listening():
        start_service()
        deadline = time.time() + START_TIMEOUT
        while time.time() < deadline:
            if listening():
                break
            time.sleep(0.5)
        else:
            sys.stderr.write(
                f"devinx failed to start on {HOST}:{PORT}\n"
                f"check {os.path.join(data_dir(), 'devinx.log')}\n")
            return 1

    for name in SCRUB:
        env.pop(name, None)
    env.update(ENV)

    # Deliberately no --dangerously-skip-permissions. Choosing a model and
    # choosing to run tools unattended are separate decisions, and this tool has
    # no business making the second one on the user's behalf: pass the flag
    # yourself if you want it.
    args = [claude] + merge_agents(passthrough, packaged_agents())
    if sys.platform == "win32":
        # No exec() on Windows that preserves the console properly; run as a child
        # and hand back its exit code.
        return subprocess.call(args, env=env)
    os.execvpe(claude, args, env)


if __name__ == "__main__":
    sys.exit(main())
