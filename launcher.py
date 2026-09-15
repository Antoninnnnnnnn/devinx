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
import hashlib
import json
import os
import shutil
import signal
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
    # window and auto-compacts there unless told otherwise. This states the real
    # one: 256Ki, what SWE-2 accepts.
    #
    # The number matters in one direction far more than the other. Too low only
    # compacts earlier than needed; too high means auto-compact aims past what
    # the upstream will take and the turn dies with "prompt is too long"
    # instead. The previous 305000 did exactly that, and subagents were where it
    # showed: they ran to ~275k before compaction was due and were refused
    # first, so they never compacted at all — they just stopped.
    #
    # It has to be the environment variable. Serving context_window and
    # runtime.max_input_tokens on the /v1/models entries looks like the right
    # answer and is not: measured against 2.1.272, the unrecognised-model notice
    # still reports the 200k it assumes, so gateway discovery does not size the
    # model from the catalog. Override with DEVINX_CONTEXT_TOKENS.
    "CLAUDE_CODE_MAX_CONTEXT_TOKENS": os.environ.get(
        "DEVINX_CONTEXT_TOKENS", str(256 * 1024)),
}

# Opt-in. Without one of these, nothing is started and nothing is injected: the
# launcher is a passthrough to plain Claude Code. `-d` is deliberately not
# accepted, it is Claude Code's own --debug short flag.
DEVIN_FLAGS = {"--devin", "--d"}

# Separately opt-in: the SWE-2 layer is about which model runs the work, the
# orchestrator is about who decides what the work is. Most sessions want the
# first without the second, so --devin alone leaves the skill out entirely.
ORCH_FLAGS = {"--or"}

# Which client to launch. Codex reaches the same service on the same port; only
# the wire differs, and devinx routes on the model name either way.
CODEX_FLAGS = {"--codex", "--cx"}

# Roles, in the order Codex should see them, with the guidance it uses to pick
# one. Each is a config layer that pins swe-2-max and nothing else: Codex honours
# `model` in a role layer but ignores `model_provider`, which is exactly why the
# split has to happen on the model name instead.
CODEX_ROLES = (
    ("swe2-explorer", "Read-only mapping: locate files, symbols, tests and the "
                      "execution path before anyone writes code."),
    ("swe2-worker", "Bounded implementation: targeted fixes and mechanical "
                    "edits in files you name explicitly."),
    ("swe2-tester", "Verification: run targeted tests, reproduce failures, "
                    "report exact commands and real output."),
    ("swe2-researcher", "Read-only research: version-specific API behaviour and "
                        "external documentation."),
    ("swe2-reviewer", "Independent read of a finished change: correctness, "
                      "regressions, scope creep, weakened tests."),
)


def split_args(argv):
    """Return (use_devin, use_orchestrator, use_codex, args_for_client).

    Everything after a bare `--` is passed through untouched, so a prompt that
    happens to contain a flag is never swallowed.
    """
    use_devin = os.environ.get("DEVINX_ALWAYS") == "1"
    use_orch = os.environ.get("DEVINX_ORCHESTRATOR") == "1"
    use_codex = False
    out = []
    for i, a in enumerate(argv):
        if a == "--":
            out.extend(argv[i:])
            break
        if a in DEVIN_FLAGS:
            use_devin = True
            continue
        if a in CODEX_FLAGS:
            # Codex needs the service for the same reason Claude Code does.
            use_codex = True
            use_devin = True
            continue
        if a in ORCH_FLAGS:
            # The orchestrator delegates to the swe2-* agents, which exist only
            # in devin mode, so asking for it asks for that too.
            use_orch = True
            use_devin = True
            continue
        out.append(a)
    return use_devin, use_orch, use_codex, out


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
        # A read-only role (explorer, researcher, reviewer) denies the editing
        # tools by name. Bash can still write, so the prompt says so too; this
        # closes the accidental path, not a determined one.
        blocked = [t.strip() for t in meta.get("disallowedTools", "").split(",")
                   if t.strip()]
        if os.environ.get("DEVINX_SUBAGENT_MCP") != "1":
            # MCP tool schemas are re-sent in full on every request, and there
            # are usually a lot of them: measured here, a subagent turn goes from
            # ~240KB to ~49KB by excluding them, and a cold first turn from ~58s
            # to a few seconds. A glob rather than an allow-list on purpose —
            # every built-in tool stays available, including ones added by a
            # future Claude Code release, so the agents keep inheriting the
            # native tool set. Only the main session keeps its connectors.
            blocked.append("mcp__*")
        if blocked:
            agent["disallowedTools"] = blocked
        out[name] = agent
    return out


def split_at_separator(args):
    """Split at the first bare `--`.

    split_args() already refuses to read flags past it; so must everything that
    builds the command line afterwards. Injecting an option after `--` puts it
    where the client will hand it to the prompt, and reading an `--agents` that
    sits there rewrites text the user asked to be passed through untouched.
    """
    if "--" in args:
        cut = args.index("--")
        return list(args[:cut]), list(args[cut:])
    return list(args), []


def merge_agents(passthrough, agents):
    """Add --agents, merging with one the user already passed rather than
    fighting over the flag. Their definitions win on a name clash.

    Only ever called with the part before `--`.
    """
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


# TOML basic strings escape a handful of characters and take everything else
# as literal UTF-8. json.dumps() looked close enough and is not: it encodes a
# character outside the basic multilingual plane as a surrogate pair, which TOML
# rejects outright ("escaped character is not a Unicode scalar value"), so a
# single emoji anywhere in the install path broke the whole Codex config.
_TOML_ESCAPES = {'"': '\\"', "\\": "\\\\", "\n": "\\n", "\r": "\\r",
                 "\t": "\\t", "\b": "\\b", "\f": "\\f"}


def _toml_string(text):
    """A TOML basic string for a -c override."""
    out = ['"']
    for ch in text:
        if ch in _TOML_ESCAPES:
            out.append(_TOML_ESCAPES[ch])
        elif ord(ch) < 0x20 or ord(ch) == 0x7F:
            out.append("\\u%04X" % ord(ch))
        else:
            out.append(ch)
    out.append('"')
    return "".join(out)


def _read(name):
    try:
        with open(os.path.join(HERE, "codex", name), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


def codex_home():
    return os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex")


def codex_args(orchestrate):
    """Everything Codex needs, as -c overrides.

    Nothing is written into ~/.codex. The user's own config, plugins and agents
    are untouched, and a session without the flag is unaffected — the same
    bargain the Claude side makes by injecting agents per session.
    """
    args = [
        "-c", 'model_providers.devinx.name="devinx"',
        "-c", f'model_providers.devinx.base_url="http://{HOST}:{PORT}/v1"',
        "-c", 'model_providers.devinx.wire_api="responses"',
        # Codex then sends its own credential, which devinx relays untouched to
        # the upstream a gpt-* model would have gone to anyway.
        "-c", "model_providers.devinx.requires_openai_auth=true",
        "-c", 'model_provider="devinx"',
        # The V1 multi-agent surface. On V2 a spawned agent's task is ciphertext
        # only OpenAI can open, so a SWE-2 executor would receive the envelope
        # and none of the letter; on V1 the same task arrives in the clear.
        "-c", "features.multi_agent_v2.enabled=false",
    ]
    if not orchestrate:
        return args
    for name, description in CODEX_ROLES:
        layer = os.path.join(HERE, "codex", "roles", f"{name}.toml")
        if not os.path.exists(layer):
            continue
        args += ["-c", f"agents.{name}.config_file={_toml_string(layer)}",
                 "-c", f"agents.{name}.description={_toml_string(description)}"]
    # Everything under [agents] is parsed as a role except a short list of
    # recognised scalars, so the doctrine cannot be injected there — an
    # unrecognised scalar is read as a role name and fails config loading
    # outright. This one is recognised, and it is the important one: every agent
    # spawned without an explicit override lands on SWE-2 Max.
    args += ["-c", 'agents.default_subagent_model="swe-2-max"']
    # The orchestrator skill travels as a Codex plugin, and a plugin has to be
    # enabled in config rather than pointed at on the command line — Codex has
    # no --plugin-dir. A -c override cannot do it either: the key holds a quoted
    # segment (plugins."name@marketplace".enabled) that the dotted-path parser
    # does not reach, so the entry stays at whatever config.toml says.
    #
    # A profile does exactly what is wanted instead. install.py writes
    # devinx.config.toml next to config.toml, where it is inert, and selecting
    # it here layers the marketplace and the enable on top for this session
    # only. A plain codex session never names the profile and so never sees the
    # skill.
    if os.path.exists(os.path.join(codex_home(), "devinx.config.toml")):
        args += ["-p", "devinx"]
    return args


def plugin_args(enabled):
    """Inject the bundled orchestrator skill, only when --or asked for it.

    --plugin-dir is per-session, which puts the skill on the same footing as the
    agents: it exists where it was asked for and nowhere else. Copying it into
    ~/.claude/skills would advertise an orchestrator in every plain session,
    where the swe2-* agents it delegates to do not exist. The flag is
    repeatable, so one the user passed themselves is unaffected.
    """
    if not enabled:
        return []
    plugin = os.path.join(HERE, "plugin")
    if not os.path.isdir(plugin):
        return []
    return ["--plugin-dir", plugin]


def local_build():
    """The fingerprint of the devinx.py sitting next to this launcher."""
    try:
        with open(os.path.join(HERE, "devinx.py"), "rb") as fh:
            return hashlib.sha1(fh.read()).hexdigest()[:12]
    except OSError:
        return None


def service_state():
    """Return (state, info) for whatever holds the port.

    absent  - nothing is listening
    foreign - something is, but it is not devinx
    stale   - devinx, running code older than the file on disk
    fresh   - devinx, running this code

    The service deliberately outlives the sessions that use it, so closing a
    session does not restart it and a pull leaves last week's code serving
    today's launcher. Checking only that *something* answers is what let that
    happen silently.
    """
    with socket.socket() as sock:
        sock.settimeout(0.5)
        if sock.connect_ex((HOST, PORT)) != 0:
            return "absent", {}
    try:
        with urllib.request.urlopen(
                f"http://{HOST}:{PORT}/api/hello", timeout=3) as r:
            info = json.loads(r.read())
    except Exception:
        # A devinx old enough to predate /api/hello still answers /v1/models.
        return ("stale", {}) if listening() else ("foreign", {})
    if info.get("service") != "devinx":
        return "foreign", {}
    want = local_build()
    if want and info.get("build") != want:
        return "stale", info
    return "fresh", info


def stop_service(info):
    """Stop a devinx we identified ourselves. Never a pid we merely guessed."""
    pid = info.get("pid")
    if not isinstance(pid, int):
        return False
    try:
        if sys.platform == "win32":
            subprocess.run(["taskkill", "/PID", str(pid), "/F"],
                           capture_output=True)
        else:
            os.kill(pid, signal.SIGTERM)
    except (OSError, ProcessLookupError):
        return False
    deadline = time.time() + 10
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.5)
            if sock.connect_ex((HOST, PORT)) != 0:
                return True
        time.sleep(0.2)
    return False


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
    use_devin, use_orch, use_codex, passthrough = split_args(sys.argv[1:])

    client = "codex" if use_codex else "claude"
    binary = shutil.which(client)
    if not binary:
        sys.stderr.write(f"{client} not found on PATH - install it first\n")
        return 1
    claude = binary

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

    state, info = service_state()
    if state == "stale":
        # Restarting under a turn that is mid-flight would cut it in half, so a
        # busy service is reported rather than replaced.
        if info.get("inflight"):
            sys.stderr.write(
                f"devinx: the service on {PORT} is running older code and is "
                f"busy ({info['inflight']} request(s) in flight).\n"
                f"        Continuing with it. Restart when it is idle: "
                f"kill {info.get('pid', '<pid>')}\n")
            state = "fresh"
        elif stop_service(info):
            print("devinx: replacing a service running older code", flush=True)
            state = "absent"
        else:
            sys.stderr.write(
                "devinx: the service on this port is running older code and "
                "could not be stopped automatically.\n"
                "        Stop it by hand and run again"
                + (f": kill {info['pid']}\n" if info.get("pid") else ".\n"))
            state = "fresh"

    if state != "fresh":
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

    if use_codex:
        # Codex is configured entirely through -c overrides, so none of the
        # Anthropic environment applies and nothing of the user's own config is
        # touched. It authenticates as itself; devinx relays that credential.
        args = [binary] + codex_args(use_orch) + passthrough
        if sys.platform == "win32":
            return subprocess.call(args, env=env)
        os.execvpe(binary, args, env)

    for name in SCRUB:
        env.pop(name, None)
    env.update(ENV)

    # Deliberately no --dangerously-skip-permissions. Choosing a model and
    # choosing to run tools unattended are separate decisions, and this tool has
    # no business making the second one on the user's behalf: pass the flag
    # yourself if you want it.
    head, tail = split_at_separator(passthrough)
    args = ([claude] + merge_agents(head, packaged_agents())
            + plugin_args(use_orch) + tail)
    if sys.platform == "win32":
        # No exec() on Windows that preserves the console properly; run as a child
        # and hand back its exit code.
        return subprocess.call(args, env=env)
    os.execvpe(claude, args, env)


if __name__ == "__main__":
    sys.exit(main())
