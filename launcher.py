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
from runtime_support import CONFIG_FIELDS, build_id, startup_lock

def _port_env(name, default):
    """A bad DEVINX_PORT must not crash the launcher before main() ever runs
    (this line executes at import time): fall back to the default and say so,
    the same clear-error spirit as _validate_devinx_env() below."""
    raw = os.environ.get(name)
    if raw is None:
        return default
    try:
        return int(raw)
    except ValueError:
        sys.stderr.write(f"devinx: {name}={raw!r} is not a valid integer; "
                         f"using {default}\n")
        return default


HERE = os.path.dirname(os.path.abspath(__file__))
PORT = _port_env("DEVINX_PORT", 8316)
HOST = "127.0.0.1"
START_TIMEOUT = 40
# Must match devinx.SWE_ALIAS: the id the service advertises and the launcher
# selects, and the one the readiness probe identifies devinx by.
SWE_ALIAS = "swe-2"

# Cleared so Claude Code falls back to its own claude.ai login. A leftover API key
# or OAuth token in the environment would make it authenticate as something else.
# Also cleared: anything that redirects the client to a different backend
# entirely (Bedrock, Vertex, a custom header set) — devin mode routes claude-*
# straight to api.anthropic.com, and a lingering provider override would take
# the model there instead, silently, with no relation to devinx at all.
SCRUB = (
    "ANTHROPIC_AUTH_TOKEN", "ANTHROPIC_API_KEY", "ANTHROPIC_MODEL",
    "ANTHROPIC_DEFAULT_OPUS_MODEL", "ANTHROPIC_DEFAULT_SONNET_MODEL",
    "ANTHROPIC_DEFAULT_HAIKU_MODEL", "CLAUDE_CODE_OAUTH_TOKEN",
    "CLAUDE_CODE_USE_BEDROCK", "CLAUDE_CODE_USE_VERTEX",
    "ANTHROPIC_CUSTOM_HEADERS", "ANTHROPIC_BEDROCK_BASE_URL",
    "ANTHROPIC_VERTEX_BASE_URL", "ANTHROPIC_VERTEX_PROJECT_ID",
    "CLOUD_ML_REGION",
)

# NO_PROXY additions for the client we launch: it talks to devinx over loopback
# and a shell-level HTTP(S)_PROXY must not swallow that traffic. Appended, never
# set outright, so a proxy that legitimately excludes other hosts keeps doing so.
NO_PROXY_HOSTS = ("127.0.0.1", "localhost")


def _add_no_proxy(env):
    for var in ("NO_PROXY", "no_proxy"):
        existing = [h for h in env.get(var, "").split(",") if h]
        for host in NO_PROXY_HOSTS:
            if host not in existing:
                existing.append(host)
        env[var] = ",".join(existing)

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
    # And the window must not be enforced locally, because for a subagent that
    # enforcement is fatal rather than corrective. Measured against 2.1.272 with
    # a window declared at 20k and a task needing more: the subagent dies with
    # "Agent terminated early due to an API error: Prompt is too long (error
    # type invalid_request)" and devinx never receives a single request — the
    # client refuses on its own estimate, without compacting and without asking.
    # With this set, the same subagent runs to completion, turns of 37k and 58k
    # reaching the upstream that was always willing to take them.
    #
    # The window above still does real work: it is what /context shows, and what
    # the overflow message reports as the maximum. What changes is who decides.
    # A turn that genuinely exceeds what SWE-2 accepts now gets refused by the
    # upstream, and that refusal the client does recover from — measured, it
    # compacts and finishes the task. Set DEVINX_ENFORCE_WINDOW=1 to put the
    # local cap back.
    **({} if os.environ.get("DEVINX_ENFORCE_WINDOW") == "1" else
       {"CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT": "1"}),
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

# One-run opt-out when DEVINX_ALWAYS=1 has made devin mode the default. It only
# cancels that default: an explicit --devin/--or/--codex on the same command
# line still wins, so `--plain` composes with a script that always adds its own
# flag rather than silently defeating it.
PLAIN_FLAGS = {"--plain"}

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
    use_orch = os.environ.get("DEVINX_ORCHESTRATOR") == "1"
    # DEVINX_ORCHESTRATOR=1 alone must behave like --or, which implies --devin
    # too: the skill delegates to agents that exist only in devin mode.
    use_devin = os.environ.get("DEVINX_ALWAYS") == "1" or use_orch
    use_codex = False
    plain = False
    explicit = False
    out = []
    for i, a in enumerate(argv):
        if a == "--":
            out.extend(argv[i:])
            break
        if a in PLAIN_FLAGS:
            plain = True
            continue
        if a in DEVIN_FLAGS:
            use_devin = True
            explicit = True
            continue
        if a in CODEX_FLAGS:
            # Codex needs the service for the same reason Claude Code does.
            use_codex = True
            use_devin = True
            explicit = True
            continue
        if a in ORCH_FLAGS:
            # The orchestrator delegates to the swe2-* agents, which exist only
            # in devin mode, so asking for it asks for that too.
            use_orch = True
            use_devin = True
            explicit = True
            continue
        out.append(a)
    if plain and not explicit:
        use_devin = False
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

    Only ever called with the part before `--`. Injected --agents is put in
    front of whatever the user already had (rather than appended after it) so
    that a client subcommand elsewhere in the list — `mcp`, `plugin`, `doctor`
    — never ends up ahead of it: those are parsed as positional and stop the
    option parser from recognising anything typed after them.
    """
    if not agents:
        return passthrough
    for i, a in enumerate(passthrough):
        # Both the two-token form (`--agents '{...}'`) and the single-token
        # `--agents={...}` form must be recognised, or the user's own agents
        # are silently ignored instead of merged.
        if a == "--agents" and i + 1 < len(passthrough):
            raw, tail_at = passthrough[i + 1], i + 2
        elif a.startswith("--agents="):
            raw, tail_at = a[len("--agents="):], i + 1
        else:
            continue
        try:
            existing = json.loads(raw)
        except ValueError:
            sys.stderr.write("devinx: --agents is not valid JSON, "
                             "leaving it alone\n")
            return passthrough
        if not isinstance(existing, dict):
            sys.stderr.write("devinx: --agents is valid JSON but not an "
                             "object, so it cannot be merged; the swe2-* "
                             "agents will not be injected\n")
            return passthrough
        merged = dict(agents)
        merged.update(existing)
        return (passthrough[:i] + ["--agents", json.dumps(merged)]
                + passthrough[tail_at:])
    return ["--agents", json.dumps(agents)] + passthrough


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


def codex_home():
    return os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex")


def codex_args(orchestrate, add_profile=True):
    """Everything Codex needs, as -c overrides.

    Nothing is written into ~/.codex. The user's own config, plugins and agents
    are untouched, and a session without the flag is unaffected — the same
    bargain the Claude side makes by injecting agents per session.

    add_profile=False keeps the roles and the default model but leaves out the
    `-p devinx` selection: Codex refuses two `--profile`/-p flags outright, so
    when the user already passed their own, ours has to be skipped rather than
    handed to Codex twice.
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
    if add_profile and os.path.exists(
            os.path.join(codex_home(), "devinx.config.toml")):
        args += ["-p", "devinx"]
    return args


def _has_profile_flag(args):
    """True if the user already named a Codex profile themselves."""
    return any(a == "-p" or a == "--profile" or a.startswith("--profile=")
               for a in args)


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


# cmd.exe's own command-line length limit; a claude.cmd/claude.bat shim (the
# form `npm install -g` produces on Windows) is invoked through cmd.exe even
# when the parent process is not one, so this ceiling applies to the whole
# command line, --agents JSON included, even though a native claude.exe would
# not be bound by it at all.
_WINDOWS_CMDLINE_LIMIT = 8191


def _warn_windows_cmd_shim(binary, args):
    """An --agents payload past cmd.exe's line limit, going through an npm
    shim, fails in a way that looks like nothing to do with its size."""
    if sys.platform != "win32" or not binary.lower().endswith((".cmd", ".bat")):
        return
    length = len(subprocess.list2cmdline(args))
    if length > _WINDOWS_CMDLINE_LIMIT:
        sys.stderr.write(
            f"devinx: the command line is {length} characters, over "
            f"cmd.exe's {_WINDOWS_CMDLINE_LIMIT}-character limit, and "
            f"{binary} runs through cmd.exe even though this process does "
            f"not. The injected --agents JSON is the likely cause; a native "
            f"claude.exe would not have this limit.\n")


def local_build():
    value = build_id(HERE)
    return None if value == "unknown" else value


# A loopback readiness check must not travel through a shell's HTTP proxy —
# diagnostics.py already does this; the launcher's own probes did not, and a
# proxy configured for the rest of the network made a running devinx look
# foreign or made a fresh start time out at 40s waiting for an answer that was
# sent straight to the proxy instead.
_opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))


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
        with _opener.open(f"http://{HOST}:{PORT}/api/hello", timeout=3) as r:
            info = json.loads(r.read())
    except Exception:
        # A devinx old enough to predate /api/hello still answers /v1/models.
        return ("stale", {}) if listening() else ("foreign", {})
    # A well-formed JSON reply that is not an object (e.g. a foreign service
    # that happens to answer with a JSON array) must not crash the launcher.
    if not isinstance(info, dict) or info.get("service") != "devinx":
        return "foreign", {}
    want = local_build()
    if want and info.get("build") != want:
        return "stale", info
    return "fresh", info


def _pid_runs_devinx(pid):
    """POSIX only: confirm the pid's own command line actually runs devinx.py
    before it is ever signalled.

    /api/hello answers with whatever pid the *listening* process reports, and
    that process is not necessarily the one that will receive the signal —
    container namespaces, WSL, or another user's process squatting a freed
    port can all put an unrelated pid in that field. An unreadable cmdline (a
    permission error, a pid that has already exited, a platform with no
    /proc) is treated as *not* verified: refusing to stop is the safe
    direction, and a real devinx always answers this.
    """
    try:
        if sys.platform == "darwin":
            r = subprocess.run(["ps", "-p", str(pid), "-o", "command="],
                               capture_output=True, text=True, timeout=3)
            return r.returncode == 0 and "devinx.py" in r.stdout
        with open(f"/proc/{pid}/cmdline", "rb") as fh:
            return b"devinx.py" in fh.read()
    except (OSError, subprocess.SubprocessError, ValueError):
        return False


def _win_terminate(pid):
    """Ask nicely before taskkill /F.

    Plain `taskkill /PID` sends a close message a console-less, detached
    process (exactly how start_service() launches devinx on Windows) usually
    has no window or message loop to receive — this fallback path is
    therefore unverified on real Windows, but trying the graceful form first
    costs one round trip and never makes the forceful one land later than it
    would have anyway.
    """
    subprocess.run(["taskkill", "/PID", str(pid)], capture_output=True)
    deadline = time.time() + 3
    while time.time() < deadline:
        with socket.socket() as sock:
            sock.settimeout(0.3)
            if sock.connect_ex((HOST, PORT)) != 0:
                return
        time.sleep(0.3)
    subprocess.run(["taskkill", "/PID", str(pid), "/F"], capture_output=True)


def _kill_hint(pid):
    """Platform-appropriate advice for a human to stop the pid by hand."""
    pid_s = str(pid) if pid is not None else "<pid>"
    if sys.platform == "win32":
        return f"taskkill /PID {pid_s} /F"
    return f"kill {pid_s}"


def stop_service(info):
    """Stop a devinx we identified ourselves. Never a pid we merely guessed."""
    pid = info.get("pid")
    # bool is a subclass of int (isinstance(True, int) is True), so it has to
    # be rejected before the int check, and again explicitly: True == 1 would
    # otherwise slip past a bare `pid <= 1` guard too.
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 1:
        return False
    # Never the launcher's own pid or process group: a bug or a race that
    # echoed our own identity back here must not make us signal ourselves,
    # and os.kill(0, ...) / os.kill(-1, ...) reach far more than one process.
    if pid == os.getpid():
        return False
    if sys.platform != "win32":
        if pid == os.getpgrp():
            return False
        if not _pid_runs_devinx(pid):
            return False
    try:
        if sys.platform == "win32":
            _win_terminate(pid)
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
        with _opener.open(f"http://{HOST}:{PORT}/v1/models", timeout=3) as r:
            parsed = json.loads(r.read())
        data = parsed.get("data") or [] if isinstance(parsed, dict) else []
        # The exact alias, not a swe-2* prefix: an older gateway sharing this
        # port advertises swe-2-max and friends without knowing `swe-2`, so a
        # prefix match accepted it as devinx and Claude Code was pointed at a
        # service that would then refuse the model this launcher selects.
        return any(isinstance(m, dict) and m.get("id") == SWE_ALIAS
                   for m in data)
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


# What the detached daemon is allowed to inherit. It outlives every session
# that starts it and is shared by every session that finds it already
# running, so a one-off shell export must not become a permanent, invisible
# part of its configuration.
_DAEMON_ENV_PREFIXES = ("DEVINX_", "XDG_")
_DAEMON_ENV_EXACT = {
    "PATH", "HOME",
    "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "LC_COLLATE", "LC_TIME",
    "LC_NUMERIC", "LC_MESSAGES",
    "TMPDIR", "TMP", "TEMP",
    "LOCALAPPDATA", "APPDATA", "USERPROFILE", "SYSTEMROOT", "SystemRoot",
    # requests/urllib3 read these for outbound calls to the real upstreams; an
    # allowlist that dropped them would silently break every relay behind a
    # corporate proxy or a private CA.
    "HTTP_PROXY", "HTTPS_PROXY", "ALL_PROXY", "NO_PROXY",
    "http_proxy", "https_proxy", "all_proxy", "no_proxy",
    "SSL_CERT_FILE", "SSL_CERT_DIR", "REQUESTS_CA_BUNDLE", "CURL_CA_BUNDLE",
}
# Loud on purpose: these two change what the *service* does for every session
# that shares it afterwards (persisting conversations to disk; dropping the
# browser-origin guard), not just the one that happened to set them.
_LOUD_DAEMON_ENV = ("DEVINX_DUMP", "DEVINX_ALLOW_BROWSER")


def _daemon_env():
    """The environment start_service() launches devinx.py with.

    A detached daemon that inherits the whole shell keeps whatever one session
    happened to have set - DEVINX_DUMP, DEVINX_ALLOW_BROWSER, unrelated
    credentials in the caller's environment - for every later session that
    shares the port, silently. Only what the service actually needs crosses
    over.
    """
    env = {name: value for name, value in os.environ.items()
          if name in _DAEMON_ENV_EXACT
          or any(name.startswith(p) for p in _DAEMON_ENV_PREFIXES)}
    for name in _LOUD_DAEMON_ENV:
        if name in env:
            sys.stderr.write(
                f"devinx: {name} is set - it will apply to every session "
                f"that uses this service from now on, not just this one.\n")
    return env


def start_service():
    """Spawn devinx.py detached so it outlives this launcher and the claude
    run. Returns the Popen handle so a caller can poll for an immediate crash
    instead of only finding out after waiting the full startup timeout."""
    log_dir = data_dir()
    os.makedirs(log_dir, exist_ok=True)
    log = open(os.path.join(log_dir, "devinx.log"), "ab")
    kwargs = {"stdout": log, "stderr": log, "stdin": subprocess.DEVNULL,
              "cwd": HERE, "env": _daemon_env()}
    if sys.platform == "win32":
        # DETACHED_PROCESS | CREATE_NEW_PROCESS_GROUP: no console window, and the
        # service is not killed when the launching terminal closes.
        kwargs["creationflags"] = 0x00000008 | 0x00000200
    else:
        kwargs["start_new_session"] = True
    return subprocess.Popen(
        [sys.executable, os.path.join(HERE, "devinx.py")], **kwargs)


def _log_tail(path, lines=20):
    """The last few lines of the service log, for an error that needs them
    right now rather than a pointer to go read the file."""
    try:
        with open(path, "rb") as fh:
            fh.seek(0, os.SEEK_END)
            size = fh.tell()
            fh.seek(max(0, size - 8192))
            text = fh.read().decode("utf-8", "replace")
        return "\n".join(text.splitlines()[-lines:])
    except OSError:
        return "(no log available)"


def _validate_devinx_env():
    """Reject an unparsable DEVINX_* runtime setting before spawning a service
    that would otherwise start with a silently wrong default, or not at all.

    Uses the same parser diagnostics.py compares the running configuration
    with, so "valid" means the same thing in both places.
    """
    import diagnostics
    bad = []
    for name in CONFIG_FIELDS:
        if name not in os.environ:
            continue
        try:
            diagnostics.parse_config_value(name, os.environ[name])
        except ValueError:
            bad.append(name)
    if bad:
        sys.stderr.write(
            "devinx: not starting - invalid value for "
            + ", ".join(f"{n}={os.environ[n]!r}" for n in bad) + "\n")
        return False
    return True


def ensure_service():
    """Perform the readiness/start sequence once across concurrent launchers."""
    try:
        # A launcher that is already holding the lock can itself take roughly:
        # a stale-service check (a few seconds), an attempted graceful stop
        # (up to 10s), then its own start-and-wait (START_TIMEOUT) - about 53s
        # worst case. A second launcher merely waiting for the lock has to
        # outlast that, or it gives up on a start that was always going to
        # succeed a few seconds later.
        with startup_lock(data_dir(), PORT, START_TIMEOUT + 25):
            state, info = service_state()
            if state == "foreign":
                sys.stderr.write(f"devinx: another service owns {HOST}:{PORT}; not starting or stopping it\n")
                return False
            if state == "stale":
                # Restarting under a turn that is mid-flight would cut it in half, so a
                # busy service is reported rather than replaced.
                if info.get("inflight"):
                    sys.stderr.write(
                        f"devinx: the service on {PORT} is running older code and is "
                        f"busy ({info['inflight']} request(s) in flight).\n"
                        f"        Continuing with it. Restart when it is idle: "
                        f"{_kill_hint(info.get('pid'))}\n")
                    state = "fresh"
                elif stop_service(info):
                    sys.stderr.write("devinx: replacing a service running older code\n")
                    state = "absent"
                else:
                    sys.stderr.write(
                        "devinx: the service on this port is running older code and "
                        "could not be stopped automatically.\n"
                        "        Stop it by hand and run again"
                        + (f": {_kill_hint(info['pid'])}\n" if info.get("pid") else ".\n"))
                    state = "fresh"

            if state == "fresh":
                # A daemon that is already up does not reread its environment;
                # a DEVINX_* setting this run asked for and the running one
                # does not have is silently unapplied unless said out loud.
                import diagnostics
                config = info.get("configuration") if isinstance(info, dict) else {}
                for warning in diagnostics.configuration_mismatches(os.environ, config or {}):
                    sys.stderr.write(f"devinx: {warning}\n")

            if state != "fresh":
                if not _validate_devinx_env():
                    return False
                proc = start_service()
                deadline = time.time() + START_TIMEOUT
                while time.time() < deadline:
                    if listening():
                        break
                    if proc.poll() is not None:
                        log_path = os.path.join(data_dir(), "devinx.log")
                        sys.stderr.write(
                            f"devinx: the service exited immediately "
                            f"(code {proc.returncode}) instead of starting.\n"
                            f"{_log_tail(log_path)}\n")
                        return False
                    time.sleep(0.5)
                else:
                    sys.stderr.write(
                        f"devinx failed to start on {HOST}:{PORT}\n"
                        f"check {os.path.join(data_dir(), 'devinx.log')}\n")
                    return False
            return True
    except (OSError, TimeoutError) as error:
        sys.stderr.write(f"devinx: could not coordinate service startup: {error}\n")
        return False


_KNOWN_OWN_FLAGS = DEVIN_FLAGS | ORCH_FLAGS | CODEX_FLAGS | PLAIN_FLAGS


def _diagnostic_flag(argv):
    """Find a devinx diagnostic flag before `--` and before any client
    subcommand or prompt, e.g. `--d --status` as well as plain `--status`.

    Every token ahead of it has to be one of devinx's own flags, or the
    position is ambiguous - `-p --status` most likely means the client should
    see a literal `--status`, so that is left alone rather than guessed at.
    """
    for a in argv:
        if a == "--":
            return None
        if a in ("--doctor", "--status", "--explain"):
            return a
        if a not in _KNOWN_OWN_FLAGS:
            return None
    return None


def main():
    flag = _diagnostic_flag(sys.argv[1:])
    if flag is not None:
        import diagnostics
        rest = [a for a in sys.argv[1:] if a != flag]
        return diagnostics.main(flag, rest, sys.modules[__name__])
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

    if not ensure_service():
        return 1

    if use_codex:
        has_profile = _has_profile_flag(passthrough)
        if has_profile and use_orch:
            sys.stderr.write(
                "devinx: -p/--profile was already given; the orchestrator "
                "profile was not applied (swe-orchestrator will not load)\n")
        # Codex is configured entirely through -c overrides, so none of the
        # Anthropic environment applies and nothing of the user's own config is
        # touched. It authenticates as itself; devinx relays that credential.
        _add_no_proxy(env)
        args = [binary] + codex_args(use_orch, add_profile=not has_profile) + passthrough
        if sys.platform == "win32":
            return subprocess.call(args, env=env)
        os.execvpe(binary, args, env)

    for name in SCRUB:
        env.pop(name, None)
    env.update(ENV)
    _add_no_proxy(env)

    # Deliberately no --dangerously-skip-permissions. Choosing a model and
    # choosing to run tools unattended are separate decisions, and this tool has
    # no business making the second one on the user's behalf: pass the flag
    # yourself if you want it.
    head, tail = split_at_separator(passthrough)
    # Both injected option groups go right after the binary, ahead of anything
    # of the user's: a client subcommand anywhere in `head` (`mcp`, `plugin`,
    # `doctor`) is parsed as positional and stops recognising options typed
    # after it, which is exactly what broke `devinx --d mcp ...` before.
    args = ([claude] + plugin_args(use_orch)
            + merge_agents(head, packaged_agents()) + tail)
    _warn_windows_cmd_shim(claude, args)
    if sys.platform == "win32":
        # No exec() on Windows that preserves the console properly; run as a child
        # and hand back its exit code.
        return subprocess.call(args, env=env)
    os.execvpe(claude, args, env)


if __name__ == "__main__":
    sys.exit(main())
