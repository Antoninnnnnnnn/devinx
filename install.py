#!/usr/bin/env python3
"""devinx installer - Windows, macOS and Linux.

    python3 install.py [--force] [--port 8316] [--no-smoke] [--bin DIR]

Creates a virtualenv next to this file, installs the two pinned dependencies,
drops a `devinx` launcher on PATH and runs a smoke test end to end. The subagents
and the orchestrator skill are injected per session by the launcher, so nothing is
written into ~/.claude unless you ask for it with --global-agents. Uses the
standard library only, so it runs before any dependency exists.
"""
import argparse
import glob
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
import venv

import diagnostics
import launcher

HERE = os.path.dirname(os.path.abspath(__file__))
MIN_PYTHON = (3, 10)

OK, WARN, BAD = "[ ok ]", "[warn]", "[fail]"


def say(tag, msg):
    print(f"{tag} {msg}", flush=True)


def die(msg):
    say(BAD, msg)
    sys.exit(1)


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


def agent_files():
    """Every agents/*.md the launcher injects.

    Globbed rather than listed: a role added to the package is picked up here
    without editing a constant that nothing else would notice was stale.
    """
    return sorted(os.path.basename(p)
                  for p in glob.glob(os.path.join(HERE, "agents", "*.md")))


def venv_python(root):
    if sys.platform == "win32":
        return os.path.join(root, ".venv", "Scripts", "python.exe")
    return os.path.join(root, ".venv", "bin", "python")


def default_bin():
    if sys.platform == "win32":
        return os.path.normpath(os.path.join(os.path.expanduser("~"), ".local", "bin"))
    return os.path.normpath(os.path.expanduser("~/.local/bin"))


def free_port():
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


# --------------------------------------------------------------------------- #

def check_python():
    if sys.version_info < MIN_PYTHON:
        die(f"Python {MIN_PYTHON[0]}.{MIN_PYTHON[1]}+ required, "
            f"found {sys.version.split()[0]}")
    say(OK, f"Python {sys.version.split()[0]}")


def check_descriptors():
    d = os.path.join(HERE, "descriptors")
    n = len([f for f in os.listdir(d) if f.endswith(".fdp")]) \
        if os.path.isdir(d) else 0
    if not n:
        die("no descriptors/*.fdp in the package - run extract_fdps.py descriptors")
    say(OK, f"{n} protobuf descriptors")


def has_ensurepip():
    """Debian and Ubuntu ship the stdlib without ensurepip (it lives in the
    separate python3-venv package), so venv.EnvBuilder(with_pip=True) raises
    there even though `import venv` succeeds."""
    try:
        import ensurepip  # noqa: F401
        return True
    except ImportError:
        return False


def check_claude():
    """devinx drives Claude Code, it does not install it. Checked here rather
    than left for the launcher to discover at first run."""
    claude = shutil.which("claude")
    if claude:
        say(OK, f"Claude Code found: {claude}")
    else:
        say(WARN, "claude is not on PATH - devinx has nothing to launch.")
        print("        Install Claude Code first: https://claude.com/claude-code")
    return bool(claude)


# Importable is not the same as the versions requirements.txt pins. A virtualenv
# left over from an older install imports both modules perfectly well while
# holding versions this code was never run against, and the installer would then
# report "dependencies already satisfied" and change nothing.
_VERSION_CHECK = """
import sys
from importlib.metadata import version, PackageNotFoundError
ok = True
for line in open(sys.argv[1], encoding='utf-8'):
    line = line.split('#')[0].strip()
    if '==' not in line:
        continue
    name, want = line.split('==', 1)
    try:
        if version(name.strip()) != want.strip():
            ok = False
    except PackageNotFoundError:
        ok = False
sys.exit(0 if ok else 1)
"""


def deps_satisfied(py):
    return subprocess.run(
        [py, "-c", _VERSION_CHECK, os.path.join(HERE, "requirements.txt")],
        capture_output=True).returncode == 0


def _running_service(port):
    """The /api/hello payload of a devinx already listening on port, or None.

    --force clears this exact virtualenv (venv.EnvBuilder(clear=True)); the
    daemon a launcher generated from this install starts is exec'd with this
    venv's own python, so a service still up on the configured port is almost
    certainly running from the directory --force is about to empty out from
    under it.
    """
    state, info = diagnostics.read_service("127.0.0.1", port)
    return info if state == "running" else None


def make_venv(force, port=None):
    py = venv_python(HERE)
    root = os.path.join(HERE, ".venv")
    req = os.path.join(HERE, "requirements.txt")
    uv = shutil.which("uv")

    if force and port is not None:
        running = _running_service(port)
        if running:
            pid = running.get("pid")
            hint = f" ({launcher._kill_hint(pid)})" if isinstance(pid, int) else ""
            die(f"a devinx service is already running on port {port}{hint} - "
                f"--force would delete the virtualenv it is running from.\n"
                f"       Stop it first, then run install.py --force again.")

    if os.path.exists(py) and not force:
        say(OK, "virtualenv already present")
        if deps_satisfied(py):
            say(OK, "dependencies already satisfied")
            return py
    elif has_ensurepip():
        say(OK, "creating virtualenv")
        venv.EnvBuilder(with_pip=True, clear=force).create(root)
    elif uv:
        say(OK, "creating virtualenv with uv (stdlib ensurepip unavailable)")
        r = subprocess.run([uv, "venv", "--python", sys.executable, root],
                           capture_output=True, text=True)
        if r.returncode:
            die(f"uv venv failed:\n{r.stdout}\n{r.stderr}")
    else:
        die("cannot create a virtualenv: this Python has no ensurepip and uv is "
            "not installed.\n       install one of them, e.g.  "
            "sudo apt install python3-venv   or   pipx install uv")

    if uv and not has_ensurepip():
        cmd = [uv, "pip", "install", "--python", py, "-r", req]
    else:
        cmd = [py, "-m", "pip", "install", "--quiet",
               "--disable-pip-version-check", "-r", req]
    r = subprocess.run(cmd, capture_output=True, text=True)
    if r.returncode:
        die(f"dependency install failed:\n{r.stdout}\n{r.stderr}")
    say(OK, "dependencies installed (protobuf, requests)")
    return py


def install_launcher(bindir, port, force):
    os.makedirs(bindir, exist_ok=True)
    py = venv_python(HERE)
    launcher = os.path.join(HERE, "launcher.py")

    # Named `devinx`, never `cc`: on Unix `cc` is the C compiler that make,
    # autoconf and cgo all invoke by name, and ~/.local/bin is prepended to PATH
    # on most distributions, so installing a `cc` there hijacks every build on
    # the machine. `cc` is also commonly a personal wrapper; see the README for
    # wiring --devin into one.
    if sys.platform == "win32":
        path = os.path.join(bindir, "devinx.cmd")
        body = ('@echo off\r\n'
                'rem generated by devinx install.py\r\n'
                'setlocal\r\n'
                f'if not defined DEVINX_PORT set "DEVINX_PORT={port}"\r\n'
                f'"{py}" "{launcher}" %*\r\n'
                'exit /b %errorlevel%\r\n')
    else:
        path = os.path.join(bindir, "devinx")
        body = ('#!/bin/sh\n'
                '# generated by devinx install.py\n'
                f'DEVINX_PORT="${{DEVINX_PORT:-{port}}}"\n'
                'export DEVINX_PORT\n'
                f'exec "{py}" "{launcher}" "$@"\n')

    if os.path.exists(path) and not force:
        say(WARN, f"{path} exists - keeping it (use --force to overwrite)")
    else:
        with open(path, "w", newline="") as fh:
            fh.write(body)
        if sys.platform != "win32":
            os.chmod(path, 0o755)
        say(OK, f"launcher installed: {path}")

    on_path = any(os.path.normcase(os.path.abspath(p)) ==
                  os.path.normcase(os.path.abspath(bindir))
                  for p in os.environ.get("PATH", "").split(os.pathsep) if p)
    if not on_path:
        say(WARN, f"{bindir} is not on PATH - add it to use "
                  f"`{os.path.basename(path)}` directly")
    warn_shadowed(path)
    return path


def warn_shadowed(path):
    """A shell function or alias with the launcher's name wins over anything on
    PATH, so the launcher can be installed successfully and still never run.
    Python cannot see the live shell's functions, but the rc files that define
    them are readable."""
    name = os.path.basename(path).split(".")[0]
    escaped = re.escape(name)
    pattern = re.compile(rf"^\s*(?:function\s+)?{escaped}\s*\(\s*\)|^\s*alias\s+{escaped}=",
                         re.M)
    for rc in ("~/.bashrc", "~/.bash_profile", "~/.bash_aliases", "~/.zshrc",
               "~/.profile"):
        p = os.path.expanduser(rc)
        try:
            with open(p, encoding="utf-8", errors="replace") as fh:
                text = fh.read()
        except OSError:
            continue
        m = pattern.search(text)
        if m:
            line = text[:m.start()].count("\n") + 1
            # Checking for the literal name (`devinx`) here is tautological:
            # the match that got us into this branch already requires that
            # exact string, so it is always present and this check could
            # never fire the warning below. Looking for the actual launcher
            # script instead — the thing the README's wiring snippet delegates
            # to — tells shadowing-but-wired-through apart from shadowing.
            if "launcher.py" in text:
                # Already wired to delegate; shadowing the PATH launcher is then
                # intentional rather than a problem.
                say(OK, f"{rc}:{line} defines `{name}` and already handles devinx")
            else:
                say(WARN, f"{rc}:{line} already defines `{name}` as a shell "
                          f"function or alias.")
                print(f"        It takes precedence over {path}, which will "
                      f"never run.\n"
                      f"        Either add --devin handling to it, or "
                      f"rename/remove it.")
            return

    other = shutil.which(name)
    if other and os.path.normcase(os.path.abspath(other)) != \
            os.path.normcase(os.path.abspath(path)):
        say(WARN, f"`{name}` on PATH resolves to {other}, not {path}")


def report_agents():
    """Agents ride on the launcher's --agents flag, so nothing is installed.

    Writing them into ~/.claude/agents made them visible in every session,
    including plain ones where invoking them fails because nothing routes swe-2
    models. It also wrote into a directory the user may have relocated with
    CLAUDE_CONFIG_DIR.
    """
    names = sorted(os.path.splitext(n)[0] for n in agent_files())
    say(OK, f"agents injected per session: {', '.join(names)}")
    agents_dir = os.path.join(claude_config_dir(), "agents")
    stale = [n for n in agent_files()
             if os.path.exists(os.path.join(agents_dir, n))]
    if stale:
        say(WARN, f"{len(stale)} agent file(s) from an older install are still "
                  f"in {agents_dir}:")
        print("        " + ", ".join(stale))
        print("        A file on disk there is a plain project/user agent, no "
              "different to one you wrote yourself, so it stays visible in "
              "every session, devin mode or not - the opposite of what "
              "session-scoped injection is for. Remove it by hand once you "
              "are happy with this install.")


def report_skill():
    """The orchestrator skill rides on the launcher's --plugin-dir, which is
    added only for --or (plugin_args() is called with use_orch, not
    use_devin) - unlike the agents, it does not exist in a plain --devin
    session, only one that also asked for --or."""
    skills = sorted(glob.glob(os.path.join(HERE, "plugin", "skills", "*",
                                           "SKILL.md")))
    if not skills:
        say(WARN, "no orchestrator skill in plugin/skills - devin sessions will "
                  "have the agents but no orchestration guidance")
        return
    # Plugin skills are invoked plugin-qualified, so report the name the user
    # will actually type rather than the bare directory name.
    try:
        with open(os.path.join(HERE, "plugin", ".claude-plugin", "plugin.json"),
                  encoding="utf-8") as fh:
            prefix = json.load(fh).get("name", "devinx")
    except (OSError, ValueError):
        prefix = "devinx"
    names = ", ".join(f"/{prefix}:{os.path.basename(os.path.dirname(p))}"
                      for p in skills)
    say(OK, f"skill available with --or: {names}")


def _with_mcp_deny(text):
    """Match launcher.packaged_agents(): a session-injected agent gets
    disallowedTools: [..., "mcp__*"] unless DEVINX_SUBAGENT_MCP=1, but a
    globally-installed one was a byte-for-byte copy of the source file and
    never got it, silently weaker than the README says it is.
    """
    if os.environ.get("DEVINX_SUBAGENT_MCP") == "1" or not text.startswith("---"):
        return text
    _, _, rest = text.partition("---")
    front, sep, body = rest.partition("\n---")
    if not sep:
        return text
    lines = front.splitlines()
    for i, line in enumerate(lines):
        key, colon, value = line.partition(":")
        if colon and key.strip() == "disallowedTools":
            tools = [t.strip() for t in value.split(",") if t.strip()]
            if "mcp__*" not in tools:
                tools.append("mcp__*")
            lines[i] = "disallowedTools: " + ", ".join(tools)
            break
    else:
        lines.append("disallowedTools: mcp__*")
    return "---" + "\n".join(lines) + "\n---" + body


def install_agents(force):
    dest = os.path.join(claude_config_dir(), "agents")
    os.makedirs(dest, exist_ok=True)
    installed, kept = [], []
    for name in agent_files():
        src = os.path.join(HERE, "agents", name)
        if not os.path.exists(src):
            say(WARN, f"missing agent definition {name}")
            continue
        target = os.path.join(dest, name)
        if os.path.exists(target) and not force:
            kept.append(name)
            continue
        # A UTF-8 BOM (utf-8-sig) at the start of the file would make the
        # "---" frontmatter check below fail to match, silently skipping the
        # deny-list patch for that one file.
        with open(src, encoding="utf-8-sig") as fh:
            text = fh.read()
        with open(target, "w", encoding="utf-8") as fh:
            fh.write(_with_mcp_deny(text))
        installed.append(name)
    if installed:
        say(OK, f"agents installed: {', '.join(installed)}")
    if kept:
        say(WARN, f"agents already present, left untouched: {', '.join(kept)}")


def claude_config_dir():
    """Claude Code itself honours CLAUDE_CONFIG_DIR to relocate ~/.claude;
    hard-coding the default here meant --global-agents (and the stale-file
    check) looked in the wrong place for anyone who has moved it."""
    return os.environ.get("CLAUDE_CONFIG_DIR") or os.path.expanduser("~/.claude")


def codex_home():
    return os.environ.get("CODEX_HOME") or os.path.expanduser("~/.codex")


def strip_plugin_entry(path, entry):
    """Remove one [plugins."..."] block from config.toml, leaving the rest alone.

    `codex plugin add` enables the plugin for every session as a side effect of
    installing it, which is the opposite of the arrangement here: the profile
    decides. Only the exact block that command writes is removed.

    The section runs to the next header, but a run of comments at its end,
    directly before that header, introduces the *next* section by convention and
    is kept. Everything else in the body must be `enabled` and blank lines; a
    comment or a setting of the user's own anywhere else means the block is left
    untouched. Removing the header while leaving a setting behind would silently
    re-parent it into the preceding section — the file stays valid and changes
    meaning, which is the worst outcome available here.
    """
    try:
        with open(path, encoding="utf-8") as fh:
            lines = fh.readlines()
    except OSError:
        return False
    header = f'[plugins."{entry}"]'
    out, i, removed = [], 0, False
    while i < len(lines):
        if lines[i].strip() != header:
            out.append(lines[i])
            i += 1
            continue
        end = i + 1
        while end < len(lines) and not lines[end].lstrip().startswith("["):
            end += 1
        body = lines[i + 1:end]
        # Comments trailing the body belong to whatever comes next, not here.
        keep_from = len(body)
        while keep_from > 0:
            stripped = body[keep_from - 1].strip()
            if not stripped or stripped.startswith("#"):
                keep_from -= 1
            else:
                break
        trailing = body[keep_from:] if end < len(lines) else []
        own = body[:keep_from] if end < len(lines) else body
        settings = [b.strip() for b in own if b.strip()]
        if settings and all(b.split("=")[0].strip() == "enabled" for b in settings):
            removed = True
            while out and not out[-1].strip():
                out.pop()
            out.append("\n")
            out.extend(trailing)
            i = end
        else:
            say(WARN, f"{path} has settings of its own under {header}; "
                      f"leaving the whole block alone")
            out.append(lines[i])
            i += 1
    if removed:
        with open(path, "w", encoding="utf-8") as fh:
            fh.writelines(out)
    return removed


def install_codex(force):
    """Install the Codex side: a profile file, and the plugin cache it needs.

    The profile sits next to config.toml and does nothing until `-p devinx`
    selects it, which the launcher passes only for --codex --or. A plain codex
    session never names it, so the skill is invisible there — the same promise
    the Claude side keeps with a session-scoped --plugin-dir.
    """
    market = os.path.join(HERE, "codex", "marketplace")
    if not os.path.isdir(market):
        say(WARN, "no codex/marketplace in the package - skipping the Codex skill")
        return
    if not shutil.which("codex"):
        say(WARN, "codex is not on PATH - skipping the Codex orchestrator skill")
        return
    home = codex_home()
    os.makedirs(home, exist_ok=True)
    profile = os.path.join(home, "devinx.config.toml")
    if os.path.exists(profile) and not force:
        say(WARN, f"{profile} exists - keeping it (use --force to overwrite)")
    else:
        # market is a filesystem path, pasted verbatim into a config file
        # Codex will parse as TOML: an unescaped quote, backslash (every
        # Windows path) or non-BMP character (an emoji anywhere in the
        # install path) produced a broken profile. _toml_string() is the
        # same escaping launcher.py already uses for its own -c overrides.
        with open(profile, "w", encoding="utf-8") as fh:
            fh.write("# Written by devinx install.py. Inert unless selected with\n"
                     "# `-p devinx`, which the devinx launcher passes only for\n"
                     "# --codex --or sessions.\n"
                     "[marketplaces.devinx]\n"
                     'source_type = "local"\n'
                     f'source = {launcher._toml_string(market)}\n\n'
                     '[plugins."swe-orchestrator@devinx"]\n'
                     "enabled = true\n")
        say(OK, f"codex profile written: {profile}")

    # The plugin has to be materialised into the cache; a profile alone leaves
    # it "not installed" and the skill never loads. Same escaping concern as
    # the profile file above, this time for a -c override on the command line.
    r = subprocess.run(
        ["codex", "-c", 'marketplaces.devinx.source_type="local"',
         "-c", f'marketplaces.devinx.source={launcher._toml_string(market)}',
         "plugin", "add", "swe-orchestrator@devinx"],
        capture_output=True, text=True)
    if r.returncode:
        say(WARN, "could not install the Codex plugin:\n        "
                  + (r.stderr or r.stdout).strip()[:300])
        return
    say(OK, "codex plugin installed: swe-orchestrator@devinx")
    if strip_plugin_entry(os.path.join(home, "config.toml"),
                          "swe-orchestrator@devinx"):
        say(OK, "removed the global enable it wrote; the profile decides instead")


def check_credential():
    """The Devin login is interactive and per-machine; it cannot be automated."""
    dd = data_dir()
    candidates = (os.path.join(dd, "devin", "credentials.toml"),
                  os.path.expanduser("~/devin-shim/data/devin/credentials.toml"),
                  os.path.expanduser("~/.local/share/devin/credentials.toml"))
    for c in candidates:
        if os.path.exists(c):
            say(OK, f"Devin credential found: {c}")
            return True
    say(WARN, "no Devin credential yet - SWE-2 subagents will not work until you run:")
    if sys.platform == "win32":
        print(f'        set "XDG_DATA_HOME={dd}" && devin auth login')
    else:
        print(f'        XDG_DATA_HOME="{dd}" devin auth login')
    return False


def smoke(py, have_credential):
    port = free_port()
    # DEVINX_DASHBOARD_PORT=0: the smoke instance is transient and on a port
    # nothing else knows about, so its dashboard listener has no business
    # binding a real port (8317 by default) that a concurrent real service
    # would want.
    env = dict(os.environ, DEVINX_PORT=str(port), DEVINX_DASHBOARD_PORT="0")
    log = open(os.path.join(data_dir(), "install-smoke.log"), "wb")
    os.makedirs(data_dir(), exist_ok=True)
    proc = subprocess.Popen([py, os.path.join(HERE, "devinx.py")],
                            stdout=log, stderr=log, stdin=subprocess.DEVNULL,
                            cwd=HERE, env=env)
    try:
        base = f"http://127.0.0.1:{port}"
        deadline = time.time() + 30
        while time.time() < deadline:
            with socket.socket() as s:
                s.settimeout(0.5)
                if s.connect_ex(("127.0.0.1", port)) == 0:
                    break
            if proc.poll() is not None:
                die(f"devinx exited during smoke test - see "
                    f"{os.path.join(data_dir(), 'install-smoke.log')}")
            time.sleep(0.5)
        else:
            die("devinx did not start within 30s")

        try:
            with urllib.request.urlopen(base + "/v1/models", timeout=10) as r:
                models = [m["id"] for m in json.loads(r.read())["data"]]
        except urllib.error.HTTPError as error:
            die(f"smoke test: /v1/models returned HTTP {error.code} - "
                f"{error.read()[:300]!r}")
        except (urllib.error.URLError, OSError, ValueError) as error:
            die(f"smoke test: could not reach /v1/models - {error}")
        say(OK, f"service responds: {', '.join(models)}")

        if not have_credential:
            say(WARN, "skipping the live SWE-2 call (no credential yet)")
            return
        # Budget has to cover the reasoning too: SWE-2 always emits a thinking
        # block first, and a tight max_tokens gets spent there before any text.
        body = json.dumps({"model": "swe-2-medium", "max_tokens": 256,
                           "messages": [{"role": "user",
                                         "content": "Reply with exactly: INSTALL-OK"}]}).encode()
        req = urllib.request.Request(base + "/v1/messages", body,
                                     {"content-type": "application/json",
                                      "anthropic-version": "2023-06-01"})
        try:
            with urllib.request.urlopen(req, timeout=180) as r:
                d = json.loads(r.read())
        except urllib.error.HTTPError as error:
            die(f"smoke test: the live SWE-2 call returned HTTP {error.code} - "
                f"{error.read()[:300]!r}")
        except (urllib.error.URLError, OSError, ValueError) as error:
            die(f"smoke test: the live SWE-2 call failed - {error}")
        text = "".join(b.get("text", "") for b in d.get("content", [])
                       if b.get("type") == "text")
        usage = d.get("usage", {})
        if "INSTALL-OK" in text:
            say(OK, f"live SWE-2 call succeeded ({usage.get('input_tokens')} in / "
                    f"{usage.get('output_tokens')} out)")
        elif text:
            say(OK, f"live SWE-2 call succeeded, wording differs: {text[:60]!r}")
        else:
            say(WARN, f"SWE-2 returned no text (stop_reason="
                      f"{d.get('stop_reason')}) - the call reached the model, "
                      f"but produced nothing usable")
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            proc.kill()
        log.close()


def main():
    ap = argparse.ArgumentParser(description="Install devinx.")
    ap.add_argument("--force", action="store_true",
                    help="overwrite an existing launcher, agents and virtualenv")
    ap.add_argument("--port", type=int, default=8316, help="service port")
    ap.add_argument("--bin", default=default_bin(), help="where to put the launcher")
    ap.add_argument("--no-smoke", action="store_true", help="skip the smoke test")
    ap.add_argument("--global-agents", action="store_true",
                    help="also install the agents into ~/.claude/agents, making "
                         "them visible outside devin mode (not recommended)")
    args = ap.parse_args()

    print(f"devinx installer - {sys.platform}\n")
    check_python()
    check_claude()
    check_descriptors()
    py = make_venv(args.force, args.port)
    os.makedirs(data_dir(), exist_ok=True)
    say(OK, f"data directory: {data_dir()}")
    if args.global_agents:
        install_agents(args.force)
    else:
        report_agents()
    report_skill()
    install_codex(args.force)
    path = install_launcher(args.bin, args.port, args.force)
    have_credential = check_credential()
    if not args.no_smoke:
        smoke(py, have_credential)

    print()
    say(OK, "done")
    dx = "devinx" if sys.platform != "win32" else "devinx.cmd"
    py = venv_python(HERE)
    print(f"\n    {dx}                plain Claude Code, no proxy\n"
          f"    {dx} --devin        with the SWE-2 layer  (--d for short)\n"
          f"    {dx} --d --resume   composes with any claude flag\n\n"
          f"    {dx} --or            adds /devinx:swe-orchestrator (implies "
          f"--devin)\n\n"
          f"    launcher: {path}\n"
          f"    plain `claude` still works and bypasses devinx entirely.\n"
          f"    devinx never adds --dangerously-skip-permissions; pass it "
          f"yourself if you want it.\n")
    if sys.platform != "win32":
        print(f"    Already have your own `cc`? Add --devin to it instead of "
              f"using {dx}:\n\n"
              f'        --devin|--d) exec "{py}" "{os.path.join(HERE, "launcher.py")}"'
              f' --devin "$@" ;;\n')


if __name__ == "__main__":
    main()
