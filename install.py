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
import urllib.request
import venv

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


def deps_satisfied(py):
    return subprocess.run([py, "-c", "import requests, google.protobuf"],
                          capture_output=True).returncode == 0


def make_venv(force):
    py = venv_python(HERE)
    root = os.path.join(HERE, ".venv")
    req = os.path.join(HERE, "requirements.txt")
    uv = shutil.which("uv")

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
    pattern = re.compile(rf"^\s*(?:function\s+)?{name}\s*\(\s*\)|^\s*alias\s+{name}=",
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
            if "devinx" in text:
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
    stale = [n for n in agent_files()
             if os.path.exists(os.path.expanduser(f"~/.claude/agents/{n}"))]
    if stale:
        say(WARN, f"{len(stale)} agent file(s) from an older install are still "
                  f"in ~/.claude/agents:")
        print("        " + ", ".join(stale))
        print("        They shadow the session-scoped ones and stay visible "
              "outside devin mode.\n"
              "        Remove them by hand once you are happy with this "
              "install.")


def install_agents(force):
    dest = os.path.expanduser("~/.claude/agents")
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
        shutil.copyfile(src, target)
        installed.append(name)
    if installed:
        say(OK, f"agents installed: {', '.join(installed)}")
    if kept:
        say(WARN, f"agents already present, left untouched: {', '.join(kept)}")


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
    env = dict(os.environ, DEVINX_PORT=str(port))
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

        with urllib.request.urlopen(base + "/v1/models", timeout=10) as r:
            models = [m["id"] for m in json.loads(r.read())["data"]]
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
        with urllib.request.urlopen(req, timeout=180) as r:
            d = json.loads(r.read())
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
    py = make_venv(args.force)
    os.makedirs(data_dir(), exist_ok=True)
    say(OK, f"data directory: {data_dir()}")
    if args.global_agents:
        install_agents(args.force)
    else:
        report_agents()
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
