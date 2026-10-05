#!/usr/bin/env python3
"""Build, install and run the claude-code-proxy sidecar for devinx's gpt-* route.

    python3 sidecar/build.py [--dest PATH] [--port 18765] [--no-service]
                             [--restart] [--force]

Claude Code on a gpt-* model reaches ChatGPT through this sidecar
(raine/claude-code-proxy), which holds its own ChatGPT login and translates
Messages to Codex Responses. Upstream accepts browser-originated requests and
any Host, so a page the user merely visits could spend that login; the patch
next to this file refuses both. Upstream's install.sh and brew install the
unpatched binary, so this builds it instead: the pinned upstream commit, the
patch, `cargo build --release --locked`.

Linux: the systemd user unit next to this file is installed and started.
Elsewhere the binary is installed and the command to run it is printed.
Standard library only, like install.py.
"""
import argparse
import filecmp
import os
import shutil
import subprocess
import sys
import tempfile

HERE = os.path.dirname(os.path.abspath(__file__))
REPO = "https://github.com/raine/claude-code-proxy.git"
VERSION = "0.1.43"
TAG = f"v{VERSION}"
# The tag's commit. A tag can be moved; the commit cannot, and the patch was
# written against this one.
COMMIT = "49b2c85d61d675217982f85b6ab982b4ae531bc1"
PATCH = os.path.join(HERE, "origin-guard.patch")
UNIT_TEMPLATE = os.path.join(HERE, "claude-code-proxy.service")
UNIT_NAME = "claude-code-proxy.service"
DEFAULT_PORT = 18765
# A string only the patched build carries: how an installed binary is told
# apart from the upstream one it may have been replaced by.
PATCH_MARKER = b"Refusing a browser-originated"

OK, WARN, BAD = "[ ok ]", "[warn]", "[fail]"


class BuildError(Exception):
    pass


def say(tag, msg):
    print(f"{tag} {msg}", flush=True)


def default_dest():
    name = "claude-code-proxy" + (".exe" if sys.platform == "win32" else "")
    return os.path.join(os.path.expanduser("~"), ".local", "bin", name)


def cache_dir():
    """Where the checkout lives between runs, so a rebuild is incremental."""
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Caches")
    else:
        base = os.environ.get("XDG_CACHE_HOME") or os.path.expanduser("~/.cache")
    return os.path.join(base, "devinx", f"claude-code-proxy-{VERSION}")


def find_cargo():
    """cargo on PATH, or where rustup puts it without touching PATH."""
    found = shutil.which("cargo")
    if found:
        return found
    rustup = os.path.join(os.path.expanduser("~"), ".cargo", "bin",
                          "cargo" + (".exe" if sys.platform == "win32" else ""))
    if os.path.isfile(rustup) and os.access(rustup, os.X_OK):
        return rustup
    raise BuildError("cargo not found. Install Rust with rustup "
                     "(https://rustup.rs), then run this again.")


def run(cmd, cwd=None, capture=False):
    try:
        done = subprocess.run(cmd, cwd=cwd, check=False, text=True,
                              capture_output=capture)
    except OSError as e:
        raise BuildError(f"{cmd[0]}: {e}")
    if done.returncode != 0:
        detail = (done.stderr or done.stdout or "").strip() if capture else ""
        raise BuildError(f"`{' '.join(cmd)}` failed ({done.returncode})"
                         + (f": {detail[-600:]}" if detail else ""))
    return done.stdout if capture else ""


def checkout(src):
    """The pinned upstream commit in `src`, clean and patched.

    Reused between runs: the target/ directory is kept, so only what changed
    is rebuilt. Everything else is reset, so a checkout edited by hand or
    patched by an older run is never built as is."""
    if not os.path.isdir(os.path.join(src, ".git")):
        os.makedirs(os.path.dirname(src), exist_ok=True)
        run(["git", "clone", "--quiet", "--depth", "1", "--branch", TAG,
             REPO, src])
    else:
        run(["git", "fetch", "--quiet", "--depth", "1", "origin",
             f"refs/tags/{TAG}:refs/tags/{TAG}"], cwd=src)
        run(["git", "checkout", "--quiet", "--force", COMMIT], cwd=src)
        run(["git", "clean", "--quiet", "-fdx", "-e", "target"], cwd=src)
    head = run(["git", "rev-parse", "HEAD"], cwd=src, capture=True).strip()
    if head != COMMIT:
        raise BuildError(f"{TAG} is {head} upstream, not the pinned {COMMIT}: "
                         f"the tag moved. Check the new commit and update "
                         f"COMMIT and the patch together.")
    run(["git", "apply", "--check", PATCH], cwd=src, capture=True)
    run(["git", "apply", PATCH], cwd=src)


def build(src, cargo):
    run([cargo, "build", "--release", "--locked"], cwd=src)
    exe = os.path.join(src, "target", "release", os.path.basename(default_dest()))
    version = run([exe, "--version"], capture=True).strip()
    if VERSION not in version:
        raise BuildError(f"built binary reports {version!r}, not {VERSION}")
    with open(exe, "rb") as fh:
        if PATCH_MARKER not in fh.read():
            raise BuildError("built binary does not carry the patch")
    return exe


def is_patched(path):
    try:
        with open(path, "rb") as fh:
            return PATCH_MARKER in fh.read()
    except OSError:
        return False


def install_binary(exe, dest):
    """Put `exe` at `dest`. Returns whether anything changed.

    An unpatched binary already there (from install.sh or brew) is kept beside
    it, never overwritten, so the switch can be undone. The new file is moved
    into place, so a sidecar running from `dest` keeps its old inode until it
    restarts instead of executing a half-written file."""
    if os.path.isfile(dest) and filecmp.cmp(exe, dest, shallow=False):
        say(OK, f"sidecar binary already up to date: {dest}")
        return False
    os.makedirs(os.path.dirname(dest), exist_ok=True)
    if os.path.isfile(dest) and not is_patched(dest):
        backup = f"{dest}.unpatched"
        if not os.path.exists(backup):
            shutil.copy2(dest, backup)
            say(OK, f"kept the unpatched binary as {backup}")
    fd, tmp = tempfile.mkstemp(dir=os.path.dirname(dest),
                               prefix=".claude-code-proxy.")
    os.close(fd)
    try:
        shutil.copy2(exe, tmp)
        os.chmod(tmp, 0o755)
        os.replace(tmp, dest)
    except BaseException:
        if os.path.exists(tmp):
            os.unlink(tmp)
        raise
    say(OK, f"installed the patched sidecar: {dest}")
    return True


def render_unit(dest, port):
    """The unit for `dest`. A path under the home directory is written with
    systemd's %h, so the unit names no user and a default install produces the
    same file on every machine."""
    with open(UNIT_TEMPLATE, encoding="utf-8") as fh:
        text = fh.read()
    home = os.path.expanduser("~").rstrip(os.sep) + os.sep
    if dest.startswith(home):
        dest = "%h/" + dest[len(home):]
    return text.replace("@BIN@", dest).replace("@PORT@", str(port))


def systemd_user_dir():
    base = os.environ.get("XDG_CONFIG_HOME") or os.path.expanduser("~/.config")
    return os.path.join(base, "systemd", "user")


def systemctl(*args, capture=False):
    return run(["systemctl", "--user", *args], capture=capture)


def service_active():
    done = subprocess.run(["systemctl", "--user", "is-active", "--quiet",
                           UNIT_NAME], check=False)
    return done.returncode == 0


def install_service(dest, port, force, restart, binary_changed):
    """Install, enable and start the user unit. A running sidecar is restarted
    only with `restart`: that cuts every GPT turn it is carrying."""
    unit = os.path.join(systemd_user_dir(), UNIT_NAME)
    wanted = render_unit(dest, port)
    current = None
    if os.path.isfile(unit):
        with open(unit, encoding="utf-8") as fh:
            current = fh.read()
    unit_changed = current != wanted
    if unit_changed and current is not None and not force:
        say(WARN, f"{unit} differs from the packaged unit; left as it is "
                  f"(--force replaces it)")
        unit_changed = False
    elif unit_changed:
        os.makedirs(os.path.dirname(unit), exist_ok=True)
        with open(unit, "w", encoding="utf-8") as fh:
            fh.write(wanted)
        say(OK, f"wrote {unit}")
        systemctl("daemon-reload")
    systemctl("enable", "--quiet", UNIT_NAME)
    if not service_active():
        systemctl("start", UNIT_NAME)
        say(OK, "sidecar started")
    elif binary_changed or unit_changed:
        if restart:
            systemctl("restart", UNIT_NAME)
            say(OK, "sidecar restarted on the new build")
        else:
            say(WARN, "the running sidecar still has the old build. Restart it "
                      "when no GPT turn is running (that cuts them): "
                      f"systemctl --user restart {UNIT_NAME}")
    else:
        say(OK, "sidecar running")


def report_login(dest):
    done = subprocess.run([dest, "codex", "auth", "status"], check=False,
                          capture_output=True, text=True)
    if done.returncode == 0 and "Account:" in done.stdout:
        say(OK, "sidecar logged in to ChatGPT")
    else:
        say(WARN, f"the sidecar has no ChatGPT login yet: {dest} codex auth login")


def main(argv=None):
    ap = argparse.ArgumentParser(description="Build and install the patched "
                                             "claude-code-proxy sidecar.")
    ap.add_argument("--dest", default=default_dest(),
                    help="where to install the binary")
    ap.add_argument("--port", type=int, default=DEFAULT_PORT,
                    help="sidecar port (devinx expects 18765 unless "
                         "DEVINX_GPT_UPSTREAM says otherwise)")
    ap.add_argument("--src", default=cache_dir(), help="build checkout")
    ap.add_argument("--no-service", action="store_true",
                    help="install the binary only")
    ap.add_argument("--restart", action="store_true",
                    help="restart a running sidecar on the new build")
    ap.add_argument("--force", action="store_true",
                    help="replace a unit file that differs from the packaged one")
    args = ap.parse_args(argv)
    dest = os.path.abspath(os.path.expanduser(args.dest))
    try:
        cargo = find_cargo()
        say(OK, f"building claude-code-proxy {VERSION} with the origin guard "
                f"(first build takes a few minutes)")
        checkout(args.src)
        exe = build(args.src, cargo)
        changed = install_binary(exe, dest)
        if args.no_service:
            pass
        elif sys.platform.startswith("linux") and shutil.which("systemctl"):
            install_service(dest, args.port, args.force, args.restart, changed)
        else:
            say(WARN, f"no systemd here: run it yourself with "
                      f"`{dest} serve --no-monitor --port {args.port}` and "
                      f"CCP_BIND_ADDRESS=127.0.0.1 CCP_CODEX_SERVER_COMPACTION=1")
        report_login(dest)
    except BuildError as e:
        say(BAD, str(e))
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())
