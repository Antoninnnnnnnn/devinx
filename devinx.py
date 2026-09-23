#!/usr/bin/env python3
"""devinx — one local service for Claude Code with native SWE-2 subagents.

Listens on 127.0.0.1:8316 and speaks the Anthropic Messages API. Requests are
routed on the model name:

    model=claude-*  -> https://api.anthropic.com, transparent relay. The caller's
                       own credential is forwarded untouched; this process never
                       holds nor stores an Anthropic credential.
    model=swe-2-*   -> server.codeium.com, translated to Cognition's Connect-RPC
                       exa.api_server_pb.ApiServerService/GetChatMessage and
                       authenticated with the Devin CLI's stored credential.

Speaking Anthropic on both sides is what removes the OpenAI round-trip that used
to sit in the middle. Two consequences worth knowing:

  * usage maps 1:1, so there is no cached-token double subtraction to work around;
  * Claude Code keeps the thinking blocks it receives and replays them on the next
    turn, and Cognition accepts replayed thinking whether or not it is signed, so
    reasoning survives across turns with nothing stored server-side. The previous
    design had to persist thinking and re-inject it only because the OpenAI hop in
    the middle discarded unsigned thinking blocks on their way back up.
"""
import base64
import collections
import contextlib
import glob
import gzip
import hashlib
import hmac
import io
import json
import math
import os
import random
import re
import select
import struct
import subprocess
import signal
import socket
import sys
import threading
import time
import uuid
from datetime import datetime
from runtime_support import CONFIG_FIELDS, PortLock, build_id, hello_proof, service_secret
from http.cookiejar import DefaultCookiePolicy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import requests
from urllib3.util.retry import Retry
try:
    import tomllib
except ImportError:          # Python < 3.11
    try:
        import tomli as tomllib
    except ImportError:
        tomllib = None       # _read_key falls back to a pattern
from google.protobuf import descriptor_pb2, descriptor_pool, message_factory
from google.protobuf import timestamp_pb2, duration_pb2, any_pb2, struct_pb2
from google.protobuf import wrappers_pb2, empty_pb2, field_mask_pb2, type_pb2
from google.protobuf import source_context_pb2, api_pb2

HERE = os.path.dirname(os.path.abspath(__file__))
HOST = "127.0.0.1"
PORT = int(os.environ.get("DEVINX_PORT", "8316"))

CLAUDE_UPSTREAM = "https://api.anthropic.com"
# Where Codex CLI sends its own traffic when authenticated with a ChatGPT
# account. Relaying there with the caller's token is what lets the root session
# stay on GPT while its subagents run on SWE-2: Codex only lets a provider be
# chosen per session, never per agent, so the split has to happen here, on the
# model name, exactly as it already does for claude-* / swe-2-*.
CODEX_UPSTREAM = "https://chatgpt.com/backend-api/codex"
COGNITION_UPSTREAM = "https://server.codeium.com"
AUTH_PATH = "/exa.auth_pb.AuthService/GetUserJwt"
CHAT_PATH = "/exa.api_server_pb.ApiServerService/GetChatMessage"

IDE_NAME = "windsurf"
IDE_VERSION = "3.51.3"
EXT_VERSION = "1.48.2"
SESSION_PREFIX = "devin-session-token$"

SWE_MODELS = (
    ("swe-2", "SWE-2 (tier follows effort)"),
    ("swe-2-max", "SWE-2 Max"),
    ("swe-2-high", "SWE-2 High"),
    ("swe-2-medium", "SWE-2 Medium"),
)
SWE_MODEL_IDS = {item[0] for item in SWE_MODELS}

# Claude Code sends the effort slider as output_config.effort. Mapping it onto a
# tier is only safe for the `swe-2` alias: an explicit swe-2-medium/high/max must
# keep meaning exactly that, or a subagent pinned to a tier would get silently
# retiered by whatever effort its parent session happens to be set to.
SWE_ALIAS = "swe-2"
EFFORT_TIERS = {
    "low": "swe-2-medium",
    "medium": "swe-2-medium",
    "high": "swe-2-high",
    "xhigh": "swe-2-max",
    "max": "swe-2-max",
    # Current Claude Code sends "xhigh" for the ultracode position (ultracode is
    # xhigh plus client-side workflows, and the Workflow tool already ships in
    # the request either way). Mapped explicitly in case a later version starts
    # sending the label itself.
    "ultracode": "swe-2-max",
}
DEFAULT_TIER = "swe-2-high"

# Codex has two multi-agent surfaces and picks between them from the model
# catalog. On V2 a child task is handed to the subagent as Fernet ciphertext only
# OpenAI can open, so a non-OpenAI executor receives an envelope and no letter.
# On V1 the same task arrives in the clear, and every catalog row is eligible as
# a spawn target. Pinning the catalog to V1 is therefore the whole difference
# between "GPT can delegate to SWE-2" and "it cannot".
MULTI_AGENT_SURFACE = "v1"

# What SWE-2 actually accepts. A client that assumes more compacts too late and
# the turn dies upstream with "prompt is too long" instead — which is how this
# was found, on subagents that never compacted at all. Advertised per model in
# /v1/models so a client that reads the catalog can size each model on its own,
# rather than taking one session-wide number for every model it talks to.
SWE_CONTEXT_TOKENS = int(os.environ.get("DEVINX_CONTEXT_TOKENS", str(256 * 1024)))
SWE_EFFORTS = ("low", "medium", "high", "xhigh")

# Cognition issues tool call ids like `read_file_0#6bd71a46…`, and Anthropic
# requires ^[a-zA-Z0-9_-]+$ and rejects the entire request over one that is not.
# Nothing complains while the conversation stays on swe-2; the moment any turn of
# it goes to api.anthropic.com — a model switch, a claude-* subagent — the whole
# history is refused with a 400 naming a block number and nothing else.
_TOOL_ID_OK = re.compile(r"^[a-zA-Z0-9_-]+$")


def safe_tool_id(tid):
    """A tool id Anthropic will accept, derived from one it might not.

    Deterministic, because the same call has to keep the same id across every
    replay of the conversation, and suffixed with a digest of the original so
    two ids that differ only in the characters being replaced cannot collide.
    """
    if not tid or _TOOL_ID_OK.match(tid):
        return tid
    cleaned = re.sub(r"[^a-zA-Z0-9_-]", "_", tid)
    return f"{cleaned}_{hashlib.sha1(tid.encode()).hexdigest()[:8]}"


def repair_tool_ids(body):
    """Rewrite tool ids a previous devinx wrote into a transcript.

    The relay is a passthrough and stays one for every request that does not
    need this: the body is only re-serialised when something actually changed.
    Without it a conversation that ran on swe-2 can never be continued on a
    claude-* model, because the ids already stored in its transcript are the
    ones the API refuses.
    """
    changed = False
    for message in body.get("messages") or []:
        content = message.get("content")
        if not isinstance(content, list):
            continue
        for block in content:
            if not isinstance(block, dict):
                continue
            for key in ("id", "tool_use_id"):
                if block.get("type") not in ("tool_use", "tool_result"):
                    continue
                value = block.get(key)
                if isinstance(value, str):
                    fixed = safe_tool_id(value)
                    if fixed != value:
                        block[key] = fixed
                        changed = True
    return changed


SRC_USER, SRC_SYSTEM, SRC_TOOL = 1, 2, 4
REQ_CASCADE, PLANNER_DEFAULT = 5, 1
STOP_MAX_TOKENS = 3
# Cognition labels every signature it returns "sealed"; Claude Code only carries
# the opaque signature string back, so the type is restored from this constant.
SIGNATURE_TYPE = "sealed"

# Generous enough for a long history with images, bounded so a malformed or
# hostile content-length cannot make the process allocate without limit.
MAX_BODY_BYTES = int(os.environ.get("DEVINX_MAX_BODY", str(128 * 1024 * 1024)))

REQUEST_EXCLUDED = {
    "connection", "content-length", "host", "proxy-authorization",
    "proxy-connection", "te", "trailer", "transfer-encoding", "upgrade",
}
RESPONSE_EXCLUDED = {
    # send_response() emits Date and Server itself; forwarding the upstream copies
    # would produce a duplicate header pair on every response.
    "connection", "date", "keep-alive", "proxy-authenticate", "proxy-authorization",
    "server", "te", "trailer", "transfer-encoding", "upgrade",
}


def data_dir():
    """Per-OS writable location for the Devin credential and runtime state."""
    if os.environ.get("DEVINX_DATA"):
        return os.path.normpath(os.environ["DEVINX_DATA"])
    if sys.platform == "win32":
        base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    elif sys.platform == "darwin":
        base = os.path.expanduser("~/Library/Application Support")
    else:
        base = os.environ.get("XDG_DATA_HOME") or os.path.expanduser("~/.local/share")
    return os.path.normpath(os.path.join(base, "devinx"))


DATA_DIR = data_dir()
_STARTED = time.time()

# The dashboard reads the log through the extractor in tools/. Parsing 120k
# lines costs about a second, so a short cache keeps several open tabs from
# each paying for it.
# How long a process leaving gives the turns it is already carrying.
DRAIN_SECONDS = int(os.environ.get("DEVINX_DRAIN", "300"))
STATS_TTL = float(os.environ.get("DEVINX_STATS_TTL", "5"))
# Reading the dashboard from anywhere but loopback costs this secret. Empty
# means loopback only, which is the safe default for a service that never
# expected to be reachable from outside the machine.
def _dashboard_token():
    """The env var, or the token file the installer writes beside the log.

    The service is usually started by the launcher, which inherits whatever
    shell happened to run `devin` — so a token that lives only in one shell's
    environment disappears on the next restart, and with it the published
    dashboard. On disk it survives.
    """
    env = os.environ.get("DEVINX_DASHBOARD_TOKEN", "")
    if env:
        return env
    try:
        with open(os.path.join(DATA_DIR, "dashboard-token"), encoding="utf-8") as fh:
            return fh.read().strip()
    except OSError:
        return ""


DASHBOARD_TOKEN = _dashboard_token()
# The port the dashboard is published on, separate from the API port on
# purpose. Opened whenever there is a token to protect it.
DASHBOARD_PORT = int(os.environ.get("DEVINX_DASHBOARD_PORT", "8317"))
# How many times one conversation may be told the mid-conversation system
# turns are not accepted before the proxy gives up and carries them anyway. A
# client that honours the contract needs one.
MID_CONV_SYSTEM_REFUSALS = int(os.environ.get("DEVINX_MID_CONV_REFUSALS", "3"))
_capability_lock = threading.Lock()
_capability_refusals = {}

_stats_lock = threading.Lock()
# One snapshot per requested window, keyed by the extractor arguments.
_stats = {}
_ISO_BOUND = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?$")


_STAMPED = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d ")


def _log_tail(n):
    """The last non-routine log lines, for the live activity panel.

    The same file the extractor reads, override included: a feed and a figure
    panel drawn from two different logs would quietly disagree.
    """
    path = os.environ.get("DEVINX_LOG", os.path.join(DATA_DIR, "devinx.log"))
    try:
        size = os.path.getsize(path)
        with open(path, "rb") as fh:
            start = max(0, size - 200000)
            fh.seek(start)
            chunk = fh.read().decode("utf-8", "replace")
    except OSError:
        return []
    lines = chunk.splitlines()
    if start and lines:
        # The seek landed mid-line; only then is the first one a fragment.
        lines = lines[1:]
    # The stamp comes off before the match. Adding it in front of every line
    # silently disarmed this filter — every line now started with "2026-" and
    # none of them started with "upstream conn:", so the panel meant to show
    # what is worth seeing has been showing raw traffic since the day the log
    # learned to write the time.
    skip = ("upstream conn:", "upstream first-frame:", "upstream done:", "route=")
    keep = []
    for l in lines:
        if not l:
            continue
        body = _STAMPED.sub("", l, count=1)
        if not body.startswith(skip):
            keep.append(l)
    return keep[-n:]


def _build_id():
    return build_id(HERE)


RISKY_FLAGS = {
    "DEVINX_DUMP": lambda: bool(os.environ.get("DEVINX_DUMP")),
    "DEVINX_ALLOW_BROWSER": lambda: os.environ.get("DEVINX_ALLOW_BROWSER") == "1",
}


def effective_configuration():
    out = {env: globals().get(name) for env, name in CONFIG_FIELDS.items()}
    # Whether, never what: the dump path and the browser switch persist for
    # every later session of a daemon started from one shell that set them,
    # and a launcher can only warn about that if the service says so.
    out.update({name: flag() for name, flag in RISKY_FLAGS.items()})
    return out


BUILD = _build_id()

# In-flight requests, so a restart can wait for an idle moment rather than
# cutting a turn in half.
_inflight_lock = threading.Lock()
# "n" is everything in flight, which is what a drain waits for; "swe" is the
# part of it that is SWE-2 turns, which have a cap of their own.
_inflight = {"n": 0, "swe": 0}
_active_requests = {}
_request_local = threading.local()
# Two caps, because the two kinds of work do not wait alike. A SWE-2 turn can
# be held for up to the whole rate-limit budget; a relayed claude-*/gpt-* turn
# or a count_tokens call is the main session and is never held. Under one
# shared cap a fleet of held subagents filled every slot and the session that
# launched them was answered 503. MAX_INFLIGHT covers everything that is not a
# SWE-2 turn — relays, count_tokens, bodies still being read — and
# MAX_SWE_INFLIGHT the SWE-2 turns. 0 disables either.
MAX_INFLIGHT = int(os.environ.get("DEVINX_MAX_INFLIGHT", "64"))
MAX_SWE_INFLIGHT = int(os.environ.get("DEVINX_MAX_SWE_INFLIGHT", "64"))
HTTP_READ_TIMEOUT = float(os.environ.get("DEVINX_HTTP_READ_TIMEOUT", "30"))
CLIENT_WRITE_TIMEOUT = float(os.environ.get("DEVINX_CLIENT_WRITE_TIMEOUT", "120"))
RELAY_READ_TIMEOUT = float(os.environ.get("DEVINX_RELAY_READ_TIMEOUT", "0")) or None


def _request_phase(phase, model=None):
    key = getattr(_request_local, "key", None)
    with _inflight_lock:
        entry = _active_requests.get(key)
        if entry is None:
            return
        if phase != entry["phase"]:
            entry["phase"] = phase
            entry["phase_at"] = time.monotonic()
        if model is not None:
            entry["model"] = model


def live_requests():
    now = time.monotonic()
    with _inflight_lock:
        return [{"id": e["id"], "model": e["model"], "phase": e["phase"],
                 "elapsed": round(now - e["started"], 1),
                 "phase_elapsed": round(now - e["phase_at"], 1)}
                for e in _active_requests.values()]


def _enter_request():
    key, now = uuid.uuid4().hex[:12], time.monotonic()
    with _inflight_lock:
        general = _inflight["n"] - _inflight.get("swe", 0)
        if MAX_INFLIGHT > 0 and general >= MAX_INFLIGHT:
            return False
        _inflight["n"] += 1
        _active_requests[key] = {"id": key, "model": None,
                                 "phase": "reading_body", "started": now,
                                 "phase_at": now}
    _request_local.key = key
    return True


def _enter_swe():
    """Move this request from the general slots to a SWE-2 one.

    Called once the body says it is a SWE-2 turn. The request stays counted
    in "n" throughout, so a drain never loses sight of it.
    """
    key = getattr(_request_local, "key", None)
    with _inflight_lock:
        entry = _active_requests.get(key)
        if entry is None or entry.get("swe"):
            return True
        if MAX_SWE_INFLIGHT > 0 and _inflight.get("swe", 0) >= MAX_SWE_INFLIGHT:
            return False
        entry["swe"] = True
        _inflight["swe"] = _inflight.get("swe", 0) + 1
        return True


def _leave_request():
    key = getattr(_request_local, "key", None)
    with _inflight_lock:
        entry = _active_requests.pop(key, None)
        if entry is not None:
            _inflight["n"] -= 1
            if entry.get("swe"):
                _inflight["swe"] = _inflight.get("swe", 0) - 1
    _request_local.key = None


class ClientGone(BaseException):
    """The client hung up while its turn was being held.

    A BaseException on purpose. Between the wait and the handler sit several
    `except Exception` rescues — compaction failing forwards the turn as is, a
    dropped connection is retried — and each of them would carry on with the
    turn for nobody, spending requests on a quota metered in requests.
    """


# What run_swe hands back when there is nobody left to answer.
CLIENT_GONE = "client_gone: the client disconnected while its turn was held"


def _peer_open(sock):
    """False once the client has closed its end of the connection.

    A closed peer reads as readable-with-nothing-to-read; a client that sent
    more (a pipelined request) reads as readable-with-data and is still there.
    Nothing is consumed either way. A check that cannot be made answers
    "still there": abandoning a live turn is the worse mistake of the two.
    poll() where it exists, because select() refuses any descriptor past
    FD_SETSIZE (1024) with a ValueError on a busy service.
    """
    try:
        if hasattr(select, "poll"):
            poller = select.poll()
            poller.register(sock, select.POLLIN)
            readable = poller.poll(0)
        else:
            readable, _, _ = select.select([sock], [], [], 0)
    except (OSError, ValueError):
        return True
    if not readable:
        return True
    try:
        return bool(sock.recv(1, socket.MSG_PEEK))
    except (BlockingIOError, InterruptedError, socket.timeout):
        return True
    except OSError:
        return False


class Turn:
    """One client turn: a single wait budget, and whether its client is there.

    One deadline for everything the turn may be held for — the summary, the
    fold of the summary and the turn's own rate-limit and outage waits. Each
    used to get a budget of its own, so one turn could be held three times
    over, an hour and a half, while occupying a slot and its conversation's
    compaction lock.

    Waits are counted as well as timed, so the budget is spent by waiting even
    where the clock says otherwise, and they are taken in short steps so a
    client that left is noticed within half a second instead of at the end
    of a thirty-minute hold.
    """

    STEP = 0.5

    def __init__(self, conn=None, gone=None, budget=None):
        self.budget = RATE_WAIT_BUDGET if budget is None else budget
        self.deadline = time.time() + self.budget
        self.slept = 0.0
        self.conn = conn
        self.gone = gone if gone is not None else threading.Event()

    def left(self):
        return min(self.deadline - time.time(), self.budget - self.slept)

    def spent(self):
        return max(0.0, self.budget - self.left())

    def client_gone(self):
        if self.gone.is_set():
            return True
        if self.conn is not None and not _peer_open(self.conn):
            self.gone.set()
            return True
        return False

    def check(self):
        if self.client_gone():
            raise ClientGone()

    def sleep(self, seconds):
        remaining = max(0.0, seconds)
        while remaining > 0:
            self.check()
            step = min(remaining, self.STEP)
            time.sleep(step)
            self.slept += step
            remaining -= step
        self.check()


def current_turn():
    """The turn this thread is serving, or a fresh one outside any turn."""
    return getattr(_request_local, "turn", None) or Turn()


# --------------------------------------------------------------------------- #
# Protobuf descriptors
# --------------------------------------------------------------------------- #

def descriptor_files():
    """Locate the extracted Cognition FileDescriptorProtos."""
    candidates = []
    if os.environ.get("DEVINX_DESCRIPTORS"):
        candidates.append(os.environ["DEVINX_DESCRIPTORS"])
    candidates += [os.path.join(HERE, "descriptors"), HERE,
                   os.path.expanduser("~/devin-shim")]
    for d in candidates:
        found = glob.glob(os.path.join(d, "*.fdp"))
        if found:
            return found
    raise RuntimeError(
        "no *.fdp descriptors found (looked in: %s) — run extract_fdps.py"
        % ", ".join(candidates))


_proto_lock = threading.Lock()
_proto = {}


def protos():
    """Build the Cognition message classes on first SWE-2 use, never at import.

    The same reasoning as the credential: the relay routes need no descriptors
    at all, so a missing or malformed one has to degrade to "SWE-2 requests
    fail" rather than "the service refuses to start" and take the main session
    down with it. Loading at import meant one bad .fdp stopped Claude Code and
    Codex from reaching their own upstreams.
    """
    with _proto_lock:
        if _proto:
            return _proto
        pool = descriptor_pool.DescriptorPool()
        for _m in (timestamp_pb2, duration_pb2, any_pb2, struct_pb2, descriptor_pb2,
                   wrappers_pb2, empty_pb2, field_mask_pb2, type_pb2,
                   source_context_pb2, api_pb2):
            fd = descriptor_pb2.FileDescriptorProto()
            fd.ParseFromString(_m.DESCRIPTOR.serialized_pb)
            try:
                pool.Add(fd)
            except Exception:
                pass

        pending = {}
        for path in descriptor_files():
            fd = descriptor_pb2.FileDescriptorProto()
            with open(path, "rb") as fh:
                fd.ParseFromString(fh.read())
            pending[fd.name] = fd
        # Descriptors reference each other; repeat until the order resolves.
        added = set()
        for _ in range(40):
            for name, fd in pending.items():
                if name in added:
                    continue
                try:
                    pool.Add(fd)
                    added.add(name)
                except Exception:
                    pass

        def msg(name):
            return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))

        _proto.update({
            "GetUserJwtRequest": msg("exa.auth_pb.GetUserJwtRequest"),
            "GetUserJwtResponse": msg("exa.auth_pb.GetUserJwtResponse"),
            "GetChatMessageRequest": msg("exa.api_server_pb.GetChatMessageRequest"),
            "GetChatMessageResponse": msg("exa.api_server_pb.GetChatMessageResponse"),
        })
        return _proto


# --------------------------------------------------------------------------- #
# Cognition credential and JWT
# --------------------------------------------------------------------------- #

def _credential_files():
    """Every credentials.toml under the data directory, plus the legacy paths.

    A second subscription is a second `devin auth login` with XDG_DATA_HOME
    pointed somewhere else, so the search is recursive: the file lands at
    <that dir>/devin/credentials.toml and both are found without configuring
    anything.
    """
    found = sorted(glob.glob(os.path.join(DATA_DIR, "**", "credentials.toml"),
                             recursive=True))
    for legacy in (os.path.expanduser("~/devin-shim/data/devin/credentials.toml"),
                   os.path.expanduser("~/.local/share/devin/credentials.toml")):
        if os.path.exists(legacy) and legacy not in found:
            found.append(legacy)
    return found


# Only for when no TOML parser is importable (Python < 3.11 without tomli):
# the one line that matters, in either quoting style TOML allows.
_KEY_LINE = re.compile(r"""^[ \t]*windsurf_api_key[ \t]*=[ \t]*"""
                       r"""(?:"((?:[^"\\\n]|\\.)*)"|'([^'\n]*)')""", re.M)


def _find_key(table):
    """windsurf_api_key at the top level, or in a table one level down."""
    value = table.get("windsurf_api_key")
    if isinstance(value, str):
        return value
    for sub in table.values():
        if isinstance(sub, dict) and isinstance(sub.get("windsurf_api_key"), str):
            return sub["windsurf_api_key"]
    return None


def _read_key(path):
    """The key in one credentials.toml, or None — never an exception.

    Split on double quotes, a file written with single quotes (valid TOML)
    raised IndexError, and since every credential is read on the same pass
    one such file made every SWE-2 request fail with "list index out of
    range". Each file now stands or falls on its own.
    """
    try:
        with open(path, "rb") as fh:
            raw = fh.read().decode("utf-8", "replace")
    except OSError:
        return None
    key = None
    if tomllib is not None:
        try:
            key = _find_key(tomllib.loads(raw))
        except Exception:
            key = None
    if key is None:
        found = _KEY_LINE.search(raw)
        if found:
            key = (found.group(1).replace('\\"', '"').replace("\\\\", "\\")
                   if found.group(1) is not None else found.group(2))
    if key is None or not key.strip():
        if os.path.exists(path):
            print(f"warning: no windsurf_api_key readable in {path}", flush=True)
        return None
    return key.strip()


# Every credentials.toml sits in a directory called "devin", so naming an
# account after its parent names them all the same and the log stops telling
# them apart — which is the whole reason the account is logged.
_GENERIC_DIRS = {"devin", "data", "share", ".local", "devinx", ""}


def _credential_name(path):
    """A label that distinguishes one credential from another in the log."""
    parts = os.path.normpath(path).split(os.sep)[:-1]
    for part in reversed(parts):
        if part not in _GENERIC_DIRS:
            return part
    return "default"


def _load_accounts():
    """Load every credential, in a stable order.

    Both of Cognition's limits are per account — a short one that recycles in
    well under a minute, and a longer window that can lock for twelve. A second
    account doubles both, and turning a twelve-minute block into a switch is
    worth far more than the averages suggest when the work is parallel by
    design.
    """
    keys, names, paths = [], [], []
    env = os.environ.get("DEVINX_API_KEYS") or os.environ.get("DEVINX_API_KEY")
    if env:
        for i, raw in enumerate(re.split(r"[,\n]", env)):
            raw = raw.strip()
            if raw:
                keys.append(raw)
                names.append(f"env[{i}]")
                paths.append(None)
    else:
        for path in _credential_files():
            try:
                key = _read_key(path)
            except Exception as e:
                # One unreadable file must not take the others down with it.
                print(f"warning: skipping {path}: {type(e).__name__}", flush=True)
                key = None
            if key and key not in keys:
                keys.append(key)
                names.append(_credential_name(path))
                paths.append(path)
    if not keys:
        raise RuntimeError(
            "no Devin credential found — run:  XDG_DATA_HOME=%s devin auth login"
            % DATA_DIR)
    # Two credentials that still land on the same label are worse than useless
    # in a log line, so make them unique.
    seen = {}
    for i, name in enumerate(names):
        seen[name] = seen.get(name, 0) + 1
        if names.count(name) > 1:
            names[i] = f"{name}{seen[name]}"
    out = []
    for key, name, path in zip(keys, names, paths):
        if not key.startswith(SESSION_PREFIX):
            key = SESSION_PREFIX + key
        out.append({"key": key, "name": name, "jwt": None, "exp": 0.0,
                    "base": None, "blocked_until": 0.0, "path": path})
    return out


def _mtime(path):
    try:
        return os.path.getmtime(path) if path else None
    except OSError:
        return None


def _jwt_claims(jwt):
    try:
        part = jwt.split(".")[1]
        part += "=" * (-len(part) % 4)
        return json.loads(base64.urlsafe_b64decode(part))
    except Exception:
        return {}


def _check_plan(acct, jwt):
    """Take a credential out of rotation the moment it is no longer paid for.

    The plan is in the JWT this proxy already fetches for every account —
    `pro` and `teams_tier` — so knowing it costs no request. A refusal's text
    cannot tell: since mid-September every refusal, paid account or not, reads
    "Reached free model rate limit. Upgrade to Max for higher limits", and the
    one credential that really was on a free plan got that same sentence.

    Only an explicit pro=false excludes. A claim that is missing or a token
    that does not decode proves nothing, and excluding a paid account on a
    parsing failure would cost more than one request to a free one.

    An excluded credential is never claimed again, so it is never retried and
    its plan is never re-read. It comes back only when it is logged in again,
    which rewrites its credentials file: the rescan sees that and clears it.
    """
    claims = _jwt_claims(jwt)
    tier = claims.get("teams_tier") or "?"
    acct["tier"] = tier
    if "pro" in claims:
        acct["pro"] = bool(claims["pro"])
    if claims.get("pro") is False and not acct.get("excluded"):
        acct["excluded"] = f"plan gratuit ({tier})"
        acct["excluded_mtime"] = _mtime(acct.get("path"))
        print(f"devinx: credential {acct['name']} is on a free plan "
              f"(pro=false, {tier}); excluded until it is logged in again",
              flush=True)


def _first_usable():
    """The first credential still in rotation, for callers that pick none."""
    live = [a for a in accounts() if not a.get("excluded")]
    if not live:
        raise RuntimeError("every Devin credential is excluded (free plan); "
                           "log one in again with `devin auth login`")
    return live[0]


_acct_lock = threading.Lock()
_accounts = []


# How often the credential files are looked at again. A `devin auth login`
# done while the service runs is picked up within this many seconds, with no
# restart: the service is meant to outlive the sessions that use it, and a new
# account is exactly the kind of change that should not need one.
RESCAN_EVERY = float(os.environ.get("DEVINX_RESCAN", "30"))
_scan = {"at": 0.0, "sig": None}


def _credential_signature():
    out = []
    for path in _credential_files():
        try:
            out.append((path, os.path.getmtime(path)))
        except OSError:
            pass
    return tuple(out)


def _maybe_rescan():
    """Add the credentials that appeared, drop the ones whose file is gone.

    Accounts already known keep their state — their JWT, and above all their
    block: a credential that is rate limited stays rate limited across a rescan.
    A rescan that finds nothing at all is treated as a failed read and changes
    nothing, so a moment of filesystem trouble cannot leave the service with no
    account.
    """
    if os.environ.get("DEVINX_API_KEYS") or os.environ.get("DEVINX_API_KEY"):
        return
    now = time.time()
    with _acct_lock:
        if not _accounts or now - _scan["at"] < RESCAN_EVERY:
            return
        _scan["at"] = now
    sig = _credential_signature()
    with _acct_lock:
        if sig == _scan["sig"]:
            return
        _scan["sig"] = sig
    try:
        fresh = _load_accounts()
    except Exception as e:
        print(f"devinx: credential rescan failed, keeping the current ones: {e}",
              flush=True)
        return
    back = []
    with _acct_lock:
        known = {a["key"] for a in _accounts}
        keep = {f["key"] for f in fresh}
        added = [f for f in fresh if f["key"] not in known]
        removed = [a for a in _accounts if a["key"] not in keep]
        for a in removed:
            _accounts.remove(a)
        _accounts.extend(added)
        for a in _accounts:
            # Logged in again: the file was rewritten since the exclusion. The
            # plan is read afresh from the next JWT rather than assumed.
            if a.get("excluded") and _mtime(a.get("path")) != a.get("excluded_mtime"):
                a.pop("excluded", None)
                a["jwt"], a["exp"] = None, 0.0
                back.append(a)
        names = ", ".join(a["name"] for a in _accounts)
    for a in back:
        print(f"devinx: credential {a['name']} logged in again; back in "
              f"rotation, plan re-read on next use", flush=True)
    for a in added:
        print(f"devinx: new Devin credential {a['name']} ({names})", flush=True)
    for a in removed:
        print(f"devinx: Devin credential {a['name']} removed ({names})", flush=True)


def accounts():
    """Resolved on first SWE-2 use, never at import, and kept current after.

    The Claude relay needs no Devin credential, so a missing or expired one must
    degrade to "SWE-2 requests fail" rather than "the service refuses to start"
    and take the main session down with it.
    """
    _maybe_rescan()
    with _acct_lock:
        if not _accounts:
            _accounts.extend(_load_accounts())
            _scan["at"], _scan["sig"] = time.time(), _credential_signature()
            if len(_accounts) > 1:
                print(f"devinx: {len(_accounts)} Devin credentials "
                      f"({', '.join(a['name'] for a in _accounts)})", flush=True)
        return list(_accounts)


def api_key():
    """The first credential. Only for callers that do not pick an account."""
    return _first_usable()["key"]


def reset_key():
    """Re-read the credential files now, keeping what is known per account.

    Called when the upstream rejects our auth: the usual cause is that the user
    just ran `devin auth login` again, which rewrites credentials.toml while this
    process happily keeps using the string it read at startup.

    It used to empty the list and let the next use reload it. That also wiped
    every account's block and pacing state — one 401 on one account released
    a burst at accounts that were rate limited — and the retry right after it
    still went out with the old key, the reload only happening on the next
    request. Now the reload happens here and updates the existing account
    dicts in place, matched by key and then by name, so a caller holding one
    retries with the new key and nothing else forgets it was blocked.
    """
    try:
        fresh = _load_accounts()
    except RuntimeError as e:
        # Nothing readable right now (a login mid-write, say): keep what is in
        # use rather than leave nothing to use at all.
        print(f"devinx: credential reload found nothing ({e}); keeping the "
              f"current ones", flush=True)
        return
    fresh_keys = {a["key"] for a in fresh}
    with _acct_lock:
        by_key = {a["key"]: a for a in _accounts}
        by_name = {a["name"]: a for a in _accounts}
        merged = []
        for new in fresh:
            old = by_key.get(new["key"])
            if old is None:
                old = by_name.get(new["name"])
                if old is not None and old["key"] not in fresh_keys:
                    # The same credential file with a new key written into it.
                    old.update(key=new["key"], jwt=None, exp=0.0, base=None)
                else:
                    old = None
            if old is None or any(old is m for m in merged):
                merged.append(new)
            else:
                merged.append(old)
        changed = {a["key"] for a in merged} != set(by_key)
        _accounts[:] = merged
    if changed:
        print(f"devinx: credentials reloaded "
              f"({', '.join(a['name'] for a in merged)})", flush=True)


_turn = {"n": 0}


# How long a success keeps counting toward an account's measured success rate.
# A refusal's memory is not a setting at all: it is the reset the upstream
# announced in that refusal, so "reset in 20 seconds" is forgotten in about a
# minute and "reset in 30 minutes" weighs for about half an hour.
SUCCESS_MEMORY = float(os.environ.get("DEVINX_SUCCESS_MEMORY", "900"))


def _success_rate(acct, now):
    """The share of this account's recent attempts that were served.

    Counted with exponential forgetting: each attempt weighs exp(-age / τ),
    τ being SUCCESS_MEMORY for attempts and the announced reset for refusals.
    Laplace-smoothed, so an account with no history — a new login — starts
    at a neutral 1/2-to-1 and earns its share from what it actually serves
    rather than from a guess.
    """
    att = acct.setdefault("attempts", collections.deque())
    refs = acct.setdefault("refusals", collections.deque())
    while att and now - att[0] > 6 * SUCCESS_MEMORY:
        att.popleft()
    while refs and now - refs[0][0] > 6 * refs[0][1]:
        refs.popleft()
    a = sum(math.exp(-(now - t) / SUCCESS_MEMORY) for t in att)
    r = sum(math.exp(-(now - t) / tau) for t, tau in refs)
    rate = (max(a - r, 0.0) + 1.0) / (a + 2.0)
    # Never exactly zero: a refusing account keeps a sliver of traffic, which
    # is how the fleet notices that its limit has freed up again.
    return max(rate, 0.02)


def shares(now=None):
    """Each usable account's share of new turns, as the picker sees it now."""
    now = now or time.time()
    with _acct_lock:
        live = [a for a in _accounts
                if not a.get("excluded") and a["blocked_until"] <= now]
        w = {a["name"]: _success_rate(a, now) for a in live}
    total = sum(w.values()) or 1.0
    return {k: v / total for k, v in w.items()}


def claim_account(avoid=None):
    """A credential that is not rate limited, and when the earliest one frees up
    if none is.

    Proportional rather than first-fit. The limits are per credential, so always
    starting at the same one keeps that one permanently at its ceiling while the
    others idle — the short limit would still be hit on every burst, merely
    followed by a switch. Spreading the turns divides the rate each account sees,
    which is the difference between switching constantly and not being limited.

    It was a strict round robin, which spreads turns evenly but blindly: an
    account being refused kept its full share, and each of those turns was
    likely one more refusal. Measured over 24 hours on 2026-09-23, the work
    served was even (12 089 against 12 295) while the refusals were not (901
    against 2 712).

    Each account now gets a share of new turns proportional to its measured
    success rate. Two accounts that serve everything split evenly; one refused
    one time in ten gets somewhat less; one refused most of the time keeps a
    sliver, enough to notice it has recovered. Nothing is winner-take-all, and
    the weights are measurements, not settings. As traffic moves off a refusing
    account its refusals thin out, its rate climbs back and so does its share.
    """
    _maybe_rescan()
    if not _accounts:
        # Nothing loaded yet, or a reload found nothing: an empty list would
        # read as "wait for nobody" rather than as the missing credential.
        try:
            accounts()
        except RuntimeError:
            pass
    now = time.time()
    with _acct_lock:
        live = [a for a in _accounts if not a.get("excluded")]
        if not live:
            # Nothing will ever come back on its own: waiting is pointless.
            return None, None
        usable = [a for a in live
                  if a["blocked_until"] <= now and a is not avoid]
        if usable:
            # Smooth weighted round robin: every account accumulates its weight
            # on each pick and the highest total is chosen and paid down by the
            # sum. Over any run of picks each account gets exactly its share,
            # interleaved rather than in streaks, with no randomness to make a
            # small fleet lurch.
            weights = {id(a): _success_rate(a, now) for a in usable}
            total = sum(weights.values())
            for a in usable:
                a["credit"] = a.get("credit", 0.0) + weights[id(a)]
            pick = max(usable, key=lambda a: a["credit"])
            pick["credit"] -= total
            pick.setdefault("attempts", collections.deque()).append(now)
            return pick, 0.0
        # The avoided account counts here. Leaving it out made the answer
        # "nothing to wait for" with a single credential — the turn was handed
        # back at once — and with two it waited out the other one's thirty
        # minutes when the one that just refused was back in five seconds.
        soonest = min((a["blocked_until"] for a in live), default=now)
        return None, max(0.0, soonest - now)


def block_account(acct, seconds):
    """Take a credential out of rotation for at least RATE_FLOOR seconds.

    The upstream does say "reset in 0 seconds" — 129 times in one log — and
    taken literally that blocks nothing: the next claim hands the same
    credential straight back and the retry goes out on the next round trip,
    for as long as the budget lasts. The floor is what makes every refusal
    cost a pause.
    """
    with _acct_lock:
        acct["blocked_until"] = time.time() + max(seconds, RATE_FLOOR)
        # The refusal is remembered for as long as the upstream said the
        # limit would last, within a minute and half an hour.
        acct.setdefault("refusals", collections.deque()).append(
            (time.time(), min(max(float(seconds), 60.0), 1800.0)))
        acct["refused_at"] = time.time()


def paced(acct):
    """Hold the fleet to a few turns at a time on a credential that just refused.

    The limit is a rate, so sending sixteen turns at a credential the instant
    it comes back does not get sixteen turns served: the first few are served
    and the rest come back refused, each refusal being itself a request against
    the same limit. Concurrency does not raise throughput here, it multiplies
    the bill — and the quota is metered in requests.

    So the cap applies only where it costs nothing: for a while after a
    credential has actually refused something. While a credential is serving
    normally, every turn goes straight through and this does nothing at all.

    "A while" is counted from when the credential comes back, not from when it
    refused. Counted from the refusal, the two minutes had long lapsed by the
    end of a 10-to-35-minute block — precisely the moment every turn held for
    that block is released at once. Measured on 2026-09-23: after a long block
    the median number of requests served before the next refusal was zero.
    """
    if not acct or PACE_CONCURRENCY <= 0:
        return contextlib.nullcontext()
    back = max(acct.get("refused_at", 0), acct.get("blocked_until", 0))
    if time.time() - back > PACE_WINDOW:
        return contextlib.nullcontext()
    sem = acct.get("pace")
    if sem is None:
        with _acct_lock:
            sem = acct.setdefault("pace", threading.Semaphore(PACE_CONCURRENCY))
    return sem


# One lock per credential, not one for the process: the lock is held across
# a network call of up to 30s, and a slow auth endpoint for one account used
# to hold up the turns of every other account behind it.
_jwt_locks = {}


def _jwt_lock_for(acct):
    with _acct_lock:
        return _jwt_locks.setdefault(acct["key"], threading.Lock())


def _metadata(jwt="", key=None):
    # The real devin-cli leaves session_id and request_id unset on inference calls.
    return {
        "api_key": key or api_key(),
        "user_jwt": jwt,
        "ide_name": IDE_NAME,
        "ide_version": IDE_VERSION,
        "extension_name": "windsurf",
        "extension_version": EXT_VERSION,
        "locale": "en",
    }


def _jwt_expiry(token):
    try:
        payload = token.split(".")[1]
        payload += "=" * (-len(payload) % 4)
        return json.loads(base64.urlsafe_b64decode(payload)).get("exp", 0)
    except Exception:
        return 0.0


def get_jwt(acct=None, force=False):
    """A JWT for one account, cached on that account rather than globally."""
    if acct is None:
        acct = _first_usable()
    with _jwt_lock_for(acct):
        now = time.time()
        if not force and acct["jwt"] and acct["exp"] - 60 > now:
            return acct["jwt"], acct["base"]
        req = protos()["GetUserJwtRequest"](metadata=_metadata(key=acct["key"]))
        r = SESSION.post(COGNITION_UPSTREAM + AUTH_PATH,
                         data=req.SerializeToString(),
                         headers={"content-type": "application/proto",
                                  "connect-protocol-version": "1"}, timeout=30)
        r.raise_for_status()
        resp = protos()["GetUserJwtResponse"]()
        try:
            resp.ParseFromString(r.content)
        except Exception:
            resp.ParseFromString(gzip.decompress(r.content))
        if not resp.user_jwt:
            raise RuntimeError("GetUserJwt returned empty jwt")
        acct["jwt"] = resp.user_jwt
        acct["exp"] = _jwt_expiry(resp.user_jwt) or now + 3300
        acct["base"] = resp.custom_api_server_url.strip() or None
        _check_plan(acct, resp.user_jwt)
        return acct["jwt"], acct["base"]


def _auth_refused(error):
    response = getattr(error, "response", None)
    return getattr(response, "status_code", None) in (401, 403)


def _jwt_or_reload(acct, force=False):
    """(jwt, base, None), or (None, None, error) when the credential is refused.

    The JWT endpoint is where an expired or replaced key is refused first,
    and a refusal there never reached reset_key(): SWE-2 stayed broken until
    a restart, and the turn failed as a 502 api_error the client cannot act
    on. Refused once, the credentials are re-read and the call tried again;
    refused twice, it is an authentication_error.
    """
    for attempt in range(2):
        try:
            jwt, base = get_jwt(acct, force=force or attempt > 0)
            return jwt, base, None
        except requests.HTTPError as e:
            if not _auth_refused(e):
                raise
            status = e.response.status_code
            if attempt == 0:
                print(f"auth endpoint refused {acct['name']} (HTTP {status}); "
                      f"re-reading the credentials", flush=True)
                reset_key()
                continue
            print(f"auth endpoint refused {acct['name']} again (HTTP {status})",
                  flush=True)
            return None, None, (
                f"unauthenticated: the Devin credential {acct['name']} was "
                f"refused (HTTP {status}); run `devin auth login`")


# --------------------------------------------------------------------------- #
# Anthropic request -> Cognition request
# --------------------------------------------------------------------------- #

# Cognition's input classifier rejects these Claude Code system-prompt blocks
# (competitor identity, security-policy vocabulary, product marketing + URLs).
# Rewrite them to neutral equivalents; behavior instructions are unchanged.
_SYS_REWRITES = [
    (re.compile(r"You are (?:a )?Claude[^.]*\."), "You are a coding agent."),
    (re.compile(r"IMPORTANT: Assist with authorized security testing.*?(?=\n\s*\n|\Z)", re.S),
     "Assist with authorized security testing and defensive security work; refuse harmful or destructive requests."),
    (re.compile(r"\n?\s*-?\s*Claude Code is available[^\n]*"), ""),
    (re.compile(r"- For clear communication with the user the assistant MUST avoid using emojis\."),
     "- For clear communication with the user, avoid emojis."),
    # Codex injects <model_switch> when a turn changes model, and the block is
    # the *other* model's entire system prompt — competitor identity, product
    # description and all. It is the single thing that made Cognition answer
    # "blocked by our content policy" on every subagent turn, and it says
    # nothing a fresh model needs: the instructions it duplicates are already in
    # the prompt beside it.
    (re.compile(r"<model_switch>.*?</model_switch>", re.S), ""),
    (re.compile(r"You are a coding agent running in the Codex CLI[^.]*\."
                r"(\s*Codex CLI is an open source project led by OpenAI\.)?"),
     "You are a coding agent."),
    (re.compile(r"You are Codex, an agent based on GPT-[\w.]+[^.]*\."),
     "You are a coding agent."),
]

# TaskOutput's shipped description trips the same classifier in combination
# (per-line fragments pass). It is deprecated upstream; send a short equivalent.
_TOOL_DESC_REWRITES = {
    "TaskOutput": "Get the output of a running or completed background task "
                  "(shell, agent, or remote session) by task_id.",
}


def _scrub_system(text):
    for rx, rep in _SYS_REWRITES:
        text = rx.sub(rep, text)
    return text


def _blocks(content):
    """Anthropic content is either a bare string or a list of typed blocks."""
    if content is None:
        return []
    if isinstance(content, str):
        return [{"type": "text", "text": content}]
    return [b for b in content if isinstance(b, dict)]


def _text_of(content):
    return "".join(b.get("text", "") for b in _blocks(content)
                   if b.get("type") == "text")


def _image_of(block):
    """Anthropic image block -> Cognition image. Only base64 sources exist here."""
    src = block.get("source") or {}
    if src.get("type") != "base64":
        return None
    return {"base64_data": src.get("data", ""),
            "mime_type": src.get("media_type") or "image/png"}


def _document_text(block):
    """(text, None) for a document the upstream can be given as text, or
    (placeholder, label) for one it cannot.

    Cognition takes text and images and nothing else, so a PDF has nowhere to
    go. It used to vanish without a word when it sat inside a tool_result —
    the Read tool returns PDFs that way — and the model answered as if it had
    read a file it never saw. A document whose source is plain text loses
    nothing by being sent as text; any other kind is replaced by a line
    saying it was left out, so the model knows to say so.
    """
    src = block.get("source") or {}
    title = block.get("title") or ""
    head = f"[document: {title}]\n" if title else ""
    if src.get("type") == "text" and isinstance(src.get("data"), str):
        return head + src["data"], None
    if src.get("type") == "content":
        text = _text_of(src.get("content"))
        if text:
            return head + text, None
    kind = src.get("media_type") or src.get("type") or "unknown"
    name = f" {title!r}" if title else ""
    return (f"[document{name} ({kind}) omitted: this model cannot read it]",
            f"document/{src.get('type')}")


def _tool_result_text(block, dropped=None):
    """tool_result content is a string or a list of blocks (text, images,
    documents). Images travel separately; anything else is named in
    `dropped` when the caller keeps that list."""
    content = block.get("content")
    if isinstance(content, str):
        return content
    text, documents = [], False
    for b in _blocks(content):
        kind = b.get("type")
        if kind == "text":
            text.append(b.get("text", ""))
        elif kind == "document":
            doc, lost = _document_text(b)
            text.append(doc)
            documents = True
            if lost and dropped is not None:
                dropped.append(lost)
        elif kind != "image" and dropped is not None:
            dropped.append(f"tool_result/{kind}")
    # Text blocks join as they always have; a document gets lines of its own.
    return ("\n" if documents else "").join(text)


def _system_text(body):
    system = body.get("system")
    if isinstance(system, str):
        return system
    return "\n\n".join(b.get("text", "") for b in _blocks(system)
                       if b.get("type") == "text")


def _conv_key(body):
    """Stable per-conversation key.

    metadata.user_id identifies the Claude Code session, but every subagent of a
    session reuses the parent's id verbatim. On its own it would collapse the
    parent and all its concurrent subagents into one cascade, one trajectory and
    one prefix cache, which is what used to make continuation turns miss the cache
    entirely. Mixing in the system prompt (distinct per agent definition) and the
    first user turn (distinct per task) separates them. Both are stable across the
    turns of a given agent, which is what cascade anchoring requires.
    """
    msgs = body.get("messages", [])
    first = _blocks(next((m for m in msgs if m.get("role") == "user"), {})
                    .get("content"))
    # Images count as identity too: a subagent whose opening task is a screenshot
    # would otherwise be keyed on the empty string and collide with every other
    # image-only task.
    first_user = "".join(b.get("text", "") for b in first if b.get("type") == "text")
    first_images = _image_digests(
        [img for img in (_image_of(b) for b in first if b.get("type") == "image")
         if img])
    digest = hashlib.sha1(
        ("\0".join([_system_text(body), first_user] + first_images)).encode()
    ).hexdigest()
    base = (body.get("metadata") or {}).get("user_id")
    # The digest carries the discrimination, so it belongs in the fallback too:
    # keyed on the first user turn alone, two agents with different system
    # prompts but the same opening task would share one cascade.
    return f"{base}\0{digest}" if base else digest


def new_message_id():
    """A fresh id for every response, because the client merges on it.

    This one constant was the whole collapsed-conversation mystery. Claude Code
    normalises its transcript into API messages with a function that keeps a
    map of message.id -> position and merges an assistant turn into the
    existing entry when the id repeats, instead of appending. The window it
    keeps is only cleared by a user message that is not a tool_result — and
    during an agent run there are none, every user turn being a tool answer.

    So with a constant id, every assistant turn of a run folded into the first
    one and every tool_result folded into the first user message: a hundred and
    seventy calls arriving as three messages, at any run length. The real API
    guarantees a unique id per response and the client is right to rely on it.
    This was never the client's bug; it was this literal.

    It is unique per response and shared by every block of that response, which
    is exactly what the client needs to reassemble one response from its
    streamed blocks. The `claude-*` routes were never affected because they are
    relayed byte for byte and carry Anthropic's own ids.
    """
    return f"msg_{uuid.uuid4().hex}"


def resolve_model(body):
    """Requested model -> concrete SWE-2 tier.

    `swe-2` is the entry shown in Claude Code's model picker: it carries no tier
    of its own and takes it from the effort slider, which is what makes that
    slider do something. The explicit tiers are passed through untouched.
    """
    model = body.get("model") or SWE_ALIAS
    if "/" in model:
        model = model.rsplit("/", 1)[-1]
    if model != SWE_ALIAS:
        return model
    effort = ((body.get("output_config") or {}).get("effort") or "").lower()
    return EFFORT_TIERS.get(effort, DEFAULT_TIER)


def _image_digests(images):
    """Images identify a turn as much as its text, but base64 payloads are far
    too large to hash on every request; their digests are enough."""
    return [hashlib.sha1((i.get("base64_data") or "").encode()).hexdigest()
            for i in images]


def _msgid(kind, payload):
    """Content-derived message id.

    Cognition's prefix cache keys on these, so they must stay identical for the
    same turn across requests. Deriving them from position would shift every id
    after a message Claude Code dropped during compaction, invalidating the cache
    for the whole remaining conversation.
    """
    blob = json.dumps(payload, sort_keys=True, default=str)
    return str(uuid.uuid5(uuid.NAMESPACE_URL, "devinx-msg\0" + kind + "\0" + blob))


# Cognition's input classifier rejects some long tool descriptions outright —
# Codex's code-mode `exec` tool ships 16KB of API documentation and is refused
# whole, while its first ~6KB passes. Rather than pattern-matching a text that
# changes with every client release, the permission_denied retry shrinks the
# descriptions and tries again. Measured against Codex 0.154: 6000 passes.
TOOL_DESC_CAPS = (None, 6000, 2500)

# A rate limit is the commonest upstream refusal by a wide margin — measured in
# one log, 1107 against 13 real context overflows — and the upstream says how
# long it wants: "Your limit will reset in 1 minute". Handing that back to the
# client ends the agent and tells the orchestrator its subagent stopped. Holding
# the request instead, waiting, and retrying keeps the turn alive: the client
# sees a request that took longer, the agent never stops, and nobody is
# notified of anything. Bounded, because the client has its own timeout and an
# answer that never comes is worse than one that says to try later.
# How long one turn may be held for the upstream to come back, rate limit or
# outage. It was 600s; on 2026-09-23 the upstream started announcing blocks of
# 10 to 35 minutes once an account had carried a heavy day, and 64 turns were
# handed back as errors after waiting the full ten. A held turn is a paused
# agent; a handed-back turn is usually a dead one.
RATE_WAIT_BUDGET = int(os.environ.get("DEVINX_RATE_WAIT", "1800"))
# The shortest a refused credential is left alone, whatever the upstream says.
RATE_FLOOR = float(os.environ.get("DEVINX_RATE_FLOOR", "3"))
# The upstream's own words when the model behind it is down, as opposed to
# refusing this account. Switching credential cannot help; waiting can.
_OUTAGE = ("experiencing issues", "currently not available",
           "try this model again later")
# Seconds of silence on a streaming response before a keepalive goes out. The
# client abandons a stream that has sent nothing for five minutes — read out of
# its own binary: max(CLAUDE_STREAM_IDLE_TIMEOUT_MS, 300000) — and reports it as
# "The response stopped arriving". Measured here: 158 turns ended that way, at a
# median latency of 343s. Anthropic's own API keeps a stream alive with `ping`
# events; nothing here did. 0 disables it.
KEEPALIVE_EVERY = int(os.environ.get("DEVINX_KEEPALIVE", "25"))
# How many turns may be in flight on a credential that has refused something
# recently, and for how long after that refusal the cap applies. 0 disables it.
PACE_CONCURRENCY = int(os.environ.get("DEVINX_PACE", "4"))
PACE_WINDOW = int(os.environ.get("DEVINX_PACE_WINDOW", "120"))

# A connection that breaks mid-response is transient and costs an agent its
# turn: measured in one log, 103 of them — connection resets and streams ending
# prematurely — every one ending the turn, because the retry loop only ever
# caught rate limits and classifier refusals. urllib3's own retries cannot help
# here: with stream=True the window closes once the response headers are read,
# so a body-phase failure surfaces to us and to nobody else.
NETWORK_RETRIES = int(os.environ.get("DEVINX_NETWORK_RETRIES", "2"))
_TRANSIENT = ("ConnectionResetError", "ChunkedEncodingError", "ConnectionError",
              "ReadTimeout", "ProtocolError", "IncompleteRead",
              "stream truncated")


def build_request(body, tool_desc_cap=None):
    """Translate one Anthropic Messages body into a GetChatMessageRequest.

    Anthropic preserves real turn structure — one assistant message per turn, tool
    results in the following user message — so prompts map across in order with no
    regrouping needed.
    """
    conv_seed = _conv_key(body)
    cascade_id = str(uuid.uuid5(uuid.NAMESPACE_URL, "devinx\0" + conv_seed))
    prompts = []

    seen_ids = {}
    dropped = []
    unknown_roles = set()

    def mid(kind, payload):
        """Content-derived id, disambiguated if the same content repeats.

        Position must not enter into this: an id derived from the index would
        shift for every message after one Claude Code dropped during compaction,
        invalidating the upstream prefix cache for the rest of the conversation.
        """
        base = _msgid(kind, payload)
        n = seen_ids.get(base, 0)
        seen_ids[base] = n + 1
        return base if n == 0 else f"{base}-{n}"

    for m in body.get("messages", []):
        role = m.get("role")
        blocks = _blocks(m.get("content"))
        if role != "assistant":
            # Anything that is not the model speaking is context addressed to
            # it. The Messages API defines only user and assistant, but clients
            # do send other roles — Claude Code puts `system` messages inside
            # `messages` — and the branch that only knew `user` dropped them
            # without a word, instructions included. Upstream has no separate
            # source for them; the user channel keeps both the content and its
            # place in the sequence.
            if role != "user":
                unknown_roles.add(str(role))
            # tool_result blocks ride in user messages; they become their own
            # SRC_TOOL prompts and must keep their position in the sequence.
            text_parts, images = [], []
            for b in blocks:
                kind = b.get("type")
                if kind == "tool_result":
                    prompts.append({
                        "message_id": mid("tool", b),
                        "source": SRC_TOOL,
                        "tool_call_id": b.get("tool_use_id", ""),
                        "prompt": _tool_result_text(b, dropped),
                        # Without this a failed tool call replays as a successful
                        # one and the model has to infer failure from the text.
                        "tool_result_is_error": bool(b.get("is_error")),
                        # Image blocks only. Any base64 source used to pass,
                        # so a PDF went up as an "image" of application/pdf.
                        "images": [img for img in
                                   (_image_of(x) for x in _blocks(b.get("content"))
                                    if x.get("type") == "image")
                                   if img],
                    })
                elif kind == "text":
                    text_parts.append(b.get("text", ""))
                elif kind == "image":
                    img = _image_of(b)
                    if img:
                        images.append(img)
                    else:
                        dropped.append("image/" + str(
                            (b.get("source") or {}).get("type")))
                elif kind == "document":
                    doc, lost = _document_text(b)
                    text_parts.append(doc)
                    if lost:
                        dropped.append(lost)
                else:
                    dropped.append(str(kind))
            if text_parts or images:
                prompts.append({"message_id": mid("user", {
                                    "text": "".join(text_parts),
                                    "images": _image_digests(images)}),
                                "source": SRC_USER,
                                "prompt": "".join(text_parts),
                                "images": images})
        else:   # the model's own turn
            texts, thinkings, signature, tool_calls = [], [], None, []
            for b in blocks:
                kind = b.get("type")
                if kind == "thinking":
                    # Replayed from what was emitted last turn. Cognition accepts
                    # replayed thinking unsigned, so losing the signature costs
                    # nothing; losing the text would cost the reasoning itself.
                    thinkings.append(b.get("thinking", ""))
                    if b.get("signature"):
                        signature = b["signature"]
                elif kind == "text":
                    texts.append(b.get("text", ""))
                elif kind == "tool_use":
                    tool_calls.append({
                        "id": b.get("id", ""),
                        "name": b.get("name", ""),
                        "arguments_json": json.dumps(b.get("input") or {}),
                    })
                else:
                    dropped.append(str(kind))
            entry = {"source": SRC_SYSTEM, "prompt": "".join(texts),
                     "tool_calls": tool_calls}
            if thinkings:
                entry["thinking"] = "\n\n".join(thinkings)
                # A signature covers one specific thinking text. Concatenating
                # several invalidates it, so send it only when it still matches.
                if signature and len(thinkings) == 1:
                    entry["signature"] = signature
                    entry["signature_type"] = SIGNATURE_TYPE
            entry["message_id"] = mid("assistant", {
                "text": entry["prompt"], "thinking": entry.get("thinking", ""),
                "tool_calls": tool_calls})
            prompts.append(entry)

    if dropped:
        # Silent loss is the failure mode that is hardest to diagnose from the
        # client side, where the model simply appears not to have seen something.
        print(f"warning: dropped unsupported content blocks: "
              f"{', '.join(sorted(set(dropped)))}", flush=True)
    if unknown_roles:
        # Naming the model matters: the two client anomalies this proxy sees —
        # roles the Messages API does not define, and a history collapsed by
        # role — do not come from the same place, and telling them apart needs
        # to be possible from the log rather than from memory.
        print(f"warning: messages with role {', '.join(sorted(unknown_roles))} "
              f"sent upstream as user content (model={body.get('model')})",
              flush=True)

    def describe(t):
        text = _TOOL_DESC_REWRITES.get(t.get("name"), t.get("description", ""))
        if tool_desc_cap and len(text) > tool_desc_cap:
            # Cut on a line boundary: stopping mid-declaration leaves the model
            # reading a truncated type signature as if it were complete.
            head = text[:tool_desc_cap]
            head = head[:head.rfind("\n") + 1] or head
            text = head + "\n(description truncated)"
        return text

    tools = [{"name": t.get("name", ""),
              "description": describe(t),
              "json_schema_string": json.dumps(t.get("input_schema") or {}),
              "strict": False}
             for t in body.get("tools") or [] if t.get("name")]

    # The real client never sends a tool_choice field and adding one risks the
    # input classifier, so the only choice expressible here is "none" — and that
    # one matters, because it forbids tool use rather than merely leaving the
    # model free. Withholding the definitions enforces it exactly. The forcing
    # variants cannot be expressed at all, so say so instead of ignoring them.
    choice = (body.get("tool_choice") or {}).get("type")
    if choice == "none":
        tools = []
    elif choice in ("any", "tool"):
        print(f"warning: tool_choice={choice} is not expressible upstream; "
              f"the model may decline to call a tool", flush=True)

    # Sampling config mirrors the real Devin client wire exactly:
    # num_completions/max_tokens/max_newlines/temperature/top_k/top_p only.
    conf = {"num_completions": 1, "max_newlines": 400, "top_k": 40,
            "max_tokens": int(body.get("max_tokens") or 128000),
            "temperature": float(body["temperature"])
            if body.get("temperature") is not None else 1.0,
            "top_p": float(body["top_p"]) if body.get("top_p") is not None else 0.95}

    model = resolve_model(body)

    # Real-client request surface: no execution_id, no tool_choice, no
    # disable_parallel_tool_calls, no system_prompt_cache_options — ever.
    req = protos()["GetChatMessageRequest"](
        metadata=_metadata(),
        prompt=_scrub_system(_system_text(body)),
        chat_message_prompts=prompts,
        chat_model_uid=model,
        request_type=REQ_CASCADE,
        planner_mode=PLANNER_DEFAULT,
        cascade_id=cascade_id,
        configuration=conf,
        tools=tools,
    )
    # Trajectory anchoring mirrors the real client: trajectory_id is a
    # session-scoped uuid distinct from cascade_id, step_index is the per-
    # trajectory step counter — 0 with step_type=USER_INPUT on the first request,
    # then n_assistant_turns+1.
    n_asst = sum(1 for p in prompts if p.get("source") == SRC_SYSTEM)
    req.trajectory_reference.trajectory_id = str(
        uuid.uuid5(uuid.NAMESPACE_URL, "devinx-traj\0" + conv_seed))
    req.trajectory_reference.trajectory_type = 4
    if any(p.get("source") == SRC_TOOL for p in prompts):
        req.trajectory_reference.step_type = 0
        req.trajectory_reference.step_index = n_asst + 1
    else:
        req.trajectory_reference.step_type = 14
        req.trajectory_reference.step_index = 0
    return req, model


MAX_FRAME_BYTES = int(os.environ.get("DEVINX_MAX_FRAME", str(16 * 1024 * 1024)))
MAX_INFLATED_FRAME_BYTES = int(os.environ.get(
    "DEVINX_MAX_INFLATED_FRAME", str(64 * 1024 * 1024)))


def _frame_payload(payload, compressed):
    if not compressed:
        if len(payload) > MAX_INFLATED_FRAME_BYTES:
            raise ValueError("upstream frame exceeds the decoded size limit")
        return payload
    with gzip.GzipFile(fileobj=io.BytesIO(payload)) as fh:
        raw = fh.read(MAX_INFLATED_FRAME_BYTES + 1)
    if len(raw) > MAX_INFLATED_FRAME_BYTES:
        raise ValueError("upstream frame exceeds the decoded size limit")
    return raw


def chat_stream(req, acct=None, purpose="turn"):
    # Bound to the frame that logs it, so the two lines of one call agree.
    """Yield (GetChatMessageResponse, None) per frame or (None, error) on trailer.

    `purpose` separates an agent's own turn from the extra call compaction
    makes for itself. Both are ordinary requests on the metered quota and were
    indistinguishable in the log, so the summariser's cost was counted as agent
    work and its latency — the pause every compacted agent pays mid-turn — was
    invisible.
    """
    if acct is None:
        acct = _first_usable()
    _request_phase("summarizing" if purpose == "summary" else "authenticating")
    jwt, base, err = _jwt_or_reload(acct)
    if err:
        yield None, err
        return
    req.metadata.api_key = acct["key"]
    req.metadata.user_jwt = jwt
    body = req.SerializeToString()
    t_start = time.time()
    n_msgs = len(req.chat_message_prompts)
    r = None
    try:
        for attempt in range(2):
            gz = gzip.compress(body, compresslevel=1)
            frame = bytes([1]) + struct.pack(">I", len(gz)) + gz
            # SESSION rather than a bare requests.post: the latter builds a
            # throwaway Session, so every turn paid a fresh TLS handshake to
            # Cognition and ignored SESSION's trust_env=False.
            _request_phase("summarizing" if purpose == "summary" else "connecting")
            r = SESSION.post((base or COGNITION_UPSTREAM) + CHAT_PATH, data=frame,
                             headers={"content-type": "application/connect+proto",
                                      "connect-protocol-version": "1",
                                      "connect-content-encoding": "gzip",
                                      "connect-accept-encoding": "gzip",
                                      "user-agent": "connect-go/1.18.1 (go1.26.3)"},
                             timeout=600, stream=True)
            if r.status_code == 200:
                break
            status, detail = r.status_code, r.text[:400]
            r.close()
            r = None
            if status in (401, 403) and attempt == 0:
                # Re-read the credential file too: after `devin auth login` the
                # process would otherwise keep retrying with the stale key it
                # memoised at first use. reset_key() updates this very dict,
                # so acct["key"] below is the reloaded one.
                reset_key()
                jwt, base, err = _jwt_or_reload(acct, force=True)
                if err:
                    yield None, err
                    return
                req.metadata.api_key = acct["key"]
                req.metadata.user_jwt = jwt
                body = req.SerializeToString()
                continue
            print(f"upstream HTTP {status} on {acct['name']}: {detail}",
                  flush=True)
            if status in (401, 403):
                yield None, f"unauthenticated: upstream {status}: {detail}"
            else:
                yield None, f"upstream {status}: {detail}"
            return
        # conv= is the cascade id, which is derived from the conversation and
        # stable across its turns: the join key the log never had. Without one,
        # nothing interleaved can be attributed to a run after the fact.
        print(f"upstream conn: {time.time() - t_start:.1f}s to headers "
              f"(acct={acct['name']} model={req.chat_model_uid} {n_msgs} msgs, "
              f"{len(body) // 1024}KB req, purpose={purpose} "
              f"conv={(req.cascade_id or '?')[:12]})", flush=True)
        _request_phase("summarizing" if purpose == "summary" else "waiting_first_frame")
        buf = b""
        first_frame = True
        end_of_stream = False
        for chunk in r.iter_content(65536):
            buf += chunk
            while len(buf) >= 5:
                flag = buf[0]
                ln = struct.unpack(">I", buf[1:5])[0]
                if ln > MAX_FRAME_BYTES:
                    raise ValueError("upstream frame exceeds the wire size limit")
                if len(buf) < 5 + ln:
                    break
                payload = buf[5:5 + ln]
                buf = buf[5 + ln:]
                if flag & 2:
                    end_of_stream = True
                    trailer = _frame_payload(payload, flag & 1)
                    try:
                        err = json.loads(trailer).get("error") or {}
                    except Exception:
                        err = {}
                    # The Connect protocol makes the error message optional; a
                    # code on its own is still an error. Testing for `message`
                    # let those through as if the turn had completed normally.
                    if err:
                        code = err.get("code", "error")
                        message = err.get("message", "(no message)")
                        print(f"upstream trailer error on {acct['name']}: "
                              f"{code}: {message}", flush=True)
                        yield None, f"{code}: {message}"
                    continue
                raw = _frame_payload(payload, flag & 1)
                msg = protos()["GetChatMessageResponse"]()
                msg.ParseFromString(raw)
                if first_frame:
                    first_frame = False
                    _request_phase("summarizing" if purpose == "summary" else "streaming")
                    print(f"upstream first-frame: {time.time() - t_start:.1f}s "
                          f"({n_msgs} msgs)", flush=True)
                yield msg, None
        if not end_of_stream:
            # Connect always terminates a stream with an end-of-stream frame.
            # Without one the connection dropped mid-answer, and reporting the
            # partial turn as complete is what lets truncated output be stored
            # and replayed as if the model had finished.
            print("upstream stream ended without an end-of-stream frame",
                  flush=True)
            yield None, "upstream stream truncated"
    finally:
        # Abandoning the generator early (client disconnect) would otherwise
        # leave the socket open until garbage collection.
        if r is not None:
            r.close()


# --------------------------------------------------------------------------- #
# Compaction
# --------------------------------------------------------------------------- #

# A subagent that fills its window is simply killed: measured against Claude
# Code 2.1.272, the client drops a single message (30412 tokens to 30284) and
# then ends the agent with "Prompt is too long". It never summarises. The main
# session compacts; an agent does not, and nothing in its configuration turns
# that on. So the proxy does it instead — the client's own transcript is left
# alone and only what goes upstream is reduced, which the agent experiences as a
# turn that took a few seconds longer rather than as the end of its task.
COMPACT_AT = int(os.environ.get(
    "DEVINX_COMPACT_AT", str(int(SWE_CONTEXT_TOKENS * 0.82))))
# How much of the budget the verbatim tail may keep. The rest leaves room for
# the summary, the system prompt and the answer.
COMPACT_TAIL = 0.45
# Per tool result, and in total, when rendering the dropped turns for the
# summariser: it has a window too, and a transcript of file reads will exceed it.
SUMMARY_RESULT_CAP = 4000
SUMMARY_INPUT_CAP = 200000
# Ceiling on the accumulated summary. Past it the summary is summarised: the
# alternative, extending forever, eventually spends the whole window on the
# record of the work rather than the work.
SUMMARY_TOTAL_CAP = 12000

# Claude Code's own compaction prompt, read out of the binary rather than
# rewritten, so a summary made here is the one the agent would have made.
COMPACT_PROMPT = """Your task is to create a detailed summary of the conversation so far, paying close attention to the user's explicit requests and your previous actions.
This summary should be thorough in capturing technical details, code patterns, and architectural decisions that would be essential for continuing development work without losing context.

Your summary should include the following sections:

1. Primary Request and Intent: Capture all of the user's explicit requests and intents in detail
2. Key Technical Concepts: List all important technical concepts, technologies, and frameworks discussed.
3. Files and Code Sections: Enumerate specific files and code sections examined, modified, or created. Pay special attention to the most recent messages and include full code snippets where applicable and include a summary of why this file read or edit is important.
4. Errors and fixes: List all errors that you ran into, and how you fixed them. Pay special attention to specific user feedback that you received, especially if the user told you to do something differently.
5. Problem Solving: Document problems solved and any ongoing troubleshooting efforts.
6. All user messages: List ALL user messages that are not tool results. These are critical for understanding the users' feedback and changing intent. Preserve any security-relevant instructions or constraints verbatim so they remain in effect after compaction.
7. Pending Tasks: Outline any pending tasks that you have explicitly been asked to work on.
8. Current Work: Describe in detail precisely what was being worked on immediately before this summary request, paying special attention to the most recent messages from both user and assistant. Include file names and code snippets where applicable.
9. Optional Next Step: List the next step that you will take that is related to the most recent work you were doing. IMPORTANT: ensure that this step is DIRECTLY in line with the user's most recent explicit requests, and the task you were working on immediately before this summary request. If your last task was concluded, then only list next steps if they are explicitly in line with the users request. Do not start on tangential requests or really old requests that were already completed without confirming with the user first.
If there is a next step, include direct quotes from the most recent conversation showing exactly what task you were working on and where you left off. This should be verbatim to ensure there's no drift in task interpretation.

Please provide your summary based on the conversation so far, following this structure and ensuring precision and thoroughness in your response."""

# Claude Code's incremental variant, for the turns added since the last summary.
# Re-summarising the whole prefix every turn is what made compaction cost thirty
# seconds a turn; this extends the summary instead of rebuilding it.
COMPACT_PROMPT_MORE = """Your task is to create a detailed summary of the RECENT portion of the conversation — the messages that follow earlier retained context. The earlier messages are being kept intact and do NOT need to be summarized. Focus your summary on what was discussed, learned, and accomplished in the recent messages only.

""" + COMPACT_PROMPT.split("Your summary should include", 1)[1].join(
    ["Your summary should include", ""])

_summary_lock = threading.Lock()
_summaries = {}
# Summaries kept per conversation key: enough for a few runs sharing one key
# (parallel subagents with the same prompt and task, a resume) not to evict
# each other's.
SUMMARIES_PER_KEY = 4
_summary_flights = {}
COMPACT_STRICT = os.environ.get("DEVINX_COMPACT_STRICT") == "1"


class CompactionUnavailable(RuntimeError):
    """Strict compaction could not preserve the input safely."""


@contextlib.contextmanager
def _summary_guard(key):
    with _summary_lock:
        flight = _summary_flights.setdefault(key, [threading.Lock(), 0])
        flight[1] += 1
    try:
        with flight[0]:
            yield
    finally:
        with _summary_lock:
            flight[1] -= 1
            if not flight[1]:
                _summary_flights.pop(key, None)


def _block_hashes(span):
    return tuple(hashlib.sha256(json.dumps(pair, sort_keys=True,
                 ensure_ascii=False, default=str).encode()).hexdigest()
                 for pair in span)


def _uncovered_blocks(span, previous, flattened=False, hashes=None):
    """Return new blocks, or None if previously summarised content changed.

    Ordinary histories must extend a prefix. Legacy flattened histories insert
    new calls before old results; there the old sequence must be a subsequence,
    and every inserted block must still be carried or summarised (not skipped
    using the old block count).
    """
    if hashes is None:
        hashes = _block_hashes(span)
    if not flattened:
        if hashes[:len(previous)] != previous:
            return None
        return span[len(previous):]
    fresh, index = [], 0
    for pair, digest in zip(span, hashes):
        if index < len(previous) and digest == previous[index]:
            index += 1
        else:
            fresh.append(pair)
    return fresh if index == len(previous) else None


def _render_turns(messages):
    """Flatten dropped turns into a transcript the summariser can read."""
    out = []
    for m in messages:
        role = m.get("role", "user")
        for b in _blocks(m.get("content")):
            kind = b.get("type")
            if kind == "text":
                out.append(f"[{role}] {b.get('text', '')}")
            elif kind == "thinking":
                continue
            elif kind == "tool_use":
                args = json.dumps(b.get("input") or {})[:SUMMARY_RESULT_CAP]
                out.append(f"[{role} calls {b.get('name')}] {args}")
            elif kind == "tool_result":
                text = _tool_result_text(b)
                if len(text) > SUMMARY_RESULT_CAP:
                    text = (text[:SUMMARY_RESULT_CAP]
                            + f"\n… [{len(text) - SUMMARY_RESULT_CAP} more characters]")
                out.append(f"[tool result] {text}")
    rendered = "\n\n".join(out)
    if len(rendered) > SUMMARY_INPUT_CAP:
        # Keep the end: what happened most recently matters most to continuing.
        rendered = ("… [earlier turns omitted]\n\n"
                    + rendered[-SUMMARY_INPUT_CAP:])
    return rendered


def _summary_body(messages, model, system, previous):
    """The summariser's request. `system` is accepted and deliberately unused:
    the agent's own system prompt (its first 2000 characters used to ride
    along) says nothing about the turns being summarised, and it was paid for
    on every summary call."""
    return {
        "model": model,
        # Room for the model to think *and* answer. At 4096 it was spending the
        # whole budget reasoning and emitting no text at all: 12 of the first
        # 21 summary calls came back with zero characters.
        "max_tokens": int(os.environ.get("DEVINX_SUMMARY_TOKENS", "16384")),
        "system": "You are summarising a coding agent's conversation so it can "
                  "continue working after its context was compacted.",
        "messages": [{"role": "user", "content": [{"type": "text", "text":
            (f"<earlier_summary>\n{previous}\n</earlier_summary>\n\n"
             if previous else "")
            + f"<conversation>\n{_render_turns(messages)}\n</conversation>\n\n"
            + (COMPACT_PROMPT_MORE if previous else COMPACT_PROMPT)}]}],
    }


_TOO_LONG = object()


def _summarise_once(messages, model, system, previous, turn):
    """One summary, waited for rather than given up on.

    Every way this call used to fail is something that passes: a credential
    refusing (another one may not), every credential refusing (they come back —
    and on 2026-09-23 this was the whole story: 39 agents lost the middle of
    their run because both accounts refused at the same instant and this
    function returned None without a word), the provider being down, a dropped
    connection, an empty answer. So each of them is waited out, within the
    turn's own budget: the summary is part of the turn, not a second hold on
    top of it. The client does not see the wait as silence: the keepalive is
    armed before compaction starts. A client that leaves ends it (ClientGone).

    Returns the text, None when the budget is spent or the error is not one
    that passes, or _TOO_LONG when the transcript itself is too big to be read
    in one call — which the caller answers by splitting it.
    """
    req, _ = build_request(_summary_body(messages, model, system, previous))
    t0 = time.time()
    acct, empties, outages, drops, others = None, 0, 0, 0, 0
    pause = turn.sleep

    while True:
        turn.check()
        left = turn.left()
        if left <= 0:
            print(f"summary: {time.time() - t0:.0f}s of waiting spent without "
                  f"an answer", flush=True)
            return None
        if acct is not None and acct.get("excluded"):
            acct = None
        if acct is None:
            acct, until = claim_account()
            if acct is None and until is None:
                print("summary: every credential is excluded (free plan)",
                      flush=True)
                return None
            if acct is None:
                wait = min(max(until or 5.0, 1.0), left)
                wait += random.uniform(0, min(5.0, wait * 0.1))
                print(f"summary: every credential rate limited, waiting "
                      f"{wait:.0f}s ({time.time() - t0:.0f}s so far)", flush=True)
                _request_phase("waiting_rate_limit")
                pause(wait)
                continue
        texts, thinks, err = [], [], None
        for msg, e in chat_stream(req, acct, purpose="summary"):
            if e:
                err = e
                break
            if msg.delta_text:
                texts.append(msg.delta_text)
            elif msg.delta_thinking:
                thinks.append(msg.delta_thinking)
        if not err:
            print(f"summary done: latency={time.time() - t0:.1f}s "
                  f"chars={sum(len(t) for t in texts)} "
                  f"thinking={sum(len(t) for t in thinks)}", flush=True)
            got = "".join(texts).strip()
            if got:
                return got
            empties += 1
            if empties < 3:
                print(f"summary: came back empty, retrying ({empties}/3)",
                      flush=True)
                continue
            # The reasoning is not the summary the prompt asked for, but it is
            # an account of the same turns.
            fallback = "".join(thinks).strip()
            if fallback:
                print(f"summary: falling back to the reasoning "
                      f"({len(fallback)} chars)", flush=True)
                return fallback
            return None
        if "resource_exhausted" in err:
            block_account(acct, reset_delay(err))
            print(f"summary: rate limited on {acct['name']}", flush=True)
            acct = None          # claim again: another account, or a wait
            continue
        if any(t in err for t in _OUTAGE):
            outages += 1
            wait = min(15 * 2 ** (outages - 1), 120, left)
            print(f"summary: provider unavailable, waiting {wait:.0f}s",
                  flush=True)
            _request_phase("waiting_outage")
            pause(wait)
            continue
        if any(t in err for t in _TRANSIENT):
            drops += 1
            wait = min(2 ** drops, 30, left)
            print(f"summary: {err[:60]}, retrying in {wait:.0f}s", flush=True)
            pause(wait)
            continue
        if "too long" in err.lower():
            return _TOO_LONG
        others += 1
        if others <= 3:
            print(f"summary: {err[:80]}, retrying ({others}/3)", flush=True)
            pause(min(5 * others, max(left, 0)))
            continue
        print(f"summary: giving up on {err[:80]}", flush=True)
        return None


def _digest_turns(messages, cap=48000):
    """What the dropped turns did, written by the proxy itself.

    The last resort, used only when the summariser could not be reached within
    the whole wait budget. It is not a summary — it says what was done and not
    why — but it is a record, and a record is what the agent needs to avoid
    redoing its own work. Dropping the turns with nothing in their place is the
    one outcome this exists to rule out.
    """
    lines = []
    for m in messages:
        for b in _blocks(m.get("content")):
            kind = b.get("type")
            if kind == "text" and b.get("text", "").strip():
                who = "agent" if m.get("role") == "assistant" else "input"
                lines.append(f"[{who}] {b['text'].strip()[:400]}")
            elif kind == "tool_use":
                args = b.get("input") or {}
                key = next((str(args[k]) for k in ("file_path", "command",
                            "pattern", "path", "url", "description")
                            if args.get(k)), json.dumps(args)[:160])
                lines.append(f"[call {b.get('name')}] {key[:240]}")
            elif kind == "tool_result":
                text = _tool_result_text(b).strip().splitlines()
                head = text[0][:160] if text else ""
                flag = " (error)" if b.get("is_error") else ""
                lines.append(f"  -> {head}{flag}")
    out = "\n".join(lines)
    if len(out) > cap:
        # Keep both ends: how the span started and, above all, how it ended.
        keep = cap // 2
        out = (out[:keep] + f"\n… [{len(out) - cap} characters of the record "
               f"omitted] …\n" + out[-keep:])
    return ("Mechanical record of the compacted turns — the summariser could "
            "not be reached, so this lists what was done rather than why. "
            "Check the working tree before relying on it.\n\n" + out)


def _chunks(messages, cap):
    """Consecutive runs of messages whose transcript fits in one summary call."""
    out, cur, size = [], [], 0
    for m in messages:
        n = len(_render_turns([m]))
        if cur and size + n > cap:
            out.append(cur)
            cur, size = [], 0
        cur.append(m)
        size += n
    if cur:
        out.append(cur)
    return out


def summarise_turns(messages, model, system, previous=None, never_empty=True):
    """Summarise dropped turns. With never_empty, this always returns a text.

    A span too big for one call is summarised in pieces, each one extending the
    summary of the pieces before it, rather than having its beginning cut off
    to fit. A piece the summariser cannot be reached for within the wait budget
    gets the proxy's own mechanical record instead of nothing. The fold of an
    existing summary passes never_empty=False: there, keeping the summary as it
    is beats replacing it with a record of it.
    """
    if not messages:
        return None
    # The turn's budget, not a fresh one (see Turn); outside a turn — tests,
    # tools — a budget of its own.
    turn = current_turn()
    summary, added = previous, []
    pending = _chunks(messages, SUMMARY_INPUT_CAP)
    if len(pending) > 1:
        print(f"summary: {len(messages)} turns in {len(pending)} pieces",
              flush=True)
    while pending:
        piece = pending.pop(0)
        got = _summarise_once(piece, model, system, summary, turn)
        if got is _TOO_LONG and len(piece) > 1:
            half = len(piece) // 2
            pending[:0] = [piece[:half], piece[half:]]
            continue
        if got is _TOO_LONG or not got:
            if not never_empty:
                return None
            got = _digest_turns(piece)
            print(f"summary: using a mechanical record for {len(piece)} turns",
                  flush=True)
        added.append(got)
        summary = f"{summary}\n\n{got}" if summary else got
    return "\n\n".join(added)


# Below this many calls collapsed into one message the shape is just an agent
# doing parallel tool calls in a single turn, which is legitimate and must be
# left alone. The most this proxy has ever measured in one real turn is 20;
# the collapsed bodies carry 174. There is a lot of room between the two, and
# the cost of guessing wrong is splitting a genuine parallel turn into a
# sequence that never happened, so the threshold sits well clear of the top of
# the measured range rather than just above it.
FLAT_RUN = 32
# Past this, the blocks that led into a collapsed run are too big to sit on one
# turn, and the replayed thinking among them gives way to the text.
LEAD_CAP = int(os.environ.get("DEVINX_LEAD_CAP", "8000"))


def _is_flattened(messages):
    """One message holding a whole run of calls, the next holding every answer.

    That is not what the Messages API describes and not what the client's own
    transcript on disk contains, but it is what arrives on the wire for swe-2:
    the history collapsed into five messages. Every heuristic downstream reads
    a conversation as a sequence of turns, so the shape has to be restored
    before any of them runs, not worked around in each of them.
    """
    for i, m in enumerate(messages[:-1]):
        if m.get("role") != "assistant":
            continue
        uses = sum(1 for b in _blocks(m.get("content"))
                   if b.get("type") == "tool_use")
        nxt = messages[i + 1]
        if nxt.get("role") != "user":
            continue
        results = sum(1 for b in _blocks(nxt.get("content"))
                      if b.get("type") == "tool_result")
        if uses >= FLAT_RUN and results >= FLAT_RUN:
            return True
    return False


def _unflatten(messages):
    """Pair each call back with its answer and give each pair its own turn.

    Order is reconstructed from the tool_use ids, which is the only record of
    it left once the blocks have been grouped by role. Thinking and text that
    led into the run stay on the first turn of it. Nothing is invented: a call
    whose answer is missing keeps its turn alone, and an answer whose call is
    missing is kept too rather than dropped, because its content is work the
    agent did.
    """
    out, i = [], 0
    while i < len(messages):
        m = messages[i]
        nxt = messages[i + 1] if i + 1 < len(messages) else None
        blocks = _blocks(m.get("content"))
        uses = [b for b in blocks if b.get("type") == "tool_use"]
        if (m.get("role") == "assistant" and len(uses) >= FLAT_RUN
                and nxt is not None and nxt.get("role") == "user"):
            answers = _blocks(nxt.get("content"))
            by_id = {}
            for b in answers:
                if b.get("type") == "tool_result":
                    by_id.setdefault(b.get("tool_use_id"), []).append(b)
            if len(by_id) < FLAT_RUN:
                out.append(m)
                i += 1
                continue
            lead = [b for b in blocks if b.get("type") != "tool_use"]
            if lead:
                size = sum(len(json.dumps(b, default=str)) for b in lead) // 4
                if size > LEAD_CAP:
                    # A whole run's narration on one message, and no record of
                    # which call each piece belonged to. Kept whole it becomes a
                    # message compaction cannot split, so if it ever lands in
                    # the verbatim tail the tail collapses to it alone. The text
                    # is what the agent said it was doing; the thinking is
                    # replayed reasoning it has already acted on. The text stays.
                    text = [b for b in lead if b.get("type") == "text"]
                    dropped = len(lead) - len(text)
                    print(f"unflatten: {size}t of leading blocks on one turn; "
                          f"keeping {len(text)} text, dropping {dropped} "
                          f"replayed thinking", flush=True)
                    lead = text
                out.append({"role": "assistant", "content": lead})
            for u in uses:
                out.append({"role": "assistant", "content": [u]})
                got = by_id.pop(u.get("id"), None)
                if got:
                    out.append({"role": "user", "content": got})
                    continue
            leftovers = [b for b in answers
                         if b.get("type") != "tool_result"
                         or b.get("tool_use_id") in by_id]
            if leftovers:
                out.append({"role": "user", "content": leftovers})
            i += 2
            continue
        out.append(m)
        i += 1
    return out


def unflatten_body(body):
    """The body as a sequence of turns, whatever shape it arrived in."""
    messages = body.get("messages") or []
    if not _is_flattened(messages):
        return body
    restored = _unflatten(messages)
    print(f"unflattened: {len(messages)} messages -> {len(restored)} turns "
          f"(model={body.get('model')})", flush=True)
    out = dict(body)
    out["messages"] = restored
    return out


def _span_blocks(messages, start):
    """Every content block the summary has to cover, in order.

    Counted in blocks and not in messages because the client does not always
    send one turn per message: a flattened body carries the whole history as
    five messages whose block counts climb turn after turn. A summary whose
    freshness is judged by len(messages) is then built once and never again —
    the conversation grows, the summary does not, and the agent works from a
    record of what it was doing hours ago. Blocks grow in both shapes.
    """
    out = []
    for m in messages[1:start]:
        role = m.get("role", "user")
        for b in _blocks(m.get("content")):
            out.append((role, b))
    return out


def _regroup(pairs):
    """(role, block) pairs back into messages, merging consecutive roles."""
    out = []
    for role, b in pairs:
        if out and out[-1]["role"] == role:
            out[-1]["content"].append(b)
        else:
            out.append({"role": role, "content": [b]})
    return out


def _count_blocks(messages):
    return sum(len(_blocks(m.get("content"))) for m in messages)


def _tail_start(messages, budget):
    """Where the verbatim tail begins.

    Never on a user turn that carries a tool_result, because the tool_use it
    answers would be in the part being dropped, leaving a result with nothing
    to attach to.
    """
    total, start = 0, len(messages)
    for i in range(len(messages) - 1, 0, -1):
        total += len(json.dumps(messages[i], default=str)) // 4
        if total > budget:
            break
        start = i
    # Step back onto the assistant turn that issued the tool_use, never forward
    # past the result. Walking forward eats the entire tail when an agent is
    # doing back-to-back tool calls — every user turn is then a tool_result, so
    # the boundary marches to the end of the conversation and the agent is left
    # with none of the work it just did. That is exactly when it needs it: it
    # reads a file, the read is dropped, and its next edit no longer matches.
    # When even the last message alone overruns the budget the loop above never
    # advances, and start stays past the end: indexing it raised, compaction was
    # abandoned, and the turn went upstream uncompacted — exactly the turns that
    # could least afford it.
    start = min(start, len(messages) - 1)
    while start > 1:
        blocks = _blocks(messages[start].get("content"))
        if any(b.get("type") == "tool_result" for b in blocks):
            start -= 1
            continue
        break
    return start


def compact_body(body):
    messages = body.get("messages") or []
    # One memo for the whole compaction: every estimate below reweighs the
    # same message objects.
    memo = {}
    if estimate_tokens(body, memo) <= COMPACT_AT:
        return body
    if len(messages) < 4:
        if COMPACT_STRICT:
            raise CompactionUnavailable("context exceeds the budget with no safely droppable turns")
        return body
    with _summary_guard(_conv_key(body)):
        return _compact_body(body, memo)


def _compact_body(body, memo=None):
    """Replace the middle of an over-long conversation with a summary.

    The first turn stays: it is the task. The recent turns stay verbatim: they
    are what the agent is doing right now. Everything between becomes one
    summary, written with Claude Code's own compaction prompt.
    """
    messages = body.get("messages") or []
    if len(messages) < 4 or estimate_tokens(body, memo) <= COMPACT_AT:
        return body
    start = _tail_start(messages, int(COMPACT_AT * COMPACT_TAIL))
    if start <= 1 or start >= len(messages):
        # Nothing to drop that would help; the size is the first turn or the
        # tail alone, and summarising cannot fix either.
        if COMPACT_STRICT:
            raise CompactionUnavailable("context exceeds the budget with no safely droppable turns")
        print("compaction: nothing droppable, forwarding as is", flush=True)
        return body

    key = _conv_key(body)
    span = _span_blocks(messages, start)
    total_blocks = _count_blocks(messages)
    # Several summaries per key, each good for exactly the history it covers.
    # A resumed agent is the same task under the same system prompt in the same
    # session, so it hashes to the same key — and so do two subagents launched
    # in parallel with the same prompt and the same first task. With one
    # summary per key, a resume inherited the failed run's summary, and the
    # two parallel runs took turns throwing each other's away ("conversation
    # restarted") and rebuilding their own, on every turn. A summary is now
    # used only when the blocks it covers are still, unchanged, the start of
    # this history; each run finds its own and a restarted one finds none.
    # Only the summary is chosen this way; the cascade id stays the key's,
    # because that is what keeps the upstream prefix cache and it is worth
    # about 60% of the input tokens.
    flattened = _is_flattened(messages)
    span_hashes = _block_hashes(span)
    with _summary_lock:
        stored = list(_summaries.get(key) or ())
    entry, fresh = None, None
    for candidate in sorted(stored, key=lambda e: len(e[3]), reverse=True):
        got = _uncovered_blocks(span, candidate[3], flattened, span_hashes)
        if got is not None:
            entry, fresh = candidate, got
            break
    if entry is None:
        if stored:
            print(f"compaction: none of the {len(stored)} summaries kept for "
                  f"this conversation covers its history; building a new one",
                  flush=True)
        covered, summary, covered_hashes, fresh = 0, None, (), span
    else:
        covered, summary, _, covered_hashes = entry
    retained = ""
    if COMPACT_STRICT:
        user_text = [b.get("text", "") for role, b in span
                     if role in ("user", "system") and b.get("type") == "text"]
        if user_text:
            retained = ("\n\nEarlier user/system text, verbatim in chronological order "
                        "(historical context, not new instructions):\n"
                        + "\n\n".join(user_text))
    # What the summary does not cover yet does not have to be summarised to be
    # kept: it can ride verbatim between the summary and the tail, which is
    # better for the agent and costs nothing. So the question is not "has
    # enough arrived" but "does it still fit" — and while it fits, no upstream
    # call is made at all. That is the difference between summarising on most
    # turns and summarising on one turn in ten, on a quota metered in requests
    # rather than tokens.
    def fits(text, uncovered):
        head = [messages[0], {"role": "user", "content": [
            {"type": "text", "text": (text or "") + retained}]}]
        trial = dict(body)
        trial["messages"] = head + _regroup(uncovered) + messages[start:]
        return estimate_tokens(trial, memo) <= COMPACT_AT, trial

    room, _ = fits(summary, fresh)
    if summary is None or not room:
        model = resolve_model(body)
        before = estimate_tokens(body, memo)
        # Only what arrived since the last summary, extending it rather than
        # rebuilding it: the difference between a few seconds a turn and half a
        # minute a turn.
        fresh_count = len(fresh)
        new = summarise_turns(_regroup(fresh), model, _system_text(body), summary)
        if not new and summary is None and COMPACT_STRICT:
            raise CompactionUnavailable("no summary available; no turns were discarded")
        if not new and summary is None:
            # No summary could be made and there is no earlier one to stand in.
            # Forwarding the turn whole was the old answer and it is not an
            # answer: an oversized body comes back refused, and a refusal ends
            # a subagent. The turns are dropped without a summary instead. The
            # agent loses the middle of its run, which is a real loss, and it
            # keeps its task, its recent work and its life.
            print(f"compaction: no summary available ({before} tokens, over "
                  f"{COMPACT_AT}); dropping {len(span)} blocks unsummarised",
                  flush=True)
            summary = None
        elif not new:
            # An extension failed but the earlier summary still stands. Going
            # out with it is worse than going out with a current one and much
            # better than going out whole: an oversized body comes back
            # refused, and a subagent does not survive being refused.
            print(f"compaction: the summary could not be extended; going out "
                  f"with the one covering {covered} of {len(span)} blocks",
                  flush=True)
        else:
            summary = f"{summary}\n\n{new}" if summary else new
        if summary and len(summary) // 4 > SUMMARY_TOTAL_CAP:
            # Fold rather than grow. Summarising the summary keeps one document
            # of the whole run instead of a chain of appendices, and costs one
            # short call against a record that would otherwise never stop.
            folded = summarise_turns(
                [{"role": "user", "content": [{"type": "text", "text": summary}]}],
                model, _system_text(body), None, never_empty=False)
            if folded:
                print(f"compaction: summary folded, {len(summary) // 4} -> "
                      f"{len(folded) // 4} tokens", flush=True)
                summary = folded
        if new:
            covered = len(span)
            covered_hashes = span_hashes
            fresh = []
        with _summary_lock:
            # Bounded insertion-order eviction, not a fleet-wide cache wipe.
            if key not in _summaries and len(_summaries) >= 64:
                _summaries.pop(next(iter(_summaries)))
            kept = [e for e in (_summaries.get(key) or ()) if e is not entry]
            _summaries[key] = (kept + [(covered, summary, total_blocks,
                                        covered_hashes)])[-SUMMARIES_PER_KEY:]
        if new:
            print(f"compaction: {fresh_count} more blocks summarised "
                  f"({covered} of {len(span)} covered, {before} tokens "
                  f"estimated, over {COMPACT_AT})", flush=True)

    # Uncovered turns ride verbatim only when there is a summary in front of
    # them. With none — the summariser could not be reached — they are what had
    # to go, and carrying them is exactly the oversized body this must not send.
    carried = _regroup(fresh) if summary else []
    if summary:
        bridge = ("This conversation was compacted to fit the context window. "
                  "The summary below replaces the turns between the task above "
                  "and the messages that follow; continue the work from it."
                  f"\n\n<summary>\n{summary}\n</summary>")
    else:
        bridge = ("This conversation was compacted to fit the context window "
                  "and no summary of the removed turns could be made. The "
                  "turns between the task above and the messages that follow "
                  "are gone. Re-establish what you need from the working tree "
                  "rather than assuming it, and say so if the task no longer "
                  "makes sense without them.")
    bridge += retained
    def assemble(keep):
        out = dict(body)
        out["messages"] = ([messages[0], {"role": "user", "content": [
            {"type": "text", "text": bridge}]}] + keep + messages[start:])
        return out

    compacted = assemble(carried)
    if COMPACT_STRICT and estimate_tokens(compacted, memo) > COMPACT_AT:
        raise CompactionUnavailable("preserved context still exceeds the compaction budget")
    if carried and estimate_tokens(compacted, memo) > COMPACT_AT:
        # The summary could not be extended far enough to make room. Whatever
        # it does not cover goes, because a body over the limit comes back
        # refused and that ends the agent.
        print(f"compaction: dropping {len(carried)} uncovered turns to fit",
              flush=True)
        compacted = assemble([])
    # Diagnostic: what the conversation is actually made of. The tail collapses
    # when single messages are large enough to spend its whole budget, and that
    # is worth knowing from measurement rather than assumption.
    def anatomy(m):
        raw = len(json.dumps(m, default=str)) // 4
        est = estimate_tokens({"messages": [m]}, memo)
        parts = []
        for b in _blocks(m.get("content")):
            kind = b.get("type")
            size = len(json.dumps(b, default=str)) // 4
            name = b.get("name") or ""
            parts.append(f"{kind}{'/' + name if name else ''}={size}t")
        return raw, est, m.get("role"), len(_blocks(m.get("content"))), parts[:3]

    worst = max(messages, key=lambda m: len(json.dumps(m, default=str)))
    raw, est, role, nblocks, parts = anatomy(worst)
    print(f"compaction: {estimate_tokens(body, memo)} -> {estimate_tokens(compacted, memo)} "
          f"tokens; {len(messages)} msgs; biggest: role={role} blocks={nblocks} "
          f"raw={raw}t est={est}t :: {' | '.join(parts)}", flush=True)
    return compacted


# --------------------------------------------------------------------------- #
# Cognition response -> Anthropic Messages
# --------------------------------------------------------------------------- #

# Connect error code -> (Anthropic error type, HTTP status). The type is not
# cosmetic: a client backs off and retries a rate_limit_error, and compacts on an
# invalid_request_error that says the prompt is too long, while an api_error just
# ends the turn. Reporting every upstream refusal as api_error is why a
# rate-limited subagent stopped dead instead of waiting out the minute it was
# told to wait — measured in one log: 1107 rate limits against 13 real overflows.
_ERROR_TYPES = {
    "resource_exhausted": ("rate_limit_error", 429),
    "invalid_argument": ("invalid_request_error", 400),
    "permission_denied": ("permission_error", 403),
    "unauthenticated": ("authentication_error", 401),
    "deadline_exceeded": ("timeout_error", 408),
    "unavailable": ("overloaded_error", 503),
}


# The upstream says how long the wait is ("Your limit will reset in 11
# minutes"). Passing that on as retry-after turns a guess into an instruction.
_RESET_AFTER = re.compile(r"reset in (\d+) (second|minute|hour)")


def reset_delay(err, default=30):
    """How long the upstream said to wait, in seconds.

    It answers in whichever unit reads best — "reset in 20 seconds" as often as
    "reset in 11 minutes" — and the pattern only ever matched minutes. Every
    short refusal therefore blocked the credential for the 30-second default
    instead of the 3 or 20 it asked for, and under saturation that is the
    difference between a credential coming back and a fleet waiting on it.
    """
    found = _RESET_AFTER.search(err or "")
    if not found:
        return default
    n, unit = int(found.group(1)), found.group(2)
    return n * {"second": 1, "minute": 60, "hour": 3600}[unit]


def anthropic_error(err, body=None):
    """Map an upstream error string onto (type, status, message, retry_after).

    The overflow message is rewritten rather than forwarded. A client recovers
    from this one by parsing two numbers out of it — measured against Claude
    Code 2.1.272, `prompt is too long[^0-9]*(\\d+) tokens? > (\\d+)` — and
    Cognition sends prose with no numbers in it at all ("The prompt is too long
    for this model"), so the parse fails, the recovery never fires, and the turn
    is simply over. Saying the same thing with the figures in it is the
    difference between an agent that compacts and an agent that stops.
    """
    code = err.split(":", 1)[0].strip()
    kind, status = _ERROR_TYPES.get(code, ("api_error", 502))
    retry_after, message = None, err
    if status == 429:
        found = _RESET_AFTER.search(err)
        if found:
            retry_after = reset_delay(err)
    elif status == 400 and "too long" in err.lower() and body is not None:
        message = (f"prompt is too long: {estimate_tokens(body)} tokens > "
                   f"{SWE_CONTEXT_TOKENS} maximum")
    return kind, status, message, retry_after


def _usage(u):
    """Cognition usage maps 1:1 onto Anthropic's — no arithmetic in between."""
    out = {"input_tokens": int(u.input_tokens),
           "output_tokens": int(u.output_tokens)}
    if u.cache_read_tokens:
        out["cache_read_input_tokens"] = int(u.cache_read_tokens)
    if u.cache_write_tokens:
        out["cache_creation_input_tokens"] = int(u.cache_write_tokens)
    return out


def _json_cut(err, raw):
    """Where the arguments stopped making sense, without quoting them.

    A call dropped for unparseable arguments has two very different causes and
    the same log line today. If the parser gave up at the very end of the
    string, the model was cut off mid-call and reporting max_tokens is exactly
    right. If it gave up in the middle, the stream was assembled wrong here and
    the turn was ours to lose. The position tells them apart; the arguments are
    the user's work and do not belong in a log.
    """
    pos = getattr(err, "pos", None)
    if pos is None:
        return "position unknown"
    where = "at the end" if pos >= len(raw) - 2 else "mid-string"
    return f"parser stopped at {pos}/{len(raw)}, {where}: {getattr(err, 'msg', '')}"


def _stop_reason(stop, has_tools):
    """max_tokens outranks tool_use on purpose.

    A turn cut off mid-tool-call carries a tool block whose JSON never closed.
    Reporting that as a clean `tool_use` invites the client to execute a
    truncated call; `max_tokens` tells it the turn was cut short, which is what
    actually happened.
    """
    if stop == STOP_MAX_TOKENS:
        return "max_tokens"
    if has_tools:
        return "tool_use"
    return "end_turn"


class _KeepAlive:
    """The keepalive both emitters share, and the client-gone flag it raises.

    A turn that spends four minutes reasoning before its first token sends no
    bytes at all, and both clients give up on a stream that has been silent for
    five: Claude Code reports "The response stopped arriving", Codex drops the
    stream and sends the request again — a duplicate, held in parallel with
    the first. Each emitter says in _keepalive() what a harmless event is in
    its own dialect.

    The first keepalive is also the point of no return: writing it commits to
    a 200, so an upstream refusal after that is an SSE error event rather than
    an HTTP status. That is the same trade the real API makes, and it only
    applies to turns already slower than any retry would be.

    Every write goes through _write(), which sets `gone` when the socket
    refuses it. That flag is the turn's: a keepalive that finds the client
    gone used to stop in silence and leave the turn retrying for nobody.
    """

    def _keep_alive_init(self):
        # One writer at a time: the keepalive runs on its own thread and an
        # interleaved write would split an event in half on the wire.
        self._wlock = threading.RLock()
        self._last_write = time.time()
        self._done = threading.Event()
        self._alive = None
        self.gone = threading.Event()

    def _write(self, data):
        try:
            self.w.write(data)
            self.w.flush()
        except OSError:
            self.gone.set()
            raise
        self._last_write = time.time()

    def arm(self):
        """Hold the connection open while the upstream thinks."""
        if KEEPALIVE_EVERY <= 0 or self._alive is not None:
            return

        def loop():
            while not self._done.wait(1.0):
                if time.time() - self._last_write < KEEPALIVE_EVERY:
                    continue
                try:
                    with self._wlock:
                        if self._done.is_set():
                            return
                        if not self.started:
                            self.start()
                        else:
                            self._keepalive()
                except Exception:
                    # The client is gone, or the socket is. Either way there is
                    # nothing left to keep alive — and the turn has to know.
                    self.gone.set()
                    return

        self._alive = threading.Thread(target=loop, daemon=True)
        self._alive.start()

    def release(self):
        # Synchronise with a keepalive that may be about to commit HTTP 200.
        # Once this returns the caller can decide safely between HTTP and SSE.
        with self._wlock:
            self._done.set()


class AnthropicStream(_KeepAlive):
    """Emits the Anthropic SSE event sequence onto a raw socket.

    Blocks are opened lazily and closed when the next kind of content starts.

    On the signature: Cognition sends it in the very last frame, after every text
    and tool delta, so a thinking block that was streamed live has already been
    closed by then and no signature_delta can be attached to it. That is
    deliberate rather than a gap — measured upstream frame order is
    think -> tool... -> SIG -> stop. It costs nothing because the signature is not
    what carries reasoning across turns: Claude Code stores the thinking *text*
    and replays it, and Cognition accepts replayed thinking with no signature at
    all (verified). Buffering the whole turn just to sign it would trade live
    output for nothing. The non-streaming path, which assembles at the end, does
    include it.
    """

    def __init__(self, wfile, model):
        self.w = wfile
        self.model = model
        self.index = -1
        self.open_kind = None
        self.open_key = None
        self.pending_signature = None
        self.started = False
        self.tools = {}
        self._keep_alive_init()

    def _keepalive(self):
        # Anthropic's own API keeps a stream alive with `ping`.
        self._send("ping", {"type": "ping"})

    def _send(self, event, data):
        with self._wlock:
            self._write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())

    def start(self, usage=None):
        with self._wlock:
            if self.started:
                return
            self.started = True
            self._write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
                        b"cache-control: no-cache\r\nconnection: close\r\n\r\n")
            self._send("message_start", {
                "type": "message_start",
                "message": {"id": new_message_id(), "type": "message",
                            "role": "assistant", "model": self.model,
                            "content": [], "stop_reason": None,
                            "stop_sequence": None,
                            "usage": usage or {"input_tokens": 0,
                                               "output_tokens": 0}}})

    def close_block(self):
        if self.open_kind is None:
            return
        if self.open_kind == "thinking" and self.pending_signature:
            self._send("content_block_delta", {
                "type": "content_block_delta", "index": self.index,
                "delta": {"type": "signature_delta",
                          "signature": self.pending_signature}})
            self.pending_signature = None
        self._send("content_block_stop",
                   {"type": "content_block_stop", "index": self.index})
        self.open_kind = None
        self.open_key = None

    def open_block(self, kind, key=None, block=None):
        if self.open_kind == kind and self.open_key == key:
            return
        self.close_block()
        self.index += 1
        self.open_kind = kind
        self.open_key = key
        self._send("content_block_start", {
            "type": "content_block_start", "index": self.index,
            "content_block": block})

    def thinking(self, text):
        self.open_block("thinking", None, {"type": "thinking", "thinking": ""})
        self._send("content_block_delta", {
            "type": "content_block_delta", "index": self.index,
            "delta": {"type": "thinking_delta", "thinking": text}})

    def signature(self, sig):
        if self.open_kind == "thinking":
            self.pending_signature = sig
        # A signature arriving after the thinking block closed cannot be attached
        # retroactively; the turn then degrades to an unsigned thinking block.

    def text(self, text):
        self.open_block("text", None, {"type": "text", "text": ""})
        self._send("content_block_delta", {
            "type": "content_block_delta", "index": self.index,
            "delta": {"type": "text_delta", "text": text}})

    def tool(self, tid, name, args_json):
        """Buffer a tool call; nothing is emitted until finish().

        Streaming tool blocks through a single open slot misattributed fragments
        whenever the upstream interleaved two call ids, and forced
        content_block_start to go out before the name was known — neither of
        which Anthropic's wire format lets you amend afterwards. Buffering costs
        nothing real: a tool call is not actionable until its JSON closes.
        """
        self.tools[tid] = {"name": name, "json": args_json}

    def flush_tools(self):
        for tid, b in self.tools.items():
            self.open_block("tool", tid, {"type": "tool_use", "id": tid,
                                          "name": b["name"], "input": {}})
            if b["json"]:
                self._send("content_block_delta", {
                    "type": "content_block_delta", "index": self.index,
                    "delta": {"type": "input_json_delta",
                              "partial_json": b["json"]}})
        self.tools = {}

    def finish(self, stop_reason, usage):
        self.release()
        self.flush_tools()
        self.close_block()
        self._send("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": usage})
        self._send("message_stop", {"type": "message_stop"})

    def error(self, message, kind="api_error"):
        self.failure = kind
        self._send("error", {"type": "error",
                             "error": {"type": kind, "message": message}})

    def stop(self):
        """End a failed stream. Deliberately no message_delta: there is no
        stop_reason that honestly describes an aborted turn, and emitting
        end_turn would tell the client the answer is complete."""
        self.release()
        self.close_block()
        self._send("message_stop", {"type": "message_stop"})


def _swe_early_error(out, err):
    if out is not None:
        out.release()
        if out.started:
            out.error(err, anthropic_error(err)[0])
            out.stop()
            return None, None
    return None, err


def run_swe(body, wfile, make_stream=None, outcome=None):
    """Run a turn, keeping the streaming lifecycle and error contract shared.

    `outcome` is an optional local diagnostic dict, never response content.
    A 200 stream that later fails must not be logged as a successful turn.
    """
    emitter = make_stream or AnthropicStream
    out = emitter(wfile, resolve_model(body)) if body.get("stream") else None
    # The connection comes from the handler through the thread, not as an
    # argument: every caller and test double keeps the same signature, and the
    # non-streaming path, which has no emitter, is watched just the same.
    turn = Turn(conn=getattr(_request_local, "conn", None),
                gone=getattr(out, "gone", None))
    outer = getattr(_request_local, "turn", None)
    _request_local.turn = turn
    try:
        if out is not None:
            out.arm()
        response, err = _run_swe(body, out)
        if outcome is not None:
            outcome["status"] = (str(anthropic_error(err)[1]) if err else
                                 "stream_error" if getattr(out, "failure", None)
                                 else "200")
        return response, err
    except ClientGone:
        # Nobody is left to answer, so nothing is written and no further
        # upstream call is made on the turn's behalf.
        print(f"client disconnected while its turn was held "
              f"({turn.spent():.0f}s in); abandoning it", flush=True)
        if outcome is not None:
            outcome["status"] = "client_disconnected"
        return None, CLIENT_GONE
    finally:
        _request_local.turn = outer
        if out is not None:
            out.release()


@contextlib.contextmanager
def _paced_for(acct, turn):
    """paced(), waited for in steps so a departed client is noticed."""
    gate = paced(acct)
    if not hasattr(gate, "acquire"):
        with gate:
            yield
        return
    while not gate.acquire(timeout=Turn.STEP):
        turn.check()
    try:
        yield
    finally:
        gate.release()


def _run_swe(body, out):
    """Run one SWE-2 turn. Returns (response_dict, error) for the non-stream path;
    streams and returns (None, None) when the client asked for SSE.

    make_stream picks the wire the answer goes back on: Anthropic by default,
    the Codex flavour of Responses when the request came in on that route. Only
    the emitter differs — everything upstream of it is shared.
    """
    turn = current_turn()
    # Before anything is sent: if this turn would not fit, reduce it here rather
    # than let the upstream refuse it and the client end the agent.
    try:
        # Order first, then size: compaction decides what to keep verbatim by
        # walking back over turns, and on a collapsed body there is only ever
        # one turn to walk back over.
        _request_phase("compacting")
        body = unflatten_body(body)
        body = compact_body(body)
    except CompactionUnavailable as e:
        return _swe_early_error(out, f"unavailable: strict compaction: {e}")
    except Exception as e:
        if COMPACT_STRICT:
            # Strict mode must not silently become lossy on an unexpected
            # summariser/parser failure. Do not include prompt-bearing details.
            return _swe_early_error(out, "unavailable: strict compaction failed")
        # Compaction is a rescue, never a new way to fail. A turn that would
        # have gone out uncompacted still goes out.
        print(f"compaction failed, forwarding as is: {e}", flush=True)
    # Report the resolved tier, not the alias, so the tier that actually ran is
    # visible in the client.
    def committed():
        """Has anything reached the client yet.

        Not the same question as "has content been emitted": the keepalive can
        open the stream on its own while the upstream is still thinking, and
        once a message_start is on the wire an HTTP status is no longer
        expressible. A retry before content can reuse that same emitter.
        """
        return emitted or (out is not None and out.started)

    # Cognition's input classifier denies borderline payloads nondeterministically
    # (the same body has been observed to pass and to fail). Retry while nothing
    # has reached the client yet.
    attempt, retries, outages = 0, 0, 0
    acct = None
    while attempt < 3:
        # Before every attempt, first included: compaction may have held the
        # turn for minutes, and every retry below is one more request.
        turn.check()
        try:
            _request_phase("preparing")
            req, model = build_request(body, TOOL_DESC_CAPS[attempt])
        except Exception as e:
            # Typically a missing or expired Devin credential, surfaced here
            # rather than at import. The streaming client has had nothing yet, so
            # it needs a real SSE error instead of a silently closed socket.
            # Nothing has been written yet either way, so this goes back as a
            # status the client can act on rather than as a 200 stream whose
            # only content is an error — and never as a finished turn.
            return _swe_early_error(out, f"request build: {e}")

        thinking, signature, texts = [], None, []
        tool_order, tool_blocks = [], {}
        usage, stop, err, emitted = {}, 0, None, False
        latency = 0.0

        if acct is not None and acct.get("excluded"):
            acct = None          # excluded mid-turn: never retried on it
        if acct is None:
            acct, _ = claim_account()
            if acct is None:
                acct = _first_usable()
        try:
          _request_phase("waiting_capacity")
          with _paced_for(acct, turn):
            for msg, e in chat_stream(req, acct):
                if e:
                    err = e
                    break
                if msg.delta_thinking:
                    thinking.append(msg.delta_thinking)
                    if out:
                        out.start(); emitted = True
                        out.thinking(msg.delta_thinking)
                if msg.delta_signature:
                    signature = msg.delta_signature
                    if out:
                        out.signature(msg.delta_signature)
                if msg.delta_text:
                    texts.append(msg.delta_text)
                    if out:
                        out.start(); emitted = True
                        out.text(msg.delta_text)
                for tc in msg.delta_tool_calls:
                    tid = safe_tool_id(tc.id) or (tool_order[-1]
                                                  if tool_order else "")
                    if not tid:
                        continue
                    if tid not in tool_blocks:
                        tool_blocks[tid] = {"name": tc.name, "json": ""}
                        tool_order.append(tid)
                    if tc.name:
                        tool_blocks[tid]["name"] = tc.name
                    if tc.arguments_json:
                        prev = tool_blocks[tid]["json"]
                        # Cognition sometimes resends the whole buffer instead of
                        # a delta; detect that rather than concatenating twice.
                        if tc.arguments_json.startswith(prev):
                            tool_blocks[tid]["json"] = tc.arguments_json
                        else:
                            tool_blocks[tid]["json"] = prev + tc.arguments_json
                if msg.usage.input_tokens or msg.usage.output_tokens or \
                        msg.usage.cache_read_tokens or msg.usage.cache_write_tokens:
                    usage = _usage(msg.usage)
                if msg.stop_reason:
                    stop = msg.stop_reason
                    latency = msg.latency
            # Logged after the stream rather than on the stop_reason frame:
            # Cognition populates usage in a frame that arrives *after* that one,
            # so reading it at stop time reported in=0 out=0 for every turn while
            # the response returned to the client had the real figures all along.
            if not err:
                # The stop reason is what separates "the agent decided it was
                # finished" from "the turn was cut short", and reading it back
                # from the client is impossible.
                print(f"upstream done: stop={_stop_reason(stop, bool(tool_order))}"
                      f"/{stop} calls={len(tool_order)} "
                      f"purpose=turn conv={(req.cascade_id or '?')[:12]} "
                      f"latency={latency:.1f}s "
                      f"usage in={usage.get('input_tokens', 0)} "
                      f"out={usage.get('output_tokens', 0)} "
                      f"cr={usage.get('cache_read_input_tokens', 0)} "
                      f"cw={usage.get('cache_creation_input_tokens', 0)}",
                      flush=True)
        except (requests.RequestException, OSError, ValueError) as e:
            # Network failure, a malformed frame, or an auth call that raised.
            # Left uncaught these reached the handler, which for a streaming
            # request had no path to answer: the client got a closed socket with
            # no status line and no SSE error at all.
            err = f"upstream {type(e).__name__}: {e}"
            print(err, flush=True)

        if err:
            # A write to a client that left raises the same OSErrors as a
            # dropped upstream — ConnectionResetError is on the transient list —
            # so without this a vanished client was retried as a network fault.
            turn.check()
        if (err and not emitted and retries < NETWORK_RETRIES
                and any(t in err for t in _TRANSIENT)):
            retries += 1
            delay = 1.5 * retries
            print(f"upstream connection failed ({err[:60]}), retrying in "
                  f"{delay:.0f}s ({retries}/{NETWORK_RETRIES})", flush=True)
            turn.sleep(delay)
            continue
        if err and not emitted and "resource_exhausted" in err:
            # Both of Cognition's limits are per account, so another credential
            # is a switch rather than a wait. Only when every one of them is
            # spent does the turn actually have to be held.
            # Floored: "reset in 0 seconds" is a real answer, and read
            # literally it made this a loop with no pause in it — two
            # credentials handed the turn back and forth on every round trip,
            # and a single one handed it back to the client at once.
            delay = max(reset_delay(err), RATE_FLOOR)
            if acct is not None:
                block_account(acct, delay)
            other, until = claim_account(avoid=acct)
            if other is not None:
                print(f"upstream rate limited on {acct['name']}, switching to "
                      f"{other['name']}", flush=True)
                acct = other
                continue
            if until is None:
                # Every credential is excluded (free plan): none comes back
                # on its own, so holding the turn would only burn its budget.
                print("upstream rate limited and every credential is excluded; "
                      "handing it back", flush=True)
                break
            # Every account is blocked; wait for the first one to come back.
            wait = min(max(until, RATE_FLOOR), turn.left())
            if wait > 0:
                wait += random.uniform(0, min(5.0, wait * 0.1))
                print(f"upstream rate limited on every credential, holding "
                      f"the turn for {wait:.0f}s "
                      f"({turn.spent():.0f}s waited so far)",
                      flush=True)
                _request_phase("waiting_rate_limit")
                turn.sleep(wait)
                acct, _ = claim_account()
                continue
            print(f"upstream rate limited and the turn's {turn.budget}s budget "
                  f"is spent; handing it back", flush=True)
            break
        if err and not emitted and any(t in err for t in _OUTAGE):
            # 93 turns died this way in twenty minutes on 2026-09-23: the
            # provider behind Cognition went down, the error came back in under
            # a second, and it was handed straight to the agent as a 502. The
            # outage cleared by itself; a turn that had waited would have lived.
            outages += 1
            wait = min(15 * 2 ** (outages - 1), 120, turn.left())
            if wait > 0:
                print(f"upstream unavailable (provider outage), holding the "
                      f"turn for {wait:.0f}s "
                      f"({turn.spent():.0f}s waited so far)",
                      flush=True)
                _request_phase("waiting_outage")
                turn.sleep(wait)
                continue
            print(f"upstream unavailable and the turn's {turn.budget}s budget "
                  f"is spent; handing it back", flush=True)
            break
        if err and not emitted and attempt < 2 and "permission_denied" in err:
            nxt = TOOL_DESC_CAPS[attempt + 1]
            print(f"upstream permission_denied, retrying (attempt "
                  f"{attempt + 2}/3, tool descriptions capped at {nxt})",
                  flush=True)
            attempt += 1
            continue
        break

    if len(tool_order) > 30:
        # A turn issuing this many calls is worth seeing. Parallel tool use is
        # normal — 13 calls across Read and Bash was measured and is legitimate
        # — but a message carrying 2322 tool_result blocks was also measured,
        # and nothing in the stream has yet explained it. The names here are
        # what will tell the two apart: one repeated name is a stream being
        # split, a spread of names is an agent working.
        names = {}
        for t in tool_order:
            n = tool_blocks[t]["name"] or "?"
            names[n] = names.get(n, 0) + 1
        print(f"WARNING: {len(tool_order)} tool calls in one turn: {names}",
              flush=True)
    stop_reason = _stop_reason(stop, bool(tool_order))
    usage = usage or {"input_tokens": 0, "output_tokens": 0}

    if out:
        if err:
            # Freeze the heartbeat before deciding which response is legal.
            out.release()
        if err and not committed():
            # Nothing has reached the client yet, so the failure can still be
            # what it actually is: an HTTP status the client knows how to act
            # on. Opening a 200 stream and putting the error inside it turns a
            # rate limit the client would have waited out into a dead turn.
            # The keepalive stops first: the caller is about to put that status
            # on this socket and a ping landing inside it would corrupt it.
            out.release()
            return None, err
        out.start()
        if err:
            # Never finalise a failed turn as a normal completion. Writing the
            # error into the assistant text and then closing with end_turn made
            # a truncated answer indistinguishable from a finished one, so the
            # client stored it as complete and had no reason to retry.
            out.error(err, anthropic_error(err)[0])
            out.stop()
            return None, None
        for tid in tool_order:
            raw_args = tool_blocks[tid]["json"] or "{}"
            try:
                json.loads(raw_args)
            except ValueError as e:
                print(f"tool call {tool_blocks[tid]['name']} has unparseable "
                      f"arguments ({len(raw_args)} chars, {_json_cut(e, raw_args)}); "
                      f"dropping it and reporting max_tokens", flush=True)
                stop_reason = "max_tokens"
                continue
            out.tool(tid, tool_blocks[tid]["name"], raw_args)
        out.finish(stop_reason, usage)
        return None, None

    if err:
        return None, err

    content = []
    if thinking:
        block = {"type": "thinking", "thinking": "".join(thinking)}
        if signature:
            block["signature"] = signature
        content.append(block)
    if texts:
        content.append({"type": "text", "text": "".join(texts)})
    for tid in tool_order:
        raw_args = tool_blocks[tid]["json"] or "{}"
        try:
            args = json.loads(raw_args)
        except ValueError as e:
            # Substituting {} would hand the client a well-formed call with its
            # arguments quietly removed — a truncated `Bash` becomes a no-arg
            # `Bash`. Report the turn as cut short instead.
            print(f"tool call {tool_blocks[tid]['name']} has unparseable "
                  f"arguments ({len(raw_args)} chars, {_json_cut(e, raw_args)}); "
                  f"reporting max_tokens", flush=True)
            stop_reason = "max_tokens"
            continue
        content.append({"type": "tool_use", "id": tid,
                        "name": tool_blocks[tid]["name"], "input": args})
    return {"id": new_message_id(), "type": "message", "role": "assistant",
            "model": resolve_model(body), "content": content,
            "stop_reason": stop_reason, "stop_sequence": None,
            "usage": usage}, None


# --------------------------------------------------------------------------- #
# OpenAI Responses (Codex) <-> the Anthropic shape
# --------------------------------------------------------------------------- #

# Codex's own tools are mostly "custom" ones: freeform bodies (JavaScript, for
# the code-mode `exec` tool) rather than JSON arguments. Cognition only accepts
# tools with a JSON schema, so a custom tool is declared as a single string
# property and unwrapped again on the way back out. The alternative — turning
# code mode off — hangs the client before it ever reaches us.
CUSTOM_TOOL_SCHEMA = {
    "type": "object",
    "properties": {"input": {"type": "string",
                             "description": "The freeform body of the call, "
                                            "verbatim and unescaped."}},
    "required": ["input"],
}


def _responses_text(content):
    """Responses content is a string or a list of input_text / output_text."""
    if isinstance(content, str):
        return content
    if not isinstance(content, list):
        return ""
    return "".join(c.get("text", "") for c in content
                   if isinstance(c, dict) and c.get("text"))


def _responses_tools(items):
    """Flatten Codex's namespaced additional_tools into Anthropic tool dicts.

    Returns (tools, custom_names): the names in the second set take a freeform
    body, so a call to one has to be re-emitted as custom_tool_call rather than
    function_call.
    """
    tools, custom = [], set()

    def add(t):
        name = t.get("name")
        if not name:
            return
        if t.get("type") == "custom":
            custom.add(name)
            schema = CUSTOM_TOOL_SCHEMA
        else:
            schema = t.get("parameters") or {}
        tools.append({"name": name, "description": t.get("description", ""),
                      "input_schema": schema})

    for item in items:
        if item.get("type") != "additional_tools":
            continue
        for entry in item.get("tools") or []:
            if entry.get("type") == "namespace":
                for t in entry.get("tools") or []:
                    add(t)
            else:
                add(entry)
    return tools, custom


def responses_to_messages(body):
    """Translate a Codex Responses request into the Anthropic-shaped body.

    Going through the shape build_request() already eats, rather than writing a
    second Cognition translator, is what stops the two front ends drifting
    apart: cascade keys, content-derived message ids and thinking replay stay
    defined in exactly one place.
    """
    items = body.get("input") or []
    tools, custom = _responses_tools(items)
    system = [body["instructions"]] if body.get("instructions") else []
    messages = []

    for item in items:
        kind = item.get("type")
        if kind in ("additional_tools", None):
            continue
        if kind == "message":
            role = item.get("role")
            text = _responses_text(item.get("content"))
            if not text:
                continue
            if role in ("developer", "system"):
                # Codex ships its system prompt as developer turns rather than
                # an instructions field; they are the system prompt.
                system.append(text)
            elif role == "assistant":
                messages.append({"role": "assistant",
                                 "content": [{"type": "text", "text": text}]})
            else:
                messages.append({"role": "user",
                                 "content": [{"type": "text", "text": text}]})
        elif kind in ("function_call", "custom_tool_call"):
            if kind == "custom_tool_call":
                args = {"input": item.get("input", "")}
            else:
                try:
                    args = json.loads(item.get("arguments") or "{}")
                except ValueError:
                    args = {}
            messages.append({"role": "assistant", "content": [{
                "type": "tool_use", "id": item.get("call_id", ""),
                "name": item.get("name", ""), "input": args}]})
        elif kind == "agent_message":
            # How Codex hands a spawned agent its task. The readable header
            # arrives as input_text and the task itself as encrypted_content,
            # which only OpenAI can open — so a non-OpenAI model receives the
            # envelope and none of the letter. Pass on what is legible and say
            # plainly that the rest was unreadable, rather than letting the
            # agent answer an empty instruction.
            text = _responses_text(item.get("content"))
            if any(isinstance(c, dict) and c.get("encrypted_content")
                   for c in (item.get("content") or [])):
                print("warning: agent_message payload is encrypted to OpenAI; "
                      "the delegated task is not readable here", flush=True)
                text += ("\n(The task payload was encrypted by the client and "
                         "could not be read. Say so instead of guessing.)")
            if text:
                messages.append({"role": "user",
                                 "content": [{"type": "text", "text": text}]})
        elif kind in ("function_call_output", "custom_tool_call_output"):
            messages.append({"role": "user", "content": [{
                "type": "tool_result", "tool_use_id": item.get("call_id", ""),
                "content": _responses_text(item.get("output"))}]})
        # `reasoning` items carry OpenAI's encrypted_content, which is opaque to
        # anyone but OpenAI. Dropped rather than forwarded as garbage.

    out = {
        "model": body.get("model"),
        "system": "\n\n".join(system),
        "messages": messages,
        "stream": bool(body.get("stream")),
        "max_tokens": int(body.get("max_output_tokens") or 128000),
    }
    if tools:
        out["tools"] = tools
    # The effort slider rides in reasoning.effort here, not output_config.
    effort = (body.get("reasoning") or {}).get("effort")
    if effort:
        out["output_config"] = {"effort": effort}
    # Codex sends a stable per-thread cache key; it is a far better conversation
    # identity than anything derivable from the prompt.
    if body.get("prompt_cache_key"):
        out["metadata"] = {"user_id": body["prompt_cache_key"]}
    return out, custom


class ResponsesStream(_KeepAlive):
    """Emits the Codex flavour of the Responses SSE stream onto a raw socket.

    The keepalive invents nothing: the Responses dialect has no `ping`, so the
    stream is opened with the response.created / response.in_progress pair it
    starts with anyway, and a silence is filled by sending response.in_progress
    again — the same response object, the next sequence_number. Codex resets
    its idle timer on any event and has no use for this one beyond that.
    Without it, Codex dropped a stream silent for five minutes (a long think,
    a held rate limit, a summary) and sent the request again, so one turn ran
    twice.

    Event order and field names are taken from a recorded upstream stream rather
    than from the public API docs: this dialect carries output_index,
    sequence_number and item_id on every event, and Codex reads them.
    """

    def __init__(self, wfile, model, custom_names=()):
        self.w = wfile
        self.model = model
        self.custom = set(custom_names)
        self.seq = 0
        self.index = -1
        self.item_id = None
        # Unique per response, for the same reason the Messages route learned
        # it the hard way: identifiers a client uses to correlate streamed
        # pieces must not repeat across responses. Reused ones let a client
        # conclude that two answers are one, and here they would also collide
        # in whatever store it keeps its items in.
        self.item_prefix = f"msg_{uuid.uuid4().hex[:16]}"
        self.response_id = f"resp_{uuid.uuid4().hex}"
        self.open_text = False
        self.text_buf = []
        self.started = False
        self.tools = {}
        # One response, one creation time, however often it is restated.
        self.created_at = int(time.time())
        self._keep_alive_init()

    def _keepalive(self):
        self._send("response.in_progress",
                   {"type": "response.in_progress",
                    "response": self._response("in_progress")})

    def _send(self, event, data):
        # The number and the write under one lock, or the keepalive thread
        # could put two events on the wire out of sequence.
        with self._wlock:
            data["sequence_number"] = self.seq
            self.seq += 1
            self._write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())

    def _response(self, status, usage=None):
        out = {"id": self.response_id, "object": "response",
               "created_at": self.created_at, "status": status,
               "model": self.model, "output": [], "error": None,
               "instructions": None, "incomplete_details": None,
               "parallel_tool_calls": False, "tool_choice": "auto",
               "tools": [], "metadata": {}}
        if usage is not None:
            # OpenAI counts cached input inside input_tokens; Anthropic, and
            # Cognition, count it beside. Passed through as it was, Codex saw a
            # 121k-token context as 3k — its context gauge and auto-compaction
            # off by forty times — and cached_tokens larger than the input.
            cached = usage.get("cache_read_input_tokens", 0)
            prompt = (usage.get("input_tokens", 0) + cached
                      + usage.get("cache_creation_input_tokens", 0))
            out["usage"] = {
                "input_tokens": prompt,
                "input_tokens_details": {"cached_tokens": cached},
                "output_tokens": usage.get("output_tokens", 0),
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": prompt + usage.get("output_tokens", 0)}
        return out

    def start(self, usage=None):
        with self._wlock:
            if self.started:
                return
            self.started = True
            self._write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
                        b"cache-control: no-cache\r\nconnection: close\r\n\r\n")
            self._send("response.created",
                       {"type": "response.created",
                        "response": self._response("in_progress")})
            self._send("response.in_progress",
                       {"type": "response.in_progress",
                        "response": self._response("in_progress")})

    def thinking(self, text):
        """Dropped on purpose: Codex only replays reasoning it can hand back as
        encrypted_content, which we cannot produce, and an unsigned reasoning
        item is refused on the next turn."""

    def signature(self, sig):
        pass

    def _open_text(self):
        if self.open_text:
            return
        self.index += 1
        self.item_id = f"{self.item_prefix}_{self.index}"
        self.open_text = True
        self._send("response.output_item.added", {
            "type": "response.output_item.added", "output_index": self.index,
            "item": {"id": self.item_id, "type": "message", "status": "in_progress",
                     "role": "assistant", "content": []}})
        self._send("response.content_part.added", {
            "type": "response.content_part.added", "content_index": 0,
            "item_id": self.item_id, "output_index": self.index,
            "part": {"type": "output_text", "annotations": [], "text": ""}})

    def text(self, text):
        self._open_text()
        self.text_buf.append(text)
        self._send("response.output_text.delta", {
            "type": "response.output_text.delta", "content_index": 0,
            "delta": text, "item_id": self.item_id, "output_index": self.index})

    def _close_text(self):
        if not self.open_text:
            return
        full = "".join(self.text_buf)
        self._send("response.output_text.done", {
            "type": "response.output_text.done", "content_index": 0,
            "item_id": self.item_id, "output_index": self.index, "text": full})
        self._send("response.content_part.done", {
            "type": "response.content_part.done", "content_index": 0,
            "item_id": self.item_id, "output_index": self.index,
            "part": {"type": "output_text", "annotations": [], "text": full}})
        self._send("response.output_item.done", {
            "type": "response.output_item.done", "output_index": self.index,
            "item": {"id": self.item_id, "type": "message", "status": "completed",
                     "role": "assistant",
                     "content": [{"type": "output_text", "annotations": [],
                                  "text": full}]}})
        self.open_text = False
        self.text_buf = []

    def tool(self, tid, name, args_json):
        self.tools[tid] = {"name": name, "json": args_json}

    def flush_tools(self):
        for tid, b in self.tools.items():
            self._close_text()
            self.index += 1
            item_id = f"call_{self.item_prefix[4:]}_{self.index}"
            is_custom = b["name"] in self.custom
            try:
                args = json.loads(b["json"] or "{}")
            except ValueError:
                args = {}
            if is_custom:
                # Unwrap the single string property back into a freeform body.
                payload = args.get("input", "")
                item = {"id": item_id, "type": "custom_tool_call",
                        "status": "in_progress", "call_id": tid,
                        "name": b["name"], "input": ""}
                delta_event = "response.custom_tool_call_input.delta"
                done_event = "response.custom_tool_call_input.done"
                done_key = "input"
            else:
                payload = b["json"] or "{}"
                item = {"id": item_id, "type": "function_call",
                        "status": "in_progress", "call_id": tid,
                        "name": b["name"], "arguments": ""}
                delta_event = "response.function_call_arguments.delta"
                done_event = "response.function_call_arguments.done"
                done_key = "arguments"
            self._send("response.output_item.added", {
                "type": "response.output_item.added",
                "output_index": self.index, "item": item})
            self._send(delta_event, {"type": delta_event, "delta": payload,
                                     "item_id": item_id,
                                     "output_index": self.index})
            self._send(done_event, {"type": done_event, done_key: payload,
                                    "item_id": item_id,
                                    "output_index": self.index})
            done_item = dict(item, status="completed", **{done_key: payload})
            self._send("response.output_item.done", {
                "type": "response.output_item.done",
                "output_index": self.index, "item": done_item})
        self.tools = {}

    def finish(self, stop_reason, usage):
        self.release()
        self.flush_tools()
        self._close_text()
        if stop_reason == "max_tokens":
            response = self._response("incomplete", usage)
            response["incomplete_details"] = {"reason": "max_output_tokens"}
            self._send("response.incomplete", {
                "type": "response.incomplete", "response": response})
        else:
            self._send("response.completed", {
                "type": "response.completed",
                "response": self._response("completed", usage)})

    def error(self, message, kind="api_error"):
        self.failure = kind
        self._send("error", {"type": "error", "code": kind,
                             "message": message})

    def stop(self):
        """No response.completed: a turn that failed must not be handed back as
        a finished one, or Codex stores the truncated answer and moves on."""
        self.release()
        self._send("response.incomplete", {
            "type": "response.incomplete",
            "response": self._response("incomplete")})


# --------------------------------------------------------------------------- #
# HTTP
# --------------------------------------------------------------------------- #

# One pooled session for the process: a fresh Session per call meant a fresh TLS
# handshake to api.anthropic.com on every turn of the main session. Cookies are
# disabled outright so a Set-Cookie from one upstream is never replayed to another.
SESSION = requests.Session()
SESSION.trust_env = False
SESSION.cookies.set_policy(DefaultCookiePolicy(allowed_domains=[]))
# An upstream is free to close an idle keep-alive socket at any time, and requests
# retries nothing by default (max_retries=0) — that dead socket would otherwise
# surface to Claude Code as a connection error and a multi-minute backoff.
#
# `read` has to be non-zero for that to work: urllib3 raises ProtocolError on a
# reset keep-alive socket and _is_read_error() routes it to the read budget,
# while `connect` only covers DNS/TCP/TLS establishment. Restrict read retries
# to safe methods: a POST can have been processed even when its response headers
# never reached us. Application-level SWE recovery remains explicit and bounded;
# this adapter must not silently multiply it, or replay a relayed generation.
_RETRY = Retry(total=3, connect=3, read=3, status=0, redirect=0,
               allowed_methods=frozenset({"GET", "HEAD", "OPTIONS"}),
               backoff_factor=0.2)
for _scheme in ("http://", "https://"):
    SESSION.mount(_scheme, requests.adapters.HTTPAdapter(
        pool_connections=8, pool_maxsize=32, max_retries=_RETRY))


# What Codex's own catalog request carries, and nothing else: the ChatGPT
# login, the workspace it belongs to, and how the client names itself.
_CODEX_CATALOG_HEADERS = {"authorization", "chatgpt-account-id", "originator",
                          "user-agent", "version", "accept",
                          "openai-organization", "openai-project"}
_CODEX_CATALOG_PREFIXES = ("x-openai-", "x-codex-", "openai-")


def _codex_catalog_header(name):
    name = name.lower()
    return (name in _CODEX_CATALOG_HEADERS
            or name.startswith(_CODEX_CATALOG_PREFIXES))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"
    timeout = HTTP_READ_TIMEOUT  # header/body inactivity, not model latency

    def log_message(self, fmt, *args):
        return

    def send_json(self, status, body, retry_after=None):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        if retry_after is not None:
            self.send_header("retry-after", str(retry_after))
        self.send_header("content-length", str(len(raw)))
        self.send_header("connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)
        self.close_connection = True

    def send_error_json(self, status, kind, message, retry_after=None):
        self.send_json(status, {"type": "error",
                                "error": {"type": kind, "message": message}},
                       retry_after=retry_after)

    def browser_origin(self):
        """True when the request looks like it came from a web page.

        The SWE-2 route spends the user's Cognition quota using a credential the
        service holds, so unlike the Claude relay it cannot rely on the caller
        proving anything. A page the user merely visits can POST here: a JSON
        body sent as text/plain is a CORS simple request, so no preflight is
        needed, and the attacker never has to read the reply for the turn to run
        and be billed.

        Browsers attach Origin to such a request and ordinary API clients do not,
        so refusing it costs nothing. Host is checked too: under DNS rebinding
        the address resolves to loopback while Host still carries the attacker's
        domain. Set DEVINX_ALLOW_BROWSER=1 if you are deliberately calling this
        from a local web UI.
        """
        if os.environ.get("DEVINX_ALLOW_BROWSER") == "1":
            return False
        if self.headers.get("origin"):
            return True
        host = (self.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
        return host not in ("", "127.0.0.1", "localhost", "::1")

    def do_HEAD(self):
        if urlsplit(self.path).path == "/api/hello":
            self.send_response(200)
            self.send_header("content-length", "0")
            self.send_header("connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        self.send_error_json(404, "not_found_error", "Not found")

    @staticmethod
    def catalog_row(slug, name, priority):
        """One catalog entry, with every field Codex's strict parser demands.

        The parser rejects the whole catalog over a single missing key — and a
        rejected catalog takes plugins, apps and MCP down with it, not just the
        row at fault — so the defaults are spelled out rather than left absent.
        """
        return {
            "slug": slug, "display_name": name, "description": name,
            "shell_type": "unified_exec", "visibility": "list",
            "supported_in_api": True, "priority": priority,
            "base_instructions": "You are a helpful coding assistant.",
            "multi_agent_version": MULTI_AGENT_SURFACE,
            "supported_reasoning_levels": [{"effort": e, "description": e}
                                           for e in SWE_EFFORTS],
            "default_reasoning_effort": "high",
            "node_repl_disabled": False,
            "node_repl_auto_review_required": False,
            "include_plugin_usage_instructions": False,
            "include_apps_usage_instructions": True,
            "supports_reasoning_summaries": False,
            "default_reasoning_summary": "none",
            "support_verbosity": True, "default_verbosity": "low",
            "apply_patch_tool_type": "freeform",
            "truncation_policy": {"mode": "tokens", "limit": 10000},
            "supports_parallel_tool_calls": True,
            "supports_image_detail_original": False,
            "experimental_supported_tools": [],
            "input_modalities": ["text"],
            "context_window": SWE_CONTEXT_TOKENS,
            "max_context_window": SWE_CONTEXT_TOKENS,
            "supports_search_tool": False,
        }

    def codex_catalog(self):
        """The model catalog Codex reads, with every row pinned to the V1
        multi-agent surface.

        The upstream catalog is fetched with the caller's own credential and
        merged, so the GPT model the root runs on keeps its real metadata and
        stays selectable; without that merge, pointing Codex at devinx would
        hide every model the account actually has. A fetch that fails degrades
        to the SWE-2 rows alone rather than failing the request.
        """
        rows = [self.catalog_row(mid, name, i)
                for i, (mid, name) in enumerate(SWE_MODELS)]
        query = urlsplit(self.path).query
        # Only a request that is identifiably Codex goes to chatgpt.com. Claude
        # Code's gateway discovery asks this same path (/v1/models?limit=1000)
        # with its own Anthropic credential, and forwarding every header of
        # every caller sent that credential to OpenAI. Codex always names its
        # version in the query and never speaks the anthropic-* dialect.
        names = {name.lower() for name in self.headers.keys()}
        if (not self.headers.get("authorization")
                or "client_version" not in parse_qs(query)
                or "x-api-key" in names
                or any(n.startswith("anthropic-") for n in names)):
            return rows
        try:
            headers = {name: value for name, value in self.headers.items()
                       if _codex_catalog_header(name)}
            # Forward the query verbatim: Codex asks for
            # /v1/models?client_version=…, and the upstream answers differently
            # — or not at all — without it.
            r = SESSION.get(CODEX_UPSTREAM + "/models"
                            + (f"?{query}" if query else ""),
                            headers=headers, timeout=(10, 20))
            status = r.status_code
            upstream = r.json().get("models") if status == 200 else None
        except (requests.RequestException, ValueError) as e:
            status, upstream = type(e).__name__, None
        if not isinstance(upstream, list):
            # The status is the only clue when the forwarded headers turn out
            # to be missing one the upstream wants.
            print(f"codex catalog: upstream unavailable ({status}), serving "
                  f"swe-2 only",
                  flush=True)
            return rows
        for entry in upstream:
            if isinstance(entry, dict):
                entry["multi_agent_version"] = MULTI_AGENT_SURFACE
        return rows + upstream

    @staticmethod
    def stats_window(query):
        """The requested window, validated before it can reach a command line.

        These two values become argv entries of a subprocess. They are checked
        against the exact shape of the log's own timestamps and nothing else
        gets through — a range picker is not a reason to widen what this
        process will execute on someone's behalf.
        """
        out = []
        for name in ("since", "until"):
            raw = (parse_qs(query).get(name) or [""])[0].strip()
            if not raw:
                continue
            if not _ISO_BOUND.match(raw):
                return None
            try:
                # The shape gate is what keeps this out of a command line; this
                # second one only spares the user a window that silently
                # matches nothing, like the 99th of month 13.
                datetime.fromisoformat(raw)
            except ValueError:
                return None
            out += [f"--{name}", raw]
        return out

    def serve_stats(self):
        """Live figures for the dashboard.

        The extractor runs as a subprocess rather than an import: it owns its
        own shape and this stays decoupled from it. A short cache means ten open
        tabs cost one pass over the log, not ten.
        """
        window = self.stats_window(urlsplit(self.path).query)
        if window is None:
            self.send_error_json(400, "invalid_request_error",
                                 "since/until must look like 2026-09-18T18:00")
            return
        key = " ".join(window)
        now = time.time()
        with _stats_lock:
            slot = _stats.setdefault(key, {"at": 0.0, "data": None,
                                           "error": None, "running": False})
            fresh = slot["at"] > now - STATS_TTL
            mine = not fresh and not slot["running"]
            if mine:
                slot["running"] = True
        if mine:
            # One pass at a time per window. Ten tabs on the same range cost
            # one pass over the log, not ten; two different ranges are two
            # different questions and cost one each.
            data, err = None, None
            try:
                r = subprocess.run(
                    [sys.executable, os.path.join(HERE, "tools", "log_stats.py")]
                    + window,
                    capture_output=True, text=True, timeout=60,
                    env=dict(os.environ, DEVINX_LOG=os.environ.get(
                        "DEVINX_LOG", os.path.join(DATA_DIR, "devinx.log"))))
                data = json.loads(r.stdout) if r.returncode == 0 else None
                if data is None:
                    err = (r.stderr or "stats failed").strip()[:200]
            except Exception as e:
                data, err = None, f"{type(e).__name__}: {e}"
            with _stats_lock:
                slot["at"], slot["error"], slot["running"] = time.time(), err, False
                # A failed pass keeps the last good figures rather than
                # replacing them with zeros that read as a healthy idle service.
                if data is not None:
                    slot["data"] = data
                if len(_stats) > 16:
                    # Windows are user-chosen; a page that asked for a hundred
                    # of them must not leave a hundred snapshots behind.
                    for k in sorted(_stats, key=lambda k: _stats[k]["at"])[:8]:
                        if k != key:
                            _stats.pop(k, None)
        with _stats_lock:
            payload = dict(slot["data"] or {})
            payload["error"] = slot["error"]
            payload["cached_age"] = round(time.time() - slot["at"], 1)
        with _inflight_lock:
            busy = _inflight["n"]
        live_shares = shares()
        payload["service"] = {"build": BUILD, "pid": os.getpid(), "port": PORT,
                              "inflight": busy, "started": _STARTED,
                              "uptime": round(time.time() - _STARTED),
                              "accounts": [
                                  {"name": a["name"],
                                   "excluded": a.get("excluded"),
                                   "tier": a.get("tier"),
                                   "pro": a.get("pro"),
                                   "share": round(live_shares.get(a["name"], 0.0), 3),
                                   # The live answer to "is the upstream
                                   # refusing work", which the log can only
                                   # reconstruct after the fact.
                                   "blocked_for": max(0, round(
                                       a.get("blocked_until", 0) - time.time()))}
                                  for a in _accounts]}
        payload["active_requests"] = live_requests()
        payload["tail"] = _log_tail(60)
        self.send_json(200, payload)

    def dashboard_allowed(self):
        """Without a token, loopback only; with one, everybody pays it.

        The dashboard rides on the port that also carries the API, and a host
        exposing one path publicly exposes them all. Judging by the Host header
        stops a rebound browser, which cannot forge one, but nothing else: any
        forwarder — socat, ssh -L, a tailnet mount — delivers its connections
        from 127.0.0.1 with whatever Host the client chose. So once a token
        exists it is the guard, for every caller. A browser pays it once, in a
        ?k= link, and rides the cookie afterwards.
        """
        if not DASHBOARD_TOKEN:
            host = (self.headers.get("host") or "").rsplit(":", 1)[0].strip("[]")
            return host in ("", "127.0.0.1", "localhost", "::1")
        given = (parse_qs(urlsplit(self.path).query).get("k") or [""])[0]
        cookie = ""
        for part in (self.headers.get("cookie") or "").split(";"):
            if part.strip().startswith("dxk="):
                cookie = part.strip()[4:]
        return self.token_ok(given) or self.token_ok(cookie)

    @staticmethod
    def token_ok(given):
        """compare_digest on str raises on anything non-ASCII: compare bytes."""
        if not given:
            return False
        return hmac.compare_digest(given.encode("utf-8", "surrogatepass"),
                                   DASHBOARD_TOKEN.encode("utf-8"))

    def reject_mid_conv_system(self, body):
        """Decline the mid-conversation system turns instead of carrying them.

        Claude Code sends `{role: "system"}` messages inside `messages`, which
        the Messages API does not define. Carrying them as user content kept
        their content, and kept the shape: the same feature drops base messages
        and replaces them with these markers, which is how a whole run arrives
        as five messages with every call in one of them.

        It does not have to be carried at all. The client publishes a contract
        for gateways — devinx is one — and it says a capability the upstream
        will not take should come back as HTTP 400 whose entire error.message
        is the token `capability_rejected: <class>`. The client matches that
        token, drops the capability, retries, and sticky-rejects it for the
        rest of the session. Its own log line for this path reads: "falling
        back to a body with no {role:\"system\"} turn".

        So this is the cure rather than the compensation: the shape stops being
        produced, instead of being repaired on every request forever.

        The cap exists because a client that did not honour it would retry the
        same body: after a few refusals per conversation the old behaviour
        takes over and the turn goes through carrying them.
        """
        messages = body.get("messages")
        if not isinstance(messages, list):
            return False
        if not any(isinstance(m, dict) and m.get("role") not in ("user", "assistant")
                   for m in messages):
            return False
        key = _conv_key(body)
        with _capability_lock:
            n = _capability_refusals.get(key, 0) + 1
            if len(_capability_refusals) > 256:
                _capability_refusals.clear()
            _capability_refusals[key] = n
        if n > MID_CONV_SYSTEM_REFUSALS:
            print(f"mid-conv-system: still sent after {n - 1} refusals; "
                  f"carrying them as user content instead", flush=True)
            return False
        print(f"mid-conv-system: declining the turn ({n}/"
              f"{MID_CONV_SYSTEM_REFUSALS}); the client drops the beta and "
              f"retries", flush=True)
        self.send_error_json(400, "invalid_request_error",
                             "capability_rejected: mid_conv_system")
        return True

    def do_GET(self):
        path = urlsplit(self.path).path
        if path in ("/dashboard", "/dashboard/", "/api/stats") and not self.dashboard_allowed():
            self.send_error_json(403, "permission_error",
                                 "dashboard token missing or wrong")
            return
        if path == "/dashboard" or path == "/dashboard/":
            try:
                with open(os.path.join(HERE, "tools", "dashboard.html"), "rb") as fh:
                    page = fh.read()
            except OSError:
                self.send_error_json(404, "not_found_error", "dashboard.html is missing")
                return
            self.send_response(200)
            self.send_header("content-type", "text/html; charset=utf-8")
            given = (parse_qs(urlsplit(self.path).query).get("k") or [""])[0]
            if self.token_ok(given):
                # HttpOnly: no script on the page ever needs to read it, and a
                # script that could would be reading it to send it elsewhere.
                self.send_header("set-cookie",
                                 f"dxk={given}; Path=/; Max-Age=2592000; "
                                 "SameSite=Lax; HttpOnly")
            self.send_header("content-length", str(len(page)))
            self.send_header("connection", "close")
            self.end_headers()
            self.wfile.write(page)
            self.close_connection = True
            return
        if path == "/api/stats":
            self.serve_stats()
            return
        if urlsplit(self.path).path == "/api/hello":
            with _inflight_lock:
                busy = _inflight["n"]
            hello = {"service": "devinx", "build": BUILD,
                     "pid": os.getpid(), "port": PORT, "inflight": busy,
                     "configuration": effective_configuration()}
            # The answer to the launcher's challenge: proof that this process
            # can read the install's secret, which a squatter of another user
            # cannot. API port only — the published dashboard port must not be
            # an oracle that signs nonces for whoever reaches it.
            nonce = (parse_qs(urlsplit(self.path).query).get("nonce") or [""])[0]
            if type(self) is Handler and re.fullmatch(r"[0-9a-f]{16,64}", nonce):
                try:
                    hello["proof"] = hello_proof(service_secret(DATA_DIR), nonce)
                except OSError:
                    pass
            self.send_json(200, hello)
            return
        if urlsplit(self.path).path != "/v1/models":
            self.send_error_json(404, "not_found_error", "Not found")
            return
        # Anthropic and OpenAI shapes in one object: Claude Code reads type /
        # display_name / created_at, Codex reads object / created / owned_by, and
        # the launcher's readiness probe reads id. Serving the union keeps a
        # single endpoint honest for all three.
        models = [{"type": "model", "id": mid, "display_name": name,
                   "created_at": "2026-01-01T00:00:00Z",
                   "object": "model", "created": 1767225600,
                   "owned_by": "devinx",
                   # Both spellings: a client reads runtime.max_input_tokens
                   # first and falls back to context_window.
                   "context_window": SWE_CONTEXT_TOKENS,
                   "runtime": {"max_input_tokens": SWE_CONTEXT_TOKENS,
                               "max_output_tokens": 128000}}
                  for mid, name in SWE_MODELS]
        # `data` is what Claude Code reads, `models` what Codex reads; serving
        # both means one endpoint rather than one per client dialect.
        self.send_json(200, {"data": models, "models": self.codex_catalog(),
                             "has_more": False,
                             "first_id": models[0]["id"],
                             "last_id": models[-1]["id"]})

    def do_POST(self):
        if not _enter_request():
            self.send_error_json(503, "overloaded_error",
                                 "Local request capacity reached; retry later", 1)
            return
        # The socket, for run_swe to tell whether anyone is still waiting on
        # a turn it is holding.
        _request_local.conn = getattr(self, "connection", None)
        try:
            self._do_POST()
        finally:
            _request_local.conn = None
            _leave_request()

    def _do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/v1/messages", "/v1/messages/count_tokens",
                        "/v1/responses"):
            self.send_error_json(404, "not_found_error", "Not found")
            return
        try:
            lengths = self.headers.get_all("content-length", [])
            if (self.headers.get("transfer-encoding") is not None
                    or len(lengths) != 1
                    or re.fullmatch(r"[0-9]+", lengths[0].strip()) is None):
                self.send_error_json(400, "invalid_request_error",
                                     "One non-negative Content-Length is required")
                return
            length = int(lengths[0])
            if length > MAX_BODY_BYTES:
                self.send_error_json(413, "invalid_request_error",
                                     f"Body exceeds {MAX_BODY_BYTES} bytes")
                return
            raw = self.rfile.read(length)
            if len(raw) != length:
                self.send_error_json(400, "invalid_request_error", "Incomplete body")
                return
            body = json.loads(raw)
            self.connection.settimeout(CLIENT_WRITE_TIMEOUT)
        except Exception:
            self.send_error_json(400, "invalid_request_error", "Invalid body")
            return
        # `[]`, `42` and `"x"` are all valid JSON. Reading .get() off them raised
        # an uncaught AttributeError, which reached the client as a dropped
        # connection rather than a 400.
        if not isinstance(body, dict):
            self.send_error_json(400, "invalid_request_error",
                                 "Body must be a JSON object")
            return

        if os.environ.get("DEVINX_DUMP"):
            # Diagnostic only: writes the verbatim request, which includes the
            # full conversation. Never leave this on outside an investigation.
            try:
                with open(f"{os.environ['DEVINX_DUMP']}.{time.time_ns()}.json",
                          "wb") as fh:
                    fh.write(raw)
            except OSError:
                pass

        model = body.get("model")
        if not isinstance(model, str) or not model:
            self.send_error_json(400, "invalid_request_error", "Missing model")
            return

        _request_phase("accepted", model=model)
        if model in SWE_MODEL_IDS and self.browser_origin():
            self.send_error_json(
                403, "permission_error",
                "Refusing a browser-originated request on the SWE-2 route")
            return

        if model in SWE_MODEL_IDS and self.reject_mid_conv_system(body):
            return

        if model in SWE_MODEL_IDS:
            if path.endswith("count_tokens"):
                self.send_json(200, {"input_tokens": estimate_tokens(body)})
                return
            if not _enter_swe():
                self.send_error_json(503, "overloaded_error",
                                     "Local SWE-2 capacity reached; retry later", 1)
                return
            if path == "/v1/responses":
                self.serve_swe_responses(body)
                return
            self.serve_swe(body)
            return

        # Anything else is relayed to the upstream the client would have used on
        # its own, with the client's own credential. The path decides which one:
        # Codex speaks Responses, Claude Code speaks Messages.
        if path == "/v1/responses":
            if not self.headers.get("authorization"):
                self.send_error_json(401, "authentication_error",
                                     "Codex login missing")
                return
            self.relay(raw, model, CODEX_UPSTREAM + "/responses", "codex")
            return

        if not model.startswith("claude-"):
            self.send_error_json(400, "invalid_request_error", "Unsupported model")
            return
        if not (self.headers.get("authorization") or self.headers.get("x-api-key")):
            self.send_error_json(401, "authentication_error",
                                 "Claude Code login missing")
            return
        # A transcript written before ids were normalised still holds the ones
        # Anthropic refuses, and would be unusable on a claude-* model forever.
        # The body is rebuilt only when something actually changed, so every
        # other request is relayed byte for byte as before.
        if repair_tool_ids(body):
            raw = json.dumps(body).encode()
            print("repaired tool ids carried by an older transcript", flush=True)
        self.relay(raw, model, CLAUDE_UPSTREAM + self.path, "claude")

    def serve_swe(self, body):
        stream = bool(body.get("stream"))
        started = time.time()
        # What the client actually got. Until now only the relayed route logged
        # at this boundary, so the SWE route's own figures were upstream
        # attempts — several of which can belong to one client turn, and some of
        # which are retried to success. The two were being read as one number.
        outcome = "200"
        try:
            if stream:
                # run_swe owns the raw socket once it has written anything; it
                # hands an error back instead while the socket is still clean.
                result = {}
                _, err = run_swe(body, self.wfile, outcome=result)
                outcome = result.get("status", "200")
                if err == CLIENT_GONE:
                    outcome = "client_disconnected"
                elif err:
                    kind, status, message, wait = anthropic_error(err, body)
                    outcome = str(status)
                    self.send_error_json(status, kind, message, wait)
            else:
                resp, err = run_swe(body, None)
                if err == CLIENT_GONE:
                    outcome = "client_disconnected"
                elif err:
                    kind, status, message, wait = anthropic_error(err, body)
                    outcome = str(status)
                    self.send_error_json(status, kind, message, wait)
                else:
                    self.send_json(200, resp)
        except (BrokenPipeError, ConnectionResetError):
            outcome = "client_disconnected"
            print("client disconnected mid-stream", flush=True)
        except Exception as e:
            outcome = type(e).__name__
            print(f"swe handler error: {type(e).__name__}", flush=True)
            if not stream:
                self.send_error_json(502, "api_error", str(e))
        finally:
            print(f"route=swe model={resolve_model(body)} status={outcome} "
                  f"in {time.time() - started:.1f}s", flush=True)
            self.close_connection = True

    def serve_swe_responses(self, body):
        """SWE-2 over the Responses wire, with the same errors as Messages."""
        try:
            translated, custom = responses_to_messages(body)
        except Exception as e:
            self.send_error_json(400, "invalid_request_error",
                                 f"could not read the Responses body: {e}")
            return
        if not translated.get("stream"):
            self.send_error_json(400, "invalid_request_error",
                                 "the SWE-2 Responses route is streaming only")
            return
        started, result, outcome = time.monotonic(), {}, "200"
        try:
            _, err = run_swe(translated, self.wfile,
                            lambda w, m: ResponsesStream(w, m, custom),
                            outcome=result)
            outcome = result.get("status", "200")
            if err == CLIENT_GONE:
                outcome = "client_disconnected"
            elif err:
                kind, status, message, wait = anthropic_error(err, translated)
                outcome = str(status)
                self.send_error_json(status, kind, message, wait)
        except (BrokenPipeError, ConnectionResetError):
            outcome = "client_disconnected"
            print("client disconnected mid-stream", flush=True)
        except Exception as e:
            outcome = type(e).__name__
            print(f"swe responses handler error: {outcome}", flush=True)
        finally:
            print(f"route=swe model={resolve_model(translated)} "
                  f"status={outcome} in {time.monotonic() - started:.1f}s "
                  f"protocol=responses",
                  flush=True)
            self.close_connection = True

    def relay(self, raw, model, url, label):
        """Transparent relay. Headers pass through untouched, including the
        caller's credential; this process adds nothing of its own."""
        response = None
        response_started = False
        relay_started = time.time()
        try:
            headers = {name: value for name, value in self.headers.items()
                       if name.lower() not in REQUEST_EXCLUDED}
            _request_phase("connecting")
            response = SESSION.request(self.command, url, data=raw,
                                       headers=headers, stream=True,
                                       allow_redirects=False,
                                       timeout=(15, RELAY_READ_TIMEOUT))
            _request_phase("relaying")
            response_started = True
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                if name.lower() not in RESPONSE_EXCLUDED:
                    self.send_header(name, value)
            self.send_header("connection", "close")
            self.end_headers()
            # Diagnostic only, behind the same gate as the request dump: the
            # upstream stream is the only authoritative description of the event
            # vocabulary a given client version actually consumes.
            tap = None
            if os.environ.get("DEVINX_DUMP") and self.command != "HEAD":
                try:
                    tap = open(f"{os.environ['DEVINX_DUMP']}.{label}-resp."
                               f"{time.time_ns()}.sse", "wb")
                except OSError:
                    tap = None
            if self.command != "HEAD":
                for chunk in response.raw.stream(65536, decode_content=False):
                    if chunk:
                        if tap is not None:
                            tap.write(chunk)
                        self.wfile.write(chunk)
                        self.wfile.flush()
            if tap is not None:
                tap.close()
            print(f"route={label} model={model} status={response.status_code} "
                  f"in {time.time() - relay_started:.1f}s",
                  flush=True)
        except (BrokenPipeError, ConnectionResetError):
            print(f"route={label} model={model} status=client_disconnected "
                  f"in {time.time() - relay_started:.1f}s",
                  flush=True)
        except requests.RequestException as error:
            print(f"route={label} model={model} status={type(error).__name__} "
                  f"in {time.time() - relay_started:.1f}s",
                  flush=True)
            if not response_started:
                self.send_error_json(502, "api_error", "Upstream unavailable")
        finally:
            if response is not None:
                response.close()
            self.close_connection = True


def _image_tokens(block):
    """What an image costs, near enough to decide whether a turn will fit.

    Counted at all, which it was not: a conversation carrying screenshots read
    as far smaller than it is, so compaction never triggered and the turn died
    upstream instead. Bounded either side because images are resized before
    they are charged — a huge one does not cost proportionally more.
    """
    src = block.get("source") or {}
    size = len(src.get("data") or "")
    return min(1600, max(200, size // 500))


# Counted on their own, in tokens rather than characters, or not content at
# all: an image's base64 payload has its own cost model, and a replayed
# thinking signature is opaque bytes this proxy mostly drops before sending.
_UNCOUNTED_KEYS = {"data", "signature"}


def _content_chars(obj):
    """Every character of content in a block, whatever shape it arrived in.

    Reading named fields — b["text"], b["thinking"], the text of a tool_result
    — misses anything shaped differently, and the miss is silent and one-sided:
    a body estimated at a hundredth of its weight is a body compaction believes
    it has room for. Measured on a real turn, a message of 97 598 tokens was
    estimated at 801, the turn went out whole and the upstream refused it.

    The two shapes that did it were a content block with no `type` key and a
    content list of bare strings, neither of which the named-field reading
    recognised. Walking everything is not more precise, it is merely impossible
    to be blindsided by: a shape nobody anticipated still gets counted.
    """
    if isinstance(obj, str):
        return len(obj)
    if isinstance(obj, dict):
        # A text document's words sit under `data` too, and they are sent.
        return sum(_content_chars(v) for k, v in obj.items()
                   if k not in _UNCOUNTED_KEYS
                   or (k == "data" and obj.get("type") == "text"))
    if isinstance(obj, (list, tuple)):
        return sum(_content_chars(v) for v in obj)
    return 0


def _image_tokens_in(obj):
    """Image cost anywhere in a block, at whatever depth it sits."""
    total = 0
    if isinstance(obj, dict):
        if obj.get("type") == "image":
            return _image_tokens(obj)
        for v in obj.values():
            total += _image_tokens_in(v)
    elif isinstance(obj, (list, tuple)):
        for v in obj:
            total += _image_tokens_in(v)
    return total


def _weigh(obj, memo, measure):
    """measure(obj), remembered in `memo` for as long as the memo lives.

    Keyed by id() and holding the object itself, so an id cannot be reused by
    a newer object while its entry is still there.
    """
    if memo is None:
        return measure(obj)
    hit = memo.get(id(obj))
    if hit is not None and hit[0] is obj:
        return hit[1]
    value = measure(obj)
    memo[id(obj)] = (obj, value)
    return value


def _message_weight(m):
    chars = tokens = 0
    for b in _blocks(m.get("content")):
        chars += _content_chars(b)
        tokens += _image_tokens_in(b)
    return chars, tokens


def _tools_chars(tools):
    return sum(len(t.get("description", "")) + len(json.dumps(t.get("input_schema") or {}))
               for t in tools)


def estimate_tokens(body, memo=None):
    """Rough local estimate. Cognition exposes no counting endpoint; this is
    what count_tokens answers and what compaction decides on.

    `memo` is for a caller that estimates many bodies sharing the same message
    objects — one compaction weighs the same few hundred kilobytes a dozen
    times over. The figure is the same with or without it.
    """
    chars, tokens = len(_system_text(body)), 0
    for m in body.get("messages", []):
        c, t = _weigh(m, memo, _message_weight)
        chars += c
        tokens += t
    tools = body.get("tools") or []
    if tools:
        chars += _weigh(tools, memo, _tools_chars)
    return max(1, chars // 4 + tokens)


class _Stamped:
    """Every log line gets the time it was written.

    Without it the journal can say what happened and never when: a rate per
    minute, a retention trend over days, the distance between two refusals —
    none of them are answerable from a file of undated lines, and all of them
    are what you need to pace a fleet against a limit metered in requests.
    Wrapping stdout rather than touching several hundred print() calls keeps
    the change in one place and makes it impossible to forget one.
    """

    def __init__(self, stream):
        self._stream = stream
        self._fresh = True

    def write(self, text):
        if not text:
            return 0
        out, stamp = [], time.strftime("%Y-%m-%dT%H:%M:%S")
        for piece in text.splitlines(keepends=True):
            if self._fresh and piece.strip():
                out.append(f"{stamp} {piece}")
            else:
                out.append(piece)
            self._fresh = piece.endswith("\n")
        return self._stream.write("".join(out))

    def __getattr__(self, name):
        return getattr(self._stream, name)


class Server(ThreadingHTTPServer):
    daemon_threads = True

    # One listener per port, enforced by PortLock rather than shared through
    # SO_REUSEPORT. SO_REUSEPORT let a second devinx bind beside the first and
    # the kernel then spread connections between them; a deploy no longer
    # needs it, because the old process closes its listener and releases the
    # lock before it drains, so the new one binds a free port. On Windows the
    # stdlib's SO_REUSEADDR has the same double-bind meaning, so it is off
    # there and the port is claimed exclusively instead.
    allow_reuse_address = os.name != "nt"

    def server_bind(self):
        if os.name == "nt" and hasattr(socket, "SO_EXCLUSIVEADDRUSE"):
            try:
                self.socket.setsockopt(socket.SOL_SOCKET,
                                       socket.SO_EXCLUSIVEADDRUSE, 1)
            except OSError:
                pass
        return ThreadingHTTPServer.server_bind(self)


def drain_and_exit(srv, extra_servers=(), on_closed=None):
    """Close listeners, then drain accepted turns without blocking signals.

    The signal handler runs on the serve_forever thread. It must return so that
    shutdown(), running on another thread, can finish. The coordinator is NOT
    a daemon: once serve_forever returns it keeps Python alive for accepted work.
    Repeated SIGTERM/SIGINT requests do not start competing shutdown workers.
    """
    requested = False
    servers = (srv,) + tuple(s for s in extra_servers if s is not None)

    def drain():
        deadline = time.monotonic() + DRAIN_SECONDS
        for server in servers:
            try:
                server.shutdown()
            finally:
                server.server_close()
        if on_closed is not None:
            # Not listening any more: a successor may take the port now,
            # while this process finishes the turns it already accepted.
            try:
                on_closed()
            except Exception:
                pass
        while time.monotonic() < deadline:
            with _inflight_lock:
                busy = _inflight["n"]
            if not busy:
                break
            time.sleep(0.05)
        with _inflight_lock:
            busy = _inflight["n"]
        print("devinx: draining complete, exiting"
              + (f" with {busy} turn(s) still in flight after "
                 f"{DRAIN_SECONDS}s" if busy else ""), flush=True)
        os._exit(0)

    def handler(signum, frame):
        nonlocal requested
        if requested:
            return
        requested = True
        threading.Thread(target=drain, name="devinx-drain", daemon=False).start()

    for sig in (signal.SIGTERM, signal.SIGINT):
        try:
            signal.signal(sig, handler)
        except (ValueError, OSError):
            pass


class DashboardHandler(Handler):
    """A second listener carrying the dashboard and nothing else.

    Publishing the dashboard means putting a forwarder in front of a port, and
    a forwarder publishes every route that answers on it — /v1/messages
    included, spending this machine's Devin account for whoever found the URL.
    It also erases the one distinction the API route relied on: the tailnet
    proxy rewrites Host to 127.0.0.1, so the guard that refuses a non-loopback
    Host sees a local call and waves it through. No header survives that, which
    is why this is a separate port rather than another check: the API simply
    does not answer on the one being published.
    """

    def do_POST(self):
        self.send_error_json(404, "not_found_error", "Not found")

    def do_GET(self):
        if urlsplit(self.path).path not in ("/dashboard", "/dashboard/",
                                            "/api/stats", "/api/hello"):
            self.send_error_json(404, "not_found_error", "Not found")
            return
        Handler.do_GET(self)

    def dashboard_allowed(self):
        # This port exists to be published, so the token is not optional on it.
        return bool(DASHBOARD_TOKEN) and Handler.dashboard_allowed(self)


def serve_dashboard_port(port):
    """The dashboard on its own port, for a tailnet or funnel mount."""
    if not DASHBOARD_TOKEN:
        print(f"dashboard port {port} not opened: DEVINX_DASHBOARD_TOKEN is "
              f"unset, and an unauthenticated port is not worth publishing",
              flush=True)
        return
    try:
        srv = Server((HOST, port), DashboardHandler)
    except OSError as e:
        # A port already taken must not take the proxy down with it: the
        # dashboard is the optional half of this process.
        print(f"dashboard port {port} not opened: {e}", flush=True)
        return
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    print(f"dashboard also on http://{HOST}:{port}/dashboard (token required, "
          f"no API routes)", flush=True)
    return srv


if __name__ == "__main__":
    sys.stdout = _Stamped(sys.stdout)
    sys.stderr = _Stamped(sys.stderr)
    _port_lock = PortLock(PORT)
    if not _port_lock.acquire(wait=15):
        print(f"devinx: another devinx is already listening on port {PORT} "
              f"(lock {_port_lock.path}); not starting a second one", flush=True)
        sys.exit(1)
    service_secret(DATA_DIR)
    _srv = Server((HOST, PORT), Handler)
    print(f"devinx listening on http://{HOST}:{PORT}  "
          f"(build {BUILD}, pid {os.getpid()}, data: {DATA_DIR})", flush=True)
    _dashboard_srv = serve_dashboard_port(DASHBOARD_PORT) if DASHBOARD_PORT else None
    drain_and_exit(_srv, (_dashboard_srv,), on_closed=_port_lock.release)
    if os.environ.get("DEVINX_DUMP"):
        print(f"WARNING: DEVINX_DUMP is set. Every request, including the full "
              f"conversation and any credentials the client sends, is being "
              f"written verbatim to {os.environ['DEVINX_DUMP']}.*.json",
              flush=True)
    _srv.serve_forever()
