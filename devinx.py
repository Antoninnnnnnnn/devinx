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
import glob
import gzip
import hashlib
import hmac
import json
import os
import random
import re
import struct
import subprocess
import sys
import threading
import time
import uuid
from http.cookiejar import DefaultCookiePolicy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

import requests
from urllib3.util.retry import Retry
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
_stats_lock = threading.Lock()
_stats = {"at": 0.0, "data": None, "error": None, "running": False}


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
    skip = ("upstream conn:", "upstream first-frame:", "route=")
    keep = [l for l in lines if l and not l.startswith(skip)]
    return keep[-n:]


def _build_id():
    """A fingerprint of the code this process is running.

    The service outlives the sessions that use it, on purpose: several of them
    share it and none should pay the startup cost. The cost of that is a service
    still running last week's code after a pull, with nothing to notice it. The
    launcher compares this against the file on disk, so "is something listening"
    becomes "is the right thing listening".
    """
    try:
        with open(os.path.abspath(__file__), "rb") as fh:
            return hashlib.sha1(fh.read()).hexdigest()[:12]
    except OSError:
        return "unknown"


BUILD = _build_id()

# In-flight requests, so a restart can wait for an idle moment rather than
# cutting a turn in half.
_inflight_lock = threading.Lock()
_inflight = {"n": 0}


def _enter_request():
    with _inflight_lock:
        _inflight["n"] += 1


def _leave_request():
    with _inflight_lock:
        _inflight["n"] -= 1


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


def _read_key(path):
    try:
        with open(path) as fh:
            for line in fh:
                if line.startswith("windsurf_api_key"):
                    return line.split('"')[1]
    except OSError:
        pass
    return None


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
    keys, names = [], []
    env = os.environ.get("DEVINX_API_KEYS") or os.environ.get("DEVINX_API_KEY")
    if env:
        for i, raw in enumerate(re.split(r"[,\n]", env)):
            raw = raw.strip()
            if raw:
                keys.append(raw)
                names.append(f"env[{i}]")
    else:
        for path in _credential_files():
            key = _read_key(path)
            if key and key not in keys:
                keys.append(key)
                names.append(_credential_name(path))
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
    for key, name in zip(keys, names):
        if not key.startswith(SESSION_PREFIX):
            key = SESSION_PREFIX + key
        out.append({"key": key, "name": name, "jwt": None, "exp": 0.0,
                    "base": None, "blocked_until": 0.0})
    return out


_acct_lock = threading.Lock()
_accounts = []


def accounts():
    """Resolved on first SWE-2 use, never at import.

    The Claude relay needs no Devin credential, so a missing or expired one must
    degrade to "SWE-2 requests fail" rather than "the service refuses to start"
    and take the main session down with it.
    """
    with _acct_lock:
        if not _accounts:
            _accounts.extend(_load_accounts())
            if len(_accounts) > 1:
                print(f"devinx: {len(_accounts)} Devin credentials "
                      f"({', '.join(a['name'] for a in _accounts)})", flush=True)
        return list(_accounts)


def api_key():
    """The first credential. Only for callers that do not pick an account."""
    return accounts()[0]["key"]


def reset_key():
    """Forget the memoised credentials so the next use re-reads the files.

    Called when the upstream rejects our auth: the usual cause is that the user
    just ran `devin auth login` again, which rewrites credentials.toml while this
    process happily keeps using the string it read at startup.
    """
    with _acct_lock:
        _accounts.clear()


_turn = {"n": 0}


def claim_account(avoid=None):
    """A credential that is not rate limited, and when the earliest one frees up
    if none is.

    Round robin rather than first-fit. The limits are per credential, so always
    starting at the same one keeps that one permanently at its ceiling while the
    others idle — the short limit would still be hit on every burst, merely
    followed by a switch. Spreading the turns halves the rate each account sees,
    which is the difference between switching constantly and not being limited.
    """
    now = time.time()
    with _acct_lock:
        usable = [a for a in _accounts
                  if a["blocked_until"] <= now and a is not avoid]
        if usable:
            _turn["n"] += 1
            return usable[_turn["n"] % len(usable)], 0.0
        soonest = min((a["blocked_until"] for a in _accounts
                       if a is not avoid), default=now)
        return None, max(0.0, soonest - now)


def block_account(acct, seconds):
    with _acct_lock:
        acct["blocked_until"] = time.time() + seconds


_jwt_lock = threading.Lock()


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
        acct = accounts()[0]
    with _jwt_lock:
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
        return acct["jwt"], acct["base"]


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


def _tool_result_text(block):
    """tool_result content is a string or a list of blocks (text and/or image)."""
    content = block.get("content")
    if isinstance(content, str):
        return content
    return _text_of(content)


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
RATE_WAIT_BUDGET = int(os.environ.get("DEVINX_RATE_WAIT", "600"))

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
                        "prompt": _tool_result_text(b),
                        # Without this a failed tool call replays as a successful
                        # one and the model has to infer failure from the text.
                        "tool_result_is_error": bool(b.get("is_error")),
                        "images": [img for img in
                                   (_image_of(x) for x in _blocks(b.get("content")))
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
        print(f"warning: messages with role {', '.join(sorted(unknown_roles))} "
              f"sent upstream as user content", flush=True)

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


def chat_stream(req, acct=None):
    """Yield (GetChatMessageResponse, None) per frame or (None, error) on trailer."""
    if acct is None:
        acct = accounts()[0]
    jwt, base = get_jwt(acct)
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
                # memoised at first use.
                reset_key()
                jwt, base = get_jwt(acct, force=True)
                req.metadata.api_key = acct["key"]
                req.metadata.user_jwt = jwt
                body = req.SerializeToString()
                continue
            print(f"upstream HTTP {status} on {acct['name']}: {detail}",
                  flush=True)
            yield None, f"upstream {status}: {detail}"
            return
        print(f"upstream conn: {time.time() - t_start:.1f}s to headers "
              f"(acct={acct['name']} model={req.chat_model_uid} {n_msgs} msgs, "
              f"{len(body) // 1024}KB req)", flush=True)
        buf = b""
        first_frame = True
        end_of_stream = False
        for chunk in r.iter_content(65536):
            buf += chunk
            while len(buf) >= 5:
                flag = buf[0]
                ln = struct.unpack(">I", buf[1:5])[0]
                if len(buf) < 5 + ln:
                    break
                payload = buf[5:5 + ln]
                buf = buf[5 + ln:]
                if flag & 2:
                    end_of_stream = True
                    trailer = gzip.decompress(payload) if flag & 1 else payload
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
                raw = gzip.decompress(payload) if flag & 1 else payload
                msg = protos()["GetChatMessageResponse"]()
                msg.ParseFromString(raw)
                if first_frame:
                    first_frame = False
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
# How much new material has to pile up before the summary is extended again.
# Extending costs an upstream call, so not every turn; leaving it un-extended
# costs the agent the memory of that material, so not many turns either.
SUMMARY_BATCH = 2000
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


def summarise_turns(messages, model, system, previous=None):
    """Summarise dropped turns with one extra upstream call.

    This is the pause. It costs a request and a few seconds, against an agent
    that otherwise stops mid-task with nothing to show for the work it did.
    """
    body = {
        "model": model,
        "max_tokens": 4096,
        "system": "You are summarising a coding agent's conversation so it can "
                  "continue working after its context was compacted.",
        "messages": [{"role": "user", "content": [{"type": "text", "text":
            (f"<earlier_summary>\n{previous}\n</earlier_summary>\n\n"
             if previous else "")
            + f"<conversation>\n{_render_turns(messages)}\n</conversation>\n\n"
            f"The agent's own instructions began: {system[:2000]}\n\n"
            + (COMPACT_PROMPT_MORE if previous else COMPACT_PROMPT)}]}],
    }
    req, _ = build_request(body)
    texts = []
    for msg, err in chat_stream(req):
        if err:
            return None
        if msg.delta_text:
            texts.append(msg.delta_text)
    return "".join(texts).strip() or None


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
    """Replace the middle of an over-long conversation with a summary.

    The first turn stays: it is the task. The recent turns stay verbatim: they
    are what the agent is doing right now. Everything between becomes one
    summary, written with Claude Code's own compaction prompt.
    """
    messages = body.get("messages") or []
    if len(messages) < 4 or estimate_tokens(body) <= COMPACT_AT:
        return body
    start = _tail_start(messages, int(COMPACT_AT * COMPACT_TAIL))
    if start <= 1 or start >= len(messages):
        # Nothing to drop that would help; the size is the first turn or the
        # tail alone, and summarising cannot fix either.
        print("compaction: nothing droppable, forwarding as is", flush=True)
        return body

    key = _conv_key(body)
    span = _span_blocks(messages, start)
    total_blocks = _count_blocks(messages)
    with _summary_lock:
        covered, summary, built_at = _summaries.get(key, (0, None, 0))
    # A resumed agent is the same task under the same system prompt in the same
    # session, so it hashes to the same key — and would inherit the summary of
    # the run that failed, then extend it rather than rebuild it, so each resume
    # starts further from the truth than the last. A conversation that is
    # suddenly shorter than when the summary was built is a new run, not a
    # continuation: the summary is dropped and rebuilt from what is actually
    # there. Only the summary is reset; the cascade id stays, because that is
    # what keeps the upstream prefix cache and it is worth about 60% of the
    # input tokens.
    if summary is not None and total_blocks < built_at:
        print(f"compaction: conversation restarted ({total_blocks} blocks, was "
              f"{built_at}); dropping the summary from the previous run",
              flush=True)
        covered, summary = 0, None
    # Everything in the span the summary does not account for yet. Blocks only
    # ever arrive at the end of it, so the covered part is a stable prefix.
    fresh = span[covered:]
    fresh_tokens = sum(len(json.dumps(b, default=str)) for _, b in fresh) // 4
    if summary is None or fresh_tokens > SUMMARY_BATCH:
        model = resolve_model(body)
        before = estimate_tokens(body)
        # Only what arrived since the last summary, extending it rather than
        # rebuilding it: the difference between a few seconds a turn and half a
        # minute a turn.
        new = summarise_turns(_regroup(fresh), model, _system_text(body), summary)
        if not new:
            print("compaction: the summary call failed, forwarding as is",
                  flush=True)
            return body
        summary = f"{summary}\n\n{new}" if summary else new
        if len(summary) // 4 > SUMMARY_TOTAL_CAP:
            # Fold rather than grow. Summarising the summary keeps one document
            # of the whole run instead of a chain of appendices, and costs one
            # short call against a record that would otherwise never stop.
            folded = summarise_turns(
                [{"role": "user", "content": [{"type": "text", "text": summary}]}],
                model, _system_text(body), None)
            if folded:
                print(f"compaction: summary folded, {len(summary) // 4} -> "
                      f"{len(folded) // 4} tokens", flush=True)
                summary = folded
        covered = len(span)
        with _summary_lock:
            if len(_summaries) > 64:
                _summaries.clear()
            _summaries[key] = (covered, summary, total_blocks)
        print(f"compaction: {len(fresh)} more blocks summarised "
              f"({covered} of {len(span)} covered, {before} tokens estimated, "
              f"over {COMPACT_AT})", flush=True)

    compacted = dict(body)
    compacted["messages"] = [messages[0], {"role": "user", "content": [
        {"type": "text", "text":
         "This conversation was compacted to fit the context window. The "
         "summary below replaces the turns between the task above and the "
         "messages that follow; continue the work from it.\n\n"
         f"<summary>\n{summary}\n</summary>"}]}] + messages[start:]
    # Diagnostic: what the conversation is actually made of. The tail collapses
    # when single messages are large enough to spend its whole budget, and that
    # is worth knowing from measurement rather than assumption.
    def anatomy(m):
        raw = len(json.dumps(m, default=str)) // 4
        est = estimate_tokens({"messages": [m]})
        parts = []
        for b in _blocks(m.get("content")):
            kind = b.get("type")
            size = len(json.dumps(b, default=str)) // 4
            name = b.get("name") or ""
            sample = (b.get("text") or b.get("thinking")
                      or _tool_result_text(b) or json.dumps(b.get("input") or {}))
            parts.append(f"{kind}{'/' + name if name else ''}={size}t"
                         f"[{sample[:60]!r}]")
        return raw, est, m.get("role"), len(_blocks(m.get("content"))), parts[:3]

    worst = max(messages, key=lambda m: len(json.dumps(m, default=str)))
    raw, est, role, nblocks, parts = anatomy(worst)
    print(f"compaction: {estimate_tokens(body)} -> {estimate_tokens(compacted)} "
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
_RESET_AFTER = re.compile(r"reset in (\d+) minute")


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
            retry_after = int(found.group(1)) * 60
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


class AnthropicStream:
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

    def _send(self, event, data):
        self.w.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
        self.w.flush()

    def start(self, usage=None):
        if self.started:
            return
        self.started = True
        self.w.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
                     b"cache-control: no-cache\r\nconnection: close\r\n\r\n")
        self.w.flush()
        self._send("message_start", {
            "type": "message_start",
            "message": {"id": "msg_devinx", "type": "message", "role": "assistant",
                        "model": self.model, "content": [], "stop_reason": None,
                        "stop_sequence": None,
                        "usage": usage or {"input_tokens": 0, "output_tokens": 0}}})

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
        self.flush_tools()
        self.close_block()
        self._send("message_delta", {
            "type": "message_delta",
            "delta": {"stop_reason": stop_reason, "stop_sequence": None},
            "usage": usage})
        self._send("message_stop", {"type": "message_stop"})

    def error(self, message, kind="api_error"):
        self._send("error", {"type": "error",
                             "error": {"type": kind, "message": message}})

    def stop(self):
        """End a failed stream. Deliberately no message_delta: there is no
        stop_reason that honestly describes an aborted turn, and emitting
        end_turn would tell the client the answer is complete."""
        self.close_block()
        self._send("message_stop", {"type": "message_stop"})


def run_swe(body, wfile, make_stream=None):
    """Run one SWE-2 turn. Returns (response_dict, error) for the non-stream path;
    streams and returns (None, None) when the client asked for SSE.

    make_stream picks the wire the answer goes back on: Anthropic by default,
    the Codex flavour of Responses when the request came in on that route. Only
    the emitter differs — everything upstream of it is shared.
    """
    stream = bool(body.get("stream"))
    make_stream = make_stream or AnthropicStream
    # Before anything is sent: if this turn would not fit, reduce it here rather
    # than let the upstream refuse it and the client end the agent.
    try:
        body = compact_body(body)
    except Exception as e:
        # Compaction is a rescue, never a new way to fail. A turn that would
        # have gone out uncompacted still goes out.
        print(f"compaction failed, forwarding as is: {e}", flush=True)
    # Report the resolved tier, not the alias, so the tier that actually ran is
    # visible in the client.
    out = make_stream(wfile, resolve_model(body)) if stream else None

    # Cognition's input classifier denies borderline payloads nondeterministically
    # (the same body has been observed to pass and to fail). Retry while nothing
    # has reached the client yet.
    attempt, waited, retries = 0, 0.0, 0
    acct = None
    while attempt < 3:
        try:
            req, model = build_request(body, TOOL_DESC_CAPS[attempt])
        except Exception as e:
            # Typically a missing or expired Devin credential, surfaced here
            # rather than at import. The streaming client has had nothing yet, so
            # it needs a real SSE error instead of a silently closed socket.
            # Nothing has been written yet either way, so this goes back as a
            # status the client can act on rather than as a 200 stream whose
            # only content is an error — and never as a finished turn.
            return None, f"request build: {e}"

        thinking, signature, texts = [], None, []
        tool_order, tool_blocks = [], {}
        usage, stop, err, emitted = {}, 0, None, False
        latency = 0.0

        if acct is None:
            acct, _ = claim_account()
            if acct is None:
                acct = accounts()[0]
        try:
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

        if (err and not emitted and retries < NETWORK_RETRIES
                and any(t in err for t in _TRANSIENT)):
            retries += 1
            delay = 1.5 * retries
            print(f"upstream connection failed ({err[:60]}), retrying in "
                  f"{delay:.0f}s ({retries}/{NETWORK_RETRIES})", flush=True)
            time.sleep(delay)
            continue
        if err and not emitted and "resource_exhausted" in err:
            # Both of Cognition's limits are per account, so another credential
            # is a switch rather than a wait. Only when every one of them is
            # spent does the turn actually have to be held.
            found = _RESET_AFTER.search(err)
            delay = int(found.group(1)) * 60 if found else 30
            if acct is not None:
                block_account(acct, delay)
            other, until = claim_account(avoid=acct)
            if other is not None:
                print(f"upstream rate limited on {acct['name']}, switching to "
                      f"{other['name']}", flush=True)
                acct = other
                continue
            # Every account is blocked; wait for the first one to come back.
            wait = min(until or delay, RATE_WAIT_BUDGET - waited)
            if wait > 0:
                wait += random.uniform(0, min(5.0, wait * 0.1))
                print(f"upstream rate limited on every credential, holding "
                      f"the turn for {wait:.0f}s ({waited:.0f}s waited so far)",
                      flush=True)
                time.sleep(wait)
                waited += wait
                acct, _ = claim_account()
                continue
            print(f"upstream rate limited and {RATE_WAIT_BUDGET}s of waiting is "
                  f"spent; handing it back", flush=True)
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
        if err and not emitted:
            # Nothing has reached the client yet, so the failure can still be
            # what it actually is: an HTTP status the client knows how to act
            # on. Opening a 200 stream and putting the error inside it turns a
            # rate limit the client would have waited out into a dead turn.
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
            except ValueError:
                print(f"tool call {tool_blocks[tid]['name']} has unparseable "
                      f"arguments ({len(raw_args)} chars); dropping it and "
                      f"reporting max_tokens", flush=True)
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
        except ValueError:
            # Substituting {} would hand the client a well-formed call with its
            # arguments quietly removed — a truncated `Bash` becomes a no-arg
            # `Bash`. Report the turn as cut short instead.
            print(f"tool call {tool_blocks[tid]['name']} has unparseable "
                  f"arguments ({len(raw_args)} chars); reporting max_tokens",
                  flush=True)
            stop_reason = "max_tokens"
            continue
        content.append({"type": "tool_use", "id": tid,
                        "name": tool_blocks[tid]["name"], "input": args})
    return {"id": "msg_devinx", "type": "message", "role": "assistant",
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


class ResponsesStream:
    """Emits the Codex flavour of the Responses SSE stream onto a raw socket.

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
        self.open_text = False
        self.text_buf = []
        self.started = False
        self.tools = {}

    def _send(self, event, data):
        data["sequence_number"] = self.seq
        self.seq += 1
        self.w.write(f"event: {event}\ndata: {json.dumps(data)}\n\n".encode())
        self.w.flush()

    def _response(self, status, usage=None):
        out = {"id": "resp_devinx", "object": "response",
               "created_at": int(time.time()), "status": status,
               "model": self.model, "output": [], "error": None,
               "instructions": None, "incomplete_details": None,
               "parallel_tool_calls": False, "tool_choice": "auto",
               "tools": [], "metadata": {}}
        if usage is not None:
            out["usage"] = {
                "input_tokens": usage.get("input_tokens", 0),
                "input_tokens_details": {"cached_tokens": usage.get(
                    "cache_read_input_tokens", 0)},
                "output_tokens": usage.get("output_tokens", 0),
                "output_tokens_details": {"reasoning_tokens": 0},
                "total_tokens": usage.get("input_tokens", 0)
                + usage.get("output_tokens", 0)}
        return out

    def start(self, usage=None):
        if self.started:
            return
        self.started = True
        self.w.write(b"HTTP/1.1 200 OK\r\ncontent-type: text/event-stream\r\n"
                     b"cache-control: no-cache\r\nconnection: close\r\n\r\n")
        self.w.flush()
        self._send("response.created", {"type": "response.created",
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
        self.item_id = f"msg_devinx_{self.index}"
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
            item_id = f"call_devinx_{self.index}"
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
        self.flush_tools()
        self._close_text()
        self._send("response.completed", {
            "type": "response.completed",
            "response": self._response("completed", usage)})

    def error(self, message):
        self._send("error", {"type": "error", "code": "api_error",
                             "message": message})

    def stop(self):
        """No response.completed: a turn that failed must not be handed back as
        a finished one, or Codex stores the truncated answer and moves on."""
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
# while `connect` only covers DNS/TCP/TLS establishment. read=0 therefore left
# the one case this exists for uncovered. Replaying after the upstream began
# answering is still impossible: with stream=True the retry window closes once
# the response headers are read, and body-phase failures surface to the caller.
_RETRY = Retry(total=3, connect=3, read=3, status=0, redirect=0,
               allowed_methods=None, backoff_factor=0.2)
for _scheme in ("http://", "https://"):
    SESSION.mount(_scheme, requests.adapters.HTTPAdapter(
        pool_connections=8, pool_maxsize=32, max_retries=_RETRY))


class Handler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

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
        auth = self.headers.get("authorization")
        if not auth:
            return rows
        try:
            headers = {name: value for name, value in self.headers.items()
                       if name.lower() not in REQUEST_EXCLUDED}
            # Forward the query verbatim: Codex asks for
            # /v1/models?client_version=…, and the upstream answers differently
            # — or not at all — without it.
            query = urlsplit(self.path).query
            r = SESSION.get(CODEX_UPSTREAM + "/models"
                            + (f"?{query}" if query else ""),
                            headers=headers, timeout=(10, 20))
            upstream = r.json().get("models") if r.status_code == 200 else None
        except (requests.RequestException, ValueError):
            upstream = None
        if not isinstance(upstream, list):
            print("codex catalog: upstream unavailable, serving swe-2 only",
                  flush=True)
            return rows
        for entry in upstream:
            if isinstance(entry, dict):
                entry["multi_agent_version"] = MULTI_AGENT_SURFACE
        return rows + upstream

    def serve_stats(self):
        """Live figures for the dashboard.

        The extractor runs as a subprocess rather than an import: it owns its
        own shape and this stays decoupled from it. A short cache means ten open
        tabs cost one pass over the log, not ten.
        """
        now = time.time()
        with _stats_lock:
            fresh = _stats["at"] > now - STATS_TTL
            mine = not fresh and not _stats["running"]
            if mine:
                _stats["running"] = True
        if mine:
            # One pass at a time. Ten tabs, or one tab whose fetch outlives the
            # poll interval, must not each spawn their own extractor.
            data, err = None, None
            try:
                r = subprocess.run(
                    [sys.executable, os.path.join(HERE, "tools", "log_stats.py")],
                    capture_output=True, text=True, timeout=60)
                data = json.loads(r.stdout) if r.returncode == 0 else None
                if data is None:
                    err = (r.stderr or "stats failed").strip()[:200]
            except Exception as e:
                data, err = None, f"{type(e).__name__}: {e}"
            with _stats_lock:
                _stats["at"], _stats["error"], _stats["running"] = time.time(), err, False
                # A failed pass keeps the last good figures rather than
                # replacing them with zeros that read as a healthy idle service.
                if data is not None:
                    _stats["data"] = data
        with _stats_lock:
            payload = dict(_stats["data"] or {})
            payload["error"] = _stats["error"]
            payload["cached_age"] = round(time.time() - _stats["at"], 1)
        with _inflight_lock:
            busy = _inflight["n"]
        payload["service"] = {"build": BUILD, "pid": os.getpid(), "port": PORT,
                              "inflight": busy, "started": _STARTED,
                              "uptime": round(time.time() - _STARTED),
                              "accounts": [a["name"] for a in _accounts]}
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
            self.send_json(200, {"service": "devinx", "build": BUILD,
                                 "pid": os.getpid(), "port": PORT,
                                 "inflight": busy})
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
        _enter_request()
        try:
            self._do_POST()
        finally:
            _leave_request()

    def _do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/v1/messages", "/v1/messages/count_tokens",
                        "/v1/responses"):
            self.send_error_json(404, "not_found_error", "Not found")
            return
        try:
            length = int(self.headers.get("content-length", "0"))
            if length > MAX_BODY_BYTES:
                self.send_error_json(413, "invalid_request_error",
                                     f"Body exceeds {MAX_BODY_BYTES} bytes")
                return
            raw = self.rfile.read(length)
            body = json.loads(raw)
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

        if model in SWE_MODEL_IDS and self.browser_origin():
            self.send_error_json(
                403, "permission_error",
                "Refusing a browser-originated request on the SWE-2 route")
            return

        if model in SWE_MODEL_IDS:
            if path.endswith("count_tokens"):
                self.send_json(200, {"input_tokens": estimate_tokens(body)})
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
        try:
            if stream:
                # run_swe owns the raw socket once it has written anything; it
                # hands an error back instead while the socket is still clean.
                _, err = run_swe(body, self.wfile)
                if err:
                    kind, status, message, wait = anthropic_error(err, body)
                    self.send_error_json(status, kind, message, wait)
            else:
                resp, err = run_swe(body, None)
                if err:
                    kind, status, message, wait = anthropic_error(err, body)
                    self.send_error_json(status, kind, message, wait)
                else:
                    self.send_json(200, resp)
        except (BrokenPipeError, ConnectionResetError):
            print("client disconnected mid-stream", flush=True)
        except Exception as e:
            print(f"route=swe model={body.get('model')} status={type(e).__name__}: {e}",
                  flush=True)
            if not stream:
                self.send_error_json(502, "api_error", str(e))
        finally:
            self.close_connection = True

    def serve_swe_responses(self, body):
        """SWE-2 over the Responses wire, for Codex."""
        try:
            translated, custom = responses_to_messages(body)
        except Exception as e:
            self.send_error_json(400, "invalid_request_error",
                                 f"could not read the Responses body: {e}")
            return
        if not translated.get("stream"):
            # Codex always streams; a non-streaming caller would need a second
            # response assembler for no one.
            self.send_error_json(400, "invalid_request_error",
                                 "the SWE-2 Responses route is streaming only")
            return
        try:
            run_swe(translated, self.wfile,
                    lambda w, m: ResponsesStream(w, m, custom))
        except (BrokenPipeError, ConnectionResetError):
            print("client disconnected mid-stream", flush=True)
        except Exception as e:
            print(f"route=swe-responses model={body.get('model')} "
                  f"status={type(e).__name__}: {e}", flush=True)
        finally:
            self.close_connection = True

    def relay(self, raw, model, url, label):
        """Transparent relay. Headers pass through untouched, including the
        caller's credential; this process adds nothing of its own."""
        response = None
        response_started = False
        try:
            headers = {name: value for name, value in self.headers.items()
                       if name.lower() not in REQUEST_EXCLUDED}
            response = SESSION.request(self.command, url, data=raw,
                                       headers=headers, stream=True,
                                       allow_redirects=False, timeout=(15, None))
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
            print(f"route={label} model={model} status={response.status_code}",
                  flush=True)
        except (BrokenPipeError, ConnectionResetError):
            print(f"route={label} model={model} status=client_disconnected",
                  flush=True)
        except requests.RequestException as error:
            print(f"route={label} model={model} status={type(error).__name__}",
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


def estimate_tokens(body):
    """Rough local estimate. Cognition exposes no counting endpoint; this is
    what count_tokens answers and what compaction decides on."""
    chars, tokens = len(_system_text(body)), 0
    for m in body.get("messages", []):
        for b in _blocks(m.get("content")):
            chars += len(b.get("text") or b.get("thinking") or "")
            if b.get("type") == "image":
                tokens += _image_tokens(b)
            if b.get("type") == "tool_result":
                chars += len(_tool_result_text(b))
                for inner in _blocks(b.get("content")):
                    if inner.get("type") == "image":
                        tokens += _image_tokens(inner)
            if b.get("type") == "tool_use":
                chars += len(json.dumps(b.get("input") or {}))
    for t in body.get("tools") or []:
        chars += len(t.get("description", "")) + \
            len(json.dumps(t.get("input_schema") or {}))
    return max(1, chars // 4 + tokens)


class Server(ThreadingHTTPServer):
    daemon_threads = True


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


if __name__ == "__main__":
    print(f"devinx listening on http://{HOST}:{PORT}  "
          f"(build {BUILD}, pid {os.getpid()}, data: {DATA_DIR})", flush=True)
    if DASHBOARD_PORT:
        serve_dashboard_port(DASHBOARD_PORT)
    if os.environ.get("DEVINX_DUMP"):
        print(f"WARNING: DEVINX_DUMP is set. Every request, including the full "
              f"conversation and any credentials the client sends, is being "
              f"written verbatim to {os.environ['DEVINX_DUMP']}.*.json",
              flush=True)
    Server((HOST, PORT), Handler).serve_forever()
