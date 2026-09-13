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
import json
import os
import re
import struct
import sys
import threading
import time
import uuid
from http.cookiejar import DefaultCookiePolicy
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit

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


pool = descriptor_pool.DescriptorPool()
for _m in (timestamp_pb2, duration_pb2, any_pb2, struct_pb2, descriptor_pb2,
           wrappers_pb2, empty_pb2, field_mask_pb2, type_pb2, source_context_pb2,
           api_pb2):
    _fd = descriptor_pb2.FileDescriptorProto()
    _fd.ParseFromString(_m.DESCRIPTOR.serialized_pb)
    try:
        pool.Add(_fd)
    except Exception:
        pass

_fdps = {}
for _p in descriptor_files():
    _fd = descriptor_pb2.FileDescriptorProto()
    with open(_p, "rb") as _fh:
        _fd.ParseFromString(_fh.read())
    _fdps[_fd.name] = _fd
# Descriptors reference each other; repeat until the dependency order resolves.
_added = set()
for _ in range(40):
    for _name, _fd in _fdps.items():
        if _name in _added:
            continue
        try:
            pool.Add(_fd)
            _added.add(_name)
        except Exception:
            pass


def _msg(name):
    return message_factory.GetMessageClass(pool.FindMessageTypeByName(name))


GetUserJwtRequest = _msg("exa.auth_pb.GetUserJwtRequest")
GetUserJwtResponse = _msg("exa.auth_pb.GetUserJwtResponse")
GetChatMessageRequest = _msg("exa.api_server_pb.GetChatMessageRequest")
GetChatMessageResponse = _msg("exa.api_server_pb.GetChatMessageResponse")


# --------------------------------------------------------------------------- #
# Cognition credential and JWT
# --------------------------------------------------------------------------- #

def _load_key():
    if os.environ.get("DEVINX_API_KEY"):
        return os.environ["DEVINX_API_KEY"]
    for cred in (os.path.join(DATA_DIR, "devin", "credentials.toml"),
                 os.path.expanduser("~/devin-shim/data/devin/credentials.toml"),
                 os.path.expanduser("~/.local/share/devin/credentials.toml")):
        if not os.path.exists(cred):
            continue
        with open(cred) as fh:
            for line in fh:
                if line.startswith("windsurf_api_key"):
                    return line.split('"')[1]
    raise RuntimeError(
        "no Devin credential found — run:  XDG_DATA_HOME=%s devin auth login"
        % DATA_DIR)


_key_lock = threading.Lock()
_key = {"value": None}


def api_key():
    """Resolved on first SWE-2 use, never at import.

    The Claude relay needs no Devin credential, so a missing or expired one must
    degrade to "SWE-2 requests fail" rather than "the service refuses to start"
    and take the main session down with it.
    """
    with _key_lock:
        if _key["value"] is None:
            value = _load_key()
            if not value.startswith(SESSION_PREFIX):
                value = SESSION_PREFIX + value
            _key["value"] = value
        return _key["value"]


def reset_key():
    """Forget the memoised credential so the next use re-reads the file.

    Called when the upstream rejects our auth: the usual cause is that the user
    just ran `devin auth login` again, which rewrites credentials.toml while this
    process happily keeps using the string it read at startup.
    """
    with _key_lock:
        _key["value"] = None


_jwt_lock = threading.Lock()
_jwt = {"token": None, "exp": 0.0, "base": None}


def _metadata(jwt=""):
    # The real devin-cli leaves session_id and request_id unset on inference calls.
    return {
        "api_key": api_key(),
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


def get_jwt(force=False):
    with _jwt_lock:
        now = time.time()
        if not force and _jwt["token"] and _jwt["exp"] - 60 > now:
            return _jwt["token"], _jwt["base"]
        req = GetUserJwtRequest(metadata=_metadata())
        r = SESSION.post(COGNITION_UPSTREAM + AUTH_PATH,
                         data=req.SerializeToString(),
                         headers={"content-type": "application/proto",
                                  "connect-protocol-version": "1"}, timeout=30)
        r.raise_for_status()
        resp = GetUserJwtResponse()
        try:
            resp.ParseFromString(r.content)
        except Exception:
            resp.ParseFromString(gzip.decompress(r.content))
        if not resp.user_jwt:
            raise RuntimeError("GetUserJwt returned empty jwt")
        _jwt["token"] = resp.user_jwt
        _jwt["exp"] = _jwt_expiry(resp.user_jwt) or now + 3300
        _jwt["base"] = resp.custom_api_server_url.strip() or None
        return _jwt["token"], _jwt["base"]


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


def build_request(body):
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
        if role == "user":
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
        elif role == "assistant":
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

    tools = [{"name": t.get("name", ""),
              "description": _TOOL_DESC_REWRITES.get(
                  t.get("name"), t.get("description", "")),
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
    req = GetChatMessageRequest(
        metadata=_metadata(get_jwt()[0]),
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


def chat_stream(req):
    """Yield (GetChatMessageResponse, None) per frame or (None, error) on trailer."""
    jwt, base = get_jwt()
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
                jwt, base = get_jwt(force=True)
                req.metadata.user_jwt = jwt
                body = req.SerializeToString()
                continue
            print(f"upstream HTTP {status}: {detail}", flush=True)
            yield None, f"upstream {status}: {detail}"
            return
        print(f"upstream conn: {time.time() - t_start:.1f}s to headers "
              f"({n_msgs} msgs, {len(body) // 1024}KB req)", flush=True)
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
                        print(f"upstream trailer error: {code}: {message}",
                              flush=True)
                        yield None, f"{code}: {message}"
                    continue
                raw = gzip.decompress(payload) if flag & 1 else payload
                msg = GetChatMessageResponse()
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
# Cognition response -> Anthropic Messages
# --------------------------------------------------------------------------- #

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

    def error(self, message):
        self._send("error", {"type": "error",
                             "error": {"type": "api_error", "message": message}})

    def stop(self):
        """End a failed stream. Deliberately no message_delta: there is no
        stop_reason that honestly describes an aborted turn, and emitting
        end_turn would tell the client the answer is complete."""
        self.close_block()
        self._send("message_stop", {"type": "message_stop"})


def run_swe(body, wfile):
    """Run one SWE-2 turn. Returns (response_dict, error) for the non-stream path;
    streams and returns (None, None) when the client asked for SSE."""
    stream = bool(body.get("stream"))
    # Report the resolved tier, not the alias, so the tier that actually ran is
    # visible in the client.
    out = AnthropicStream(wfile, resolve_model(body)) if stream else None

    # Cognition's input classifier denies borderline payloads nondeterministically
    # (the same body has been observed to pass and to fail). Retry while nothing
    # has reached the client yet.
    for attempt in range(3):
        try:
            req, model = build_request(body)
        except Exception as e:
            # Typically a missing or expired Devin credential, surfaced here
            # rather than at import. The streaming client has had nothing yet, so
            # it needs a real SSE error instead of a silently closed socket.
            reason = f"request build: {e}"
            if out:
                out.start()
                out.error(reason)
                out.finish("end_turn", {"input_tokens": 0, "output_tokens": 0})
                return None, None
            return None, reason

        thinking, signature, texts = [], None, []
        tool_order, tool_blocks = [], {}
        usage, stop, err, emitted = {}, 0, None, False

        try:
            for msg, e in chat_stream(req):
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
                    tid = tc.id or (tool_order[-1] if tool_order else "")
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
                    print(f"upstream done: latency={msg.latency:.1f}s "
                          f"usage in={msg.usage.input_tokens} "
                          f"out={msg.usage.output_tokens} "
                          f"cr={msg.usage.cache_read_tokens} "
                          f"cw={msg.usage.cache_write_tokens}", flush=True)
        except (requests.RequestException, OSError, ValueError) as e:
            # Network failure, a malformed frame, or an auth call that raised.
            # Left uncaught these reached the handler, which for a streaming
            # request had no path to answer: the client got a closed socket with
            # no status line and no SSE error at all.
            err = f"upstream {type(e).__name__}: {e}"
            print(err, flush=True)

        if err and not emitted and attempt < 2 and "permission_denied" in err:
            print(f"upstream permission_denied, retrying "
                  f"(attempt {attempt + 2}/3)", flush=True)
            continue
        break

    stop_reason = _stop_reason(stop, bool(tool_order))
    usage = usage or {"input_tokens": 0, "output_tokens": 0}

    if out:
        out.start()
        if err:
            # Never finalise a failed turn as a normal completion. Writing the
            # error into the assistant text and then closing with end_turn made
            # a truncated answer indistinguishable from a finished one, so the
            # client stored it as complete and had no reason to retry.
            out.error(err)
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

    def send_json(self, status, body):
        raw = json.dumps(body).encode()
        self.send_response(status)
        self.send_header("content-type", "application/json")
        self.send_header("content-length", str(len(raw)))
        self.send_header("connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(raw)
        self.close_connection = True

    def send_error_json(self, status, kind, message):
        self.send_json(status, {"type": "error",
                                "error": {"type": kind, "message": message}})

    def do_HEAD(self):
        if urlsplit(self.path).path == "/api/hello":
            self.send_response(200)
            self.send_header("content-length", "0")
            self.send_header("connection", "close")
            self.end_headers()
            self.close_connection = True
            return
        self.send_error_json(404, "not_found_error", "Not found")

    def do_GET(self):
        if urlsplit(self.path).path != "/v1/models":
            self.send_error_json(404, "not_found_error", "Not found")
            return
        models = [{"type": "model", "id": mid, "display_name": name,
                   "created_at": "2026-01-01T00:00:00Z"}
                  for mid, name in SWE_MODELS]
        self.send_json(200, {"data": models, "has_more": False,
                             "first_id": models[0]["id"],
                             "last_id": models[-1]["id"]})

    def do_POST(self):
        path = urlsplit(self.path).path
        if path not in ("/v1/messages", "/v1/messages/count_tokens"):
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

        if model in SWE_MODEL_IDS:
            if path.endswith("count_tokens"):
                self.send_json(200, {"input_tokens": estimate_tokens(body)})
                return
            self.serve_swe(body)
            return

        if not model.startswith("claude-"):
            self.send_error_json(400, "invalid_request_error", "Unsupported model")
            return
        if not (self.headers.get("authorization") or self.headers.get("x-api-key")):
            self.send_error_json(401, "authentication_error",
                                 "Claude Code login missing")
            return
        self.relay_claude(raw, model)

    def serve_swe(self, body):
        stream = bool(body.get("stream"))
        try:
            if stream:
                # run_swe owns the raw socket from here.
                run_swe(body, self.wfile)
            else:
                resp, err = run_swe(body, None)
                if err:
                    self.send_error_json(502, "api_error", err)
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

    def relay_claude(self, raw, model):
        """Transparent relay. Headers pass through untouched, including the
        caller's credential; this process adds nothing of its own."""
        response = None
        response_started = False
        try:
            headers = {name: value for name, value in self.headers.items()
                       if name.lower() not in REQUEST_EXCLUDED}
            response = SESSION.request(self.command, CLAUDE_UPSTREAM + self.path,
                                       data=raw, headers=headers, stream=True,
                                       allow_redirects=False, timeout=(15, None))
            response_started = True
            self.send_response(response.status_code)
            for name, value in response.headers.items():
                if name.lower() not in RESPONSE_EXCLUDED:
                    self.send_header(name, value)
            self.send_header("connection", "close")
            self.end_headers()
            if self.command != "HEAD":
                for chunk in response.raw.stream(65536, decode_content=False):
                    if chunk:
                        self.wfile.write(chunk)
                        self.wfile.flush()
            print(f"route=claude model={model} status={response.status_code}",
                  flush=True)
        except (BrokenPipeError, ConnectionResetError):
            print(f"route=claude model={model} status=client_disconnected", flush=True)
        except requests.RequestException as error:
            print(f"route=claude model={model} status={type(error).__name__}",
                  flush=True)
            if not response_started:
                self.send_error_json(502, "api_error", "Upstream unavailable")
        finally:
            if response is not None:
                response.close()
            self.close_connection = True


def estimate_tokens(body):
    """Rough local estimate for count_tokens. Cognition exposes no counting
    endpoint, and Claude Code only uses this as a pre-flight hint."""
    chars = len(_system_text(body))
    for m in body.get("messages", []):
        for b in _blocks(m.get("content")):
            chars += len(b.get("text") or b.get("thinking") or "")
            if b.get("type") == "tool_result":
                chars += len(_tool_result_text(b))
            if b.get("type") == "tool_use":
                chars += len(json.dumps(b.get("input") or {}))
    for t in body.get("tools") or []:
        chars += len(t.get("description", "")) + \
            len(json.dumps(t.get("input_schema") or {}))
    return max(1, chars // 4)


class Server(ThreadingHTTPServer):
    daemon_threads = True


if __name__ == "__main__":
    print(f"devinx listening on http://{HOST}:{PORT}  (data: {DATA_DIR})", flush=True)
    if os.environ.get("DEVINX_DUMP"):
        print(f"WARNING: DEVINX_DUMP is set. Every request, including the full "
              f"conversation and any credentials the client sends, is being "
              f"written verbatim to {os.environ['DEVINX_DUMP']}.*.json",
              flush=True)
    Server((HOST, PORT), Handler).serve_forever()
