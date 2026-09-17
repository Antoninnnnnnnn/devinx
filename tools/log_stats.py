#!/usr/bin/env python3
"""Statistics extractor for the devinx log.

Reads ~/.local/share/devinx/devinx.log and prints one JSON object to stdout.
The log has no timestamps and has changed shape over time, so both dialects
are parsed: early lines carry no acct/model/stop fields, newer ones do.
Anything that matches no known shape is skipped, so a truncated line, a
leaked traceback or a pasted nginx 502 page cannot crash the run.

Attribution: every upstream attempt logs its own "upstream conn" line, so a
completed "upstream done" is credited to the acct/model of the most recent
conn line. That stays correct across mid-turn account switches (the retry
logs a new conn first) and is only approximate under interleaved concurrent
requests. Turns from before those fields existed land under "unknown".

Definitions:
  - a rate-limit refusal is a resource_exhausted trailer error or an
    upstream HTTP 429; relay route=... status=429 lines are the client
    side of the same event and stay under "relay".
  - a burst is a run of refusals with no "upstream done" between them.
  - turns_failed counts upstream attempts that ended in error: trailer
    errors that are not rate limits, non-429 HTTP statuses, dropped
    streams and connection exceptions. Retried and rate-limited attempts
    are tracked in their own sections instead.
"""

import json
import os
import re
import statistics
from collections import Counter, defaultdict
from datetime import datetime

# DEVINX_LOG exists so the extractor can be checked against a frozen copy of
# the live, ever-appending log; the default is the real path.
LOG_PATH = os.environ.get(
    "DEVINX_LOG", os.path.expanduser("~/.local/share/devinx/devinx.log"))

RE_CONN = re.compile(
    r"^upstream conn: [\d.]+s to headers "
    r"\((?:acct=(\S+) )?(?:model=(\S+) )?(\d+) msgs, (\d+)KB req\)")
RE_DONE = re.compile(
    r"^upstream done: (?:stop=([a-z_]+)/\d+ calls=(\d+) )?"
    r"latency=([\d.]+)s usage in=(\d+) out=(\d+) cr=(\d+) cw=(\d+)")
RE_TRAILER = re.compile(
    r"^upstream trailer error(?: on (\S+))?: (\w+)(?:: ?(.*))?$")
RE_HTTP = re.compile(r"^upstream HTTP (\d+) on (\S+):")
RE_HOLD = re.compile(r"holding the turn for (\d+)s")
RE_QUOTA = re.compile(r"Reached (.+?) rate limit")
RE_RESET = re.compile(r"reset in (\d+) (minute|second)s?\b")
RE_COMPACT = re.compile(r"^compaction: (\d+) -> (\d+) tokens")
RE_BIGTOOL = re.compile(r"^WARNING: (\d+) tool calls in one turn: (.*)$")
RE_TOOLNAME = re.compile(r"'([^']+)': (\d+)")
RE_UNPARSEABLE = re.compile(r"^tool call (\S+) has unparseable arguments")
RE_ROUTE = re.compile(r"^route=(\S+) model=\S+ status=(\S+)")
RE_BUILD = re.compile(r"\(build ([0-9a-f]+),")
RE_UPSTREAM_ERR = re.compile(r"^upstream ([A-Z]\w+):")


def pct(values, p):
    """Percentile by sort-and-index: sorted[int(len*p)], clamped.

    Returns 0 on an empty list, as the frontend contract requires.
    """
    if not values:
        return 0
    s = sorted(values)
    return s[min(int(len(s) * p), len(s) - 1)]


def collect(path):
    st = {
        "lines": 0, "bytes": 0, "restarts": 0, "builds": [],
        "turns_ok": 0, "turns_failed": 0,
        "in": 0, "out": 0, "cr": 0, "cw": 0,
        "lat": [], "kb": [], "msgs": [], "calls": [],
        "calls_hist": Counter(), "stops": Counter(),
        "by_model": defaultdict(lambda: {"turns": 0, "input": 0, "output": 0}),
        "by_account": defaultdict(lambda: {"turns": 0, "refusals": 0}),
        "rl_total": 0, "by_quota": Counter(), "waits": [],
        "switches": 0, "holds": 0, "held_seconds": 0, "budget": 0,
        "bursts": [], "cur_burst": 0,
        "comp_count": 0, "comp_fail": 0, "before": [], "after": [],
        "relay": defaultdict(Counter),
        "conn_reset": 0, "chunked": 0, "net_retries": 0,
        "truncated": 0, "client_disc": 0,
        "unparseable": 0, "unparseable_by_tool": Counter(),
        "big_tool_turns": [],
        "busiest": None,  # (input + output, latency, input, output)
    }
    seen_builds = set()
    last_acct = None
    last_model = None

    def refusal(acct, msg):
        st["rl_total"] += 1
        st["cur_burst"] += 1
        q = RE_QUOTA.search(msg or "")
        st["by_quota"][q.group(1) if q else "unknown"] += 1
        r = RE_RESET.search(msg or "")
        if r:
            n = int(r.group(1))
            st["waits"].append(n * 60 if r.group(2) == "minute" else n)
        st["by_account"][acct or last_acct or "unknown"]["refusals"] += 1

    try:
        st["bytes"] = os.path.getsize(path)
        fh = open(path, "r", encoding="utf-8", errors="replace")
    except OSError:
        fh = None
    if fh is None:
        return st

    with fh:
        for line in fh:
            st["lines"] += 1
            try:
                if line.startswith("upstream conn:"):
                    m = RE_CONN.match(line)
                    if m:
                        st["msgs"].append(int(m.group(3)))
                        st["kb"].append(int(m.group(4)))
                        last_acct, last_model = m.group(1), m.group(2)
                elif line.startswith("upstream done:"):
                    m = RE_DONE.match(line)
                    if m:
                        stop, calls = m.group(1), m.group(2)
                        lat = float(m.group(3))
                        i, o = int(m.group(4)), int(m.group(5))
                        cr, cw = int(m.group(6)), int(m.group(7))
                        st["turns_ok"] += 1
                        if st["cur_burst"]:
                            st["bursts"].append(st["cur_burst"])
                            st["cur_burst"] = 0
                        st["lat"].append(lat)
                        st["in"] += i
                        st["out"] += o
                        st["cr"] += cr
                        st["cw"] += cw
                        if stop:
                            st["stops"][stop] += 1
                        if calls is not None:
                            st["calls"].append(int(calls))
                            st["calls_hist"][calls] += 1
                        bm = st["by_model"][last_model or "unknown"]
                        bm["turns"] += 1
                        bm["input"] += i
                        bm["output"] += o
                        st["by_account"][last_acct or "unknown"]["turns"] += 1
                        if st["busiest"] is None or i + o > st["busiest"][0]:
                            st["busiest"] = (i + o, lat, i, o)
                elif line.startswith("upstream first-frame:"):
                    pass  # informational only; latency comes from done lines
                elif line.startswith("upstream trailer error"):
                    m = RE_TRAILER.match(line)
                    if m:
                        if m.group(2) == "resource_exhausted":
                            refusal(m.group(1), m.group(3))
                        else:
                            st["turns_failed"] += 1
                elif line.startswith("upstream rate limited"):
                    if "switching to" in line:
                        st["switches"] += 1
                    elif "handing it back" in line:
                        st["budget"] += 1
                    else:
                        h = RE_HOLD.search(line)
                        if h:
                            st["holds"] += 1
                            st["held_seconds"] += int(h.group(1))
                elif line.startswith("upstream HTTP "):
                    m = RE_HTTP.match(line)
                    if m:
                        if m.group(1) == "429":
                            refusal(m.group(2), line)
                        else:
                            st["turns_failed"] += 1
                elif line.startswith("upstream stream"):
                    # "...ended without an end-of-stream frame" (and the
                    # older "...truncated" wording) mean a dropped stream.
                    st["truncated"] += 1
                    st["turns_failed"] += 1
                elif line.startswith("upstream connection failed"):
                    st["net_retries"] += 1
                elif line.startswith("upstream "):
                    m = RE_UPSTREAM_ERR.match(line)
                    if m:
                        # "upstream <ExceptionName>: ..." — a dead attempt.
                        # BrokenPipeError lands here too; it is an upstream
                        # write failure, counted with the other resets.
                        if m.group(1) == "ChunkedEncodingError":
                            st["chunked"] += 1
                        else:
                            st["conn_reset"] += 1
                        st["turns_failed"] += 1
                elif line.startswith("client disconnected"):
                    st["client_disc"] += 1
                elif line.startswith("compaction:"):
                    m = RE_COMPACT.match(line)
                    if m:
                        st["comp_count"] += 1
                        st["before"].append(int(m.group(1)))
                        st["after"].append(int(m.group(2)))
                    elif "summary call failed" in line:
                        st["comp_fail"] += 1
                    # "more turns summarised" and "nothing droppable" are
                    # progress notes, not completed compactions.
                elif line.startswith("compaction failed"):
                    # compact_body raised; the request went out uncompacted.
                    st["comp_fail"] += 1
                elif line.startswith("WARNING:"):
                    m = RE_BIGTOOL.match(line)
                    if m:
                        names = {k: int(v)
                                 for k, v in RE_TOOLNAME.findall(m.group(2))}
                        st["big_tool_turns"].append(
                            {"calls": int(m.group(1)), "names": names})
                elif line.startswith("tool call "):
                    m = RE_UNPARSEABLE.match(line)
                    if m:
                        st["unparseable"] += 1
                        st["unparseable_by_tool"][m.group(1)] += 1
                elif line.startswith("route="):
                    m = RE_ROUTE.match(line)
                    if m:
                        st["relay"][m.group(1)][m.group(2).rstrip(":")] += 1
                elif line.startswith("devinx listening"):
                    st["restarts"] += 1
                    b = RE_BUILD.search(line)
                    if b and b.group(1) not in seen_builds:
                        seen_builds.add(b.group(1))
                        st["builds"].append(b.group(1))
            except Exception:
                # A malformed line is skipped, never fatal.
                continue
    if st["cur_burst"]:
        st["bursts"].append(st["cur_burst"])
    return st


def main():
    st = collect(LOG_PATH)

    lat = st["lat"]
    lat_total = sum(lat)
    total_tokens = st["in"] + st["out"] + st["cr"] + st["cw"]
    hours = lat_total / 3600.0
    busiest = st["busiest"]
    bursts = st["bursts"]

    out = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "log": {
            "path": LOG_PATH,
            "lines": st["lines"],
            "bytes": st["bytes"],
            "restarts": st["restarts"],
            "builds": st["builds"],
        },
        "swe": {
            "turns_ok": st["turns_ok"],
            "turns_failed": st["turns_failed"],
            "tokens": {
                "input": st["in"],
                "output": st["out"],
                "cache_read": st["cr"],
                "cache_write": st["cw"],
            },
            "latency": {
                "p50": round(float(pct(lat, 0.5)), 1),
                "p90": round(float(pct(lat, 0.9)), 1),
                "p99": round(float(pct(lat, 0.99)), 1),
                "max": round(max(lat), 1) if lat else 0,
                "total_seconds": round(lat_total, 1),
            },
            "request_kb": {
                "p50": pct(st["kb"], 0.5),
                "p90": pct(st["kb"], 0.9),
                "max": max(st["kb"]) if st["kb"] else 0,
                "total_mb": round(sum(st["kb"]) / 1024.0, 1),
            },
            "messages_per_request": {
                "p50": pct(st["msgs"], 0.5),
                "p90": pct(st["msgs"], 0.9),
                "max": max(st["msgs"]) if st["msgs"] else 0,
            },
            "by_model": {k: dict(v) for k, v in st["by_model"].items()},
            "by_account": {k: dict(v) for k, v in st["by_account"].items()},
            "stop_reasons": dict(st["stops"]),
            "tool_calls_per_turn": {
                "p50": pct(st["calls"], 0.5),
                "max": max(st["calls"]) if st["calls"] else 0,
                "histogram": dict(st["calls_hist"]),
            },
        },
        "rate_limits": {
            "total": st["rl_total"],
            "by_quota": dict(st["by_quota"]),
            "wait_seconds": {
                "p50": pct(st["waits"], 0.5),
                "p90": pct(st["waits"], 0.9),
                "max": max(st["waits"]) if st["waits"] else 0,
                "announced_total": sum(st["waits"]),
            },
            "switches": st["switches"],
            "holds": st["holds"],
            "held_seconds_total": st["held_seconds"],
            "budget_exhausted": st["budget"],
            "bursts": {
                "count": len(bursts),
                "longest": max(bursts) if bursts else 0,
                "median_length": statistics.median(bursts) if bursts else 0,
            },
        },
        "compaction": {
            "count": st["comp_count"],
            "summary_failures": st["comp_fail"],
            "before_tokens": {
                "p50": pct(st["before"], 0.5),
                "p90": pct(st["before"], 0.9),
                "max": max(st["before"]) if st["before"] else 0,
            },
            "after_tokens": {
                "p50": pct(st["after"], 0.5),
                "p90": pct(st["after"], 0.9),
                "max": max(st["after"]) if st["after"] else 0,
            },
        },
        "relay": {k: dict(v) for k, v in st["relay"].items()},
        "incidents": {
            "connection_reset": st["conn_reset"],
            "chunked_encoding": st["chunked"],
            "network_retries": st["net_retries"],
            "stream_truncated": st["truncated"],
            "client_disconnected": st["client_disc"],
            "unparseable_tool_args": {
                "total": st["unparseable"],
                "by_tool": dict(st["unparseable_by_tool"]),
            },
            "big_tool_turns": st["big_tool_turns"],
        },
        "fun": {
            "busiest_single_turn": {
                "latency": round(busiest[1], 1) if busiest else 0,
                "input": busiest[2] if busiest else 0,
                "output": busiest[3] if busiest else 0,
            },
            "biggest_request_kb": max(st["kb"]) if st["kb"] else 0,
            "cache_hit_ratio": (round(st["cr"] / (st["cr"] + st["in"]), 4)
                                if st["cr"] + st["in"] else 0.0),
            "total_wall_hours_in_upstream_calls": round(hours, 2),
            "tokens_per_hour_of_calls": int(total_tokens / hours) if hours else 0,
        },
    }
    print(json.dumps(out, indent=2))


if __name__ == "__main__":
    main()
