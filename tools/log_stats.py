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
  - "refusals" here are quota rejections and nothing else: the model never
    refused anything on content. A credential pointed at a spent quota looks
    alarming in this column and means only that it was spent.
  - a rate-limit refusal is a resource_exhausted trailer error or an
    upstream HTTP 429; relay route=... status=429 lines are the client
    side of the same event and stay under "relay".
  - a burst is a run of refusals with no "upstream done" between them.
  - turns_failed counts upstream attempts that ended in error: trailer
    errors that are not rate limits, non-429 HTTP statuses, dropped
    streams and connection exceptions. Retried and rate-limited attempts
    are tracked in their own sections instead.
"""

import argparse
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

# Lines written since 2026-09-17 carry an ISO timestamp; older ones do not, and
# both have to parse or the history disappears the day the format changed.
# Non-capturing on purpose: it prefixes patterns whose groups are read by
# position, and a capture here would shift every one of them by a slot.
STAMP = r"^(?:\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d )?"
RE_STAMP = re.compile(r"^(\d{4}-\d\d-\d\dT\d\d:\d\d:\d\d) ")
STAMP_LEN = len("2026-09-17T22:00:00 ")

RE_CONN = re.compile(
    STAMP + r"upstream conn: [\d.]+s to headers "
    r"\((?:acct=(\S+) )?(?:model=(\S+) )?(\d+) msgs, (\d+)KB req\)")
RE_DONE = re.compile(
    STAMP + r"upstream done: (?:stop=([a-z_]+)/\d+ calls=(\d+) )?"
    r"latency=([\d.]+)s usage in=(\d+) out=(\d+) cr=(\d+) cw=(\d+)")
RE_TRAILER = re.compile(
    STAMP + r"upstream trailer error(?: on (\S+))?: (\w+)(?:: ?(.*))?$")
RE_HTTP = re.compile(STAMP + r"upstream HTTP (\d+) on (\S+):")
RE_HOLD = re.compile(r"holding the turn for (\d+)s")
RE_QUOTA = re.compile(r"Reached (.+?) rate limit")
RE_RESET = re.compile(r"reset in (\d+) (minute|second)s?\b")
RE_COMPACT = re.compile(STAMP + r"compaction: (\d+) -> (\d+) tokens")
RE_DROPPED = re.compile(r"dropping (\d+) blocks unsummarised")
RE_BIGTOOL = re.compile(STAMP + r"WARNING: (\d+) tool calls in one turn: (.*)$")
RE_TOOLNAME = re.compile(r"'([^']+)': (\d+)")
RE_UNPARSEABLE = re.compile(STAMP + r"tool call (\S+) has unparseable arguments")
RE_ROUTE = re.compile(STAMP + r"route=(\S+) model=\S+ status=(\S+)")
RE_BUILD = re.compile(r"\(build ([0-9a-f]+),")
RE_UPSTREAM_ERR = re.compile(STAMP + r"upstream ([A-Z]\w+):")


def pct(values, p):
    """Percentile by sort-and-index: sorted[int(len*p)], clamped.

    Returns 0 on an empty list, as the frontend contract requires.
    """
    if not values:
        return 0
    s = sorted(values)
    return s[min(int(len(s) * p), len(s) - 1)]


def in_window(at, since, until):
    """Is this line inside the requested window.

    Only dated lines can answer. The log learned to write the time on
    2026-09-17, so everything before that is undated and no bounded window can
    honestly claim to contain or exclude it — asked for one, this drops it and
    the payload says how many it dropped, rather than quietly counting twenty
    days of history as if it had happened inside the last hour.
    """
    if since is None and until is None:
        return True
    if at is None:
        return False
    if since is not None and at < since:
        return False
    if until is not None and at > until:
        return False
    return True


def collect(path, since=None, until=None):
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
        "comp_nosummary": 0, "comp_blocks_lost": 0, "comp_stale": 0,
        "comp_uncovered": 0,
        "relay": defaultdict(Counter),
        "fail_codes": Counter(),
        "done_spans": [],
        "conn_reset": 0, "chunked": 0, "net_retries": 0,
        "truncated": 0, "client_disc": 0,
        "unparseable": 0, "unparseable_by_tool": Counter(),
        "big_tool_turns": [],
        "busiest": None,  # (input + output, latency, input, output)
        # Per-minute buckets, for the only question a request-metered quota
        # really asks: how close to the ceiling is this fleet running. Only
        # timestamped lines land here, so the series starts the day the log
        # learned to write the time.
        "per_min_req": Counter(), "per_min_ref": Counter(),
        "retention_day": defaultdict(list),
        "first_stamp": None, "last_stamp": None,
        "undated_skipped": 0,
    }
    seen_builds = set()
    last_acct = None
    last_model = None

    def stamp_of(line):
        m = RE_STAMP.match(line)
        return m.group(1) if m else None

    def refusal(acct, msg, minute=None):
        if minute:
            st["per_min_ref"][minute] += 1
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
        for raw in fh:
            st["lines"] += 1
            # The timestamp comes off here, once, rather than being tolerated
            # by every pattern and every startswith below it.
            at = stamp_of(raw)
            if not in_window(at, since, until):
                if at is None:
                    st["undated_skipped"] += 1
                continue
            if at:
                # Recorded after the window test, so the reported coverage is
                # the coverage of what was counted and not of the whole file.
                if st["first_stamp"] is None:
                    st["first_stamp"] = at
                st["last_stamp"] = at
            line = raw[STAMP_LEN:] if at else raw
            minute = at[:16] if at else None
            try:
                if line.startswith("upstream conn:"):
                    if minute:
                        st["per_min_req"][minute] += 1
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
                        if at:
                            # [fin - latence, fin] : le seul intervalle que le
                            # journal donne vraiment. Compter les conn sans les
                            # done fuit — une conn abandonnée ne se ferme jamais.
                            end = datetime.fromisoformat(at).timestamp()
                            st["done_spans"].append((end - lat, end))
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
                            refusal(m.group(1), m.group(3), minute)
                        else:
                            st["turns_failed"] += 1
                            # "prompt is too long" is a compaction defect and
                            # "unimplemented" is an upstream one; both were
                            # landing in the same anonymous total.
                            detail = (m.group(3) or "").strip()
                            code = m.group(2)
                            if "too long" in detail.lower():
                                code += ": prompt trop long"
                            elif detail:
                                code += ": " + detail.split("(trace")[0].strip()[:60]
                            st["fail_codes"][code] += 1
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
                            refusal(m.group(2), line, minute)
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
                        before, after = int(m.group(1)), int(m.group(2))
                        st["before"].append(before)
                        st["after"].append(after)
                        if at and before:
                            st["retention_day"][at[:10]].append(100.0 * after / before)
                    elif "no summary available" in line:
                        # Le pire résultat : l'agent perd le milieu de son run.
                        st["comp_nosummary"] += 1
                        m2 = RE_DROPPED.search(line)
                        if m2:
                            st["comp_blocks_lost"] += int(m2.group(1))
                    elif "could not be extended" in line:
                        st["comp_stale"] += 1
                    elif "uncovered turns to fit" in line:
                        st["comp_uncovered"] += 1
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


def _concurrency(spans):
    """How many upstream calls were open at once, by sweep over their intervals.

    This is the figure that answers "how many agents can I run": the header's
    in-flight count is a single instant, and the request rate says nothing
    about how many conversations produced it.
    """
    if not spans:
        return {"peak": 0, "p50": 0, "p90": 0, "peak_at": None}
    events = []
    for a, b in spans:
        events.append((a, 1))
        events.append((b, -1))
    events.sort()
    cur = best = 0
    best_at = None
    samples = []
    for t, delta in events:
        cur += delta
        samples.append(cur)
        if cur > best:
            best, best_at = cur, t
    samples.sort()
    return {
        "peak": best,
        "peak_at": (datetime.fromtimestamp(best_at).isoformat(timespec="seconds")
                    if best_at else None),
        "p50": samples[len(samples) // 2],
        "p90": samples[min(int(len(samples) * 0.9), len(samples) - 1)],
    }


def _throughput(st, swe_total=0):
    """What a request-metered quota actually asks: how close to the ceiling.

    Only timestamped lines carry this, so the series begins the day the log
    learned to write the time. Everything here is per wall-clock minute, which
    is the unit the upstream's own limit is expressed in.
    """
    req, ref = st["per_min_req"], st["per_min_ref"]
    minutes = sorted(req)
    counts = [req[m] for m in minutes]
    recent = minutes[-60:]
    rec_req = sum(req[m] for m in recent)
    rec_ref = sum(ref.get(m, 0) for m in recent)
    served = [req[m] - ref.get(m, 0) for m in minutes]
    relayed = sum(st["relay"][r].total() if hasattr(st["relay"][r], "total")
                  else sum(st["relay"][r].values()) for r in st["relay"])
    return {
        "minutes_measured": len(minutes),
        # Which meter the fleet is actually spending. The relayed routes run on
        # the root model's own subscription; only the SWE ones touch the quota
        # that runs out.
        "on_metered_quota": swe_total,
        "relayed": relayed,
        "metered_share": (round(swe_total / (swe_total + relayed), 3)
                          if swe_total + relayed else 0),
        "concurrency": _concurrency(st["done_spans"]),
        "first": st["first_stamp"],
        "last": st["last_stamp"],
        "req_per_min": {
            "p50": pct(counts, 0.5), "p90": pct(counts, 0.9),
            "max": max(counts, default=0),
        },
        # The best minute that was not mostly refusals is the closest thing to
        # an observed ceiling: the upstream never says what the limit is.
        "served_per_min_max": max(served, default=0),
        "recent_60min": {
            "requests": rec_req, "refusals": rec_ref,
            "refusal_share": round(rec_ref / rec_req, 3) if rec_req else 0,
            "req_per_min": round(rec_req / len(recent), 1) if recent else 0,
        },
        "series": [{"at": m, "req": req[m], "ref": ref.get(m, 0)}
                   for m in minutes[-120:]],
    }


def _retention_days(st):
    out = []
    for day in sorted(st["retention_day"]):
        vals = st["retention_day"][day]
        out.append({"day": day, "n": len(vals),
                    "p50": round(pct(vals, 0.5), 1),
                    "p90": round(pct(vals, 0.9), 1)})
    return out


ISO = re.compile(r"^\d{4}-\d\d-\d\dT\d\d:\d\d(:\d\d)?$")


def bound(value, name):
    """A window bound, or a refusal. Compared as a string against the log's own
    ISO stamps, so it has to be shaped exactly like one."""
    if value in (None, "", "all"):
        return None
    value = value.strip()
    if not ISO.match(value):
        raise SystemExit(f"{name}: expected YYYY-MM-DDTHH:MM[:SS], got {value!r}")
    return value if len(value) > 16 else value + ":00"


def main():
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--since", help="ISO instant; only dated lines at or after it")
    ap.add_argument("--until", help="ISO instant; only dated lines at or before it")
    args = ap.parse_args()
    since = bound(args.since, "--since")
    until = bound(args.until, "--until")
    st = collect(LOG_PATH, since, until)

    lat = st["lat"]
    lat_total = sum(lat)
    total_tokens = st["in"] + st["out"] + st["cr"] + st["cw"]
    hours = lat_total / 3600.0
    busiest = st["busiest"]
    bursts = st["bursts"]

    out = {
        "generated_at": datetime.now().astimezone().isoformat(timespec="seconds"),
        "window": {
            "since": since,
            "until": until,
            # What was actually counted, which is not what was asked for: a
            # bounded window can only contain dated lines, and the log has
            # twenty days of undated history behind it.
            "dated_from": st["first_stamp"],
            "dated_to": st["last_stamp"],
            "undated_skipped": st["undated_skipped"],
            "bounded": bool(since or until),
        },
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
        "throughput": _throughput(st, st["turns_ok"] + st["turns_failed"]
                                   + st["rl_total"]),
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
            "retention_by_day": _retention_days(st),
            "count": st["comp_count"],
            "summary_failures": st["comp_fail"],
            # Trois issues distinctes, pas une. La première est une perte de
            # contexte pour l'agent, les deux autres une dégradation.
            "no_summary": st["comp_nosummary"],
            "blocks_lost": st["comp_blocks_lost"],
            "stale_summary": st["comp_stale"],
            "uncovered_dropped": st["comp_uncovered"],
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
            "failure_codes": dict(st["fail_codes"].most_common(8)),
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
