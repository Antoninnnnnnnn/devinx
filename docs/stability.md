# Stability changes and validation

This is a targeted reliability update, not a new agent harness. Models, role
prompts, opt-in orchestration and client permission decisions remain unchanged.
No production account or live inference call is required by the test suite.

## Local diagnostics

```sh
devinx --status
devinx --doctor --json
devinx --explain --cx --or
```

These flags are recognised in the first launcher argument, and also after
devinx's own flags (`devinx --d --status`) as long as they come before `--`
and before any client subcommand or prompt — an ambiguous position (anything
that is not one of devinx's own flags precedes it) is left to the client
instead. A plain `devinx`, client subcommands and arguments after `--` keep
their existing meaning. Diagnostics never start a service, read credentials or
make an inference call. `--status` and `--doctor` query the local `/api/hello`
endpoint and return 0 for a running devinx service, 1 otherwise. `--doctor`
adds dependency/client presence and descriptor counts; this is a local check,
**not** proof that an upstream account is working. `--explain` shows the
selected client and injected agents, not the user's prompt, and returns 0 once
it has answered that question — whether or not a service happens to be
running is not a failure of the explanation. `--json` is useful for support
reports.

The service reports an explicit allowlist of numeric/boolean runtime settings.
Diagnostics compare explicitly requested environment settings with the daemon's
actual values. Changing a variable in a new terminal does not reconfigure an
already-running process. Runtime fingerprints now include shared runtime code,
descriptors and dashboard assets, not just `devinx.py`.

The dashboard adds a live request table (phase and age). It is independent of
the historical time-range filter. These are **request** identities, not agent
identities. No prompt or tool payload is collected for this table. Existing
charts and the separate dashboard listener remain in place. The compaction
shape log no longer prints snippets of conversation content. Other diagnostic
logs are not certified secret-free: do not share raw logs or `DEVINX_DUMP`
output as a substitute for the allowlisted diagnostics.

## Errors, streaming and lifecycle

- Both streaming emitters accept the same typed error call. Early Codex-route
  failures return an HTTP error rather than silently dropping the connection.
  A token-limited Responses output is incomplete, never `response.completed`.
- A committed stream error is logged as `stream_error`, not as a successful 200.
- `Retry-After` uses the provider's seconds/minutes/hours correctly.
- Anthropic keepalive starts before compaction and is released on every exit.
  A heartbeat-only response can be reused before content; a response with
  emitted content is not replayed. Responses still has no invented ping event.
- The HTTP adapter no longer automatically retries POST read errors. Connection
  establishment retries and the bounded application-level retry policy remain.
  This is **not an exactly-once inference guarantee**: a network failure after
  sending a request can still leave its upstream outcome unknown.
- SIGTERM/SIGINT initiate one non-daemon drain coordinator; the signal handler
  returns so `serve_forever` can stop. Both listeners close before waiting for
  accepted POST work. Repeated signals do not cut short that work. The configured
  drain deadline can still terminate long-running requests when it expires.
- Concurrent launchers with the same data directory and port use an OS file
  lock. A foreign service is never started over or killed. An older busy devinx
  is still left running, with the existing warning. This is not automatic
  blue/green deployment or cross-user process isolation.

## Resource controls

Settings are read when the **service starts**:

| Variable | Default | Meaning |
|---|---:|---|
| `DEVINX_MAX_INFLIGHT` | 64 | Maximum accepted active POST handlers; 0 disables the cap. Excess receives 503 with Retry-After. |
| `DEVINX_HTTP_READ_TIMEOUT` | 30 | Socket inactivity limit in seconds while receiving HTTP headers/body. |
| `DEVINX_CLIENT_WRITE_TIMEOUT` | 120 | Socket inactivity limit in seconds while writing to the client. |
| `DEVINX_MAX_FRAME` | 16777216 | Maximum encoded upstream Connect frame bytes. |
| `DEVINX_MAX_INFLATED_FRAME` | 67108864 | Maximum decoded frame bytes, including concatenated gzip streams. |
| `DEVINX_RELAY_READ_TIMEOUT` | 0 | Relay read inactivity limit in seconds; 0 keeps the previous unlimited read wait. |
| `DEVINX_COMPACT_STRICT` | 0 | Set to 1 for the strict compaction policy below. |

Other existing settings, including the 128 MiB request body limit and drain
budget, keep their defaults. Body framing now requires exactly one non-negative
Content-Length and rejects Transfer-Encoding instead of attempting ambiguous
reads. HTTP socket limits are inactivity limits, **not an end-to-end deadline**.
The POST cap does not bound all accepted TCP connections or dashboard GET work.
Use finite positive values for byte and socket limits.

## Compaction integrity

Summaries are generated under a per-conversation lock, not a global inference
lock. Covered content is fingerprinted. Rewriting a previously covered turn,
even at the same length, invalidates the old summary. Legacy flattened histories
are handled as an ordered subsequence, so inserted calls/results are not lost or
recounted using a stale block offset. Cache eviction removes one old entry rather
than wiping every conversation's summary. Summaries still live in process memory.

By default the prior last-resort behaviour remains: if no summary is available,
the proxy may discard middle turns with an explicit notice to the model.
`DEVINX_COMPACT_STRICT=1` changes this **opt-in** policy: intermediate user/system
text blocks are retained verbatim in chronological order alongside the summary;
missing summaries, unexpected compaction failures and context that still exceeds
the compaction budget produce an explicit unavailable error instead of silently
falling back. Before streaming this is HTTP 503; after streaming starts it is a
typed SSE error. The original client transcript is not rewritten.

Strict mode can therefore stop a turn that the default mode would continue.
It does not make model summaries lossless, reconstruct unsupported input types,
or prove that the model obeys every retained instruction. Validate it on the
workloads where that trade-off is desirable before making it your default.

## Validation and deliberately separate work

```sh
python -m pip install -r requirements-test.txt
python -m unittest discover -s tests -v
node tests/check_dashboard.js
```

The original baseline had 55 tests; two failed without real Devin credentials
because their fixtures did not mock account lookup. Those fixtures now use fake
accounts with their original assertions intact. The legacy flattened-history
fixture uses an explicitly smaller budget to exercise summary extension after
removing duplicated uncovered results. New tests exercise the real emitters,
local HTTP sockets, fake upstream frames, concurrency and a real POSIX signal
shutdown. No test installs/executes a live coding client or authenticates an
upstream account.

The CI runs the complete Python suite on Linux (3.10, 3.12, 3.13) and macOS
(3.12). Windows runs the new runtime/stability suites, with the POSIX signal
test explicitly skipped; the pre-existing POSIX-path fixtures are not claimed
as Windows coverage. A separate Node check validates script syntax and safe
live-table rendering; it is not a full browser visual test.

A full request deadline/cancellation propagation system, persistent incremental
telemetry, work profiles, agent-identity integration, sandboxed ownership and a
large protocol/module rewrite are intentionally **not** bundled into this update.
They need separate acceptance tests and, for client integration, real client
compatibility validation. No real-provider end-to-end or production-load test is
implied by the offline CI.
