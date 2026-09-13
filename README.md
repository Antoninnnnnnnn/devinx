# devinx

Claude Code stays logged in with your own claude.ai subscription, while its
subagents run natively on SWE-2 Medium, High or Max.

One local service, one port, no external binary.

```
devinx --devin
 └─ Claude Code (claude.ai login, no ANTHROPIC_API_KEY)
      └─ devinx.py on 127.0.0.1:8316
           ├─ model=claude-*  ->  api.anthropic.com      transparent relay
           └─ model=swe-2-*   ->  server.codeium.com     SWE-2
```

The subagents are real Claude Code subagents: same tools, same harness, same
transcripts. Nothing spawns a second `claude` process.

## Read this first

This talks to Cognition's private API, not a public one, and it gets there by
looking like something it is not:

- it identifies itself as the Windsurf IDE (`IDE_NAME`, `IDE_VERSION`,
  `EXT_VERSION` and a matching user-agent in `devinx.py`);
- `_SYS_REWRITES` in `devinx.py` rewrites parts of Claude Code's system prompt
  for the specific purpose of getting past Cognition's input classifier, which
  otherwise rejects them. That is circumvention of a check the provider put
  there, not a compatibility shim;
- `descriptors/*.fdp` are protobuf definitions of that private API, extracted
  from a published npm package.

It runs on **your own** Devin/Windsurf subscription and spends your own quota.
Using it plausibly breaches Cognition's terms of service. That is your call and
your risk, not the authors'.

Not affiliated with, endorsed by, or supported by Anthropic or Cognition.

## Install

Requires Python 3.10+, the [Claude Code CLI](https://claude.com/claude-code) on
PATH, and a Devin CLI login for the SWE-2 side.

```sh
python3 install.py
```

It creates a virtualenv, installs two dependencies, drops a `devinx` launcher in
`~/.local/bin`, and runs a smoke test that ends with a real SWE-2 call.

The subagent definitions are **not** installed into `~/.claude/agents`: the
launcher injects them per session with `--agents`, so a plain session shows no
`swe2-*` agent at all. Installing them globally would list agents that fail when
invoked outside devin mode, since nothing routes swe-2 models there. Pass
`--global-agents` for the old behaviour.

If you have not logged into Devin on this machine yet, the installer prints the
exact command — the login is interactive and cannot be automated:

```sh
XDG_DATA_HOME="<data dir printed by the installer>" devin auth login
```

Useful flags: `--force` (overwrite an existing launcher and virtualenv),
`--port N`, `--bin DIR`, `--no-smoke`, `--global-agents`.

## Use

The SWE-2 layer is opt-in. Without the flag, `devinx` is a plain passthrough to
Claude Code: nothing is started, nothing is injected, no proxy.

```sh
devinx                      # plain Claude Code, exactly as `claude`
devinx --devin              # with the SWE-2 layer  (--d is a shorthand)
devinx --d --resume         # composes with any claude flag
devinx --resume x -p "..."  # flags and prompts pass through untouched
```

**devinx never adds `--dangerously-skip-permissions`.** Choosing a model and
choosing to run tools unattended are separate decisions; pass the flag yourself
if you want it. The launcher is deliberately not called `cc`: on Unix that is
the C compiler, which `make`, autoconf and cgo invoke by name.

Already have your own `cc` wrapper? Add a branch to it rather than using
`devinx`, and keep whatever flags you already pass:

```sh
--devin|--d) exec ~/devinx/.venv/bin/python ~/devinx/launcher.py --devin "$@" ;;
```

Everything after a bare `--` is passed through verbatim, so a prompt containing
`--devin` is never mistaken for the flag. `-d` is left alone — it is Claude
Code's own `--debug`. Set `DEVINX_ALWAYS=1` to make the layer the default.

In devin mode the service starts on demand the first time and stays up
afterwards.

### Choosing a tier for the main session

`/model` offers a single `swe-2` entry. It has no tier of its own: the effort
slider beside it picks one, which is what makes that slider meaningful.

| effort | tier |
|---|---|
| low, medium | `swe-2-medium` |
| high *(default)* | `swe-2-high` |
| xhigh, max | `swe-2-max` |

The three tiers are also selectable by name (`--model swe-2-high`). Asked for
explicitly they are never retiered by effort — otherwise a subagent pinned to a
tier would follow whatever its parent session was set to. The response reports
the tier that actually ran, not the alias.

### Choosing a tier for a subagent

Delegate as usual and pick the agent:

| agent | for |
|---|---|
| `swe2-medium` | quick searches, small mechanical edits, routine work |
| `swe2-high` | normal implementation, debugging, testing, review |
| `swe2-max` | hardest architecture and debugging, quality over latency |

Subagents are given `disallowedTools: ["mcp__*"]`. MCP tool schemas are re-sent
in full on every request and there are usually many of them: measured here, a
subagent turn drops from ~240KB to ~49KB and a cold first turn from ~58s to a
few seconds. It is a glob rather than an allow-list on purpose — every built-in
tool stays available, including ones a future Claude Code release adds, so the
agents keep inheriting the native tool set.

Only the subagents are affected; your main session keeps its connectors. Set
`DEVINX_SUBAGENT_MCP=1` to give them back, or pass `--strict-mcp-config` to drop
MCP for the whole session instead.

## How it works

`devinx.py` speaks the Anthropic Messages API and routes on the model name.

`claude-*` is relayed to `api.anthropic.com` untouched. The service holds no
Anthropic credential of its own and forwards yours; with no credential in the
request it answers 401 rather than inventing one.

`swe-2-*` is translated to Cognition's Connect-RPC `GetChatMessage`. On this
branch no client header is forwarded at all: the Cognition request is built
from scratch with its own header set, so the claude.ai token cannot reach it.

Speaking Anthropic on both sides rather than translating through OpenAI in the
middle is what keeps usage accounting exact (input, cache read and cache write
map 1:1) and lets reasoning survive across turns: Claude Code keeps the thinking
blocks it receives and replays them, and nothing has to be stored server-side.

Each subagent gets its own conversation key, derived from the session id plus its
system prompt and first task. Sharing the parent's key collapses them into a
single upstream cascade and costs the prefix cache on every continuation turn.

The SWE-2 route refuses requests that carry an `Origin` header, or a `Host` that
is not loopback. It spends your quota with a credential the service holds, so it
cannot make the caller prove anything — and a page you merely visit could
otherwise POST to it, since a JSON body sent as `text/plain` needs no CORS
preflight and the attacker never has to read the reply. Browsers send `Origin`
on such a request and API clients do not. Set `DEVINX_ALLOW_BROWSER=1` if you
are deliberately driving it from a local web UI. This is not isolation between
users of the machine: anything running as you can still reach the port.

## Troubleshooting

Logs are in `devinx.log`, in the data directory printed by the installer
(`%LOCALAPPDATA%\devinx`, `~/Library/Application Support/devinx`, or
`$XDG_DATA_HOME/devinx`). Each request logs a line: `route=swe model=…` or
`route=claude model=… status=…`.

**SWE-2 calls fail, Claude still works.** Expected when the Devin credential is
missing or expired — the service starts anyway so the main session is unaffected.
Log in again with the command above; the running service drops its cached
credential when the upstream rejects it, so it picks the new one up without a
restart.

**The launcher reports the service failed to start.** Read `devinx.log`. A port conflict
on 8316 is the usual cause; `--port` at install time changes it.

**Everything is broken.** `claude` on its own does not go through devinx at all
and is always available as a fallback.

## Refreshing the protobuf descriptors

`descriptors/*.fdp` are Cognition's message definitions, shipped with the
package. They only need refreshing if the upstream wire format changes:

```sh
python3 extract_fdps.py descriptors
```

It resolves the `latest` published catalog, so it can pull a version newer than
the one this release was tested against.
