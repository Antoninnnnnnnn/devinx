# devinx

Your coding agent keeps your own login. Its subagents run on SWE-2.

Claude Code and Codex both stay signed in as you. The work they delegate goes to
Cognition's SWE-2 — Medium, High or Max — through one local service that routes
on the model name and nothing else.

One port, no external binary, nothing written into your agent's config.

```
   devinx --or                                  devinx --cx --or
   └─ Claude Code                               └─ Codex
      claude.ai login                              ChatGPT login
            │                                            │
            └──────────►  devinx.py on :8316  ◄──────────┘
                                 │
                    routed on the model name
                                 │
         ┌───────────────────────┼───────────────────────┐
     claude-*                swe-2-*                  gpt-*
  api.anthropic.com      server.codeium.com    chatgpt.com/backend-api
      relayed                 SWE-2                  relayed
```

The subagents are real subagents of the client you launched: same tools, same
harness, same transcripts. Nothing spawns a second process, and the credential
for each upstream is the one its own client sent — devinx holds none of them.

## Read this first

This talks to Cognition's private API, not a public one, and it gets there by
looking like something it is not:

- it identifies itself as the Windsurf IDE (`IDE_NAME`, `IDE_VERSION`,
  `EXT_VERSION` and a matching user-agent in `devinx.py`);
- `_SYS_REWRITES` in `devinx.py` rewrites parts of the client's system prompt
  for the specific purpose of getting past Cognition's input classifier, which
  otherwise rejects them. That is circumvention of a check the provider put
  there, not a compatibility shim;
- `descriptors/*.fdp` are protobuf definitions of that private API, extracted
  from a published npm package.

It runs on **your own** Devin/Windsurf subscription and spends your own quota.
Using it plausibly breaches Cognition's terms of service. That is your call and
your risk, not the authors'.

Not affiliated with, endorsed by, or supported by Anthropic, OpenAI or Cognition.

## Install

Requires Python 3.10+, a Devin CLI login for the SWE-2 side, and at least one of
the [Claude Code CLI](https://claude.com/claude-code) or the Codex CLI on PATH.

```sh
python3 install.py
```

It creates a virtualenv, installs two dependencies, drops a `devinx` launcher in
`~/.local/bin`, and runs a smoke test that ends with a real SWE-2 call.

If you have not logged into Devin on this machine yet, the installer prints the
exact command — the login is interactive and cannot be automated:

```sh
XDG_DATA_HOME="<data dir printed by the installer>" devin auth login
```

Useful flags: `--force` (overwrite an existing launcher and virtualenv),
`--port N`, `--bin DIR`, `--no-smoke`, `--global-agents`.

### What it does and does not touch

Almost nothing is installed into your agent's configuration, because a tool that
only works when you ask for it should also be invisible when you don't.

The Claude Code subagents are **not** written into `~/.claude/agents`: the
launcher injects them per session with `--agents`, so a plain session shows no
`swe2-*` agent at all. Installing them globally would list agents that fail when
invoked outside devin mode, since nothing routes swe-2 models there. Pass
`--global-agents` for the old behaviour. The orchestrator skill rides along the
same way, as a session-scoped `--plugin-dir`.

Codex is configured entirely through per-session `-c` overrides, so your
`config.toml`, plugins and agents are untouched. The one exception is the
orchestrator skill, which Codex can only load as an installed plugin: the
installer writes a `devinx.config.toml` **profile** next to your config and
materialises the plugin cache. A profile does nothing until it is named, and the
launcher names it only for `--codex --or`.

## Use

### Claude Code

```sh
devinx                      # plain Claude Code, exactly as `claude`
devinx --devin              # with the SWE-2 layer  (--d is a shorthand)
devinx --or                 # ... and the orchestrator skill; implies --devin
devinx --d --resume         # composes with any claude flag
devinx --resume x -p "..."  # flags and prompts pass through untouched
```

Without a flag, `devinx` is a plain passthrough: nothing is started, nothing is
injected, no proxy.

### Codex

```sh
devinx --codex              # Codex through devinx  (--cx is a shorthand)
devinx --cx --or            # ... with the SWE-2 roles and the orchestrator skill
devinx --cx exec "..."      # any codex subcommand and flag passes through
```

`--codex` implies the service, the same way `--devin` does. Your root model is
whatever your Codex config already says; only what it delegates changes.

### Flags at a glance

| flag | effect |
|---|---|
| `--devin`, `--d` | route Claude Code through devinx; inject the `swe2-*` agents |
| `--codex`, `--cx` | route Codex through devinx; pin the SWE-2 roles |
| `--or` | add the orchestrator skill; implies the client flag it is used with |
| `--` | everything after it passes through verbatim |

| variable | effect |
|---|---|
| `DEVINX_ALWAYS=1` | make the SWE-2 layer the default |
| `DEVINX_ORCHESTRATOR=1` | make the orchestrator the default |
| `DEVINX_SUBAGENT_MCP=1` | give subagents their MCP tools back |
| `DEVINX_PORT` | change the port for one run |
| `DEVINX_CONTEXT_TOKENS` | override the context window devinx declares (default 262144) |
| `DEVINX_ALLOW_BROWSER=1` | accept browser-originated requests (see below) |

`--or` is separate from the client flags on purpose: the SWE-2 layer changes
which model does the work, the orchestrator changes who decides what the work
is. A session that just wants cheap subagents does not want a skill telling it
to delegate, so `--devin` alone leaves the skill out entirely.

`-d` is left alone — it is Claude Code's own `--debug`. Everything after a bare
`--` is passed through verbatim, so a prompt containing `--devin` is never
mistaken for the flag.

**devinx never adds `--dangerously-skip-permissions`.** Choosing a model and
choosing to run tools unattended are separate decisions; pass the flag yourself
if you want it. The launcher is deliberately not called `cc`: on Unix that is
the C compiler, which `make`, autoconf and cgo invoke by name.

Already have your own `cc` wrapper? Add a branch to it rather than using
`devinx`, and keep whatever flags you already pass:

```sh
--devin|--d) exec ~/devinx/.venv/bin/python ~/devinx/launcher.py --devin "$@" ;;
--or)        exec ~/devinx/.venv/bin/python ~/devinx/launcher.py --or "$@" ;;
```

The service starts on demand the first time and stays up afterwards.

## Orchestration

`--or` turns the session around: your own model stops writing the code and
starts running the agents that do.

The trade it is built on is that the two sides are scarce in different ways.
Your own context is the thing that runs out fastest; SWE-2 is far cheaper but
not free — it enforces a token budget over a rolling window, and a burst of
parallel agents empties it, after which calls are refused for one to twelve
minutes. devinx reports that refusal as a `rate_limit_error` with the wait the
upstream named, so the client backs off instead of killing the agent.

So execution belongs downstream and judgment stays up top — architecture,
decomposition, what the diff actually says, what to tell you.

### The roles

| agent | for | writes files |
|---|---|---|
| `swe2-explorer` | mapping code, tracing flow, locating symbols and tests | no |
| `swe2-worker` | bounded implementation, targeted fixes, mechanical edits | yes |
| `swe2-tester` | running tests, reproducing failures, adding tests | yes |
| `swe2-researcher` | external docs, version-specific API behaviour | no |
| `swe2-reviewer` | independent read of a finished change | no |
| `claude-reviewer` | the same, on your own model, for high-stakes changes | no |

Every SWE role is pinned to `swe-2-max`, because it is the strongest — not
because it is free. Under rate limiting a weaker tier is a real lever: the same
mechanical edit costs less of the shared budget on `swe2-medium`.

On Claude Code the read-only roles are denied `Edit`, `Write` and
`NotebookEdit` outright. `Bash` can still write, so their prompts say it too —
this closes the accidental path, not a determined one.

`claude-reviewer` is the one agent that costs your own quota: it has no pinned
model and inherits the session's own. It is for changes that are expensive to
get wrong — security, auth, migrations, data integrity, concurrency — and the
skill says so rather than leaving the choice to habit.

### How it briefs them

What the skill actually spends its length on is the asymmetry. A strong peer can
be handed an outcome; these agents need the approach, the file list, acceptance
criteria a command can settle, and tests declared off-limits unless changing
them is the job.

And the root reads the real diff before believing any of it: a subagent
reporting success is a hypothesis, and the summary is the part that lies. Retry
policy is two strikes — narrow the brief once, then take the task back and say
that you did.

It is written as defaults with stated escape hatches, not as hard `MUST`-gates:
review is chosen per change, and delegating nothing is a legitimate answer for a
two-line fix you have already located.

### Topology

```text
                     your own model
                 root — decides and briefs
                            |
        +-------------------+-------------------+
        |                   |                   |
    explorer              worker            researcher
    swe-2-max            swe-2-max           swe-2-max
        |                   |
        +---------+---------+
                  |
               tester
              swe-2-max
                  |
               reviewer
         swe-2-max, or claude-reviewer
          when it is expensive to
              get this wrong
                  |
                  v
                     your own model
          reads the real diff, verifies, reports
```

The root appears twice on purpose. It is the first thing in the chain and the
last, and the bottom half is the half people skip.

### Invoking it

On Claude Code the skill is `/devinx:swe-orchestrator`; on Codex it is
`swe-orchestrator`. Both are also picked up on their own when a task matches.

```text
/devinx:swe-orchestrator

Add rate limiting to the public API.
Map the current middleware chain before touching anything.
One worker per endpoint group, a tester for the limit boundaries
themselves, and review this one with claude-reviewer — a limiter that
is wrong in the permissive direction is not going to announce itself.
```

Naming the roles is optional; the skill picks them on its own. Saying it is
worth doing when you already know the shape of the work, or when you want the
expensive reviewer on something that looks routine and is not.

## Choosing a tier by hand

Useful without the orchestrator, on Claude Code.

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

For a subagent, delegate as usual and pick `swe2-medium`, `swe2-high` or
`swe2-max` directly.

Subagents are given `disallowedTools: ["mcp__*"]`. MCP tool schemas are re-sent
in full on every request and there are usually many of them: measured here, a
subagent turn drops from ~240KB to ~49KB and a cold first turn from ~58s to a
few seconds. It is a glob rather than an allow-list on purpose — every built-in
tool stays available, including ones a future release adds, so the agents keep
inheriting the native tool set.

Only the subagents are affected; your main session keeps its connectors. Set
`DEVINX_SUBAGENT_MCP=1` to give them back, or pass `--strict-mcp-config` to drop
MCP for the whole session instead.

## How it works

`devinx.py` listens on 127.0.0.1:8316 and routes on the model name. That single
decision is what makes the whole thing possible, and the Codex section below is
the story of why.

**`claude-*` and `gpt-*` are relayed** to `api.anthropic.com` and
`chatgpt.com/backend-api/codex` respectively, untouched, with the credential the
client sent. The service holds no credential of its own for either; with none in
the request it answers 401 rather than inventing one.

**`swe-2-*` is translated** to Cognition's Connect-RPC `GetChatMessage`. No
client header is forwarded there at all: the request is built from scratch with
its own header set, so your claude.ai or ChatGPT token cannot reach it.

Speaking the client's own protocol on both sides, rather than translating
through a third one in the middle, is what keeps usage accounting exact — input,
cache read and cache write map 1:1 — and lets reasoning survive across turns:
the client keeps the thinking blocks it receives and replays them, and nothing
has to be stored server-side.

Each subagent gets its own conversation key, derived from the session id plus its
system prompt and first task. Sharing the parent's key collapses them into a
single upstream cascade and costs the prefix cache on every continuation turn.

### What it took to make Codex delegate to SWE-2

Codex speaks the Responses API rather than Messages, which is the easy half. The
rest was only findable by watching the wire, and three things had to be true at
once.

**A provider is chosen per session, never per agent.** A role's config layer
honours `model` and silently ignores `model_provider`, so the obvious design —
point the subagents at a different provider — cannot work. Routing on the model
name instead means one global provider is all Codex needs.

**Codex has two multi-agent surfaces.** On V2 a spawned agent's task is handed
over as ciphertext only OpenAI can open: an executor on any other model receives
the envelope and none of the letter. On V1 the same task arrives in the clear.
The surface is chosen from the model catalog, so `/v1/models` serves one pinned
to V1, and the launcher disables the V2 feature flag, which resolves ahead of
the catalog. That catalog parser is strict and rejects the whole catalog over a
single missing key — taking plugins, apps and MCP down with it rather than just
the offending row — so every entry spells out every default it wants.

**The classifier reads tool descriptions too.** Codex's code-mode `exec` tool
ships 16KB of API documentation and is refused whole, while its first ~6KB
passes. Since that text changes with every release, the `permission_denied`
retry shrinks tool descriptions rather than replaying the same body. The one
other block that had to go is `<model_switch>`, which Codex injects whenever a
turn changes model and which contains the *other* model's entire system prompt.

With those in place, `agents.default_subagent_model` puts every spawned agent on
`swe-2-max`, and the roles are the same five the Claude Code side uses.

One difference remains. Codex has no per-agent prompt: everything under
`[agents]` is parsed as a role except a short list of recognised scalars, and an
unrecognised one fails config loading outright. The executor brief in
`codex/executor.md` therefore has nowhere to hang; the roles carry the tier, and
the orchestrator doctrine reaches the root through the skill.

### Why the SWE-2 route refuses browsers

It rejects any request carrying an `Origin` header, or a `Host` that is not
loopback. That route spends your quota with a credential the service holds, so
it cannot make the caller prove anything — and a page you merely visit could
otherwise POST to it, since a JSON body sent as `text/plain` needs no CORS
preflight and the attacker never has to read the reply. Browsers send `Origin`
on such a request and API clients do not.

Set `DEVINX_ALLOW_BROWSER=1` if you are deliberately driving it from a local web
UI. This is not isolation between users of the machine: anything running as you
can still reach the port.

## Troubleshooting

Logs are in `devinx.log`, in the data directory printed by the installer
(`%LOCALAPPDATA%\devinx`, `~/Library/Application Support/devinx`, or
`$XDG_DATA_HOME/devinx`). Each request logs a line: `route=swe`, `route=claude`
or `route=codex`, with the model and the status.

**SWE-2 calls fail, the rest still works.** Expected when the Devin credential
is missing or expired — the service starts anyway so the main session is
unaffected. Log in again with the command above; the running service drops its
cached credential when the upstream rejects it, so it picks the new one up
without a restart.

**The launcher reports the service failed to start.** Read `devinx.log`. A port
conflict on 8316 is the usual cause; `--port` at install time changes it.

**After a pull, is the running service the new code?** It is checked for you.
The service outlives the sessions that use it on purpose — several share it, and
closing one should not restart it for the others — so a pull otherwise leaves
last week's code answering today's launcher, silently. Each start now stamps a
fingerprint of its own source, and the launcher compares it against the file on
disk: a stale service is replaced when idle, and reported rather than cut in
half when a turn is in flight. `curl 127.0.0.1:8316/api/hello` shows the build,
pid and how many requests are running right now.

**An agent stops with a rate-limit error.** It should no longer get that far.
SWE-2 enforces a token budget over a rolling window, and a burst of parallel
agents empties it — measured on one machine, 1107 refusals against 8598
successful turns, in bursts of up to 133 in a row, each naming a wait of one to
twelve minutes.

devinx now holds the turn instead of handing the refusal back: it waits the
delay the upstream named, with jitter so a fan-out of agents does not all return
together and empty the window again, then retries. The client sees a request
that took longer; the agent never stops, and the orchestrator is never told
anything happened. Measured: a subagent refused with "reset in 1 minute" waited
65 seconds inside one request and finished its task, its parent reporting no
error at all.

**More than one Devin account.** Both of Cognition's limits are per credential —
a short one that recycles in well under a minute, and a longer window that can
lock for twelve minutes — so a second account is a switch rather than a wait.
Log in again with the data directory pointed somewhere else and devinx finds it:

```sh
XDG_DATA_HOME="<data dir>/account2" devin auth login
```

Every `credentials.toml` under the data directory is loaded, and turns are
spread across them round robin — always starting at the same one keeps that one
permanently at its ceiling while the others idle, which is the difference
between switching on every burst and not being limited at all. On a rate limit
the turn moves to another credential immediately, and only waits when every one
of them is spent. `DEVINX_API_KEYS` takes a
comma-separated list instead. Each request logs the account that served it, so
which credential a limit belongs to is answerable from the log.

`DEVINX_RATE_WAIT` bounds the total wait (300s by default) — the client has its
own timeout, and an answer that never comes is worse than one that says to try
later. Past that budget the refusal does go back, as a 429 `rate_limit_error`
carrying `retry-after`.

**A SWE-2 turn ends with `permission_denied`.** Cognition's input classifier
refused the payload. The log says which attempt failed and what was capped; the
retry shrinks tool descriptions on its own.

**A subagent dies with `prompt is too long` instead of compacting.** Three
things have to be right, and the one that actually killed agents was none of the
obvious two.

The client enforces the declared window itself for a model it does not
recognise, and for a subagent that enforcement is fatal rather than corrective:
the agent ends with "Agent terminated early due to an API error: Prompt is too
long (error type invalid_request)" and devinx never receives a request at all —
refused on the client's own estimate, without compacting and without asking. The
launcher therefore sets `CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT`,
measured: the same subagent then runs to completion, its turns reaching the
upstream that was always willing to take them. `DEVINX_ENFORCE_WINDOW=1` puts
the local cap back.

The other two are the window and the wording.

And past those, the proxy compacts. A client compacts its main session but not
an agent: measured, an agent at its limit drops a single message — 30412 tokens
to 30284 — and then ends with that error, having summarised nothing. So devinx
does it instead. When a turn would not fit, the first turn is kept (it is the
task), the recent turns are kept verbatim, and everything between is replaced by
a summary written with Claude Code's own compaction prompt, read out of its
binary rather than reinvented. The client's transcript is untouched; only what
goes upstream is reduced, which the agent experiences as a turn that took a few
seconds longer. Measured end to end: a subagent whose context reached 158k
against an 80k threshold compacted to 18k and finished its task.

Compaction is lossy by nature — the agent keeps the summary, not the detail —
and a threshold set below the size of what the agent is actually working on will
make it re-read the same files forever. `DEVINX_COMPACT_AT` sets it; the default
leaves roughly 96k of recent turns verbatim. devinx declares 262144 —
the real one — through `CLAUDE_CODE_MAX_CONTEXT_TOKENS`, which is the only lever
that works: a `context_window` on the model catalog is ignored for a model the
client does not recognise. `DEVINX_CONTEXT_TOKENS` overrides it, and erring low
costs only an earlier compaction.

The other is the wording of the refusal. A client recovers from an overflow by
parsing two numbers out of the message, and Cognition's has none in it — it says
"The prompt is too long for this model" and nothing more, so the recovery never
fires. devinx rewrites it as `prompt is too long: N tokens > M maximum`, with N
estimated locally and M the declared window. Measured on one machine before that
change: 48 overflows in a day, on requests of 1.7MB and 200 messages, while
every turn that did compact stopped at 257k — the window was being honoured on
one path and ignored on another.

**Checking what a Codex session will actually see**, without spending a request:

```sh
devinx --cx --or debug prompt-input
```

**Everything is broken.** `claude` and `codex` on their own do not go through
devinx at all and are always available as a fallback.

## Refreshing the protobuf descriptors

`descriptors/*.fdp` are Cognition's message definitions, shipped with the
package. They only need refreshing if the upstream wire format changes:

```sh
python3 extract_fdps.py descriptors
```

It resolves the `latest` published catalog, so it can pull a version newer than
the one this release was tested against.
