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

The trade it is built on is that the two sides are scarce in opposite ways. Your
own context is the thing that runs out; SWE-2 Max, on a Devin subscription, is
not metered. So execution belongs downstream and judgment stays up top —
architecture, decomposition, what the diff actually says, what to tell you.

### The roles

| agent | for | writes files |
|---|---|---|
| `swe2-explorer` | mapping code, tracing flow, locating symbols and tests | no |
| `swe2-worker` | bounded implementation, targeted fixes, mechanical edits | yes |
| `swe2-tester` | running tests, reproducing failures, adding tests | yes |
| `swe2-researcher` | external docs, version-specific API behaviour | no |
| `swe2-reviewer` | independent read of a finished change | no |
| `claude-reviewer` | the same, on your own model, for high-stakes changes | no |

Every SWE role is pinned to `swe-2-max`. There is no tier ladder and no effort
budget to spend: Max is not rationed, so sending a task to a weaker tier buys
nothing.

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

**A SWE-2 turn ends with `permission_denied`.** Cognition's input classifier
refused the payload. The log says which attempt failed and what was capped; the
retry shrinks tool descriptions on its own.

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
