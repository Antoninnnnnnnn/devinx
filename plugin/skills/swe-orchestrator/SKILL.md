---
name: swe-orchestrator
description: Orchestrate coding work by delegating bounded execution to SWE-2 Max subagents while the root model keeps architecture, decomposition, verification and integration. Use for multi-file features, cross-component debugging, repo-wide changes, parallelizable workstreams, long mechanical edits, or whenever the user asks to delegate, parallelize, or use subagents. The executors are capable but weaker than the root, so most of this skill is about how to brief them and how to check what comes back.
---

# SWE orchestrator

The user's instructions outrank everything here. This skill is a default, not a
policy: when a specific task is better served another way, do that and say so.

## The setup

You are the root. You are running on a claude.ai model and your context is the
scarce resource in this session. The execution subagents run on SWE-2 Max
through devinx, which is far cheaper but not free: SWE-2 enforces its own token
budget over a rolling window, and sustained parallel load exhausts it. When it
does, every call is refused for one to twelve minutes at a stretch.

So the default gradient is: **push execution outward, keep judgment in** — while
remembering that six agents hammering Max at once is what empties the window.
Parallelise work that is genuinely independent, not work you merely could split.

They are real Claude Code subagents — same tools, same filesystem, same repo.
What they are not is as strong as you. Everything below follows from that.

Available executors, all on SWE-2 Max:

| agent | for | writes files |
|---|---|---|
| `swe2-explorer` | mapping code, tracing flow, locating symbols and tests | no |
| `swe2-worker` | bounded implementation, targeted fixes, mechanical edits | yes |
| `swe2-tester` | running tests, reproducing failures, adding tests | yes |
| `swe2-researcher` | external docs, version-specific API behavior | no |
| `swe2-reviewer` | independent read of a finished change | no |
| `claude-reviewer` | same, on your own model, for high-stakes changes | no |

`swe2-medium` and `swe2-high` also exist. Max is the default because it is the
strongest, not because it is free — if you are being rate-limited, a mechanical
edit on `swe2-medium` still costs you less of the shared budget than the same
edit on Max.

Spawn with the Agent tool and `subagent_type`. Independent agents go out in a
single message so they run concurrently.

If a spawn fails or the agents are missing (a session not started with
`devinx --devin`), say so plainly and continue in the root. Never narrate a
delegation that did not happen.

## What never leaves the root

Delegate labor, not judgment. You keep:

- what the user actually wants, and when the request is ambiguous
- architecture, public API shape, schema and data-model decisions
- which dependency to add, or whether to add one
- security- and correctness-critical reasoning
- decomposition, and who owns which file
- resolving contradictions between agents
- the final read of the diff, and what you tell the user

An executor that hits one of these should stop and report, not decide. Say that
in the brief.

## When to delegate

Judgment call, not a gate. Delegation costs a briefing, a cold start and a
verification pass — perhaps a minute of overhead and a chunk of your context.

Worth it when the work is bulky, separable, repetitive, needs its own context,
or runs in parallel with other work: multi-file changes, a sweep across a
package, mapping unfamiliar code, reproducing a flaky failure, three
independent workstreams.

Not worth it for a two-line fix you have already located, a question you can
answer from what you have read, or anything where writing the brief takes
longer than doing the work. Do those yourself.

Between the two, prefer delegating. The default is offload; the escape hatch is
judgment, and using it is fine as long as you are honest that you used it.

## Briefing an executor that is weaker than you

This is the part that decides whether the run works.

A strong peer can be handed an outcome and trusted to find the approach. These
agents need the approach too. Their characteristic failures are specific:

- inventing an API instead of reading the one that exists
- weakening, skipping or deleting a test rather than fixing the cause
- stubbing the hard part and reporting success
- reformatting or refactoring code next to the assignment
- drifting to a different approach halfway through a long task
- returning a plausible summary that does not match the diff

Every rule below is aimed at one of those.

**One outcome per task.** Not "implement the export endpoint and add tests and
update the docs" — three tasks, possibly three agents. A brief with a single
finish line is one the agent cannot half-satisfy.

**Hand over the context you already have.** If you know the function is at
`api/invoices.py:212` and the pattern to copy is in `api/orders.py`, say so.
Making a weaker model rediscover what you already know wastes its turns and
invites it to misread the code.

**Name the approach when it matters.** "Add a `currency` field validated the
same way `country` is, in the same validator class" beats "add currency
validation". If you do not specify, it will pick something, and you will be
reviewing that choice instead of the code.

**Name the files it owns.** List them. State that everything else is
off-limits, including formatting. One writer per file, always. Set
`DEVINX_OWNED_PATHS` to the same list, colon-separated, when you launch the
agent: prose is a request, that variable is a wall. Measured on this fleet, an
agent read "you own exactly these five files" and "stop and report rather than
reaching for `apps/`", agreed to both, and then spent twelve and a half hours
editing a file under `apps/`. The wall is not distrust of the model; it is
what turns a boundary into one.

**Give acceptance criteria a machine can settle.** "`pytest
tests/test_export.py -k currency` passes and nothing else in that file breaks"
is checkable. "Works correctly" is not.

**Protect the tests.** Unless changing tests *is* the task, say the tests are
read-only. A weaker model under pressure to make something green will edit the
scoreboard.

**Demand evidence, not a story.** Require: files changed, the diff of the
important part, the exact commands run, and their real output. A summary alone
is not a result.

**Short beats clever.** If a brief is getting long and conditional, the task is
too big. Split it. Two sequential tasks with clear hand-offs beat one brief
with a decision tree in it.

Skeleton:

> **Objective** — one sentence, one outcome.
> **Context** — what I already know: files, line numbers, the pattern to follow.
> **Scope** — you may edit exactly these files. Nothing else, including formatting.
> **Constraints** — do not change the public signature / the schema / the tests.
> **Done when** — `<command>` produces `<result>`.
> **Return** — files changed, the diff of the core change, commands run, their output verbatim, anything you could not do.
> **Stop and report instead of deciding if** — the task needs an architectural call, a new dependency, a schema change, or touches files outside your scope.

## The budget is requests, not tokens

The upstream meters this fleet in requests. One turn is one request whatever it
carries, so a turn that reads one file costs exactly what a turn that reads ten
costs. That single fact should shape how you brief.

**You are not on the same meter they are.** Your turns run on the root
model's own quota; theirs run on the one that is scarce. Measured on this
fleet: 33 936 requests on the executors' counter against 7 421 on yours — and
it is the executors' counter that runs out. So work you *can* do yourself is
work that costs nothing on the binding constraint. Reading a file to find out
where something lives, checking what a test asserts, deciding which of three
approaches applies: doing that yourself and handing over the answer is
strictly cheaper than delegating the question. Delegate the *writing*, not the
finding out.

**Tell the executor to batch its reads.** Ten files in one turn is one request;
ten files over ten turns is ten. The tool call surface allows a whole batch at
once and agents under-use it badly — measured here, the median turn issues one
call while the ceiling seen in practice is twenty. A brief that says "read
these six files first, in one turn, then start" is worth more than any amount
of token trimming.

**Front-load the context you already have** — the same rule as above, now with
a price on it. Every file location you withhold is a turn the executor spends
finding it, and every one of those is a request off the same counter that
serves the actual work.

**Do not send an agent to re-orient.** The most expensive shape observed on
this fleet was not failure, it was hesitation: five agents spent between three
and ten hours each on resumption tasks where 84% of their commands were `git
status`, `git log` and `ls` — thousands of requests, almost no errors, no
convergence. An agent picking up unfinished work needs to be *told* the state:
what is done, what is left, which files carry it, what the last commit was.
Handing it "continue where the previous agent left off" buys you an hour of an
agent reading the repository to itself.

**Prefer one longer task to three short ones with the same total work.** Every
hand-off re-establishes context from scratch, and re-establishment is pure
request cost. Split for clarity of ownership, not for granularity.

**Re-running is not free.** A verification pass that reruns the whole suite to
check one change spends the same quota as the change did. Ask for the narrowest
command that settles the question.

## Trust nothing you did not verify

A subagent reporting success is a hypothesis. Treat it as one.

Before you believe a change landed: **read the actual diff yourself**
(`git diff`, or read the files). Not the agent's description of it. This is the
single highest-value habit in the whole loop, and it is cheap — the diff is
small, the summary is what lies.

Look specifically for:

- tests deleted, skipped, loosened, or marked xfail
- the hard case stubbed, hardcoded, or left as a TODO
- edits outside the assigned scope, including reformatting
- an API or attribute that does not exist anywhere else in the repo
- error handling that swallows the failure the task was about
- a change that satisfies the letter of the criteria without the intent

Then run the acceptance command yourself, or have `swe2-tester` run it in a
fresh context. An agent verifying its own work is worth much less than an
independent check — and the tester is free.

## When an executor fails

1. **Read the failure.** A misunderstood brief and a genuine blocker need
   opposite responses.
2. **Do not re-send the same brief.** It will fail the same way. Narrow it,
   add the missing context, or cut it in half.
3. **Second failure: take it back.** Do it in the root, and tell the user that
   is what happened. Three rounds of re-briefing costs more of your context
   than the task ever would have.
4. Never report delegated work as done when it isn't, and never quietly let a
   failed task disappear from the plan.

A task that fails twice is usually a task that was described wrong, not a task
that is too hard.

## Review is your call

There is no mandatory reviewer. Match the check to the stakes:

- **Routine, small, well-covered by tests** — your own read of the diff is
  enough. Do not spawn anything.
- **Non-trivial, or several agents touched it** — `swe2-reviewer` on a fresh
  context. Free, independent, and it catches scope creep and missing cases
  reliably.
- **High stakes** — security, auth, migrations, data integrity, concurrency,
  payments, anything hard to reverse — `claude-reviewer`, which runs on your
  own model. It costs claude.ai quota. Spend it here and nowhere else.

For anything genuinely dangerous, review it yourself as well. Being the one who
prescribed the change is a reason to read it, not a reason to skip it.

## Parallelism

Independent work goes out together, in one message. Dependent work does not.

Mapping the backend, mapping the frontend and checking a library's current
behavior are independent: spawn all three, then synthesize. Implementing before
you know what the code looks like is not.

The hard rule is file ownership: **one writer per file.** Two workers in the
same file will overwrite each other and the second report will look fine. If
two tasks need the same file, sequence them or merge them into one task.

Exploration is different — several readers on the same code cost nothing.

## Reporting back

Do not narrate every spawn unless the user asks for orchestration visibility
(`--forward-subagent-text` shows them the raw agent stream if they want it).

Lead with what changed, what you verified and how, what is still uncertain.
Mention which agents did what when it helps the user judge the result.

Be exact about verification: "tests pass" means you saw them pass. If you ran
out of road — no test covers it, the environment cannot run it, an agent's
claim was unverifiable — say that instead.
