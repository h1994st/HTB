---
name: htb
description: Entry point for working a Hack The Box machine in this repo. Use when starting a box, resuming one mid-session, or whenever the next move is unclear — it holds the phase model, the rules of engagement, and dispatches to the focused htb-* skills.
---

# Working an HTB box

Authorized practice against HTB's own targets. The user drives box control (VPN, resets,
scope) and often runs commands themselves; I drive enumeration and exploitation.

## Phase model

Phases are a default order, not a pipeline — later phases loop back constantly. Identify
the current phase from what already exists, then invoke that skill. **Sequencing lives here
and only here**: each phase skill is self-contained and does not name what comes next, so
this table is what decides the order.

`htb-threat-model` and `htb-hypotheses` are the thinking phases. The model is worth building
on every box; the hypothesis round earns its cost on a hard one, when there is enough
information to reason from but no obvious path.

| Phase | Skill | Done when |
|---|---|---|
| 0 Bootstrap | `htb-init` | working dir, artifacts, and notebook exist; host resolves |
| 1 Model | `htb-threat-model` | assets, principals, and trust boundaries written down |
| 2 Recon | `htb-recon` | every reachable surface has an exact version in `ledger.md` |
| 3 Research | `htb-vuln-research` | each component classified exploit-path or usage-path |
| 4 Hypotheses | `htb-hypotheses` | competing candidates ranked, execution mode chosen |
| 5 Foothold | `htb-foothold` | command execution, and a repeatable way back in |
| 6 Enumerate | `htb-enumerate` | the host sweep has run in full, coverage reported |
| 7 Escalate | `htb-privesc` | next principal reached — repeat 5→7 until root |
| 8 Writeup | `htb-writeup` | notebook runs cold to both flags, outputs kept |
| — Stuck | `htb-unstuck` | invoke from *any* phase after ~45 min without progress |

Loot found in one phase re-enters an earlier one: new credentials go back to the spray
reflex in `htb-foothold`; a newly reachable service goes back to `htb-recon`; an internal
host restarts the whole model behind the pivot.

Three artifacts live in the working directory alongside the scripts and loot —
`ledger.md` (state), `threat-model.md` (structure), `hypotheses.md` (candidates). All three
are created at bootstrap and are meant to be written to as work happens, not at the end.

## Dispatch

Invoke one skill at a time and finish its phase before moving on. When resuming a box,
read the working dir's `ledger.md` first and rebuild the task list from it — it is the source of truth for what has been
tried, what is dead, and which credentials exist.

Phase boundaries are also the checkpoints worth reporting: say what the phase established,
what it ruled out, and what the next phase will try.

## Ledger and task list

Two trackers, different lifetimes. Keep both.

**`ledger.md` in the working directory is durable shared state.** The user reads and writes
it too, so it is how you stay in sync with them — and it is what survives a box reset, a
context compaction, or a new session days later. It carries status, access per principal,
credentials and where each was sprayed, services and versions, open leads with their kill
criteria, dead branches with the evidence that killed them, provisional results, and a
timeline. Append and supersede; never delete. A fact that cost effort goes in the moment it
is obtained, not at the end of the phase.

**The `Task*` tools are the in-session working set.** At the start of a phase, `TaskCreate`
one task per open lead and per checklist item. `TaskList` picks the next one — lowest ID
first, since earlier tasks set up context for later ones — `TaskGet` gives its full detail
and dependencies, and `TaskUpdate` moves it to `in_progress` before work starts and
`completed` when it lands. Read a task with `TaskGet` before updating it; state goes stale.
Keep exactly one task `in_progress`.

Use the structure these tools provide rather than a flat list:

- **`addBlockedBy`** for genuine preconditions — the exploit task blocked by the cheap check
  that would kill it, the escalation task blocked by the enumeration sweep. A blocked task
  cannot be claimed, which is what mechanically prevents starting on a hypothesis whose
  premise is unverified.
- **`metadata`** to carry the ledger's lead number, so a task and its ledger row stay linked
  across a compaction.
- **`owner`** when a subagent takes a task, so the dispatch is visible in the list rather
  than only in your head.
- **`activeForm`** so the spinner names the actual probe in progress.
- **`completed`** means the result is written to the ledger — including a *disproven*
  hypothesis, which is finished work with a row in **Dead**, not a deletion. Reserve
  `deleted` for tasks created in error.

The task list is a scratch view over the ledger, never the record itself — if the two
disagree the ledger wins, and the list is rebuilt from it with `TaskCreate`.

The handoff rule: **a task is not done when the command succeeds, it is done when its result
is in the ledger.** The same applies to anything a subagent returns — record its finding and
the excerpt it was working from, so a later session can judge it.

## Rules of engagement

**Pace.** These are small single-host VMs. One job at a time, 2–4 threads, and never stack
a web sweep with a spray and an expensive server-side render. A degraded target silently
turns timeouts into false negatives — classify errors/timeouts as a *third* outcome
distinct from hit and miss, and abort a sweep when they appear rather than recording them
as misses. Before launching a sweep, estimate the request count and say it out loud.

**Never probe append-only shared state with a malformed payload.** Before any probe, ask
whether an accepted value can be removed again. If it cannot — a transaction pool, job
queue, ledger, append-only table — test validation with well-formed-but-wrong values, never
with an empty or truncated body. A stuck malformed entry can break the progression path and
force a reset.

**No box writeups or walkthroughs.** Researching a CVE, tool, or underlying primitive is
encouraged; searching for this machine's solution is not.

**Distinguish observation from inference.** An exploit that visibly worked is a result.
"Nothing called back", "the sweep found nothing", "the port is closed" are inferences from
absence — label them provisional in `ledger.md`, because a degraded target manufactures them.

**Suspect the target, not just the approach.** Repeated stalls under light load, especially
combined with no community first blood well after release, is evidence about the box. Say so
early and offer parking it as a real option instead of escalating effort.

**Record artifacts, not just outcomes.** Every step goes into the working directory as a
numbered, re-runnable script. Boxes get reset; anything not scripted will be retyped.
