---
name: htb
description: Entry point for working a Hack The Box machine in this repo. Use when starting a box, resuming one mid-session, or whenever the next move is unclear — it holds the phase model, the rules of engagement, and dispatches to the focused htb-* skills.
---

# Working an HTB box

Authorized practice against HTB's own targets. The user drives box control (VPN, resets,
scope) and often runs commands themselves; I drive enumeration and exploitation.

## Phase model

Phases are a default order, not a pipeline — later phases loop back constantly. Identify
the current phase from what already exists, then invoke that skill.

| Phase | Skill | Done when |
|---|---|---|
| 0 Bootstrap | `htb-init` | working dir + notebook exist, host resolves |
| 1 Recon | `htb-recon` | every reachable surface has an exact version in `notes.md` |
| 2 Research | `htb-vuln-research` | each service is classified exploit-path or usage-path |
| 3 Foothold | `htb-foothold` | a shell, *and* a scriptable channel to it |
| 4 Enumerate | `htb-enumerate` | the host sweep has run in full, coverage reported |
| 5 Escalate | `htb-privesc` | next principal reached — repeat 3→5 until root |
| 6 Writeup | `htb-writeup` | notebook runs cold to both flags, outputs cleared |
| — Stuck | `htb-unstuck` | invoke from *any* phase after ~45 min without progress |

Loot found in one phase re-enters an earlier one: new credentials go back to the spray
reflex in `htb-foothold`; a newly reachable service goes back to `htb-recon`; an internal
host restarts the whole model behind the pivot.

## Dispatch

Invoke one skill at a time and finish its phase before moving on. When resuming a box,
read the working dir's `notes.md` first — it is the source of truth for what has been
tried, what is dead, and which credentials exist.

Phase boundaries are also the checkpoints worth reporting: say what the phase established,
what it ruled out, and what the next phase will try.

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
absence — label them provisional in `notes.md`, because a degraded target manufactures them.

**Suspect the target, not just the approach.** Repeated stalls under light load, especially
combined with no community first blood well after release, is evidence about the box. Say so
early and offer parking it as a real option instead of escalating effort.

**Record artifacts, not just outcomes.** Every step goes into the working directory as a
numbered, re-runnable script. Boxes get reset; anything not scripted will be retyped.
