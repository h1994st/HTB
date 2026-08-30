---
name: htb-privesc
description: Turn enumeration findings into the next principal — lateral movement or privilege escalation — with explicit hypothesis discipline. Use after the post-foothold sweep, and repeat per principal until root.
---

# Escalation

The sweep produced leads. This phase converts one into access. Work one hypothesis at a
time; parallel half-attempts produce ambiguous results and load the target.

## Choosing the lead

Rank by specificity, not by familiarity. A custom service, a non-stock unit, a delegated
right, or a held-back package beats a generic misconfiguration, because these machines are
authored — the unusual thing is usually the intended thing. Prefer leads where the
precondition can be tested in one cheap step.

## Hypothesis discipline

For each candidate, state up front:

- **What it grants** if it works.
- **Its preconditions**, and the cheapest check for each.
- **Its kill criterion** — the observation that would prove it dead.

Then run the cheap checks before building the exploit. When the kill criterion is met, say
so out loud and drop the branch; a hypothesis that has been silently disproven but not
abandoned is the main way hours disappear. Record dead branches in `notes.md` with the
evidence that killed them, so they are not re-attempted after a reset or a context change.

## Probing opaque components

When the privileged component cannot be read — an unreadable script, a compiled binary, a
service reachable only through its side effects — do not settle in to watch it. Passive
observation of an idle, event-driven component is circular: anything that appears only once
it acts cannot tell you how to make it act.

Instead, drive it. Enumerate the small hypothesis space its own naming implies — the unit
name, the working directory, the log vocabulary, the surrounding configuration — and test
the whole set in one batch, then look for a reaction. Bounded stimulus beats unbounded
observation, and usually costs a couple of minutes.

## Races and timing

When the path depends on a window between two operations, first prove the window exists by
observing the two operations, then decide whether to win it by racing or to sidestep it by
controlling an input. Establish the component's period before designing around it.

## Verifying

Confirm the new principal actually holds the expected rights before declaring success, and
re-establish a scriptable channel for it (`htb-foothold`). Then spray its credentials, and
run `htb-enumerate` again from the new position — the sweep is per principal, not per box.

If ~45 minutes pass on this phase with no new fact, invoke `htb-unstuck` rather than
deepening the current attempt.
