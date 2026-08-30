---
name: htb-hypotheses
description: For a hard box — once enough information is collected but the path is not obvious — generate several competing hypotheses, rank them by discriminating power, and let the user choose whether to test them in parallel with a subagent fan-out or sequentially one at a time. Use before committing hours to a single guess, and after any round of hypotheses is exhausted.
---

# Hypotheses

Use this when there is enough information to reason from but no obvious path — and instead
of committing to whichever idea arrived first, a set of candidates should be laid out and
compared. Generating one hypothesis and pursuing it is how hours disappear; the failure is
not picking the wrong one, it is never having written down the others.

## The artifact

Hypotheses live in **`boxname.htb/hypotheses.md`**, created at bootstrap. Work in rounds:
each round records the facts it reasoned from, the candidates, the ranking, the execution
mode chosen, and — afterwards — the outcome of each. Keep superseded rounds; a hypothesis
that was killed is a fact, and the record of *why* stops it being re-proposed later.

## Generating

First write down what is actually known, and — more importantly — **the notable gaps**. A
hypothesis set generated from an unexamined inventory just re-encodes the blind spot.

Then produce **several genuinely different** candidates, not one idea in three costumes.
Force variety by generating along different axes:

- the trust boundaries in the threat model, one hypothesis per boundary
- the components nobody has explained yet — the service that exists for no clear reason
- the facts nothing currently accounts for — an odd permission, an unexplained account, a
  name that does not fit
- what the machine's theme implies the author meant to teach
- the mundane option: a credential, a reused password, a readable file. It is frequently
  right and it is the one that gets skipped as too boring.

Include at least one hypothesis that contradicts the current working assumption. If every
candidate depends on the same premise, that premise is the thing to test first.

For each: the **mechanism**, what it **predicts** that the others do not, the **cheapest
discriminating test**, its **kill criterion**, and its **cost**.

## Ranking

Rank by discriminating power per unit cost, not by plausibility. A cheap test that
eliminates three candidates beats an expensive one that confirms the favourite. Where
several share a premise, test the premise first — one probe can retire a whole branch.

## Choosing an execution mode

Present the ranked set to the user and **ask which mode to use**. This is their call, not
a default:

- **Parallel fan-out** — a subagent per hypothesis, working aggressively and concurrently.
  Fast and thorough, costs many tokens, and each agent must return a verdict against its own
  kill criterion rather than a narrative.
- **Sequential** — one hypothesis at a time, in ranked order, with the user in the loop
  between each. Slower, far easier to follow and to learn from, and it lets a result from
  the first candidate re-rank the rest.

A fan-out does not lift the request budget — it divides it. Concurrent agents all probing
one small VM will knock it over, and a degraded target then manufactures false negatives
across every branch simultaneously, which is worse than testing sequentially. So: fan out
freely on *analysis* — reading source, researching primitives, reasoning over already
collected loot — and serialize anything that touches the target. Give each agent an explicit
request budget, require a verdict against its own kill criterion rather than a narrative, and
set each agent's task `owner` so the fan-out is visible.

## Closing a round

Every candidate ends explicitly: confirmed, killed with its evidence, or untested with a
reason. Killed ones get their row in the ledger's **Dead** table. Then look at what no
hypothesis explained — that residue is usually where the next round comes from, and if the
residue is empty while the box is unsolved, the gap is in the facts, not in the reasoning.
