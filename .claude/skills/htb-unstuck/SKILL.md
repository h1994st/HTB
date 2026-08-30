---
name: htb-unstuck
description: Recovery protocol for an HTB box that has stopped progressing — roughly 45 minutes on one pivot with no new fact, repeated failed attempts, or a hunt that has become a loop. Use from any phase; it is a diagnosis of the search, not of the target.
---

# Unstuck protocol

Being stuck is a property of the search, not a signal to search harder in the same place.
Work these in order and stop at the one that produces a new fact.

## 1. Inventory what was never looked at

List the things not yet examined, not the things already examined more deeply. Common gaps:
a credential store never opened, a service definition never read, a version never compared
against its patched release, a directory never listed, a reachable host never scanned, a
configuration file mentioned but never fetched, an account known but never sprayed.

The answer to a long stall is almost always a cheap fact that was never collected — not a
subtle insight about facts already in hand.

## 2. Re-read the evidence rather than re-running it

Go back to raw collected output and read it, instead of re-running the collection. Loot
gathered early and skimmed under a different hypothesis routinely contains the answer to the
current one.

## 3. Check for circular expectations

Is the thing being waited on only observable *after* the step being searched for? A log a
component writes when triggered cannot disclose its trigger; a callback cannot confirm a
listener that was never reached. If the disclosure is circular, no amount of waiting
resolves it — switch to bounded stimulus (`htb-privesc`).

## 4. Distinguish absence from evidence

Separate what was directly observed from what was inferred from silence. Re-test any
inference-from-absence that a currently blocked path depends on, ideally with a different
oracle, and especially if the target has been unstable.

## 5. Widen the frame by one level

Re-ask the questions that were settled early and never revisited: is this the only host? the
only interface? the only domain? the intended account? Is the current target actually on the
path, or a plausible detour? Enumerate what the machine's authored details point at — its
custom names and unusual components — rather than what generic methodology suggests next.

## 6. Re-read the user's own steers

Scan back over what the user has said this session. A user's stated theory of the blocker is
the highest-value lead available and is easy to acknowledge and then drift away from. Treat
it as a hard interrupt: re-plan around it, and if a different branch is resumed later, say
why explicitly.

## 7. Consider the target

Persistent instability under light load — especially without a community first blood well
after release — is evidence about the machine. Say so plainly and offer parking it. On an
unstable target, results inferred from absence are untrustworthy and should not be recorded
as findings.

## Then

Whatever breaks the stall, write down in `ledger.md` *what* the missing fact was and *why*
it was not collected earlier. That is the reusable part.
