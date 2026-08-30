---
name: htb-threat-model
description: Build a working model of an HTB target as a system — its assets, actors, trust boundaries, and the shape its author intended — so that enumeration is directed rather than generic. Use before serious enumeration, and revise it whenever a pivot changes what the system looks like.
---

# Threat model

Do this before grinding. A machine is an authored system with an intended path; a model of
that system turns enumeration from a checklist sweep into a set of targeted questions. The
model is cheap, revisable, and wrong at first — that is fine, its value is in directing the
next hour.

## The artifact

The model lives in **`boxname.htb/threat-model.md`**, created at bootstrap. It is a
deliverable, not a thinking exercise: if it is only in the conversation it does not survive a
compaction, a reset, or tomorrow. Fill it in before serious enumeration, revise it as facts
arrive, and append to its **Revisions** log when the shape of the system changes. A model
that never changes is not being used.

Mark every line **observed** or **assumed** — the distinction is the point.

Findings themselves still go to `ledger.md`; the threat model holds the *structure* that
says which findings to go looking for.

## What to build

**Assets.** What is worth reaching, in the machine's own terms: the flags, but also the
data each service holds, the accounts it defines, and the credentials it must store to
function. Which components are *between* you and each asset?

**Actors and principals.** Every identity the system defines — service accounts, application
users, OS users, roles, groups, machine accounts. Which are reachable from where? An account
that exists but has no obvious way to authenticate is a question, not a footnote.

**Trust boundaries.** Where does data cross from something you influence into something more
privileged? Between the unauthenticated and authenticated surface; between a web app and the
OS; between a user account and a daemon; between one container or host and the next; between
one domain or forest and another. **A boundary that a component crosses on your behalf is
the most likely intended path**, because that is where an author puts the bug.

**Inputs the system consumes.** What does it parse, render, deserialize, execute, schedule,
or fetch — and which of those inputs can you influence, even indirectly? Include the ones
that arrive on a timer or from another component rather than from a request.

**The author's intent.** Themed names, unusual components, a deliberately old version, a
custom group, a share description, a service that exists for no production reason — these
are signals. Ask what the machine is *about*, and what a designer wanting to teach that
topic would have built.

## Turning the model into questions

For each boundary, state the question that would confirm or kill it: what crosses it, who
controls that input, what would happen if the input were hostile, and what is the cheapest
observation that settles it. These questions are what enumeration should be answering.

Rank them by reachability first and by how odd the component is second. Generic
misconfigurations rank below anything the author clearly built on purpose.

## Keeping it honest

Distinguish the parts of the model observed directly from the parts assumed. Assumptions
inherited from a familiar-looking stack are the ones that quietly misdirect an entire
session — a service that resembles a common deployment may be configured deliberately
unlike one.

When a pivot lands, rebuild the model from the new position rather than extending the old
one: the reachable surface, the trust boundaries, and the interesting assets are all
different behind a pivot.
