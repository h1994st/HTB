---
name: htb-vuln-research
description: Assess a fingerprinted component for known vulnerabilities — classify it as an exploit path or a usage path, then dispatch the cve-researcher subagent to do the reading so the source diffs and advisories never enter the main context. Use once a component has an exact version, and whenever a new one appears.
---

# Vulnerability research

Recon produced versions. This phase decides what each version *means*, before any time is
spent on exploitation.

## Classify every component first

- **Outdated or unusual build** → exploit path. Research the specific vulnerability.
- **Latest or fully patched** → the author is signalling the vulnerability is not in that
  software. Flip the question from "how do I exploit this?" to "how is it *used* here?" —
  which accounts exist, what credentials it stores, what it links to, what it renders, what
  it trusts. Do not spend turns hunting CVEs in a patched component.
- **Custom or in-house code** → the highest-value target. Read the source if any is
  reachable; the bug is intended and usually reachable from the visible interface.
- **Deliberately held-back package** (installed version behind the distro's patched one) →
  treat as an intended path even when the component looks boring.

Rank by reachability first, then by how much the version deviates from stock.

## Verify before investing

Confirm the premise with one cheap request before researching a theory — that the feature
exists, that the code path is reachable, that the plugin is actually enabled. A theory that
survives one probe is worth research; one that does not was never a lead.

## Delegate the reading

**Dispatch the `cve-researcher` subagent per component; do not do the reading here.** Proper
assessment means release notes, advisories, patch diffs and upstream source at an exact tag —
tens of thousands of tokens of material whose value is a few lines of conclusion. Keeping
that out of the main context is the point of the subagent, and it is why several components
can be assessed at once while other work continues.

Give each one the exact version and the reachable surface. Require it to verify claims
against source at that version rather than trusting a database entry, to report what it could
*not* confirm, and to say plainly when a component is a dead end. Create a task per component
with its `owner` set to the subagent so the dispatch is visible in `TaskList`, and fold the
returned assessment into the ledger before closing it.

Research the **primitive**, never the machine: the CVE mechanics, the parser or protocol
behaviour, the tool's technique. Searching for this box's writeup or walkthrough is out of
bounds for both you and the subagent.

## Output

Per component, record in `ledger.md`: the classification, the candidate primitive, what it
would grant, its preconditions, and the cheapest way to test whether those preconditions
hold. That last field is the one that gets acted on first.
