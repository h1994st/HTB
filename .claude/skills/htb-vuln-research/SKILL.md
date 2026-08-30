---
name: htb-vuln-research
description: Turn a fingerprinted service inventory into a ranked attack plan — classify each component as an exploit path or a usage path, then research the underlying CVE or primitive (optionally via the cve-researcher subagent). Use after recon, and whenever a new component appears.
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

## Researching

Research the **primitive**: the CVE mechanics, the parser or protocol behaviour, the tool's
technique. Prefer primary sources — the patch diff, the release notes, the advisory, the
vendor source at the exact version — over summaries. Never search for this machine's
writeup or walkthrough.

For a component with many candidate CVEs, or when two components need researching at once,
dispatch the **`cve-researcher`** subagent per component and keep working meanwhile. Give it
the exact version and the reachable surface; require it to verify claims against the source
at that version and to report what it could *not* confirm.

## Output

Per component, record in `ledger.md`: the classification, the candidate primitive, what it
would grant, its preconditions, and the cheapest way to test whether those preconditions
hold. That last field is what the next phase acts on.

Next phase: `htb-foothold`.
