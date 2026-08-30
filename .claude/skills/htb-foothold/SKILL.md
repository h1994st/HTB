---
name: htb-foothold
description: Convert a lead or a credential into command execution on the target, then make that access scriptable. Use when an exploit path is ready to fire, whenever new credentials appear, and after any lateral pivot to a new principal.
---

# Foothold

Two ways in: credentials, or a vulnerability. Try credentials first — they are cheaper and
more often the intended path.

## The spray reflex

The instant any password, hash, key, or token appears — from a share, a config, a dump, a
crack, a backup — spray it against **every** service and **every** known identity: remote
shell, file shares, remote management, the web applications, mail, databases. One loop,
seconds. Do it again every time a new secret appears; reuse across accounts and across
services is the single most common progression on these machines.

Then read everything the new access opens — mailboxes, shares, configs, databases, history
files, backups. Credentials chain to credentials.

## Exploitation

Build the exploit as a script in the working directory, parameterised by target and
attacker IP, so it survives a box reset. Test the primitive in isolation (does the injection
reach the sink? does the file get written?) before wrapping a full payload around it.
Prefer the quietest primitive that proves execution.

For callbacks and listeners use the helpers in `common/` rather than ad-hoc servers, and
take the attacker IP from `common.get_openvpn_utun_ip()`.

## Immediately after execution

Upgrade the shell to a usable TTY (`shell_upgrade.md`), then make the access repeatable —
a key, a helper function, or a small script that takes a command and returns its output —
and verify it round-trips before going further.

## When the user drives the shell

The user often runs commands themselves and pastes the output back. **This is a deliberate
choice, not a limitation to route around.** They are learning from the box, and short
user-anchored turns bound how much work is lost when a guardrail interrupt forces a rewind
to their last message. Do not push for a handover or a key as a matter of course; offer one
only when the work genuinely needs volume, and accept a no.

What this does mean is that **a round-trip is the scarce resource, so maximize information
per round-trip** rather than minimizing round-trips:

- **Batch.** Send one paste-ready block that answers several questions at once, not one
  command at a time. A block that covers a whole checklist costs the same round-trip as a
  single `ls`.
- **Self-label the output.** Print a marker before each section (`echo "=== sudo ==="`) so
  the paste is readable without a follow-up asking which output is which.
- **Ask for the discriminating output.** Request what separates the live hypotheses, not
  general context. If two candidates differ only in one file's permissions, ask for that.
- **Make blocks safe to re-run and independent of shell state** — no reliance on a variable
  set in an earlier paste, since the session may have died in between.
- **Say what each block is testing** before sending it, so the user can redirect before
  spending a round-trip rather than after.

Failing probes cost the same round-trip as succeeding ones, so put the cheap
hypothesis-killers first in the block.

## Record

The working exploit path, the access method, and any flag go in `ledger.md` as soon as they
land. New credentials from this principal re-enter the spray reflex above.
