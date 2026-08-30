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

Delivery is its own problem, separate from the bug. Establish which direction traffic can
flow before designing a payload: outbound to an arbitrary port, outbound on a permitted port
only, or no egress at all — in which case the result has to come back through the same
channel that carried the request. Watch for transformations between you and the sink —
URL and shell decoding, length limits, character filters, encoding conversions — and test
the primitive against a harmless marker before wrapping a payload around it. When a payload
must survive a hostile parser, stage it: land an encoded blob first, decode it on the target,
then execute.

## Immediately after execution

Upgrade the shell to a usable TTY (`shell_upgrade.md`), then make the access repeatable —
a key, a helper function, or a small script that takes a command and returns its output —
and verify it round-trips before going further.

## Record

The working exploit path, the access method, and any flag go in `ledger.md` as soon as they
land. New credentials from this principal re-enter the spray reflex above.
