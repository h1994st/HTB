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

**Make the channel scriptable before enumerating anything.** A raw reverse shell, a
copy-paste loop, or a one-command-at-a-time web shell caps the whole engagement at human
typing speed. First actions, in order:

1. Upgrade the shell to a usable TTY (`shell_upgrade.md`).
2. Establish durable, repeatable access — install a key, or wrap the channel in a small
   helper function or script that takes a command and returns its output.
3. Verify the helper round-trips before moving on.

If the user is driving the shell manually, ask for a key or a handover — that request is
worth making early and explicitly, not after hours of pasted output.

## Then

Record the working exploit path and the access helper in `ledger.md`, grab the flag if this
principal has one, and move to `htb-enumerate`. After any later pivot, return here: the new
principal's credentials get sprayed too.
