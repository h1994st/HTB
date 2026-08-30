---
name: htb-privesc
description: Escalate from the current principal to the next one — lateral movement or privilege escalation — using the vector families that actually appear on these targets. Use once a host sweep has produced leads, and repeat per principal until root.
---

# Escalation

The sweep produced findings. This phase matches them against the vector families below and
converts one into access. Work one candidate at a time — parallel half-attempts produce
ambiguous results.

## Choosing among the leads

Rank by specificity: a custom service, a non-stock unit, a delegated right, a held-back
package or an odd group outranks a generic misconfiguration. Then prefer whichever candidate
has a precondition that one cheap observation settles, and settle it before building
anything.

## Vector families

**Delegated execution.** Sudo rules — read the exact command, its arguments, and whether
environment or a wildcard is preserved; argument injection into a permitted binary is more
common than a permitted shell. Setuid/setgid binaries and file capabilities, including
non-standard ones. Policy-mediated services (polkit, D-Bus) that perform a privileged action
on request.

**Privileged scheduled or event-driven work.** Cron entries, timers, service units,
watchers, startup items running as another account. The exploitable part is rarely the
schedule — it is a writable script, a writable *directory* containing the script, a writable
config it reads, a relative or unquoted path it invokes, or a wildcard in its command line
that expands into attacker-controlled filenames.

**Hijackable resolution.** Anything resolved by search order rather than absolute path:
`PATH`, the dynamic linker (`LD_PRELOAD`, `LD_LIBRARY_PATH`, `RPATH`), interpreter module
paths, plugin and extension directories a privileged process loads from. A writable entry
early in any search order is execution as that process.

**Privileged consumers of input you control.** A root-owned process that parses, renders,
deserializes, extracts, or imports something you can write. Archive extraction (path
traversal and symlink members), configuration reload, template rendering, log ingestion,
backup restore, document conversion. Ask what a privileged component *eats*, then look at
who can write its food.

**Race windows on privileged file operations.** Verify-then-use, create-then-chmod,
extract-then-move. First prove the two operations exist and measure the period, then decide
whether to win the window or sidestep it by controlling an input instead.

**Credentials at rest.** Keys, tokens, application configs, database dumps, backups, shell
and editor history, credential vaults, browser and OS credential stores, and dumps
containing rows deleted from the live database. Anything recovered here re-enters the spray
reflex against every principal and service, which frequently beats an escalation entirely.

**Group membership as a capability.** Membership in a group that owns a privileged socket,
device, or directory is a designed grant, not decoration — container and virtualization
groups, disk and device groups, groups that can read shadow or logs, and any custom group
the machine defines. Enumerate what the group actually owns rather than assuming from its
name.

**Boundaries between containers, VMs, and hosts.** Identify which side you are on before
theorising. Then look at what crosses: bind mounts, shared directories, exposed runtime
sockets, excess capabilities, device access, and host paths that appear inside a container
image layer. Escaping is often writing to something the host later reads or executes.

**Directory-service edges (AD).** Object ACLs that grant write, reset, or membership
control; delegation settings; certificate-services templates and enrolment rights; restorable
deleted objects; managed service account relationships; trust attributes and SID handling
across domains; backup or replication privileges that yield secrets wholesale. Verify the
edge on the object in front of you rather than trusting a graph that may not have collected
it.

**Opaque privileged components.** When the privileged thing cannot be read — a compiled
binary, an unreadable script, a service visible only through its effects — do not settle in
to watch it. Drive it: enumerate the small input space its own naming implies (its unit
name, working directory, config vocabulary, the files it already touches) and test the whole
set in one batch, then look for a reaction.

## Verifying

Confirm the new principal actually holds the expected rights before declaring success, then
establish repeatable access as that principal and collect any flag it owns. Spray its
credentials, and run the host sweep again from the new position — the sweep is per principal,
not per box. A pivot also changes the reachable surface and the trust boundaries, so the
model of the system is rebuilt from where you now stand rather than extended.
