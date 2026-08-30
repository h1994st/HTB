---
name: htb-enumerate
description: Systematic post-foothold enumeration of a compromised host — the full sweep of identity, scheduled work, services, filesystem, network, and stored credentials. Use immediately after gaining any shell, once per principal, before hunting a privesc path.
---

# Post-foothold enumeration

Run this **once, in full, timeboxed**, and report which items ran. It is deliberately a
checklist rather than a hunch: the missing fact is usually cheap and boring, and skipping
ahead to the interesting-looking lead is what turns a short box into a long one.

Automated enumeration scripts run **last**, as a net under a sweep already done by hand —
their output is long, easy to skim past, and silently incomplete.

## Every host

- **Identity** — user, groups, and what those groups grant; other accounts with shells or
  home directories; what this principal can do that the previous one could not.
- **Elevation config** — the local privilege-delegation rules (sudo policy, roles, admin
  group membership), and any credential-free path they expose.
- **Privileged binaries** — setuid/setgid, capabilities, and their versions.
- **Scheduled and event-driven work** — cron, timers, service units, watchers, startup
  items. For every non-stock unit, read its definition: the unit's *name*, its command
  line, its working directory, and the account it runs as. This is the most commonly
  decisive item in the sweep and the most commonly skipped.
- **Listening services** — including loopback-only and container-network ports invisible
  from outside. Anything bound locally is a service the author expected only insiders to
  reach.
- **Filesystem** — application roots and custom directories outside the package manager;
  directories owned by a privileged account but writable by one of my groups; recently
  modified files; world-readable logs; backups, archives, and database dumps.
- **Package state** — installed versions against the distribution's patched versions.
  A held-back or downgraded package is a deliberate signal.
- **Stored credentials** — history files, configuration, environment, key material, token
  caches, credential vaults and password managers, browser stores, saved remote-access
  credentials, and database dumps containing rows deleted from the live database.
- **Neighbourhood** — other hosts, containers, and networks reachable from here that were
  not reachable from outside. Each one restarts the phase model behind the pivot.

## Directory-service environments

Collect the graph, then verify what the graph does not carry: granular per-object rights,
deleted/tombstoned objects, certificate-services templates and enrolment rights, delegation
settings, share descriptions, and script or policy directories. Read the collected data
before chasing errors — group names and memberships usually telegraph the intended path.
Take the same care with per-object permissions on the objects you can already touch.

## Output

Write the findings into `notes.md` as facts with their evidence, and list the checklist
items that ran. Anything unreadable or denied is itself a finding — record *what* was denied
and to whom, because that is often the shape of the intended path.

Next phase: `htb-privesc`.
