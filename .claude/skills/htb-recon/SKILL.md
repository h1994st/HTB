---
name: htb-recon
description: Discover and fingerprint every reachable surface on an HTB target — ports, services, web content, virtual hosts, and anonymous shares — and pin an exact version to each. Use after bootstrapping a box, and again whenever a pivot exposes a new network.
---

# Recon

Goal: a written inventory in `ledger.md` where **every listening service and every web
application has an exact version**, and every anonymous surface has been read. Breadth
before depth — the next foothold is usually in something already visible, not in something
undiscovered.

## Order

1. **Ports.** Full TCP sweep first, then targeted service/script scans on what is open.
   UDP top-ports only when TCP is thin. `common.scan_ports` handles the scan-and-parse.
2. **Per-service banners and versions.** Every open port gets fingerprinted, not just the
   web ones. Note the OS and any hostname/domain the services leak.
3. **Web surface.** Directory and file discovery, then virtual-host discovery against every
   domain the certificates, redirects, or page content reveal. New vhosts go into
   `/etc/hosts` and are then treated as new targets from step 2.
4. **Client-side.** Read the JavaScript bundles, source maps, comments, and API definitions
   before fuzzing for endpoints — applications usually name their own routes. Check
   `robots.txt`, exposed `.git`, backup and editor swap files.
5. **Anonymous surfaces.** SMB, NFS, FTP, rsync, LDAP, SNMP, DNS zone transfer, mail verbs —
   anything that answers unauthenticated. Read what they hold; do not just list them.
6. **Identity harvest.** Collect every username, email, hostname, and internal path seen
   anywhere in the above. Every one of them is a spray candidate later.

## Pacing

One sweep at a time, 2–4 threads. Estimate and state the request count before launching a
wordlist; if it runs into the thousands, narrow the wordlist first. Watch for the target
degrading and stop rather than collecting false negatives.

## Recording

`ledger.md` gets a service table (port, service, exact version, auth required, notes) and a
credential/identity list. Scans write into the working dir. A surface that answered but
yielded nothing is still a recorded fact — with *how* it was checked, so it is not
re-checked blindly later.
