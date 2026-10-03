---
name: sunder-recon
description: Discover and fingerprint every reachable surface on a target — ports, services, web content, virtual hosts, and anonymous shares — and pin an exact version to each. Use at the start of an engagement, and again whenever a pivot exposes a new network.
---

# Recon

Goal: a written inventory in `ledger.md` where **every listening service and every web
application has an exact version**, and every anonymous surface has been read. Breadth
before depth — the next foothold is usually in something already visible, not in something
undiscovered.

## Order

1. **Ports.** Full TCP sweep first, then targeted service/script scans on what is open.
   UDP top-ports only when TCP is thin. Run `.claude/skills/sunder-recon/scripts/portscan.sh
   <target>` for the live sweep — it needs root (SYN scan), so on macOS **prompt the user to
   run it manually with `sudo`**; it writes `-oA` output into `./scans`. `common.scan_ports`
   is the notebook equivalent.
2. **Per-service banners and versions.** Every open port gets fingerprinted, not just the
   web ones. Note the OS and any hostname/domain the services leak.
3. **Web surface.** Directory and file discovery
   (`.claude/skills/sunder-recon/scripts/dirscan-ferox.sh <url>`), then virtual-host discovery
   (`.claude/skills/sunder-recon/scripts/vhost-ffuf.sh <url> <base-domain[:port]>`) against
   every domain the certificates, redirects, or page content reveal. Both fuzzers read
   `$SECLISTS` — **ask the user for their SecLists checkout and `export SECLISTS=<path>`; never
   hardcode a path** — or take a wordlist as the last argument. Mind the pace (see the sunder
   *Rules of engagement*): estimate the request count, narrow the wordlist, lower `THREADS`
   for a fragile host, and never stack a sweep with a spray. New vhosts go into `/etc/hosts`
   and are then treated as new targets from step 2.
4. **Client-side.** Read the JavaScript bundles, source maps, comments, and API definitions
   before fuzzing for endpoints — applications usually name their own routes. Check
   `robots.txt`, exposed `.git`, backup and editor swap files.
5. **Anonymous surfaces.** SMB, NFS, FTP, rsync, LDAP, SNMP, DNS zone transfer, mail verbs —
   anything that answers unauthenticated. Read what they hold; do not just list them.
6. **Identity harvest.** Collect every username, email, hostname, and internal path seen
   anywhere in the above. Every one of them is a spray candidate later.

## Recording

`ledger.md` gets a service table (port, service, exact version, auth required, notes) and a
credential/identity list. Scans write into the working dir. A surface that answered but
yielded nothing is still a recorded fact — with *how* it was checked, so it is not
re-checked blindly later.
