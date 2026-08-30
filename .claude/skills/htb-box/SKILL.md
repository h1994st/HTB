---
name: htb-box
description: Use when starting, working, or wrapping up a Hack The Box machine in this repo — bootstraps the gitignored working dir and the BoxName.ipynb writeup, then drives the standard recon → fingerprint → loot/spray → foothold → post-foothold sweep → privesc → writeup loop, with this project's pacing and anti-stall rules.
---

# Working an HTB box

The user drives recon decisions and box control (VPN, resets, pasted terminal output);
I drive exploitation. This is authorized practice on HTB's own targets.

## 0. Bootstrap

```bash
uv run python .claude/skills/htb-box/scripts/new_box.py BoxName 10.129.x.y
```

Creates `boxname.htb/` (gitignored) and `BoxName.ipynb` from `assets/box-template.ipynb`
with the IP/host filled in. Then remind the user to add the `/etc/hosts` line; get the VPN
IP for payloads with `from common import get_openvpn_utun_ip`.

Everything I produce goes in `boxname.htb/` as a **numbered, re-runnable script**
(`01-recon.sh`, `12-sm-exploit.py`, …), never as a one-off inline blob — the box will be
reset and every step will need replaying. Keep a running `boxname.htb/notes.md`.

## 1. Recon — breadth first, one job at a time

Full TCP first, then targeted service scans; UDP top-100 only if TCP is thin.
Web: `feroxbuster`/`ffuf` for dirs, `ffuf -H 'Host: FUZZ.box.htb'` for vhosts — **2–4
threads, one sweep at a time** (see Rules of engagement). Anonymous surfaces get looted
immediately: SMB/NFS/FTP/rsync/LDAP/SNMP, `.git`, `robots.txt`, JS bundles, source maps.

## 2. Fingerprint every service, then decide

Pin an exact version for each listening service and each web app. Then branch:

- **Outdated** → known-exploit path; research the CVE/primitive (never the box writeup).
- **Latest/patched** → the author is signalling the vuln is *not* in that software. Flip
  from "how do I exploit this?" to "how is it *used*?" — credentials, config, what it
  links to, which accounts exist. Do not burn turns CVE-hunting a patched service.

Verify a theory with one cheap request before researching it.

## 3. Loot and spray — the reflex

The instant any password, hash, or key appears: spray it against **every** service and
**every** known username (SSH, SMB, WinRM, the web app, mail, DB). One loop, ~30s. Then
read every mailbox, share, config, and DB now reachable — creds chain to creds. On AD,
also run `bloodyAD get writable` alongside BloodHound (graph collectors miss CREATE_CHILD
on OUs, tombstones in `CN=Deleted Objects`, DNS zones) and read SMB share **remarks**.

Most easy/medium boxes reach the next foothold on steps 1–3 with no CVE at all.

## 4. Foothold

Reverse shell: listener via `common.ReverseShell`, upgrade per `shell_upgrade.md`.
Prefer a payload that survives box resets, and record it as a script.

## 5. Autonomy first — before enumerating anything

**The very next action after a foothold is making the loop scriptable.** Drop an SSH key,
or wrap the channel in a helper (`H(){ ssh -i key user@host "$@"; }`, or a small
`run_as_user.py`). Ask the user for a key/handover if that is faster.

Rationale: on BlockSynergy I spent ~2h at ~6 tool calls/hr with the user hand-pasting 49k
characters of terminal output; the rate hit 40/hr the minute a key existed. Never run a
multi-hour campaign through copy-paste.

## 6. Post-foothold sweep — run it once, in full, timeboxed ~10 min

Say which items ran. Do not skip ahead to a hunch; this sweep has contained the answer on
most boxes where I later needed a hint.

- `id`, groups, `sudo -l`, `/etc/passwd` (who else has a shell), home dirs of other users
- SUID/SGID + `getcap -r /`
- cron (`/etc/cron*`, user crontabs) **and** systemd: `systemctl list-units --all`,
  `list-timers`, then **`systemctl cat` every non-stock unit** — the unit name, its
  `ExecStart`, and its working dir are frequently the whole privesc path
- listening sockets (`ss -lntup`) incl. localhost-only and container subnets
- readable `/var/log/*` — but see the circular-artifact trap in §7
- root-owned dirs writable by one of my groups; recently-modified files under `/opt`, `/srv`
- **package versions vs distro-patched**: `apt list --upgradable`, held-back packages,
  `dpkg -l` on anything unusual — a deliberately held-back package *is* the vuln
- Windows: DPAPI blobs + Credential Manager, saved RDP creds, browser stores, `.bak` dirs,
  SYSVOL scripts, backup SQL dumps
- `linpeas`/`winPEAS` last, as a net — not as a substitute for the above

## 7. Privesc loop — and the stall breakers

Pick the most specific lead from the sweep. Then, for each hypothesis:

**State a cost and a kill criterion out loud, and announce the kill.** ("This dies if the
daemon verifies the archive against a root-only manifest." It did — and I still ran it for
hours on BlockSynergy.)

**If the target component is opaque and event-driven, stop watching and start poking.**
Polling an idle root daemon is circular: anything that only appears when the trigger fires
cannot tell you how to fire it — a self-written log is empty pre-trigger, and `[ -f x ]` on
a missing path emits no inotify event. Replace the watch with one batched stimulus-response
probe drawn from the subsystem's own vocabulary:

```bash
for n in restore trigger run start reload .restore restore.flag; do touch "$DIR/$n"; done
sleep 60; ls -la "$DIR"; tail /var/log/<svc>.log
```

Two minutes. The service/unit name and its work dir are the naming anchor — that is the
intended nudge.

**A user redirect is a hard interrupt.** When the user names the blocker ("the problem is
how to trigger restore"), re-plan around it and do not drift back to the old branch without
saying why.

**Stuck >45 min on one pivot ⇒ inventory what was never looked at**, not more depth on what
was: unexamined credential stores, units never `systemctl cat`'d, versions never compared,
directories never listed, containers never enumerated. The answer to "we needed a hint" has
almost always been a cheap fact I never went and got.

**Declare red herrings dead in `notes.md`** with the evidence that killed them.

## 8. Writeup and commit

Fold the working path into `BoxName.ipynb` as it happens — `## Shell as <user>` sections in
execution order, ending at root. Keep it executable from a cold kernel; use
`common.hide_flag` for flags kept in a cell. Then:

```bash
uv run python -m jupyter nbconvert --clear-output --inplace BoxName.ipynb
git add BoxName.ipynb && git commit -m "HTB: BoxName"     # on the locked-seasonNN branch
```

Never push. Common helpers that emerged go to `common/` on `main` first (see CLAUDE.md).
Durable, non-obvious lessons go to the memory directory.

## Rules of engagement

- **Pace**: one job at a time, 2–4 threads. These are small single-host VMs; stacked sweeps
  knock them over, and a degraded box silently turns timeouts into false negatives. Classify
  errors/timeouts as a *third* outcome, not as misses, and abort the sweep when they appear.
- **Never probe append-only shared state with malformed payloads.** If a probe is accepted
  and cannot be removed (tx pool, queue, ledger), it can brick the box. Test validation with
  well-formed-but-wrong values, never with `{}`.
- **No box writeups / walkthroughs.** Researching the underlying CVE, tool, or primitive is
  encouraged; searching "HTB <Box> writeup" is not.
- **Broken-box signals**: no community first blood after several hours **plus** the target
  falling over under light load = evidence about the *target*. Say so early and offer
  parking it. On such a box, label inferred-from-absence results as provisional.
