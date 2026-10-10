#!/usr/bin/env bash
# vhost-ffuf.sh — virtual-host discovery with ffuf.
#     vhost-ffuf.sh <url> <base-domain[:port]> [wordlist]
#   e.g. vhost-ffuf.sh http://10.129.1.2:8443 touch.htb:8443
#
# Wordlist: 3rd arg, else $SECLISTS/Discovery/DNS/subdomains-top1million-20000.txt.
# Ask the user for their SecLists checkout and `export SECLISTS=<path>` — never hardcode one.
# Env overrides:  THREADS (default 20)  OUTDIR (default ./scans)
#
# Pacing (see sunder Rules of engagement): estimate the request count first, narrow the
# wordlist if it runs to thousands, lower THREADS for a fragile host, and don't stack this
# with another sweep or a spray. Add `-mc` / `-fs` to filter once you see the baseline.
set -euo pipefail

URL="${1:?usage: vhost-ffuf.sh <url> <base-domain[:port]> [wordlist]}"
BASE="${2:?usage: vhost-ffuf.sh <url> <base-domain[:port]> [wordlist]}"
WL="${3:-${SECLISTS:?set SECLISTS=<path to SecLists> (ask the user) or pass a wordlist as arg 3}/Discovery/DNS/subdomains-top1million-20000.txt}"
OUTDIR="${OUTDIR:-scans}"; mkdir -p "$OUTDIR"
THREADS="${THREADS:-20}"

echo "[*] vhost fuzz $URL   Host: FUZZ.$BASE   (wl=$WL, t=$THREADS)"
ffuf -u "$URL" -H "Host: FUZZ.$BASE" -w "$WL" -ac -t "$THREADS" -o "$OUTDIR/ffuf-vhost.json"
