#!/usr/bin/env bash
# dirscan-ferox.sh — web content/directory discovery with feroxbuster.
#     dirscan-ferox.sh <url> [wordlist]
#   e.g. dirscan-ferox.sh http://touch.htb:8443
#
# Wordlist: 2nd arg, else $SECLISTS/Discovery/Web-Content/raft-medium-directories-lowercase.txt.
# Ask the user for their SecLists checkout and `export SECLISTS=<path>` — never hardcode one.
# Env overrides:  THREADS (default 20)  OUTDIR (default ./scans)
#
# Pacing (see sunder Rules of engagement): lower THREADS for a fragile host, prefer a smaller
# wordlist first, and don't stack this with another sweep or a spray.
set -euo pipefail

URL="${1:?usage: dirscan-ferox.sh <url> [wordlist]}"
WL="${2:-${SECLISTS:?set SECLISTS=<path to SecLists> (ask the user) or pass a wordlist as arg 2}/Discovery/Web-Content/raft-medium-directories-lowercase.txt}"
OUTDIR="${OUTDIR:-scans}"; mkdir -p "$OUTDIR"
THREADS="${THREADS:-20}"

echo "[*] feroxbuster $URL   (wl=$WL, t=$THREADS)"
feroxbuster -u "$URL" -w "$WL" -t "$THREADS" -o "$OUTDIR/ferox.txt"
