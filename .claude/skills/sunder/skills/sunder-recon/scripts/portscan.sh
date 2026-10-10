#!/usr/bin/env bash
# portscan.sh — full TCP SYN sweep, then a targeted service/script scan on the open ports.
#
# Needs root (SYN scan). On macOS fast scanning requires sudo, so RUN IT MANUALLY:
#     sudo .../portscan.sh <target> [outdir]
# Re-runnable after a box reset; writes nmap -oA output into <outdir> (default ./scans).
#
# Env overrides:  NMAP=/path/to/nmap  RATE=<min-rate, default 5000>
set -euo pipefail

TARGET="${1:?usage: portscan.sh <target> [outdir]}"
OUTDIR="${2:-scans}"
NMAP="${NMAP:-/opt/homebrew/bin/nmap}"
RATE="${RATE:-5000}"

if [ "$(id -u)" -ne 0 ]; then
  echo "[-] needs root for -sS. Re-run:  sudo $0 $TARGET $OUTDIR" >&2
  exit 1
fi

mkdir -p "$OUTDIR"

echo "[*] full TCP SYN sweep (-Pn, ICMP is usually filtered) -> $OUTDIR/full-tcp.*"
"$NMAP" -Pn -p- -sS --min-rate "$RATE" --max-retries 2 -T4 -vv -oA "$OUTDIR/full-tcp" "$TARGET"

OPEN=$(grep -oE '[0-9]+/open' "$OUTDIR/full-tcp.gnmap" 2>/dev/null | cut -d/ -f1 | paste -sd, - || true)
echo "[*] open TCP ports: ${OPEN:-none}"
[ -z "${OPEN:-}" ] && exit 0

echo "[*] targeted service/version/script scan -> $OUTDIR/services.*"
"$NMAP" -Pn -p "$OPEN" -sS -sC -sV -A -T4 -vv -oA "$OUTDIR/services" "$TARGET"
echo "[*] done."
