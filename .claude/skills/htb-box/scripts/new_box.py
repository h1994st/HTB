#!/usr/bin/env python3
"""Bootstrap a new HTB box: gitignored working directory + writeup notebook.

Usage:  uv run python .claude/skills/htb-box/scripts/new_box.py BoxName [10.129.x.y]

Creates ``boxname.htb/`` (working dir, gitignored via ``*.htb/``) and
``BoxName.ipynb`` from the skill's four-cell template, with the box name, host,
and target IP substituted. Refuses to clobber an existing notebook.
"""

import argparse
import sys
from pathlib import Path

SKILL_DIR = Path(__file__).resolve().parent.parent
TEMPLATE = SKILL_DIR / "assets" / "box-template.ipynb"
REPO_ROOT = SKILL_DIR.parents[2]  # .claude/skills/htb-box -> repo root

PLACEHOLDER_IP = "10.129.0.0"


def main() -> int:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("box", help="Machine name as HTB spells it, e.g. BlockSynergy")
    ap.add_argument("ip", nargs="?", default=PLACEHOLDER_IP, help="Target IP")
    ap.add_argument("--host", help="Override the vhost (default: <box>.htb, lowercased)")
    args = ap.parse_args()

    box = args.box.strip()
    host = args.host or f"{box.lower()}.htb"

    notebook = REPO_ROOT / f"{box}.ipynb"
    workdir = REPO_ROOT / host

    if notebook.exists():
        print(f"[-] {notebook.name} already exists — refusing to overwrite.")
        return 1

    body = TEMPLATE.read_text()
    for needle, value in (
        ("__BOX_NAME__", box),
        ("__BOX_HOST__", host),
        ("__TARGET_IP__", args.ip),
    ):
        body = body.replace(needle, value)

    workdir.mkdir(exist_ok=True)
    notebook.write_text(body)

    print(f"[+] working dir : {workdir.relative_to(REPO_ROOT)}/   (gitignored)")
    print(f"[+] notebook    : {notebook.relative_to(REPO_ROOT)}")
    print()
    print("Next:")
    print(f"  sudo sh -c 'echo \"{args.ip}  {host}\" >> /etc/hosts'")
    if args.ip == PLACEHOLDER_IP:
        print("  (no IP given — update TARGET_IP in the notebook once you have it)")
    print("  put scans/loot/exploit scripts in the working dir, numbered and re-runnable")
    return 0


if __name__ == "__main__":
    sys.exit(main())
