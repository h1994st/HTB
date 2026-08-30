---
name: htb-init
description: Bootstrap a new Hack The Box machine in this repo — creates the gitignored working directory and the BoxName.ipynb writeup from the four-cell template, and sets up hosts/VPN context. Use at the very start of a box, before any scanning.
---

# Bootstrap a box

```bash
uv run python .claude/skills/htb-init/scripts/new_box.py BoxName 10.129.x.y
```

Creates `boxname.htb/` (gitignored via `*.htb/`) and `BoxName.ipynb` at the repo root from
`assets/box-template.ipynb`, substituting the machine name, host, and IP. It refuses to
overwrite an existing notebook. Pass `--host` when the vhost is not simply the lowercased
machine name. If the IP is not known yet, omit it and fill in `TARGET_IP` later.

## Then

- Ask the user to add the `/etc/hosts` mapping (the script prints the exact line). Add
  every vhost discovered later to the same line.
- Get the attacker IP for payloads and listeners from `common.get_openvpn_utun_ip()` — never
  hardcode it, it changes with each VPN session.
- `boxname.htb/ledger.md` is created for you — the shared state file both you and the user
  read and write. Fill in **Status** before scanning, and route every later phase's findings
  into it. The ledger discipline itself lives in the `htb` skill.

## Conventions this sets up

The working directory holds everything volatile — scans, loot, keys, exploit scripts,
and the ledger. Name scripts numerically in the order they were needed (`01-recon.sh`,
`02-vhosts.sh`, …) so the whole chain can be replayed after a box reset; a reset is normal,
not exceptional. The notebook is the distilled writeup and is assembled as work proceeds
(see `htb-writeup`), not reconstructed at the end.

Next phase: `htb-recon`.
