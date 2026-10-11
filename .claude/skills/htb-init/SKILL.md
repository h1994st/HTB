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
- The box's shared state lives in the **sunder engagement store**, not in hand-written files.
  Once the working dir exists, start it with the sunder `init` MCP tool —
  `init(box_dir="<host>", target="<ip-or-host>")` — which creates `<host>/sunder.db` and
  renders `ledger.md` and `hypotheses.md` into the working dir (`ledger.md` = shared state;
  `hypotheses.md` opens with the *Surface & boundaries* map that seeds the ranked rounds).
  **Both files are regenerated on every store write — never hand-edit them:** record facts,
  hypotheses, and results through the `sunder:*` tools. The user reads them and writes notes
  or steers only between the `<!-- sunder:human:begin -->` and `<!-- sunder:human:end -->`
  markers in `ledger.md`; that region survives re-renders and the agent reads it. The plugin
  also ships a `sunder` CLI (run against its project root,
  `uv run --project <sunder-plugin-root> sunder …`): `note` adds a human note, `state` prints
  JSON, `render` regenerates the two files, and `export` writes `attack-path.md` for the writeup.

## Conventions this sets up

The working directory holds everything volatile — scans, loot, keys, exploit scripts,
and the ledger. Name scripts numerically in the order they were needed (`01-recon.sh`,
`02-vhosts.sh`, …) so the whole chain can be replayed after a box reset; a reset is normal,
not exceptional. The notebook is the distilled writeup and is assembled as work proceeds,
not reconstructed at the end.
