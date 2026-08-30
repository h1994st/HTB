# CLAUDE.md

This file provides guidance to Claude Code (claude.ai/code) when working with code in this repository.

## What this repo is

A personal Hack The Box workspace. Each machine produces **two** artifacts:

| Artifact | Naming | Tracked? |
|---|---|---|
| Writeup notebook | `BoxName.ipynb` (CamelCase, repo root) | yes — one commit `HTB: BoxName` |
| Working directory | `boxname.htb/` (lowercase) | **no** — `.gitignore` has `*.htb/` |

Everything volatile (scans, loot, exploit scripts, keys, flags, `notes.md`) lives in the
working directory. The notebook is the distilled, re-runnable writeup.

For the end-to-end procedure on a box, use the **`htb-box`** skill
(`.claude/skills/htb-box/`) — it carries the recon→root workflow, the notebook
template, and the anti-stall rules. Invoke it at the start of every box.

## Commands

```bash
uv sync                     # install deps into .venv (README's requirements.txt is stale)
brew bundle                 # nmap, ffuf, feroxbuster, hashcat, chisel, sqlmap, ...
uv run python <script>.py   # ALWAYS run Python this way — never bare python/python3/pip
uv add <pkg>                # ALWAYS add deps this way — never hand-edit pyproject.toml
uv run python -m jupyter nbconvert --clear-output --inplace BoxName.ipynb   # before committing
```

`.claude/settings.json` denies bare `python`/`pip` and `git push`; that is intentional, not a
misconfiguration. There is no test suite — the verification for a notebook is that it runs
top-to-bottom from a cold kernel to both flags.

## Notebook contract

Every `BoxName.ipynb` opens with the same four cells (see the skill's
`assets/box-template.ipynb`):

1. markdown — `# BoxName` + the hackthebox.com machine URL
2. markdown — `## Port Scanning`, the `/etc/hosts` mapping, and the raw `nmap` command
3. code — `TARGET_IP`, `TARGET_HOST`, `OUTPUT_DIR = TARGET_HOST`, `CREDENTIALS: dict[str, str]`
4. code — `from common import scan_ports` + the scan call

After that, one `##` section per milestone, in execution order, ending at root — e.g.
`## Version Enumeration`, `## <Service> Enumeration`, `## Shell as <user>`, `## Shell as root`.
Long shell sequences go in `%%script env ... bash` cells so the notebook stays executable;
manual steps (reverse-shell upgrade, a second terminal) go in fenced bash blocks in markdown.

Kernel is the project venv (`python3` / `htb (3.14.x)`). `OUTPUT_DIR` points at the
gitignored working dir, so cells may read/write loot freely — but **clear outputs before
committing**: flags, hashes, and session tokens leak through cell outputs.

## `common/` package

Shared helpers only — anything reused across boxes belongs here, not copy-pasted into a
notebook. Add the function, export it in `common/__init__.py`'s imports *and* `__all__`.

`scan_ports` (nmap XML → parsed open ports; prompts for sudo) · `get_openvpn_utun_ip`
(the tun IP to use in payloads) · `ReverseShell` (pwntools listener with prompt-suppression
and marker-delimited `run()`, sync + async) · `get_stdout` (asyncssh) · `crack_hashes`
(hashcat wrapper) · `parse_ffuf_json` · `xss_get_secret_data` (aiohttp exfil callback
server) · `hide_flag` (redact a flag for a committed cell).

`common/` is macOS-specific in places (`/opt/homebrew/bin/nmap`, OpenVPN Connect + `utun`
lookup) — keep that assumption rather than genericizing it.

## Branch strategy

- `main` — **common infrastructure only**: `common/`, `pyproject.toml`/`uv.lock`, `.claude/`,
  `CLAUDE.md`, `Brewfile`, docs. No box writeups.
- `locked-seasonNN` — one branch per HTB season, created manually by the user; carries that
  season's `BoxName.ipynb` commits on top of `main`.
- **Never `git push`, and never push on the user's behalf** — these branches stay local.
  `.claude/settings.json` denies it.

Worktrees: `.worktrees/main`, `.worktrees/seasonNN` (the `.worktrees/` dir is gitignored).
The repo root is checked out to the *current* season.

Changing anything common (including this file and the skills) is a **main-first** flow:

```bash
cd .worktrees/main && git add -A && git commit -m "..."      # 1. land it on main
cd ../../ && git rebase main                                  # 2. current season, in repo root
git -C .worktrees/seasonNN rebase main                        # 3. each older season worktree
```

Box work is the opposite: commit `BoxName.ipynb` directly on the season branch.

## Local tooling gotchas

- `nxc` → `uvx --python 3.13 --from git+https://github.com/Pennyw0rth/NetExec nxc ...`
- `evil-winrm` → `/opt/homebrew/lib/ruby/gems/4.0.0/bin/evil-winrm` (not on PATH); on macOS
  use NTLM `-H <hash>`, not Kerberos — the `gssapi` gem needs MIT krb5, macOS ships Heimdal.
- ADCS tool is `certipy` (ly4k v4.8.2 in `.venv`), **not** `certipy-ad`.
- `faketime` for Kerberos skew works on impacket binaries but **not** through `uvx`
  (SIP strips `DYLD_INSERT_LIBRARIES` on re-exec) — for `nxc`, `sudo sntp -sS <dc>` instead.
- Wordlists: `rockyou.txt` and SecLists are installed locally; `sshpass`, `hashcat`, `chisel`
  come from the `Brewfile`.
