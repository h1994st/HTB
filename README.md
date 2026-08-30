# Hack The Box

Writeups for **retired** Hack The Box machines, as runnable Jupyter notebooks.

Per HTB's terms, writeups for active (non-retired) machines are not published — those live
on local, unpushed season branches and only land here once the machine retires.

> References
>
> - <https://0xdf.gitlab.io/cheatsheets/offsec>

## Layout

- `BoxName.ipynb` — one notebook per machine, runnable top-to-bottom from recon to root.
- `common/` — helpers shared across boxes (nmap scan + parse, reverse-shell listener,
  OpenVPN tun IP lookup, hashcat wrapper, ffuf/XSS-callback utilities).
- `Brewfile`, `pyproject.toml` — external tooling and Python dependencies.
- `shell_upgrade.md` — reverse shell TTY upgrade cheatsheet.

## Setup

```bash
brew bundle    # nmap, ffuf, feroxbuster, hashcat, hydra, chisel, sqlmap, ...
uv sync        # Python dependencies into .venv
```

Then open a notebook and run it with the project kernel. Notebooks target macOS
(Homebrew paths, OpenVPN Connect `utun` interfaces).
