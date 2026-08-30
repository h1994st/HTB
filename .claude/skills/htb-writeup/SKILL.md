---
name: htb-writeup
description: Assemble and commit the BoxName.ipynb writeup for an HTB machine — structure, executability, output stripping, and the single-commit convention. Use as milestones are reached, and at the end of a box before committing.
---

# Writeup

The notebook is the deliverable; the working directory is scratch. Build the notebook as
milestones land, not in one pass at the end — reconstructing a chain days later loses the
detail that made it work.

## Structure

After the fixed four opening cells (title and machine URL, port-scanning markdown, the
`TARGET_IP`/`TARGET_HOST`/`OUTPUT_DIR`/`CREDENTIALS` cell, and the scan call), add one `##`
section per milestone **in execution order**, ending at root. Typical shape: enumeration of
each significant service, then one `## Shell as <principal>` section per principal reached.

Each section should carry enough prose to explain *why* the step works — the mechanism, not
just the command. A reader should be able to follow the reasoning without the commands.

## Executability

The notebook must run top-to-bottom from a cold kernel and reach both flags.

- Python steps go in code cells; multi-command shell sequences go in `%%script env ... bash`
  cells so they stay runnable.
- Steps that genuinely cannot be automated — a TTY upgrade, a second terminal, a listener
  the user runs — go in fenced bash blocks inside markdown, clearly marked as manual.
- Read and write loot through `OUTPUT_DIR` so the notebook and working directory stay
  consistent.
- Reuse `common/` helpers rather than inlining a listener, scanner, or cracker. Anything
  written twice across boxes belongs in `common/` on `main` (see CLAUDE.md).
- Values that change per session — attacker IP, target IP, ports — come from constants or
  helpers, never hardcoded mid-notebook.

## Keep the outputs

**Do not clear cell outputs.** They are committed deliberately: the notebook *and* its
outputs are the source for the blog write-up, exported with

```bash
uv run python -m jupyter nbconvert --to markdown BoxName.ipynb
```

That makes output hygiene an authoring-time concern rather than a cleanup pass. While
writing cells:

- Print what a reader needs to follow the step, not raw dumps — slice long output.
- Wrap flags in `common.hide_flag` where they are printed.
- Do not print live secrets in full — private keys, session tokens, uncracked hashes, and
  anything reused beyond this machine. Show enough to prove the step worked.
- Re-run any cell you edited, so committed outputs match committed code.

## Committing

Commit exactly one commit for the box, on the current season branch:

```bash
git add BoxName.ipynb && git commit -m "HTB: BoxName"
```

No prefix, no body, one commit per box — amend rather than stacking follow-ups. Never push;
season branches stay local because publishing a writeup for a non-retired machine violates
HTB's terms.

## Afterwards

Durable, non-obvious lessons — a tool invocation quirk, a technique worth reusing, a habit
that cost time — belong in the memory directory, not in the notebook.
