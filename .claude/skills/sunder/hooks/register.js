// sunder mod — put the method's discipline where a SKILL sentence can't reach.
//
//   Gate   deny dispatching a worker (agent.spawn) until the active engagement's
//          hypotheses.md declares a ranked set — the marker flipped to complete.
//          This is the "model & rank before you act" rule with teeth.
//   Nudge  while the gate is closed, inject a one-line reminder each prompt.
//   Pane   a live panel (phase · hypotheses · ledger) read from the sunder
//          artifacts, so it survives /clear, /compact and resets.
//
// Keyed on the sunder artifact `hypotheses.md` (not on any HTB-specific naming),
// so the method stays portable. Handlers fail OPEN: an internal error never traps
// the user.
//
// Mods run sandboxed: NO node:fs / node:path imports, NO process.*, NO setTimeout.
// Files go through $.fs, the project root through $.session, timers through $.clock.

const PANE_ID = 'sunder'
const GATE_OPEN = /sunder:gate\s+ranked-set=complete/i // NB: won't match "...=incomplete"
const MAX = 4000 // chars of each artifact to show in the pane

// Analysis workers (reading, research, planning) build the model during sense-making and are
// fanned out in parallel BEFORE the ranked set exists — the method relies on that, so they are
// never gated. Only lead-pursuit / target-action dispatch waits for the ranked set.
const ANALYSIS_AGENT = /(^|:)(cve-researcher|explore|plan)$/i

// Mods API call-site rule: $ is always spelled $.noun.event(...). $.session.root()/cwd()
// are methods; which one a build exposes can vary, so try root first, then cwd.
async function projectRoot($) {
  try { const r = await $.session.root(); if (r) return r } catch { /* */ }
  try { const c = await $.session.cwd(); if (c) return c } catch { /* */ }
  return '.'
}

async function slurp($, path) {
  try {
    const t = await $.fs.read(path)
    return typeof t === 'string' ? t : (t?.text ?? '')
  } catch {
    return ''
  }
}

function mtimeOf(st) {
  // field name isn't pinned across builds — accept the common spellings.
  return st?.mtimeMs ?? st?.mtime ?? st?.modified ?? st?.modifiedMs ?? st?.ctimeMs ?? 0
}
const isDir = (ent) => ent?.kind === 'dir' || ent?.kind === 'directory' || ent?.isDir === true

// Active working dir = the newest immediate subdir that holds a hypotheses.md.
async function activeBox($) {
  const root = await projectRoot($)
  let best
  try {
    for (const ent of await $.fs.list(root)) {
      if (!isDir(ent)) continue
      const hyp = `${root}/${ent.name}/hypotheses.md`
      let st
      try {
        st = await $.fs.stat(hyp)
      } catch {
        continue // no hypotheses.md in this dir
      }
      const t = mtimeOf(st)
      if (!best || t >= best.t) best = { dir: `${root}/${ent.name}`, t }
    }
  } catch {
    /* project root unreadable — treat as no active box */
  }
  return best?.dir
}

const rankedSetDeclared = async ($, box) => GATE_OPEN.test(await slurp($, `${box}/hypotheses.md`))

export function register(on) {
  // --- Gate: no lead dispatched before the ranked set is declared ------------
  on('agent.spawn', async ($, e, next) => {
    try {
      if (!ANALYSIS_AGENT.test(String(e.subagentType ?? ''))) {
        const box = await activeBox($)
        if (box && !(await rankedSetDeclared($, box))) {
          return {
            deny:
              'sunder first-moves gate: finish the recon sweep, write a ranked candidate set ' +
              `in ${box}/hypotheses.md, and flip its marker to "ranked-set=complete" before ` +
              'dispatching a worker to a lead. (Model & rank first; analysis workers are exempt.)',
          }
        }
      }
    } catch {
      /* fail open — never trap the user on an internal error */
    }
    return next(e)
  })

  // --- Nudge: keep the gate visible while it is closed -----------------------
  on('prompt.submit', async ($, e, next) => {
    try {
      const box = await activeBox($)
      if (box && !(await rankedSetDeclared($, box))) {
        const note =
          '[sunder] recon phase — breadth first, then a ranked hypothesis set with kill ' +
          'criteria, before any lead is dispatched (the first-moves gate is holding agent.spawn).'
        return next({ ...e, context: [...(e.context ?? []), note] })
      }
    } catch {
      /* ignore */
    }
    return next(e)
  })

  // --- Pane: live view of the engagement, read from the artifacts ------------
  let started = false
  on('turn.start', async ($, e, next) => {
    try {
      if (!started && (await activeBox($))) {
        started = true
        await $.ui.open({ id: PANE_ID, title: 'sunder', closeOnEscape: true })
        $.clock.every(2000, () => {
          try {
            $.ui.invalidate('ui.render')
          } catch {
            /* */
          }
        })
      }
    } catch {
      /* ignore */
    }
    return next(e)
  })

  on('ui.render', { component: 'Pane' }, async ($, e, next) => {
    if (e.requestId !== PANE_ID) return next(e)
    try {
      const { Box, Text, Markdown } = $.ui.resolve(e)
      const box = await activeBox($)
      if (!box) {
        return Box({ children: [Text({ children: ['no active sunder engagement (no */hypotheses.md)'] })] })
      }
      const name = box.split('/').pop()
      const phase = (await rankedSetDeclared($, box)) ? 'ENGAGED · gate open' : 'RECON · gate closed'
      const hyp = (await slurp($, `${box}/hypotheses.md`)).slice(0, MAX)
      const led = (await slurp($, `${box}/ledger.md`)).slice(0, MAX)
      return Box({
        flexDirection: 'column',
        children: [
          Text({ children: [`${name} — ${phase}`], bold: true }),
          Markdown({ text: `## hypotheses\n\n${hyp || '_empty_'}` }),
          Markdown({ text: `## ledger\n\n${led || '_empty_'}` }),
        ],
      })
    } catch {
      return next(e) // on any render error, let Claude Code draw its default
    }
  })
}
