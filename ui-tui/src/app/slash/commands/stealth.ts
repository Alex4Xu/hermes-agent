import { withInkSuspended } from '@hermes/ink'

import { launchHermesCommand } from '../../../lib/externalCli.js'
import type { SlashCommand } from '../types.js'

const isStealthHome = () => /(?:^|\/)\.hermes\/profiles\/stealth\/?$/.test(process.env.HERMES_HOME || '')

const runBackendStealth = (arg: string, ctx: Parameters<SlashCommand['run']>[1]) => {
  const command = `stealth ${arg}`.trim()

  ctx.gateway.gw
    .request<{ output?: string; warning?: string }>('slash.exec', { command, session_id: ctx.sid })
    .then(r => {
      if (ctx.stale()) {
        return
      }

      const body = r?.output || `/${command}: no output`
      const text = r?.warning ? `warning: ${r.warning}\n${body}` : body
      const long = text.length > 180 || text.split('\n').filter(Boolean).length > 2

      long ? ctx.transcript.page(text, 'Stealth') : ctx.transcript.sys(text)
    })
    .catch(ctx.guardedErr)
}

export const stealthCommands: SlashCommand[] = [
  {
    help: 'enter or inspect the isolated stealth profile',
    name: 'stealth',
    run: (arg, ctx) => {
      const sub = arg.trim().toLowerCase()

      if (sub === 'status' || sub === 'audit' || sub === 'exit') {
        runBackendStealth(sub, ctx)

        return
      }

      if (sub) {
        ctx.transcript.sys('usage: /stealth [status|audit|exit]')

        return
      }

      if (isStealthHome()) {
        runBackendStealth('status', ctx)

        return
      }

      ctx.transcript.sys('entering stealth profile; current TUI is suspended and will resume after stealth exits…')
      void withInkSuspended(async () => {
        const result = await launchHermesCommand(['--profile', 'stealth'])

        if (result.error) {
          ctx.transcript.sys(`error launching stealth: ${result.error}`)

          return
        }

        if (result.code !== 0 && result.code !== null) {
          ctx.transcript.sys(`stealth exited with code ${result.code}`)

          return
        }

        ctx.transcript.sys('stealth session ended — resumed previous Hermes session')
      })
    },
    usage: '/stealth [status|audit|exit]'
  }
]
