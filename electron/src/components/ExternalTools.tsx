import { useCallback, useEffect, useState } from 'react'
import { CheckCircle2, Download, RefreshCw, Terminal, Wrench } from 'lucide-react'
import { requestApi } from '@/hooks/useApi'

/**
 * External tools (`deps` in the CLI, /api/toolchain here).
 *
 * A missing binary used to look exactly like a clean run: the command produced
 * nothing and the module stored an empty result. This section names what is
 * absent, the exact command that WOULD install it on THIS machine (Kali/WSL,
 * other Linux, macOS, Windows — the backend detects the family and the package
 * manager), and asks before running a package manager: one click per tool, and
 * the request carries confirm=true, which the backend refuses without.
 */

type MissingTool = { tool: string; why: string; command: string[] }
type Toolchain = {
  environment: string
  os: string
  distro: string
  manager: string
  wsl: boolean
  needs_sudo: boolean
  missing: MissingTool[]
}

export default function ExternalTools() {
  const [data, setData] = useState<Toolchain | null>(null)
  const [loading, setLoading] = useState(false)
  const [busy, setBusy] = useState('')
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await requestApi('GET', '/api/toolchain')
      setData((res?.data ?? null) as Toolchain | null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const install = async (tool: string) => {
    setBusy(tool)
    setMsg('')
    try {
      const res = await requestApi('POST', '/api/toolchain', { tool, confirm: true })
      const d = (res?.data ?? {}) as { ok?: boolean; message?: string }
      setMsg(d.message || (d.ok ? `${tool} installed` : `${tool} not installed`))
      await load()
    } finally {
      setBusy('')
    }
  }

  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-3">
      <div className="flex items-center justify-between mb-3">
        <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
          <Wrench size={13} /> External tools
        </h2>
        <div className="flex items-center gap-2">
          {data && (
            <span className="text-[10px] text-text-dim font-mono">{data.environment}</span>
          )}
          <button onClick={load} disabled={loading}
            className="text-[10px] text-text-dim hover:text-phantom-cyan flex items-center gap-1">
            <RefreshCw size={10} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
        </div>
      </div>

      {!data && <p className="text-[10px] text-text-dim">Loading the tool report…</p>}

      {data && data.missing.length === 0 && (
        <p className="text-[10px] text-phantom-green flex items-center gap-1">
          <CheckCircle2 size={11} /> Nothing missing on this machine.
        </p>
      )}

      <div className="space-y-2">
        {data?.missing.map((row) => (
          <div key={row.tool} className="flex items-start justify-between gap-3">
            <div className="min-w-0">
              <p className="text-xs font-medium text-text-primary">
                <span className="font-mono">{row.tool}</span>
              </p>
              <p className="text-[10px] text-text-dim">{row.why}</p>
              {row.command.length > 0 ? (
                <p className="text-[9px] font-mono text-text-dim/80 mt-0.5 flex items-center gap-1">
                  <Terminal size={9} /> {row.command.join(' ')}
                  {data.needs_sudo && <span className="text-amber-400/80"> (sudo)</span>}
                </p>
              ) : (
                <p className="text-[9px] text-amber-400/80 mt-0.5">
                  no package for this distro — install it by hand
                </p>
              )}
            </div>
            {row.command.length > 0 && (
              <button onClick={() => install(row.tool)} disabled={busy === row.tool}
                className="shrink-0 flex items-center gap-1 px-2 py-1 rounded text-[10px]
                  border border-phantom-cyan/40 text-phantom-cyan hover:bg-phantom-cyan/10
                  disabled:opacity-40">
                <Download size={10} /> {busy === row.tool ? 'installing…' : 'Install'}
              </button>
            )}
          </div>
        ))}
      </div>

      <p className="text-[9px] text-text-dim/70 mt-2 border-t border-surface-border pt-2">
        Nothing is installed by a scan. Each click asks the package manager of
        this machine ({data?.manager || 'detecting…'}
        {data?.wsl ? ', WSL' : ''}) for one tool only, and the request carries an
        explicit confirmation the backend refuses without.
      </p>
      {msg && <p className="text-[10px] text-text-secondary mt-1">{msg}</p>}
    </div>
  )
}
