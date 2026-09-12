import { useCallback, useEffect, useState } from 'react'
import { Package, Download, Upload, RefreshCw, FileBox } from 'lucide-react'
import { requestApi } from '@/hooks/useApi'
import { useStore } from '@/store'

/**
 * BundlesPanel — the .pm engagement bundles tab.
 *
 * A .pm is ONE portable file carrying the whole engagement (session +
 * auto-mode checkpoint + report index + C2 intel), AES-GCM encrypted.
 * Electron auto-exports one on app close; this tab lists every bundle,
 * exports the current engagement on demand, and re-imports a bundle to
 * restore target/scope/notes/knowledge/reasoning state.
 */

interface Bundle {
  name: string
  size: number
  mtime: string
  target: string
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export default function BundlesPanel() {
  const pushToast = useStore((s) => s.pushToast)
  const [bundles, setBundles] = useState<Bundle[]>([])
  const [busy, setBusy] = useState(false)
  const [importName, setImportName] = useState('')

  const refresh = useCallback(async () => {
    const res = await requestApi('GET', '/api/pm/list')
    if (res.status === 200) {
      setBundles(((res.data as { bundles?: Bundle[] }).bundles) || [])
    }
  }, [])

  useEffect(() => {
    void refresh()
    const h = setInterval(() => void refresh(), 8000)
    return () => clearInterval(h)
  }, [refresh])

  const exportNow = async () => {
    setBusy(true)
    try {
      const res = await requestApi('POST', '/api/pm/export', {})
      if (res.status === 200) {
        const d = res.data as { name: string; path: string }
        pushToast({ title: 'Bundle exported', description: d.path, type: 'success' })
        await refresh()
      } else {
        pushToast({ title: 'Export failed', description: String((res.data as { error?: string }).error), type: 'error' })
      }
    } finally {
      setBusy(false)
    }
  }

  const importBundle = async (name: string) => {
    if (!name) return
    setBusy(true)
    try {
      const res = await requestApi('POST', '/api/pm/import', { name })
      if (res.status === 200) {
        const d = res.data as { summary: string; target: string }
        pushToast({ title: `Imported ${name}`, description: d.summary, type: 'success' })
      } else {
        pushToast({ title: 'Import failed', description: String((res.data as { error?: string }).error), type: 'error' })
      }
    } finally {
      setBusy(false)
    }
  }

  return (
    <div className="h-full flex flex-col p-4 gap-4 overflow-auto">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Package size={18} className="text-phantom-cyan" />
          <h2 className="text-lg font-bold text-text-primary">Session Bundles (.pm)</h2>
        </div>
        <div className="flex items-center gap-2">
          <button
            onClick={() => void refresh()}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-surface-card border border-surface-border text-xs text-text-secondary hover:text-text-primary"
          >
            <RefreshCw size={12} /> Refresh
          </button>
          <button
            onClick={() => void exportNow()}
            disabled={busy}
            className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-phantom-cyan/15 text-phantom-cyan text-xs hover:bg-phantom-cyan/25 disabled:opacity-50"
          >
            <Download size={12} /> Export current engagement
          </button>
        </div>
      </div>

      <p className="text-xs text-text-dim max-w-3xl">
        A <code className="text-phantom-cyan">.pm</code> bundle carries the full engagement — session state, knowledge
        base, auto-mode checkpoint and C2 intel — encrypted (AES-256-GCM). Phantom auto-exports one every time the app
        closes; share the file with another operator or import it later to resume exactly where you stopped.
      </p>

      {/* manual import by name */}
      <div className="flex items-center gap-2">
        <FileBox size={14} className="text-text-dim" />
        <input
          value={importName}
          onChange={(e) => setImportName(e.target.value)}
          placeholder="bundle name (e.g. phantom_1720000000.pm) or absolute path"
          className="flex-1 max-w-md px-3 py-1.5 rounded bg-surface-card border border-surface-border text-xs text-text-primary outline-none focus:border-phantom-cyan/50"
        />
        <button
          onClick={() => void importBundle(importName.trim())}
          disabled={busy || !importName.trim()}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-surface-card border border-surface-border text-xs text-text-secondary hover:text-text-primary disabled:opacity-40"
        >
          <Upload size={12} /> Import
        </button>
      </div>

      {bundles.length === 0 ? (
        <div className="text-xs text-text-dim p-6 text-center border border-dashed border-surface-border rounded-lg">
          No bundles yet. Export the current engagement or close the app once (auto-export on quit).
        </div>
      ) : (
        <div className="rounded-lg border border-surface-border overflow-hidden">
          <table className="w-full text-xs">
            <thead className="bg-surface-card text-text-dim">
              <tr>
                <th className="text-left px-3 py-2 font-medium">Bundle</th>
                <th className="text-left px-3 py-2 font-medium">Target</th>
                <th className="text-left px-3 py-2 font-medium">Saved</th>
                <th className="text-left px-3 py-2 font-medium">Size</th>
                <th className="px-3 py-2" />
              </tr>
            </thead>
            <tbody>
              {bundles.map((b) => (
                <tr key={b.name} className="border-t border-surface-border hover:bg-surface-card/60">
                  <td className="px-3 py-2 font-mono text-text-primary">{b.name}</td>
                  <td className="px-3 py-2 text-text-secondary">{b.target || '—'}</td>
                  <td className="px-3 py-2 text-text-dim">{b.mtime}</td>
                  <td className="px-3 py-2 text-text-dim">{fmtSize(b.size)}</td>
                  <td className="px-3 py-2 text-right">
                    <button
                      onClick={() => void importBundle(b.name)}
                      disabled={busy}
                      className="px-2 py-1 rounded bg-phantom-cyan/10 text-phantom-cyan text-[10px] hover:bg-phantom-cyan/20 disabled:opacity-40"
                    >
                      import
                    </button>
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}
    </div>
  )
}
