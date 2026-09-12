import { useEffect, useState } from 'react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'
import Sidebar from '@/components/Sidebar'
import StatusBar from '@/components/StatusBar'
import C2Dashboard from '@/components/C2Dashboard'
import SessionPanel from '@/components/SessionPanel'
import AutoModePanel from '@/components/AutoModePanel'
import ReportsPanel from '@/components/ReportsPanel'
import SettingsPanel from '@/components/SettingsPanel'
import ModulePanel from '@/components/ModulePanel'
import CommandPalette from '@/components/CommandPalette'
import TimelinePanel from '@/components/TimelinePanel'
import VaultPanel from '@/components/VaultPanel'
import NetworkMap from '@/components/NetworkMap'
import AuditViewer from '@/components/AuditViewer'
import RecordingsPanel from '@/components/RecordingsPanel'
import BundlesPanel from '@/components/BundlesPanel'
import LearningPanel from '@/components/LearningPanel'
import AdGraphPanel from '@/components/AdGraphPanel'
import { ToastContainer } from '@/components/Toast'

export default function App() {
  const { activeTab, elapsed, setElapsed, setSettings } = useStore()
  const [backendError, setBackendError] = useState<string | null>(null)
  useApi(true)

  // Surface backend lifecycle failures instead of a silent dead UI
  useEffect(() => {
    window.phantom?.onApiStatus?.((s) => {
      if (s.state === 'error') setBackendError(s.detail || 'backend failed to start')
      else if (s.state === 'exited') setBackendError(`backend exited (code ${s.code})`)
    })
  }, [])

  // Hydrate settings from the backend at startup — the store starts with
  // defaults, so without this the saved WSL2/SSH config looked "lost" on
  // every app restart (it was saved, just never loaded back into the UI).
  useEffect(() => {
    let cancelled = false
    ;(async () => {
      const res = await window.phantom?.request('GET', '/api/backend/config')
      if (!cancelled && res?.status === 200 && res.data) {
        const d = res.data as { kind: string; distro: string; host: string; port: number; user: string }
        setSettings({
          backend_type: (['wsl2', 'native', 'ssh', 'none'].includes(d.kind) ? d.kind : 'none') as never,
          wsl_distro: d.distro || 'kali-linux',
          ssh_host: d.host || '',
          ssh_port: d.port || 22,
          ssh_user: d.user || 'root',
        })
      }
    })()
    return () => { cancelled = true }
  }, [setSettings])

  // Session timer
  useEffect(() => {
    // Start the timer
    const start = Date.now()
    const tick = () => {
      const secs = Math.floor((Date.now() - start) / 1000)
      const h = Math.floor(secs / 3600)
      const m = Math.floor((secs % 3600) / 60)
      const s = secs % 60
      if (h) setElapsed(`${h}h ${m}m`)
      else if (m) setElapsed(`${m}m ${s}s`)
      else setElapsed(`${s}s`)
    }
    tick()
    const interval = setInterval(tick, 1000)
    return () => clearInterval(interval)
  }, [setElapsed])

  // Every panel stays MOUNTED (hidden when inactive) instead of being
  // unmounted on tab switch. Unmounting wiped each panel's local state —
  // a network scan, craft output, module form or auto-mode view reset to
  // zero the moment you looked at another tab. Panels are cheap to keep
  // around and their polls are light, so state survives navigation.
  const MODULE_TABS = ['scan', 'web', 'exploit', 'brute', 'osint', 'wifi', 'payload', 'pivot', 'handler', 'analyzer', 'wordlist']
  const panels: Array<{ id: string; node: React.ReactNode }> = [
    { id: 'c2', node: <C2Dashboard /> },
    { id: 'session', node: <SessionPanel /> },
    { id: 'automode', node: <AutoModePanel /> },
    { id: 'reports', node: <ReportsPanel /> },
    { id: 'settings', node: <SettingsPanel /> },
    { id: 'timeline', node: <TimelinePanel standalone /> },
    { id: 'vault', node: <VaultPanel standalone /> },
    { id: 'network', node: <NetworkMap standalone /> },
    { id: 'audit', node: <AuditViewer standalone /> },
    { id: 'recordings', node: <RecordingsPanel /> },
    { id: 'bundles', node: <BundlesPanel /> },
    { id: 'learning', node: <LearningPanel /> },
    { id: 'adgraph', node: <AdGraphPanel /> },
  ]
  for (const m of MODULE_TABS) panels.push({ id: m, node: <ModulePanel moduleId={m} /> })
  const active = panels.find((p) => p.id === activeTab) ?? panels[0]

  if (backendError) {
    return (
      <div className="h-screen w-screen flex flex-col items-center justify-center bg-surface text-text-primary gap-3 p-8">
        <p className="text-lg font-bold text-phantom-red">Phantom backend is not running</p>
        <pre className="text-xs font-mono text-text-dim max-w-xl whitespace-pre-wrap text-center">{backendError}</pre>
        <p className="text-xs text-text-secondary max-w-lg text-center">
          The Python API process could not start (missing backend executable or a
          crash at boot). In dev, run <code className="text-phantom-cyan">python phantom/api/launcher.py --port 9876</code> and
          check its output; in the packaged app reinstall Phantom.
        </p>
        <button
          onClick={() => location.reload()}
          className="mt-2 px-4 py-2 rounded bg-phantom-cyan/15 text-phantom-cyan text-sm hover:bg-phantom-cyan/25"
        >
          Retry
        </button>
      </div>
    )
  }

  return (
    <div className="flex h-screen w-screen overflow-hidden">
      <Sidebar />
      <div className="flex-1 flex flex-col min-w-0">
        {/* Title bar with drag region */}
        <div style={{ WebkitAppRegion: 'drag' } as any} className="h-9 flex-shrink-0 bg-surface-card border-b border-surface-border flex items-center px-4">
          <span className="text-sm font-semibold text-phantom-red tracking-wider">
            PHANTOM
          </span>
          <span className="ml-2 text-xs text-text-dim">
            v3.0.0
          </span>
        </div>

        {/* Panel content — all panels mounted, only the active one visible */}
        <div className="flex-1 overflow-auto min-h-0">
          {panels.map((p) => (
            <div key={p.id} className={p.id === active.id ? 'h-full' : 'hidden'}>
              {p.node}
            </div>
          ))}
        </div>

        {/* Status bar */}
        <StatusBar />

        {/* Command Palette (global Ctrl+K) */}
        <CommandPalette />
        
        {/* Global Toasts */}
        <ToastContainer />
      </div>
    </div>
  )
}