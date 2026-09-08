import { useEffect, useMemo, useState } from 'react'
import {
  AlertTriangle, CheckCircle2, CirclePlay, Layers, Loader2, RefreshCw, StopCircle,
  Terminal, Pencil, Wrench, Brain, Play
} from 'lucide-react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'

interface ModuleData {
  id: string
  label: string
  suggestions: Record<string, string[]>
  commands: Record<string, string[]>
}

interface GroupResult {
  index: number
  command: string
  combined: string
  returncode: number | null
  timed_out: boolean
  error: string | null
  duration: number
}

export default function ModulePanel({ moduleId }: { moduleId: string }) {
  const { session } = useStore()
  const { api } = useApi()
  const [module, setModule] = useState<ModuleData | null>(null)
  const [selected, setSelected] = useState('')
  const [output, setOutput] = useState('')
  const [running, setRunning] = useState(false)
  const [error, setError] = useState('')

  // Edit mode
  const [editing, setEditing] = useState(false)
  const [editValue, setEditValue] = useState('')

  // Batch run-group state
  const [batchRunning, setBatchRunning] = useState(false)
  const [batchGroup, setBatchGroup] = useState('')
  const [batchTotal, setBatchTotal] = useState(0)
  const [batchCompleted, setBatchCompleted] = useState(0)
  const [batchResults, setBatchResults] = useState<GroupResult[]>([])

  // Preflight per-module
  const [preflight, setPreflight] = useState<{ missing: Array<{ tool: string; module: string; hint: string }>; ok: boolean; message: string } | null>(null)
  const [installing, setInstalling] = useState<Record<string, { busy: boolean; output: string; ok?: boolean }>>({})

  const load = async () => {
    setError('')
    setBatchResults([])
    setBatchRunning(false)
    setPreflight(null)
    const response = await api('GET', `/api/modules/${moduleId}`)
    if (response.status !== 200) {
      setError(String((response.data as { error?: string })?.error || 'Module unavailable'))
      return
    }
    const data = response.data as ModuleData
    setModule(data)
    const first = Object.values(data.suggestions || {}).flat()[0]
      || Object.values(data.commands || {}).flat()[0]
      || ''
    setSelected((current) => current || first)
  }

  useEffect(() => {
    setModule(null); setSelected(''); setOutput(''); setBatchResults([]); setPreflight(null)
    load()
  }, [moduleId])

  const groups = useMemo(() => {
    if (!module) return []
    return [
      ...Object.entries(module.suggestions || {}).map(([name, commands]) => ({ name: `SUGGESTED · ${name}`, commands, suggested: true })),
      ...Object.entries(module.commands || {}).map(([name, commands]) => ({ name, commands, suggested: false }))
    ]
  }, [module])

  const run = async () => {
    if (!selected) return
    setRunning(true); setError('')
    setOutput(`$ ${selected}\n\n`)
    const response = await api('POST', `/api/modules/${moduleId}/run`, {
      command: selected, target: session.target, timeout: 120
    })
    setRunning(false)
    const data = response.data as { combined?: string; error?: string; returncode?: number }
    if (response.status !== 200 || data.error) {
      setError(data.error || `Command failed (${data.returncode ?? response.status})`)
      setOutput((current) => `${current}${data.combined || ''}`)
      return
    }
    setOutput((current) => `${current}${data.combined || '(no output)'}`)
  }

  const runGroup = async (groupName: string, commands: string[]) => {
    setBatchRunning(true); setBatchGroup(groupName); setBatchTotal(commands.length)
    setBatchCompleted(0); setBatchResults([]); setError('')
    const response = await api('POST', `/api/modules/${moduleId}/run-group`, {
      commands, target: session.target, timeout: 300,
    })
    setBatchRunning(false)
    const data = response.data as {
      results?: GroupResult[]; total?: number; completed?: number
      total_duration?: number; error?: string
    }
    if (response.status !== 200 || data.error) {
      setError(data.error || 'Group execution failed')
      return
    }
    const results = data.results || []
    setBatchCompleted(data.completed || results.length)
    let out = `═══ GROUP: ${groupName} ═══\n\n`
    for (const r of results) {
      out += `$ ${r.command}\n${r.combined || '(no output)'}\n`
      if (r.error) out += `[!] ${r.error}\n`
      out += `⏱ ${r.duration.toFixed(1)}s`
      if (r.returncode !== 0) out += `  (exit ${r.returncode})`
      out += '\n\n'
    }
    if (data.total_duration) out += `═══ Total: ${data.total_duration.toFixed(1)}s  ·  ${results.length}/${commands.length} completed ═══\n`
    setOutput(out)
    setBatchResults(results)
  }

  /** Run ALL groups sequentially — same as CLI `run-all`. */
  const runAll = async () => {
    const allCommands = groups.flatMap(g => g.commands)
    if (allCommands.length === 0) return
    setBatchRunning(true); setBatchGroup('ALL GROUPS'); setBatchTotal(allCommands.length)
    setBatchCompleted(0); setBatchResults([]); setError('')
    const response = await api('POST', `/api/modules/${moduleId}/run-group`, {
      commands: allCommands, target: session.target, timeout: 600,
    })
    setBatchRunning(false)
    const data = response.data as {
      results?: GroupResult[]; total?: number; completed?: number
      total_duration?: number; error?: string
    }
    if (response.status !== 200 || data.error) {
      setError(data.error || 'Run-all failed')
      return
    }
    const results = data.results || []
    setBatchCompleted(data.completed || results.length)
    let out = `═══ RUN-ALL (${groups.length} groups) ═══\n\n`
    for (const r of results) {
      out += `$ ${r.command}\n${r.combined || '(no output)'}\n`
      if (r.error) out += `[!] ${r.error}\n`
      out += `⏱ ${r.duration.toFixed(1)}s`
      if (r.returncode !== 0) out += `  (exit ${r.returncode})`
      out += '\n\n'
    }
    if (data.total_duration) out += `═══ Total: ${data.total_duration.toFixed(1)}s ═══\n`
    setOutput(out)
    setBatchResults(results)
  }

  const anyRunning = running || batchRunning

  // Edit handlers
  const startEdit = () => { setEditing(true); setEditValue(selected) }
  const confirmEdit = () => {
    setSelected(editValue)
    // Also update the module's commands in-place for groups
    if (module) {
      for (const g of groups) {
        const idx = g.commands.indexOf(selected)
        if (idx !== -1) { g.commands[idx] = editValue; break }
      }
    }
    setEditing(false)
  }

  const handlePreflight = async () => {
    const res = await api('POST', '/api/session/preflight', { module: moduleId })
    setPreflight(res.data as { missing: []; ok: boolean; message: string })
  }

  const handleInstallTool = async (tool: string) => {
    setInstalling((s) => ({ ...s, [tool]: { busy: true, output: `Installing ${tool}...` } }))
    const res = await api('POST', '/api/backend/install-tool', { tool })
    const d = res.data as { ok?: boolean; output?: string; command?: string }
    setInstalling((s) => ({
      ...s,
      [tool]: {
        busy: false,
        ok: d?.ok,
        output: d?.output ? `$ ${d.command}\n${d.output}`.slice(-1600) : (res.status !== 200 ? 'Install failed (backend unavailable)' : 'Installed')
      }
    }))
    if (d?.ok) handlePreflight()
  }

  const allCommands = groups.flatMap(g => g.commands)
  const canRunAll = allCommands.length > 1 && !anyRunning && !!session.target

  return (
    <div className="p-4 flex flex-col gap-4 h-full">
      <div className="flex items-start justify-between">
        <div>
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <Terminal size={19} className="text-phantom-cyan" /> {moduleId.toUpperCase()}
          </h1>
          <p className="text-xs text-text-dim mt-0.5">State-aware · edit · run-group · run-all · preflight</p>
        </div>
        <div className="flex gap-1">
          <button onClick={handlePreflight} className="p-2 rounded text-text-secondary hover:text-text-primary hover:bg-surface-hover" title="Preflight: check tools">
            <Wrench size={14} />
          </button>
          <button onClick={load} className="p-2 rounded text-text-secondary hover:text-text-primary hover:bg-surface-hover" title="Refresh commands">
            <RefreshCw size={14} />
          </button>
        </div>
      </div>

      {!session.target && (
        <div className="flex items-center gap-2 rounded border border-phantom-yellow/30 bg-phantom-yellow/10 px-3 py-2 text-xs text-phantom-yellow">
          <AlertTriangle size={14} /> Set a target in Session before running module commands.
        </div>
      )}

      {error && (
        <div className="flex items-center gap-2 rounded border border-phantom-error/30 bg-phantom-error/10 px-3 py-2 text-xs text-phantom-error">
          <AlertTriangle size={14} /> {error}
        </div>
      )}

      {/* Preflight result */}
      {preflight && (
        <div className={`rounded border px-3 py-2 text-xs ${preflight.ok ? 'border-phantom-green/30 bg-phantom-green/10 text-phantom-green' : 'border-phantom-yellow/30 bg-phantom-yellow/10 text-phantom-yellow'}`}>
          {preflight.ok ? (
            <><CheckCircle2 size={12} className="inline mr-1" /> All tools installed</>
          ) : (
            <>
              <AlertTriangle size={12} className="inline mr-1" /> {preflight.message}
              {preflight.missing.slice(0, 7).map((m, i) => (
                <div key={i} className="ml-5 text-[10px] text-text-secondary">
                  <span className="text-phantom-error">{m.tool}</span> — {m.hint}
                  <button
                    onClick={() => handleInstallTool(m.tool)}
                    disabled={installing[m.tool]?.busy}
                    className="ml-1.5 px-1.5 py-0.5 rounded bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30 disabled:opacity-50 transition-colors"
                  >
                    {installing[m.tool]?.busy ? '...' : 'Install'}
                  </button>
                  {installing[m.tool]?.output && (
                    <pre className={`mt-1 font-mono text-[9px] whitespace-pre-wrap max-h-24 overflow-auto ${installing[m.tool]?.ok ? 'text-phantom-green' : 'text-text-dim'}`}>
                      {installing[m.tool]?.output}
                    </pre>
                  )}
                </div>
              ))}
            </>
          )}
        </div>
      )}

      {/* Batch progress bar */}
      {batchRunning && (
        <div className="bg-phantom-magenta/10 border border-phantom-magenta/30 rounded-lg px-3 py-2 flex items-center gap-3 text-xs">
          <Loader2 size={14} className="text-phantom-magenta animate-spin" />
          <span className="text-phantom-magenta font-medium">Running: {batchGroup}</span>
          <span className="text-text-dim">({batchCompleted}/{batchTotal})</span>
          <div className="flex-1 h-1.5 bg-surface-border rounded-full overflow-hidden">
            <div className="h-full bg-phantom-magenta rounded-full transition-all duration-300"
              style={{ width: batchTotal ? `${(batchCompleted / batchTotal) * 100}%` : '0%' }} />
          </div>
        </div>
      )}

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Command list */}
        <div className="w-[380px] flex-shrink-0 bg-surface-card border border-surface-border rounded-lg overflow-auto">
          <div className="px-3 py-2 border-b border-surface-border text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center justify-between">
            Commands
            {canRunAll && (
              <button onClick={runAll}
                className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-phantom-magenta/20 text-phantom-magenta hover:bg-phantom-magenta/30 transition-colors">
                <Play size={10} /> Run All ({allCommands.length})
              </button>
            )}
          </div>
          {groups.length === 0 ? (
            <div className="p-4 text-xs text-text-dim">No commands available for the current session.</div>
          ) : groups.map((group) => (
            <div key={group.name} className="border-b border-surface-border/60">
              <div className="flex items-center justify-between px-3 py-1.5">
                <span className={`text-[10px] font-semibold uppercase tracking-wider ${group.suggested ? 'text-phantom-green' : 'text-text-dim'}`}>
                  {group.suggested ? <CheckCircle2 size={11} className="inline mr-1" /> : <CirclePlay size={11} className="inline mr-1" />}
                  {group.name}
                  <span className="ml-2 text-text-dim font-normal">({group.commands.length})</span>
                </span>
                {group.commands.length > 1 && (
                  <button onClick={() => runGroup(group.name, group.commands)}
                    disabled={anyRunning || !session.target}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px] font-medium bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30 disabled:opacity-30 disabled:cursor-not-allowed transition-colors">
                    <Layers size={10} /> Run Group
                  </button>
                )}
              </div>
              {group.commands.map((command) => {
                const batchResult = batchResults.find((r) => r.command === command)
                const batchOk = batchResult && !batchResult.error && batchResult.returncode === 0
                const batchFail = batchResult && (batchResult.error || batchResult.returncode !== 0)
                return (
                  <button key={command} onClick={() => setSelected(command)}
                    className={`w-full text-left px-3 py-2 text-[11px] font-mono border-l-2 transition-colors break-words ${
                      selected === command
                        ? 'bg-phantom-cyan/10 border-l-phantom-cyan text-phantom-cyan'
                        : batchOk ? 'border-l-phantom-green bg-phantom-green/5 text-text-primary'
                        : batchFail ? 'border-l-phantom-error bg-phantom-error/5 text-text-primary'
                        : 'border-l-transparent text-text-secondary hover:bg-surface-hover hover:text-text-primary'
                    }`}>
                    {command}
                    {batchOk && <CheckCircle2 size={10} className="inline ml-1.5 text-phantom-green" />}
                    {batchFail && <AlertTriangle size={10} className="inline ml-1.5 text-phantom-error" />}
                  </button>
                )
              })}
            </div>
          ))}
        </div>

        {/* Output area */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          {/* Selected command + execute */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <div className="flex items-center justify-between mb-2">
              <span className="text-[10px] uppercase tracking-wider text-text-dim">Selected command</span>
              <button onClick={startEdit} disabled={!selected || anyRunning}
                className="flex items-center gap-1 text-[10px] text-text-dim hover:text-phantom-cyan transition-colors disabled:opacity-30"
                title="Edit command inline before running">
                <Pencil size={11} /> Edit
              </button>
            </div>
            {editing ? (
              <div className="flex gap-2">
                <input type="text" value={editValue} onChange={(e) => setEditValue(e.target.value)}
                  onKeyDown={(e) => { if (e.key === 'Enter') confirmEdit(); if (e.key === 'Escape') setEditing(false) }}
                  className="flex-1 bg-surface border border-phantom-cyan rounded px-3 py-2 text-xs font-mono text-text-primary focus:outline-none"
                  autoFocus />
                <button onClick={confirmEdit}
                  className="px-3 py-2 rounded bg-phantom-cyan/20 text-phantom-cyan text-xs font-medium">✓</button>
                <button onClick={() => setEditing(false)}
                  className="px-3 py-2 rounded bg-surface-border text-text-secondary text-xs font-medium">✗</button>
              </div>
            ) : (
              <div className="bg-surface border border-surface-border rounded px-3 py-2 text-xs font-mono text-text-primary break-words min-h-[42px]">
                {selected || 'Select a command (or use Run Group to execute a whole group)'}
              </div>
            )}
            <div className="flex gap-2 mt-3">
              <button onClick={run} disabled={!selected || !session.target || anyRunning}
                className="flex-1 px-3 py-2 rounded bg-phantom-cyan/20 text-phantom-cyan text-xs font-semibold hover:bg-phantom-cyan/30 disabled:opacity-30 disabled:cursor-not-allowed flex items-center justify-center gap-2">
                {running ? <Loader2 size={13} className="animate-spin" /> : <CirclePlay size={13} />}
                {running ? 'Running...' : 'Run Selected'}
              </button>
              {batchRunning && (
                <button onClick={() => setBatchRunning(false)}
                  className="px-3 py-2 rounded bg-phantom-error/20 text-phantom-error text-xs font-semibold hover:bg-phantom-error/30 flex items-center gap-2">
                  <StopCircle size={13} /> Stop
                </button>
              )}
            </div>
          </div>

          {/* Output */}
          <div className="bg-surface-card border border-surface-border rounded-lg flex-1 flex flex-col min-h-0">
            <div className="px-3 py-2 border-b border-surface-border text-xs font-semibold text-text-secondary uppercase tracking-wider">
              Output
              {batchResults.length > 0 && (
                <span className="ml-2 font-normal text-text-dim">
                  · {batchResults.filter((r) => !r.error && r.returncode === 0).length}/{batchResults.length} OK
                </span>
              )}
            </div>
            <pre className="flex-1 overflow-auto p-3 text-xs leading-5 font-mono text-text-primary whitespace-pre-wrap">
              {output || 'Command output will appear here.'}
            </pre>
          </div>
        </div>
      </div>
    </div>
  )
}