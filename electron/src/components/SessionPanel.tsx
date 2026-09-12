import { useState, useEffect, useRef } from 'react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'
import {
  Target, Crosshair, BookOpen, StickyNote, History, Save, FolderOpen,
  Play, Wrench, Brain, ListTree, Download, Upload, Search,
  Wand2, AlertTriangle, CheckCircle2, RefreshCw, X
} from 'lucide-react'

export default function SessionPanel() {
  const { session, setSession, addNote } = useStore()
  const { api } = useApi()
  const [newNote, setNewNote] = useState('')
  const [profileName, setProfileName] = useState('')
  const [sessionName, setSessionName] = useState('')
  const [showKnowledge, setShowKnowledge] = useState(false)
  const [showWordlists, setShowWordlists] = useState(false)

  // Wordlist state
  const [wordlists, setWordlists] = useState<string[]>([])
  const [wlSearch, setWlSearch] = useState('')
  const [wlMsg, setWlMsg] = useState('')
  const [wlPattern, setWlPattern] = useState('aA1')
  const [wlName, setWlName] = useState('custom')

  // Knowledge state
  const [knowledge, setKnowledge] = useState<{ summary: Record<string, number>; hypotheses: Array<{ kind: string; text: string }>; target: string } | null>(null)

  // Core-sync state: what the auto-mode bridged into the manual session
  // (services/creds/OS, internal peers, cloud, EDR gaps, mobile surfaces)
  type CoreKnowledge = {
    services?: Array<{ port: number; service?: string; version?: string; host?: string }>
    os_info?: { name?: string; accuracy?: number }
    creds_found?: Array<{ username: string; service?: string; host?: string }>
    next_targets?: Array<{ ip: string; service?: string; via?: string }>
    beacon_deployed?: boolean
    persistence_set?: boolean
    cloud_findings?: Record<string, unknown[]>
    edr_gaps?: string[]
    mobile_surface?: { platforms?: string[]; mdm?: unknown[]; surface?: unknown[] }
    k8s_escape?: boolean
  }
  const [coreKnow, setCoreKnow] = useState<CoreKnowledge | null>(null)

  const loadCoreKnowledge = async () => {
    const res = await api('GET', '/api/session')
    if (res.status === 200 && res.data) {
      const d = res.data as { knowledge?: CoreKnowledge }
      setCoreKnow(d.knowledge || {})
    } else {
      setCoreKnow({})
    }
  }

  useEffect(() => { void loadCoreKnowledge() }, [])

  // Craft-lure state
  const [crafting, setCrafting] = useState(false)
  const [craftOut, setCraftOut] = useState<{ kind?: string; url?: string; code?: string; html?: string; payload_url?: string; hint?: string; video_title?: string; error?: string } | null>(null)
  const [craftReelArg, setCraftReelArg] = useState('')
  const [craftImgArg, setCraftImgArg] = useState('')
  const [craftMsg, setCraftMsg] = useState('')
  const [watching, setWatching] = useState(false)
  const [hitsCount, setHitsCount] = useState(0)
  const watchRef = useRef<ReturnType<typeof setInterval> | null>(null)

  const handleCraft = async (type: string, arg?: string) => {
    setCrafting(true)
    setCraftMsg('')
    setHitsCount(0)
    if (watchRef.current) { clearInterval(watchRef.current); watchRef.current = null; setWatching(false) }
    const body: Record<string, unknown> = { type }
    if (arg) body.arg = arg
    const res = await api('POST', '/api/craft', body)
    setCrafting(false)
    if (res.status === 200 && res.data) {
      setCraftOut(res.data as typeof craftOut)
    } else {
      const d = res.data as { error?: string }
      setCraftOut({ error: d?.error || 'craft failed' })
    }
  }

  const handleWatch = async () => {
    if (!craftOut?.code) return
    if (watching) {
      if (watchRef.current) { clearInterval(watchRef.current); watchRef.current = null }
      setWatching(false)
      return
    }
    setWatching(true)
    const tick = async () => {
      const r = await api('GET', `/api/craft/hits?code=${craftOut.code}`)
      if (r.status === 200 && r.data) {
        const d = r.data as { hits?: unknown[]; opens?: unknown[]; creds?: unknown[] }
        setHitsCount((d.hits || []).length + (d.opens || []).length)
      }
    }
    void tick()
    watchRef.current = setInterval(tick, 3000)
  }

  useEffect(() => () => { if (watchRef.current) clearInterval(watchRef.current) }, [])

  // Preflight state
  const [preflight, setPreflight] = useState<{ missing: Array<{ tool: string; module: string; hint: string }>; ok: boolean; message: string } | null>(null)
  const [pfLoading, setPfLoading] = useState(false)
  const [installing, setInstalling] = useState<Record<string, { busy: boolean; output: string; ok?: boolean }>>({})

  // Local edit buffers: while the user types we must NOT let the 2s session
  // poll clobber the field (the poll returns the last SAVED value). Each
  // field keeps its draft until blur/Enter persists it to the backend.
  const [draftTarget, setDraftTarget] = useState<string | null>(null)
  const [draftScope, setDraftScope] = useState<string | null>(null)
  const [draftLhost, setDraftLhost] = useState<string | null>(null)
  const [draftLport, setDraftLport] = useState<string | null>(null)
  const [setMsg, setSetMsg] = useState<{ ok: boolean; text: string } | null>(null)

  const persist = async (key: string, value: unknown, clearDraft: () => void) => {
    const res = await api('POST', '/api/session/set', { key, value })
    const d = res.data as { status?: string; error?: string; value?: unknown }
    if (res.status === 200 && d.status === 'ok') {
      setSession({ [key]: value } as never)
      setSetMsg({ ok: true, text: `${key} saved` })
    } else {
      setSetMsg({ ok: false, text: d.error || `failed to set ${key}` })
    }
    clearDraft()
  }

  const handleSetTarget = (value: string) => {
    setDraftTarget(value)
  }
  const handleSetScope = (value: string) => {
    setDraftScope(value)
  }
  const handleSetLhost = (value: string) => {
    setDraftLhost(value)
  }
  const handleSetLport = (value: string) => {
    setDraftLport(value)
    const p = parseInt(value, 10)
    if (!isNaN(p) && value) setSession({ lport: p })
  }

  const handleAddNote = async () => {
    if (!newNote.trim()) return
    const note = newNote.trim()
    setNewNote('')
    // notes must reach the backend session, otherwise the 2s poll
    // overwrites the store with the backend's (older) note list
    const res = await api('POST', '/api/session/notes', { note })
    if (res.status === 200) addNote(note)
  }

  const handleSaveProfile = () => {
    if (!profileName.trim()) return
    api('POST', '/api/session/profile/save', { name: profileName })
    setProfileName('')
  }

  const handleLoadProfile = (name: string) =>
    api('POST', '/api/session/profile/load', { name })

  const [suggestion, setSuggestion] = useState<{ module: string; reason: string; commands: string[] } | null>(null)
  const [suggLoading, setSuggLoading] = useState(false)

  const handleNext = async () => {
    setSuggLoading(true)
    const res = await api('POST', '/api/session/next')
    setSuggLoading(false)
    setSuggestion(res.data as { module: string; reason: string; commands: string[] })
  }
  const handleRunSequence = async () => {
    const res = await api('POST', '/api/session/run')
    if (res.status === 200) api('POST', '/api/session/history', { cmd: 'run <sequence>' })
    return res
  }

  const handlePreflight = async (module?: string) => {
    setPfLoading(true)
    setShowKnowledge(false)
    const res = await api('POST', '/api/session/preflight', { module })
    setPfLoading(false)
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

  const handleShowKnowledge = async () => {
    setPreflight(null)
    setShowKnowledge(!showKnowledge)
    if (!showKnowledge) {
      const res = await api('GET', '/api/session/knowledge')
      setKnowledge(res.data as { summary: Record<string, number>; hypotheses: []; target: string })
    }
  }

  const handleResetKnowledge = async () => {
    await api('POST', '/api/session/knowledge/reset')
    setKnowledge(null)
    setShowKnowledge(false)
  }

  // Session save/load
  const handleSaveSession = async () => {
    if (!sessionName.trim()) return
    await api('POST', '/api/session/save', { name: sessionName })
    setSessionName('')
  }
  const handleLoadSession = async (name: string) =>
    api('POST', '/api/session/load', { name })

  // Wordlist management
  const handleLoadWordlists = async () => {
    setShowWordlists(!showWordlists)
    if (!showWordlists) {
      const res = await api('GET', '/api/session/wordlists?action=list')
      setWordlists((res.data as { wordlists: string[] })?.wordlists || [])
    }
  }
  const handleUseWordlist = async (name: string) => {
    const res = await api('POST', '/api/session/wordlists/use', { name })
    if (res.status === 200) setWlMsg(`Active: ${name}`)
    else setWlMsg('Failed')
  }
  const handleGenerateWordlist = async () => {
    setWlMsg('Generating...')
    const res = await api('POST', '/api/session/wordlists/generate', { pattern: wlPattern, name: wlName, min: 4, max: 8, mutate: true })
    if (res.status === 200) { setWlMsg('Generated ✓'); handleLoadWordlists() }
    else setWlMsg('Generation failed')
  }

  return (
    <div className="p-4 flex flex-col gap-4 h-full">
      <div>
        <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
          <Target size={19} className="text-phantom-cyan" /> Session Manager
        </h1>
        <p className="text-xs text-text-dim mt-0.5">Target, scope, wordlists, knowledge, and engagement state</p>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Left: Configuration */}
        <div className="w-[380px] flex-shrink-0 flex flex-col gap-2 overflow-auto">
          {/* Target */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 0 }}>
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3 flex items-center gap-1.5">
              <Crosshair size={13} /> Target
            </h2>
            <div className="space-y-2">
              <div className="flex items-end gap-1.5">
                <div className="flex-1">
                  <InputGroup label="Target" value={draftTarget ?? session.target} onChange={handleSetTarget} placeholder="10.0.0.5 or mario@corp.com"
                    onBlur={() => draftTarget !== null && persist('target', draftTarget.trim(), () => setDraftTarget(null))}
                    onEnter={() => draftTarget !== null && persist('target', draftTarget.trim(), () => setDraftTarget(null))} />
                </div>
                {session.target && (
                  <button title="Remove target (leave session without a target)"
                    onClick={async () => {
                      const res = await api('POST', '/api/session/set', { key: 'target', value: '' })
                      const d = res.data as { status?: string; error?: string; cleared?: boolean }
                      if (res.status === 200 && d.status === 'ok') {
                        setSession({ target: '' } as never)
                        setSetMsg({ ok: true, text: d.cleared ? 'target removed' : 'no target set' })
                      } else {
                        setSetMsg({ ok: false, text: d.error || 'failed to remove target' })
                      }
                    }}
                    className="h-[38px] px-2.5 rounded bg-surface border border-surface-border text-text-dim hover:text-red-400 hover:border-red-500/40 transition-colors flex items-center"
                  >
                    <X size={14} />
                  </button>
                )}
              </div>
              <InputGroup label="Scope" value={draftScope ?? session.scope.join(', ')} onChange={handleSetScope} placeholder="10.0.0.0/24"
                onBlur={() => draftScope !== null && persist('scope', draftScope, () => setDraftScope(null))}
                onEnter={() => draftScope !== null && persist('scope', draftScope, () => setDraftScope(null))} />
              <div className="flex gap-2">
                <InputGroup label="LHOST" value={draftLhost ?? session.lhost} onChange={handleSetLhost} placeholder="0.0.0.0"
                  onBlur={() => draftLhost !== null && persist('lhost', draftLhost, () => setDraftLhost(null))}
                  onEnter={() => draftLhost !== null && persist('lhost', draftLhost, () => setDraftLhost(null))} />
                <InputGroup label="LPORT" value={draftLport ?? (session.lport ? String(session.lport) : '')} onChange={handleSetLport} placeholder="4444"
                  onBlur={() => draftLport !== null && persist('lport', draftLport, () => setDraftLport(null))}
                  onEnter={() => draftLport !== null && persist('lport', draftLport, () => setDraftLport(null))} />
              </div>
              {setMsg && (
                <div className={`text-[10px] ${setMsg.ok ? 'text-emerald-400' : 'text-red-400'}`}>
                  {setMsg.ok ? '✓ ' : '✗ '}{setMsg.text}
                </div>
              )}

              {/* Suggested next step */}
              <div className="flex gap-1.5">
                <button onClick={handleNext} disabled={!session.target || suggLoading}
                  className={`flex-1 py-2 rounded text-xs font-semibold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors
                    ${session.target ? 'bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30' : 'bg-surface-border text-text-dim cursor-not-allowed'}`}>
                  <Brain size={12} /> {suggLoading ? 'Thinking...' : 'Suggest Next'}
                </button>
                <button onClick={handleRunSequence} disabled={!session.target}
                  className={`flex-1 py-2 rounded text-xs font-semibold uppercase tracking-wider flex items-center justify-center gap-1.5 transition-colors
                    ${session.target ? 'bg-phantom-magenta/20 text-phantom-magenta hover:bg-phantom-magenta/30' : 'bg-surface-border text-text-dim cursor-not-allowed'}`}>
                  <Play size={12} /> Run
                </button>
              </div>
              {suggestion && (
                <div className="mt-2 p-2 rounded bg-surface border border-phantom-cyan/40">
                  <div className="text-[10px] font-semibold text-phantom-cyan uppercase tracking-wider">
                    Next: {suggestion.module.toUpperCase()}
                  </div>
                  <div className="text-[10px] text-text-secondary mt-0.5">{suggestion.reason}</div>
                  {suggestion.commands.length > 0 && (
                    <div className="mt-1.5 space-y-0.5 max-h-[110px] overflow-auto">
                      {suggestion.commands.slice(0, 6).map((c, i) => (
                        <div key={i} className="text-[10px] font-mono text-text-primary truncate">▸ {c}</div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </div>
          </div>

          {/* Knowledge */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 3 }}>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Brain size={13} className="text-phantom-green" /> Knowledge
              </h2>
              <div className="flex gap-1">
                <button onClick={handleShowKnowledge} className="text-[10px] text-text-dim hover:text-text-primary px-2 py-0.5 rounded bg-surface border border-surface-border">
                  {showKnowledge ? 'Hide' : 'Show'}
                </button>
                <button onClick={handleResetKnowledge} className="text-[10px] text-text-dim hover:text-text-primary px-2 py-0.5 rounded bg-surface border border-surface-border">
                  Reset
                </button>
              </div>
            </div>
            {showKnowledge && knowledge && (
              <div className="space-y-1.5 text-xs">
                <div className="text-text-dim">Target: <span className="text-text-primary">{knowledge.target || '—'}</span></div>
                {Object.entries(knowledge.summary).map(([k, v]) => (
                  <div key={k} className="flex justify-between">
                    <span className="text-text-secondary capitalize">{k}</span>
                    <span className="text-text-primary font-mono">{v}</span>
                  </div>
                ))}
                {knowledge.hypotheses.length > 0 && (
                  <div className="mt-2 pt-2 border-t border-surface-border">
                    <div className="text-phantom-green text-[10px] font-semibold mb-1">▶ Live Hypotheses</div>
                    {knowledge.hypotheses.map((h, i) => (
                      <div key={i} className="text-text-secondary text-[10px]">{h.kind}: {h.text}</div>
                    ))}
                  </div>
                )}
              </div>
            )}
            {showKnowledge && !knowledge && (
              <div className="text-xs text-text-dim">Click Show to load WorldModel state</div>
            )}
          </div>

          {/* Core sync — facts the auto-mode bridged into the manual session */}
          {coreKnow && (
            <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 3 }}>
              <div className="flex items-center justify-between mb-2">
                <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                  <Brain size={13} className="text-phantom-green" /> Core Sync
                </h2>
                <button onClick={loadCoreKnowledge}
                  className="text-[10px] text-text-dim hover:text-text-primary px-2 py-0.5 rounded bg-surface border border-surface-border">
                  Refresh
                </button>
              </div>
              <div className="grid grid-cols-2 gap-x-3 gap-y-1 text-[10px]">
                <div className="flex justify-between"><span className="text-text-dim">Services</span><span className="text-text-primary font-mono">{(coreKnow.services || []).length}</span></div>
                <div className="flex justify-between"><span className="text-text-dim">Credentials</span><span className="text-text-primary font-mono">{(coreKnow.creds_found || []).length}</span></div>
                <div className="flex justify-between"><span className="text-text-dim">OS</span><span className="text-text-primary">{coreKnow.os_info?.name || '—'}</span></div>
                <div className="flex justify-between"><span className="text-text-dim">Pivot peers</span><span className="text-text-primary font-mono">{(coreKnow.next_targets || []).length}</span></div>
                <div className="flex justify-between"><span className="text-text-dim">EDR gaps</span><span className="text-text-primary font-mono">{(coreKnow.edr_gaps || []).length}</span></div>
                <div className="flex justify-between"><span className="text-text-dim">Beacon</span><span className={coreKnow.beacon_deployed ? 'text-phantom-green' : 'text-text-dim'}>{coreKnow.beacon_deployed ? 'UP' : '—'}</span></div>
                <div className="flex justify-between"><span className="text-text-dim">Persistence</span><span className={coreKnow.persistence_set ? 'text-phantom-green' : 'text-text-dim'}>{coreKnow.persistence_set ? 'SET' : '—'}</span></div>
                <div className="flex justify-between"><span className="text-text-dim">Mobile</span><span className="text-text-primary">{(coreKnow.mobile_surface?.platforms || []).join(', ') || '—'}</span></div>
              </div>
              {(coreKnow.next_targets || []).length > 0 && (
                <div className="mt-2 pt-2 border-t border-surface-border">
                  <div className="text-phantom-yellow text-[10px] font-semibold mb-1">▶ Internal pivot candidates</div>
                  {(coreKnow.next_targets || []).slice(0, 6).map((n, i) => (
                    <div key={i} className="flex items-center justify-between text-[10px] text-text-secondary">
                      <span className="font-mono">{n.ip}{n.service ? ` · ${n.service}` : ''}</span>
                      <button onClick={async () => { await api('POST', '/api/session/set', { key: 'target', value: n.ip }) }}
                        className="text-[9px] text-text-dim hover:text-phantom-green">Use as target</button>
                    </div>
                  ))}
                </div>
              )}
            </div>
          )}

          {/* Preflight */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 4 }}>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Wrench size={13} className="text-phantom-yellow" /> Preflight
              </h2>
            </div>
            <div className="flex gap-1.5 mb-2">
              <button onClick={() => handlePreflight()} disabled={pfLoading}
                className="flex-1 py-1.5 rounded text-[10px] font-medium bg-surface border border-surface-border text-text-secondary hover:text-text-primary transition-colors">
                {pfLoading ? 'Checking...' : 'Check Mode'}
              </button>
              <button onClick={() => handlePreflight('scan')} disabled={pfLoading}
                className="flex-1 py-1.5 rounded text-[10px] font-medium bg-surface border border-surface-border text-text-secondary hover:text-text-primary transition-colors">
                Scan
              </button>
              <button onClick={() => handlePreflight('exploit')} disabled={pfLoading}
                className="flex-1 py-1.5 rounded text-[10px] font-medium bg-surface border border-surface-border text-text-secondary hover:text-text-primary transition-colors">
                Exploit
              </button>
            </div>
            {preflight && (
              <div className="text-xs">
                {preflight.ok ? (
                  <div className="flex items-center gap-1.5 text-phantom-green"><CheckCircle2 size={12} /> All tools installed</div>
                ) : (
                  <>
                    <div className="flex items-center gap-1.5 text-phantom-yellow mb-1"><AlertTriangle size={12} /> {preflight.message}</div>
                    {preflight.missing.slice(0, 6).map((m, i) => (
                      <div key={i} className="text-[10px] text-text-secondary ml-5">
                        <span className="text-phantom-error">{m.tool}</span> [{m.module}] — {m.hint}
                        <button
                          onClick={() => handleInstallTool(m.tool)}
                          disabled={installing[m.tool]?.busy}
                          className="ml-1.5 px-1.5 py-0.5 rounded bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30 disabled:opacity-50 transition-colors"
                        >
                          {installing[m.tool]?.busy ? '...' : 'Install'}
                        </button>
                        {installing[m.tool]?.output && (
                          <pre className={`mt-1 ml-1 font-mono text-[9px] whitespace-pre-wrap max-h-24 overflow-auto ${installing[m.tool]?.ok ? 'text-phantom-green' : 'text-text-dim'}`}>
                            {installing[m.tool]?.output}
                          </pre>
                        )}
                      </div>
                    ))}
                  </>
                )}
              </div>
            )}
          </div>

          {/* Craft Lures */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 1 }}>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Wand2 size={13} className="text-phantom-magenta" /> Craft Lure
              </h2>
            </div>
            <p className="text-[10px] text-text-dim mb-2">Build the delivery layer: IP grabbers on a link or image YOU choose, zero-click pixels, or a camouflaged beacon link. Paste into a DM / WhatsApp / email, then watch for the target.</p>
            <div className="grid grid-cols-2 gap-1.5 mb-2">
              <button onClick={() => handleCraft('ipgrab')} disabled={crafting}
                className="py-1.5 rounded text-[10px] font-medium bg-surface border border-surface-border text-text-secondary hover:text-text-primary disabled:opacity-50 transition-colors">IP Grabber</button>
              <button onClick={() => handleCraft('pixel')} disabled={crafting}
                className="py-1.5 rounded text-[10px] font-medium bg-surface border border-surface-border text-text-secondary hover:text-text-primary disabled:opacity-50 transition-colors">Pixel (zero-click)</button>
              <button onClick={() => handleCraft('beacon')} disabled={crafting}
                className="py-1.5 rounded text-[10px] font-medium bg-surface border border-surface-border text-text-secondary hover:text-text-primary disabled:opacity-50 transition-colors">Beacon link</button>
              <button onClick={() => handleCraft('beacon-player')} disabled={crafting}
                className="py-1.5 rounded text-[10px] font-medium bg-surface border border-surface-border text-text-secondary hover:text-text-primary disabled:opacity-50 transition-colors">Beacon Player</button>
            </div>
            <div className="space-y-1.5 mb-2">
              <div className="flex gap-1.5">
                <input type="text" value={craftReelArg} onChange={(e) => setCraftReelArg(e.target.value)}
                  placeholder="Reel: paste an IG/TikTok/YT link or a search term"
                  className="flex-1 bg-surface border border-surface-border rounded px-2 py-1 text-[10px] font-mono text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-magenta" />
                <button onClick={() => handleCraft('reel', craftReelArg)} disabled={crafting || !craftReelArg.trim()}
                  className="px-2.5 py-1 rounded bg-phantom-magenta/20 text-phantom-magenta text-[10px] font-medium disabled:opacity-50">Reel</button>
              </div>
              <div className="flex gap-1.5">
                <input type="text" value={craftImgArg} onChange={(e) => setCraftImgArg(e.target.value)}
                  placeholder="Image: local path or URL (zero-click on render)"
                  className="flex-1 bg-surface border border-surface-border rounded px-2 py-1 text-[10px] font-mono text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-magenta" />
                <button onClick={() => handleCraft('image', craftImgArg)} disabled={crafting || !craftImgArg.trim()}
                  className="px-2.5 py-1 rounded bg-phantom-magenta/20 text-phantom-magenta text-[10px] font-medium disabled:opacity-50">Image</button>
              </div>
            </div>
            {crafting && <div className="text-[10px] text-text-dim">Crafting...</div>}
            {craftOut && !crafting && (
              <div className="rounded bg-surface border border-phantom-magenta/40 p-2 space-y-1.5">
                <div className="flex items-center justify-between">
                  <span className="text-[10px] font-bold text-phantom-magenta uppercase tracking-wider">READY TO PASTE</span>
                  <button onClick={() => { if (craftOut.url) navigator.clipboard?.writeText(craftOut.url); setCraftMsg('Copied!') }}
                    className="px-1.5 py-0.5 rounded bg-surface-border text-text-secondary text-[9px] hover:text-text-primary">
                    {craftMsg || 'Copy'}
                  </button>
                </div>
                <div className="text-[10px] font-mono text-text-primary break-all">{craftOut.url}</div>
                {craftOut.code && <div className="text-[9px] text-text-dim font-mono">code: {craftOut.code}</div>}
                {craftOut.video_title && <div className="text-[9px] text-text-dim truncate">video: {craftOut.video_title}</div>}
                {craftOut.html && (
                  <pre className="text-[9px] font-mono text-text-secondary whitespace-pre-wrap break-all bg-surface-card rounded p-1.5 max-h-16 overflow-auto">{craftOut.html}</pre>
                )}
                {craftOut.payload_url && <div className="text-[9px] text-text-dim font-mono break-all">serves: {craftOut.payload_url}</div>}
                {craftOut.hint && <div className="text-[9px] text-text-dim">{craftOut.hint}</div>}
                {craftOut.error && <div className="text-[9px] text-phantom-error">{craftOut.error}</div>}
                {craftOut.code && (
                  <div className="flex items-center justify-between">
                    <button onClick={handleWatch} className="text-[9px] text-phantom-green hover:text-phantom-magenta">
                      {watching ? `Watching (${hitsCount} hit${hitsCount === 1 ? '' : 's'})...` : 'Watch for target'}
                    </button>
                    <button onClick={async () => { if (craftOut.code) { const r = await api('GET', `/api/craft/hits?code=${craftOut.code}`); if (r.status === 200 && r.data) { const d = r.data as { hits?: unknown[]; opens?: unknown[]; creds?: unknown[] }; setCraftMsg(`hits ${(d.hits || []).length} · opens ${(d.opens || []).length} · creds ${(d.creds || []).length}`) } } }} className="text-[9px] text-text-dim hover:text-text-primary">Check now</button>
                  </div>
                )}
              </div>
            )}
          </div>

          {/* Wordlists */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 5 }}>
            <div className="flex items-center justify-between mb-2">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <BookOpen size={13} className="text-phantom-cyan" /> Wordlists
              </h2>
              <button onClick={handleLoadWordlists} className="text-[10px] text-text-dim hover:text-text-primary px-2 py-0.5 rounded bg-surface border border-surface-border">
                {showWordlists ? 'Hide' : 'Manage'}
              </button>
            </div>
            {session.active_wordlist && (
              <div className="text-[10px] text-text-dim mb-2">Active: <span className="text-phantom-green font-mono">{session.active_wordlist.split('/').pop()}</span></div>
            )}
            {showWordlists && (
              <div className="space-y-2 text-xs">
                <div className="flex gap-1">
                  <input type="text" value={wlSearch} onChange={(e) => setWlSearch(e.target.value)} placeholder="Search..."
                    className="flex-1 bg-surface border border-surface-border rounded px-2 py-1 text-[10px] text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-cyan" />
                  <button className="px-2 py-1 rounded bg-phantom-cyan/20 text-phantom-cyan text-[10px]"><Search size={11} /></button>
                </div>
                {wlMsg && <div className={`text-[10px] ${wlMsg.includes('✓') ? 'text-phantom-green' : 'text-phantom-yellow'}`}>{wlMsg}</div>}
                <div className="max-h-[80px] overflow-auto space-y-0.5">
                  {wordlists.map((w) => (
                    <div key={w} className="flex justify-between items-center text-[10px] bg-surface rounded px-2 py-1">
                      <span className="text-text-primary truncate">{w}</span>
                      <button onClick={() => handleUseWordlist(w)} className="text-phantom-cyan hover:text-phantom-magenta ml-1">use</button>
                    </div>
                  ))}
                </div>
                {/* Generate */}
                <div className="pt-1 border-t border-surface-border">
                  <div className="text-[10px] text-text-dim mb-1">Generate custom</div>
                  <div className="flex gap-1">
                    <input type="text" value={wlPattern} onChange={(e) => setWlPattern(e.target.value)}
                      className="w-12 bg-surface border border-surface-border rounded px-1.5 py-1 text-[10px] font-mono text-text-primary focus:outline-none focus:border-phantom-cyan" />
                    <input type="text" value={wlName} onChange={(e) => setWlName(e.target.value)}
                      className="flex-1 bg-surface border border-surface-border rounded px-1.5 py-1 text-[10px] text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-cyan" />
                    <button onClick={handleGenerateWordlist}
                      className="px-2 py-1 rounded bg-phantom-green/20 text-phantom-green text-[10px] flex items-center gap-1">
                      <Wand2 size={10} /> Gen
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Profiles */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 6 }}>
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Save size={13} /> Profiles
            </h2>
            <div className="flex gap-1.5 mb-2">
              <input type="text" value={profileName} onChange={(e) => setProfileName(e.target.value)} placeholder="profile name"
                className="flex-1 bg-surface border border-surface-border rounded px-2 py-1 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-cyan" />
              <button onClick={handleSaveProfile}
                className="px-2.5 py-1 rounded bg-phantom-cyan/20 text-phantom-cyan text-xs hover:bg-phantom-cyan/30">Save</button>
            </div>
          </div>

          {/* Full Session Save/Load */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3" style={{ order: 7 }}>
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <FolderOpen size={13} /> Session Save/Load
            </h2>
            <div className="flex gap-1.5">
              <input type="text" value={sessionName} onChange={(e) => setSessionName(e.target.value)} placeholder="session name"
                className="flex-1 bg-surface border border-surface-border rounded px-2 py-1 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-cyan" />
              <button onClick={handleSaveSession}
                className="px-2.5 py-1 rounded bg-phantom-green/20 text-phantom-green text-xs flex items-center gap-1 hover:bg-phantom-green/30">
                <Download size={11} /> Save
              </button>
            </div>
          </div>
        </div>

        {/* Right: History + Notes */}
        <div className="flex-1 flex flex-col gap-2 min-w-0">
          <div className="bg-surface-card border border-surface-border rounded-lg flex-1 flex flex-col min-h-0">
            <div className="px-3 py-2 border-b border-surface-border">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <StickyNote size={13} /> Notes
              </h2>
            </div>
            <div className="flex-1 overflow-auto p-2 space-y-1">
              {session.notes.length === 0 ? (
                <div className="text-xs text-text-dim p-4 text-center">No notes yet</div>
              ) : session.notes.map((n, i) => (
                <div key={i} className="text-xs text-text-primary py-1 px-2 rounded bg-surface border border-surface-border">
                  ✓ {typeof n === 'string' ? n : n?.text ?? String(n)}
                </div>
              ))}
            </div>
            <div className="p-2 border-t border-surface-border flex gap-2">
              <input type="text" value={newNote} onChange={(e) => setNewNote(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddNote()} placeholder="Add a note..."
                className="flex-1 bg-surface border border-surface-border rounded px-2 py-1 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-cyan" />
              <button onClick={handleAddNote}
                className="px-2.5 py-1 rounded bg-phantom-cyan/20 text-phantom-cyan text-xs hover:bg-phantom-cyan/30">Add</button>
            </div>
          </div>

          <div className="bg-surface-card border border-surface-border rounded-lg h-[160px] flex-shrink-0 flex flex-col">
            <div className="px-3 py-2 border-b border-surface-border">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <History size={13} /> Command History
              </h2>
            </div>
            <div className="flex-1 overflow-auto p-2">
              {session.history.length === 0 ? (
                <div className="text-xs text-text-dim p-4 text-center">No commands yet</div>
              ) : session.history.slice(-20).map((h, i) => (
                <div key={i} className="text-xs font-mono text-text-secondary py-0.5">
                  <span className="text-text-dim mr-2">{String(i + 1).padStart(2)}</span>{h}
                </div>
              ))}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function InputGroup({ label, value, onChange, placeholder, onBlur, onEnter }: { label: string; value: string; onChange: (v: string) => void; placeholder: string; onBlur?: () => void; onEnter?: () => void }) {
  return (
    <div className={label.length < 6 ? 'flex-1' : ''}>
      <label className="text-[10px] text-text-dim block mb-1">{label}</label>
      <input type="text" value={value} onChange={(e) => onChange(e.target.value)} placeholder={placeholder}
        onBlur={onBlur}
        onKeyDown={(e) => { if (e.key === 'Enter' && onEnter) { onEnter(); (e.target as HTMLInputElement).blur() } }}
        className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5 text-xs font-mono text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-cyan" />
    </div>
  )
}