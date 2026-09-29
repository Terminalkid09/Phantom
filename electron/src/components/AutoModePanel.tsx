import { useState, useRef, useEffect } from 'react'
import { useStore } from '@/store'
import { apiError, useApi } from '@/hooks/useApi'
import { useSerialPoll } from '@/hooks/useSerialPoll'
import {
  Bot, Play, Square, FileText, Plus, X, Zap,
  Shield, Gauge, Swords, CheckCircle2, Circle,
  Loader2, AlertTriangle, ChevronRight, Brain, UserCheck, Copy
} from 'lucide-react'

const MODE_ICONS = {
  default: Gauge,
  stealth: Shield,
  aggressive: Swords,
  speed: Zap
}

const MODE_LABELS: Record<string, string> = {
  default: 'Default — balanced OPSEC vs speed',
  stealth: 'Stealth — paranoid, minimal footprint, slower',
  aggressive: 'Aggressive — loud tools, fast results',
  speed: 'Speed — first viable opening, opportunistic'
}

const PROFILES = ['enterprise', 'smb', 'cloud', 'financial', 'government', 'mobile']
const GOALS = ['deep', 'deliver', 'complete_kill_chain', 'footprint', 'beacon', 'creds', 'web', 'identity', 'post_exploit', 'ad', 'crack', 'lateral', 'cleanup']

const GOAL_HINTS: Record<string, string> = {
  deep: 'Full ladder: beacon → SYSTEM/root → AD (kerberoast/AS-REP/DCSync) → crack → lateral',
  deliver: 'Stop at beacon injection + persistence (default)',
  complete_kill_chain: 'Complete kill chain with all phases attempted',
  footprint: 'External footprint only — no exploitation',
  beacon: 'Beacon as fast as possible',
  creds: 'Focus on credential harvesting',
  web: 'Web app chain: footprint → hunt → RCE foothold (no beacon needed)',
  identity: 'Identity/OSINT focus',
  post_exploit: 'Beacon + privilege escalation + injection',
  ad: 'Active Directory: enum + kerberoast/AS-REP/DCSync',
  crack: 'Hash cracking emphasis',
  lateral: 'Lateral movement emphasis',
  cleanup: 'Post-engagement cleanup simulation'
}

interface IdentityCandidate {
  handle: string
  platform: string
  avatar_url?: string
  bio?: string
  followers?: string
  following?: string
  link?: string
  tier?: string
  score?: number
  evidence?: string
}

interface IdentityCheck {
  id: string
  kind: string
  target: string
  candidates: IdentityCandidate[]
  description: string
}

interface ProfilePreview {
  username: string
  platform: string
  state: string
  full_name: string
  bio: string
  link: string
  followers: string
  following: string
  posts: string
  avatar_url: string
}

export default function AutoModePanel() {
  const { autoMode, setAutoMode, appendReasoning, updateStep, ensureStep, session } = useStore()
  const { api, pollC2 } = useApi()
  const [newTarget, setNewTarget] = useState('')
  const reasoningRef = useRef<HTMLDivElement>(null)
  const pollIntervalRef = useRef<NodeJS.Timeout | null>(null)

  // identity start-gate: precise username + platform -> preview card
  const [idUser, setIdUser] = useState('')
  const [idPlatform, setIdPlatform] = useState('instagram')
  const [idPreview, setIdPreview] = useState<ProfilePreview | null>(null)
  const [idLoading, setIdLoading] = useState(false)
  // mid-run ambiguity decisions (operator eyes on close candidates)
  const [idChecks, setIdChecks] = useState<IdentityCheck[]>([])

  // Unmount cleanup
  useEffect(() => {
    return () => {
      if (pollIntervalRef.current) clearInterval(pollIntervalRef.current)
    }
  }, [])

  const handleClearLog = () => setAutoMode({ reasoning: [] })

  const handlePreview = async () => {
    const username = idUser.trim().replace(/^@/, '')
    if (!username) return
    setIdLoading(true)
    setIdPreview(null)
    const res = await api('POST', '/api/osint/preview', { username, platform: idPlatform })
    setIdLoading(false)
    if (res.status === 200 && res.data) setIdPreview(res.data as ProfilePreview)
  }

  const handlePreviewLaunch = () => {
    if (!idPreview) return
    if (!autoMode.targets.includes(idPreview.username)) {
      setAutoMode({ targets: [...autoMode.targets, idPreview.username] })
    }
    setIdPreview(null)
    setIdUser('')
  }

  const loadIdChecks = async () => {
    const res = await api('GET', '/api/identity/checks')
    if (res.status === 200 && res.data) {
      setIdChecks(((res.data as { checks?: IdentityCheck[] }).checks) || [])
    }
  }
  useSerialPoll(loadIdChecks, 5000)

  const answerCheck = async (id: string, decision: string) => {
    await api('POST', '/api/identity/confirm', { id, decision })
    void loadIdChecks()
  }

  const copyText = (text: string) => {
    navigator.clipboard?.writeText(text)
  }

  // Auto-scroll reasoning stream
  useEffect(() => {
    if (reasoningRef.current) {
      reasoningRef.current.scrollTop = reasoningRef.current.scrollHeight
    }
  }, [autoMode.reasoning])

  const handleAddTarget = () => {
    if (!newTarget.trim()) return
    setAutoMode({ targets: [...autoMode.targets, newTarget.trim()] })
    setNewTarget('')
  }

  const handleRemoveTarget = (i: number) => {
    setAutoMode({ targets: autoMode.targets.filter((_, j) => j !== i) })
  }

  const handleSetMode = (mode: typeof autoMode.mode) => {
    setAutoMode({ mode })
  }

  const handleLaunch = async () => {
    // SESSION TARGET FIRST: the Session panel's target is target #1 of the
    // run (the two panels share one backend session); extra targets added
    // here are ADDITIONAL targets, and duplicates are dropped.
    const all = [...(session.target ? [session.target] : []),
                 ...autoMode.targets]
    const targets = [...new Set(all.map((t) => t.trim()).filter(Boolean))]
    if (targets.length === 0) return

    setAutoMode({
      running: true,
      run_state: 'starting',
      startedAt: Date.now(),
      targets,
      plan: [],
      steps: [
        { name: 'SCAN', status: 'waiting' },
        { name: 'OSINT', status: 'waiting' },
        { name: 'OS DETECT', status: 'waiting' },
        { name: 'WEB RECON', status: 'waiting' },
        { name: 'CVE CORRELATE', status: 'waiting' },
        { name: 'CREDS', status: 'waiting' },
        { name: 'BEACON', status: 'waiting' },
        { name: 'PERSIST', status: 'waiting' }
      ],
      reasoning: [],
      current_step: 0
    })

    // Make sure the backend session carries the same target (Suggest Next,
    // reports and the manual Run all read session.target server-side)
    if (!session.target && targets[0]) {
      await api('POST', '/api/session/set', { key: 'target', value: targets[0] })
    }

    // Start the auto-mode engine
    const res = await api('POST', '/api/automode/run', {
      targets,
      mode: autoMode.mode,
      engine: autoMode.engine,
      force_network: autoMode.forceNetwork,
      profile: autoMode.profile,
      goal: autoMode.goal,
      agents: autoMode.agents,
      llm: autoMode.llm,
      experience: autoMode.experience,
      verbose: autoMode.verbose
    })

    if (res.status === 200) {
      // Poll for stream updates
      setAutoMode({ run_state: 'active' })
      pollStream()
    } else {
      setAutoMode({ running: false, run_state: 'failed' })
      appendReasoning(new Date().toLocaleTimeString(), 'ERROR: Failed to start auto-mode')
    }
  }

  const pollStream = async () => {
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current)
    // P1-14: SERIAL polling — an in-flight request is never overlapped by
    // the next tick (the old async setInterval stacked concurrent fetches
    // when the backend answered slowly, and served the same log twice).
    let busy = false
    pollIntervalRef.current = setInterval(async () => {
      if (busy) return            // previous poll still in flight
      busy = true
      try {
      const res = await api('GET', '/api/automode/stream')
      if (res.status === 200 && res.data) {
        const d = res.data as {
          done: boolean
          step_updates?: Array<{ step: number; status: string; detail: string; name?: string }>
          current_step?: number
          log?: Array<{
            time: string
            text: string
            level?: 'info' | 'success' | 'warn' | 'error' | 'dim'
            command?: string
            reason?: string
            stealth?: string
          }>
        }

        if (d.step_updates) {
          d.step_updates.forEach((u) => {
            // dynamic steps (deep goals): the backend allocates idx 8+
            // with a name — append before updating, or they vanish
            if (u.step >= 8 && u.name) ensureStep(u.step, u.name)
            updateStep(u.step, u.status, u.detail)
          })
        }
        if (d.current_step !== undefined && d.current_step !== -1) {
          setAutoMode({ current_step: d.current_step })
        }
        if (d.log) {
          // P1-14: dedup by time+text — a reconnect/duplicate stream
          // response must not double the reasoning lines
          const seen = new Set<string>()
          d.log.forEach((l) => {
            const key = `${l.time}|${l.text}`
            if (seen.has(key)) return
            seen.add(key)
            appendReasoning(l.time, l.text, {
              command: l.command || undefined,
              reason: l.reason || undefined,
              stealth: l.stealth || undefined
            })
          })
        }

        if (d.done) {
          clearInterval(pollIntervalRef.current!)
          setAutoMode({ running: false, run_state: 'done' })
          appendReasoning(new Date().toLocaleTimeString(), '[■] Auto-mode complete')
          pollC2()
        }
      }
      } finally {
        busy = false
      }
    }, 800)
  }

  const handleLlmToggle = async (checked: boolean) => {
    setAutoMode({ llm: checked })
    // live mid-run approval (Fase 6): when a run is active the checkbox
    // flips the backend gate immediately, so a pending orchestrator
    // request fires on the next wave; at launch the flag pre-approves
    if (autoMode.running) {
      const res = await api('POST', '/api/automode/llm', { allow: checked })
      if (res.status !== 200) {
        appendReasoning(new Date().toLocaleTimeString(),
          `ERROR: LLM toggle failed — ${apiError(res)}`)
      }
    }
  }

  const handleStop = async () => {
    setAutoMode({ run_state: 'stopping' })   // explicit in-flight stop state
    await api('POST', '/api/automode/stop')
    if (pollIntervalRef.current) clearInterval(pollIntervalRef.current)
    setAutoMode({ running: false, run_state: 'idle' })
  }

  const handleDryRun = async () => {
    // same precedence as Launch: session target is #1, extras after
    const all = [...(session.target ? [session.target] : []),
                 ...autoMode.targets]
    const targets = [...new Set(all.map((t) => t.trim()).filter(Boolean))]
    if (targets.length === 0) return

    setAutoMode({
      running: true,
      plan: [],
      steps: [],
      reasoning: [],
      current_step: 0
    })

    const res = await api('POST', '/api/automode/plan', {
      targets,
      mode: autoMode.mode,
      profile: autoMode.profile,
      goal: autoMode.goal
    })

    if (res.status === 200 && res.data) {
      const d = res.data as { plan: string[] }
      setAutoMode({ plan: d.plan, running: false })
    } else {
      setAutoMode({ running: false })
    }
  }

  const ModeIcon = MODE_ICONS[autoMode.mode] || Gauge

  return (
    <div className="p-4 flex flex-col gap-4 h-full">
      <div>
        <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
          <Bot size={19} className="text-phantom-magenta" /> Auto-Mode
        </h1>
        <p className="text-xs text-text-dim mt-0.5">Autonomous kill chain — from scan to beacon injection</p>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Left: Configuration */}
        <div className="w-[340px] flex-shrink-0 flex flex-col gap-3">
          {/* Targets */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
              Targets
            </h2>
            <div className="flex gap-1.5 mb-2">
              <input
                type="text"
                value={newTarget}
                onChange={(e) => setNewTarget(e.target.value)}
                onKeyDown={(e) => e.key === 'Enter' && handleAddTarget()}
                placeholder="IP, domain, email, phone..."
                disabled={autoMode.running}
                className="flex-1 bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs font-mono text-text-primary placeholder-text-dim
                  focus:outline-none focus:border-phantom-magenta
                  disabled:opacity-50 disabled:cursor-not-allowed"
              />
              <button
                onClick={handleAddTarget}
                disabled={autoMode.running}
                className="px-2.5 py-1.5 rounded bg-phantom-magenta/20 text-phantom-magenta
                  text-xs hover:bg-phantom-magenta/30 transition-colors
                  disabled:opacity-30 disabled:cursor-not-allowed"
              >
                <Plus size={14} />
              </button>
            </div>
            <div className="flex flex-wrap gap-1">
              {session.target && (
                <span className="inline-flex items-center gap-1 px-2 py-0.5 rounded bg-phantom-green/10 text-phantom-green border border-phantom-green/30 text-[11px] font-mono">
                  {session.target} <span className="text-[9px] opacity-60">(session target #1)</span>
                </span>
              )}
              {autoMode.targets.map((t, i) => (
                <span key={i} className="inline-flex items-center gap-1 px-2 py-0.5 rounded
                  bg-phantom-magenta/10 text-phantom-magenta border border-phantom-magenta/30 text-[11px] font-mono">
                  {t}
                  <button
                    onClick={() => handleRemoveTarget(i)}
                    disabled={autoMode.running}
                    className="hover:text-phantom-error transition-colors"
                  >
                    <X size={11} />
                  </button>
                </span>
              ))}
            </div>
            {!session.target && autoMode.targets.length === 0 && (
              <p className="text-[10px] text-text-dim mt-1">Set a target in Session (or on the map) or add one above — Launch unlocks as soon as there is at least one.</p>
            )}
          </div>

          {/* Identity start-gate: precise username + platform -> preview,
              confirm it is really him before burning OSINT hours */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <UserCheck size={12} /> Identity check
            </h2>
            <div className="flex gap-1.5 mb-2">
              <input
                type="text"
                value={idUser}
                onChange={(e) => setIdUser(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') void handlePreview() }}
                placeholder="@username"
                className="flex-1 bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs font-mono text-text-primary placeholder-text-dim
                  focus:outline-none focus:border-phantom-magenta"
              />
              <select
                value={idPlatform}
                onChange={(e) => setIdPlatform(e.target.value)}
                className="bg-surface border border-surface-border rounded px-2 py-1.5
                  text-xs text-text-primary focus:outline-none"
              >
                {['instagram', 'tiktok', 'x', 'github', 'telegram'].map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
              <button
                onClick={() => void handlePreview()}
                disabled={idLoading || !idUser.trim()}
                className="px-2.5 py-1.5 rounded bg-phantom-cyan/20 text-phantom-cyan
                  text-xs hover:bg-phantom-cyan/30 transition-colors
                  disabled:opacity-30 disabled:cursor-not-allowed"
              >
                {idLoading ? <Loader2 size={14} className="animate-spin" /> : 'Preview'}
              </button>
            </div>
            {idPreview && (
              <div className="rounded border border-surface-border bg-surface p-2.5 flex gap-2.5">
                {idPreview.avatar_url ? (
                  // eslint-disable-next-line @next/next/no-img-element
                  <img src={idPreview.avatar_url} alt="avatar"
                    className="w-12 h-12 rounded-full object-cover flex-shrink-0" />
                ) : (
                  <div className="w-12 h-12 rounded-full bg-surface-border flex-shrink-0" />
                )}
                <div className="min-w-0 flex-1">
                  <p className="text-xs font-semibold text-text-primary">
                    @{idPreview.username}
                    <span className="ml-1.5 text-[10px] font-normal text-text-dim">
                      {idPreview.platform} · {idPreview.state}
                    </span>
                  </p>
                  {idPreview.bio && <p className="text-[11px] text-text-secondary break-words mt-0.5">{idPreview.bio}</p>}
                  {(idPreview.followers || idPreview.following) && (
                    <p className="text-[10px] text-text-dim mt-0.5">
                      {idPreview.followers && `${idPreview.followers} followers`}
                      {idPreview.followers && idPreview.following && ' · '}
                      {idPreview.following && `${idPreview.following} following`}
                    </p>
                  )}
                  <div className="flex gap-1.5 mt-1.5">
                    <button
                      onClick={handlePreviewLaunch}
                      className="px-2 py-1 rounded bg-phantom-green/20 text-phantom-green
                        text-[11px] font-medium hover:bg-phantom-green/30 transition-colors"
                    >
                      It's him — add target
                    </button>
                    <button
                      onClick={() => { setIdPreview(null); setIdUser('') }}
                      className="px-2 py-1 rounded bg-surface-border text-text-secondary
                        text-[11px] hover:text-text-primary transition-colors"
                    >
                      Not him
                    </button>
                  </div>
                </div>
              </div>
            )}
          </div>

          {/* Mode selector */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
              Mode
            </h2>
            <div className="grid grid-cols-2 gap-1.5">
              {(Object.keys(MODE_ICONS) as Array<keyof typeof MODE_ICONS>).map((m) => {
                const Icon = MODE_ICONS[m]
                return (
                  <button
                    key={m}
                    onClick={() => handleSetMode(m)}
                    disabled={autoMode.running}
                    className={`flex items-center gap-2 px-2.5 py-2 rounded text-xs
                      transition-colors text-left
                      ${autoMode.mode === m
                        ? 'bg-phantom-magenta/20 text-phantom-magenta border border-phantom-magenta/50'
                        : 'bg-surface text-text-secondary hover:bg-surface-hover border border-surface-border'
                      }
                      disabled:opacity-30`}
                  >
                    <Icon size={14} />
                    <span className="capitalize">{m}</span>
                  </button>
                )
              })}
            </div>
            <p className="text-[10px] text-text-dim mt-2">{MODE_LABELS[autoMode.mode]}</p>
          </div>

          {/* Profile & Goal */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3 space-y-2.5">
            <div>
              <label className="text-[10px] text-text-dim block mb-1">Profile</label>
              <select
                value={autoMode.profile}
                onChange={(e) => setAutoMode({ profile: e.target.value })}
                disabled={autoMode.running}
                className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs text-text-primary focus:outline-none focus:border-phantom-magenta
                  disabled:opacity-50"
              >
                {PROFILES.map((p) => (
                  <option key={p} value={p}>{p}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-text-dim block mb-1">Goal</label>
              <select
                value={autoMode.goal}
                onChange={(e) => setAutoMode({ goal: e.target.value })}
                disabled={autoMode.running}
                className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs text-text-primary focus:outline-none focus:border-phantom-magenta
                  disabled:opacity-50"
              >
                {GOALS.map((g) => (
                  <option key={g} value={g}>{g.replace(/_/g, ' ')}</option>
                ))}
              </select>
              <p className="text-[10px] text-text-dim mt-1">{GOAL_HINTS[autoMode.goal]}</p>
            </div>
            <div>
              <label className="text-[10px] text-text-dim block mb-1">Sub-Agents</label>
              <select
                value={autoMode.agents}
                onChange={(e) => setAutoMode({ agents: parseInt(e.target.value) })}
                disabled={autoMode.running}
                className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs text-text-primary focus:outline-none focus:border-phantom-magenta
                  disabled:opacity-50"
              >
                <option value={0}>auto (decide for me)</option>
                {[1, 2, 3, 4, 5, 6, 7, 8].map((n) => (
                  <option key={n} value={n}>{n} agent{n > 1 ? 's' : ''}</option>
                ))}
              </select>
            </div>
            <div>
              <label className="text-[10px] text-text-dim block mb-1">Engine</label>
              <select
                value={autoMode.engine}
                onChange={(e) => setAutoMode({ engine: e.target.value as 'agent' | 'swarm' })}
                disabled={autoMode.running}
                className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs text-text-primary focus:outline-none focus:border-phantom-magenta
                  disabled:opacity-50"
              >
                <option value="agent">agent — single planner chain</option>
                <option value="swarm">swarm — fact-driven tasks, shared board</option>
              </select>
              <p className="text-[9px] text-text-dim mt-0.5">
                Swarm splits the chain into tasks over a shared blackboard
                (orchestrator + workers); agent runs the classic single chain.
              </p>
            </div>
            <div>
              <label className="flex items-center justify-between cursor-pointer">
                <span className="text-[10px] text-text-dim">Force full range engagement</span>
                <input type="checkbox" checked={autoMode.forceNetwork}
                  onChange={(e) => setAutoMode({ forceNetwork: e.target.checked })}
                  disabled={autoMode.running}
                  className="accent-phantom-error" />
              </label>
              <p className="text-[9px] text-text-dim mt-0.5">
                CIDR/range inputs only discover hosts by default. This engages
                the FULL chain on every discovered host — loud, use only on
                authorized ranges.
              </p>
            </div>
            <div>
              <label className="flex items-center justify-between cursor-pointer">
                <span className="text-[10px] text-text-dim">Learning memory</span>
                <input type="checkbox" checked={autoMode.experience}
                  onChange={(e) => setAutoMode({ experience: e.target.checked })}
                  className="accent-phantom-green" />
              </label>
              <p className="text-[9px] text-text-dim mt-0.5">
                Cross-engagement memory: runs record what worked, why walls
                happened and what unblocked them (data/experience_cases.json,
                local disk only). Unchecked = run-only for the next run.
              </p>
            </div>
            <div>
              <label className="flex items-center justify-between cursor-pointer">
                <span className="text-[10px] text-text-dim">Local-LLM advisor</span>
                <input type="checkbox" checked={autoMode.llm}
                  onChange={(e) => void handleLlmToggle(e.target.checked)}
                  className="accent-phantom-magenta" />
              </label>
              <p className="text-[9px] text-text-dim mt-0.5">
                Optional hypothesis advisor (needs PHANTOM_LLM_MODEL). Local only —
                never gates or executes, data never leaves the machine.
                {autoMode.running
                  ? ' Flippable live: approval applies from the next wave.'
                  : ' Checked at launch pre-approves the session.'}
              </p>
            </div>
            <div>
              <label className="flex items-center justify-between cursor-pointer">
                <span className="text-[10px] text-text-dim">Verbose reasoning trace</span>
                <input type="checkbox" checked={autoMode.verbose}
                  onChange={(e) => setAutoMode({ verbose: e.target.checked })}
                  disabled={autoMode.running}
                  className="accent-phantom-cyan" />
              </label>
              <p className="text-[9px] text-text-dim mt-0.5">
                Every run already shows the real command + why. Verbose adds the
                full trace: inferences, hypotheses, hunt probes.
              </p>
            </div>
          </div>

          {/* Action buttons */}
          <div className="flex gap-2">
            <button
              onClick={handleLaunch}
              disabled={autoMode.running || (autoMode.targets.length === 0 && !session.target)}
              className={`flex-1 py-2 rounded text-xs font-semibold uppercase tracking-wider
                flex items-center justify-center gap-1.5 transition-colors
                ${autoMode.running || (autoMode.targets.length === 0 && !session.target)
                  ? 'bg-surface-border text-text-dim cursor-not-allowed'
                  : 'bg-phantom-magenta/20 text-phantom-magenta hover:bg-phantom-magenta/30'
                }`}
            >
              {autoMode.running ? (
                <><Loader2 size={13} className="animate-spin" /> Running</>
              ) : (
                <><Play size={13} /> Launch</>
              )}
            </button>
            <button
              onClick={handleDryRun}
              disabled={autoMode.running || (autoMode.targets.length === 0 && !session.target)}
              className={`px-3 py-2 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors
                ${autoMode.running || (autoMode.targets.length === 0 && !session.target)
                  ? 'bg-surface-border text-text-dim cursor-not-allowed'
                  : 'bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30'
                }`}
            >
              <FileText size={13} /> Dry Run
            </button>
            {autoMode.running && (
              <button
                onClick={handleStop}
                className="px-3 py-2 rounded bg-phantom-error/20 text-phantom-error
                  text-xs font-semibold flex items-center gap-1.5 hover:bg-phantom-error/30"
              >
                <Square size={13} /> Stop
              </button>
            )}
          </div>

          {/* WorldModel knowledge */}
          <KnowledgeWidget api={api} />

          {/* Dry-run plan */}
          {autoMode.plan.length > 0 && (
            <div className="bg-surface-card border border-surface-border rounded-lg p-3">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
                Dry-Run Plan
              </h2>
              <div className="space-y-1">
                {autoMode.plan.map((p, i) => (
                  <div key={i} className="text-xs text-text-primary flex items-center gap-2">
                    <ChevronRight size={11} className="text-phantom-cyan" />
                    <span>{p}</span>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>

        {/* Right: Kill chain + Reasoning */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          {/* Kill Chain Graph */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-4">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
              Kill Chain
            </h2>
            <div className="flex items-center gap-1 flex-wrap">
              {autoMode.steps.map((step, i) => (
                <div key={i} className="flex items-center gap-1">
                  <div className={`animate-step-enter`} style={{ animationDelay: `${i * 50}ms` }}>
                    <KillChainStep
                      name={step.name}
                      status={step.status}
                      detail={step.detail}
                      isActive={i === autoMode.current_step}
                    />
                  </div>
                  {i < autoMode.steps.length - 1 && (
                    <ChevronRight size={14} className="text-text-dim flex-shrink-0" />
                  )}
                </div>
              ))}

              {autoMode.steps.length === 0 && (
                <div className="text-xs text-text-dim py-4 text-center w-full">
                  Launch auto-mode to see the kill chain progress
                </div>
              )}
            </div>
          </div>

          {/* Reasoning stream */}
          {/* Pending identity decisions: close candidates the engine
              will not guess on — your eyes, one click, then it moves */}
          {idChecks.length > 0 && (
            <div className="bg-phantom-yellow/10 border border-phantom-yellow/30 rounded-lg p-3 space-y-2">
              <h2 className="text-xs font-semibold text-phantom-yellow uppercase tracking-wider flex items-center gap-1.5">
                <UserCheck size={13} /> Identity decision needed ({idChecks.length})
              </h2>
              {idChecks.map((check) => (
                <div key={check.id} className="rounded border border-surface-border bg-surface p-2">
                  <p className="text-[11px] text-text-secondary mb-1.5">{check.description}</p>
                  <div className="flex gap-2 overflow-auto">
                    {check.candidates.map((c) => (
                      <div key={`${c.platform}:${c.handle}`} className="flex-shrink-0 w-44 rounded border border-surface-border bg-surface-card p-2">
                        {c.avatar_url ? (
                          // eslint-disable-next-line @next/next/no-img-element
                          <img src={c.avatar_url} alt="avatar"
                            className="w-10 h-10 rounded-full object-cover mb-1" />
                        ) : (
                          <div className="w-10 h-10 rounded-full bg-surface-border mb-1" />
                        )}
                        <p className="text-[11px] font-semibold text-text-primary break-words">@{c.handle}</p>
                        <p className="text-[10px] text-text-dim">{c.platform}{c.tier ? ` · ${c.tier}` : ''}</p>
                        {c.bio && <p className="text-[10px] text-text-secondary break-words mt-0.5 line-clamp-2">{c.bio}</p>}
                        {(c.followers || c.following) && (
                          <p className="text-[10px] text-text-dim">{c.followers || '?'} / {c.following || '?'} fol.</p>
                        )}
                        <div className="flex gap-1 mt-1.5">
                          <button
                            onClick={() => void answerCheck(check.id, `same:${c.handle}`)}
                            className="flex-1 px-1.5 py-1 rounded bg-phantom-green/20 text-phantom-green
                              text-[10px] font-medium hover:bg-phantom-green/30 transition-colors"
                          >
                            It's him
                          </button>
                          <button
                            onClick={() => copyText(`https://${c.platform}.com/${c.handle}`)}
                            title="Copy profile URL"
                            className="px-1.5 py-1 rounded bg-surface-border text-text-secondary
                              hover:text-text-primary transition-colors"
                          >
                            <Copy size={11} />
                          </button>
                        </div>
                      </div>
                    ))}
                  </div>
                  <div className="flex gap-1.5 mt-2">
                    <button
                      onClick={() => void answerCheck(check.id, 'stop')}
                      className="px-2 py-1 rounded bg-phantom-error/20 text-phantom-error
                        text-[11px] font-medium hover:bg-phantom-error/30 transition-colors"
                    >
                      Stop — wrong person
                    </button>
                    <button
                      onClick={() => void answerCheck(check.id, 'widen')}
                      className="px-2 py-1 rounded bg-surface-border text-text-secondary
                        text-[11px] hover:text-text-primary transition-colors"
                    >
                      Keep searching
                    </button>
                  </div>
                </div>
              ))}
            </div>
          )}
          <div className="bg-surface-card border border-surface-border rounded-lg flex-1 flex flex-col min-h-0 relative">
            {/* Global Progress Bar */}
            {autoMode.running && (
              <div className="absolute top-0 left-0 h-1 bg-phantom-magenta transition-all duration-500 rounded-tl-lg" 
                   style={{ width: `${Math.max(5, (autoMode.current_step / Math.max(1, autoMode.steps.length - 1)) * 100)}%` }} />
            )}
            <div className="px-3 py-2 border-b border-surface-border flex items-center justify-between">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                Reasoning Stream
              </h2>
              <button onClick={handleClearLog} className="text-[10px] text-text-dim hover:text-text-primary transition-colors">
                Clear
              </button>
            </div>
            <div
              ref={reasoningRef}
              className="flex-1 overflow-auto p-3 font-mono text-[11px] space-y-1"
            >
              {autoMode.reasoning.length === 0 ? (
                <div className="text-text-dim py-4 text-center text-xs">
                  <p>Reasoning trace appears here during auto-mode execution.</p>
                  <p className="text-text-dim mt-1">Shows inferences, hypotheses, confirmations, and decisions.</p>
                </div>
              ) : (
                autoMode.reasoning.map((r, i) => {
                  let colorClass = 'text-text-primary'
                  if (r.text.includes('[+]') || r.text.includes('[★]')) colorClass = 'text-phantom-green font-medium'
                  else if (r.text.includes('[ERROR]')) colorClass = 'text-phantom-error font-medium'
                  else if (r.text.includes('[!]')) colorClass = 'text-phantom-yellow font-medium'
                  else if (r.text.includes('[~]') || r.text.includes('[?]')) colorClass = 'text-text-dim'
                  else if (r.text.includes('[▶]')) colorClass = 'text-phantom-cyan'

                  const showCmd = r.command && r.command.length > 0
                  const showWhy = r.reason && r.reason.length > 0
                  const stealth = r.stealth || ''
                  const stealthLabel =
                    stealth === 'paranoid' ? '⚡ paranoid' :
                    stealth === 'active' ? '● active' :
                    stealth === 'aggressive' ? '🎯 aggressive' : ''

                  return (
                    <div key={i} className="animate-stream-fade flex gap-3 hover:bg-surface-hover/50 px-1 py-0.5 rounded transition-colors">
                      <span className="text-text-dim flex-shrink-0 w-14">{r.time}</span>
                      <div className="min-w-0 flex-1">
                        <div className={`break-all ${colorClass}`}>
                          {r.text}
                          {stealthLabel && <span className="text-text-dim ml-2">{stealthLabel}</span>}
                        </div>
                        {showCmd && (
                          <div className="text-phantom-cyan/90 font-mono text-[10.5px] mt-0.5 break-all">
                            <span className="text-text-dim select-none">$ </span>{r.command}
                          </div>
                        )}
                        {showWhy && (
                          <div className="text-text-dim text-[10.5px] mt-0.5 break-all">
                            <span className="select-none">why: </span>{r.reason}
                          </div>
                        )}
                      </div>
                    </div>
                  )
                })
              )}
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function KillChainStep({
  name, status, detail, isActive
}: {
  name: string
  status: string
  detail?: string
  isActive: boolean
}) {
  return (
    <div className={`flex flex-col items-center gap-1 px-2 py-1.5 rounded-lg text-center min-w-[80px]
      ${status === 'done' ? 'bg-phantom-green/10 border border-phantom-green/30' :
        status === 'running' ? 'bg-phantom-magenta/10 border border-phantom-magenta/30' :
        status === 'failed' ? 'bg-phantom-error/10 border border-phantom-error/30' :
        'bg-surface border border-surface-border'
      }
      ${isActive ? 'ring-1 ring-phantom-magenta/50' : ''}
    `}>
      {status === 'done' ? (
        <CheckCircle2 size={14} className="text-phantom-green" />
      ) : status === 'running' ? (
        <Loader2 size={14} className="text-phantom-magenta animate-spin" />
      ) : status === 'failed' ? (
        <AlertTriangle size={14} className="text-phantom-error" />
      ) : (
        <Circle size={14} className="text-text-dim" />
      )}
      <span className={`text-[10px] font-semibold ${
        status === 'done' ? 'text-phantom-green' :
        status === 'running' ? 'text-phantom-magenta' :
        status === 'failed' ? 'text-phantom-error' :
        'text-text-dim'
      }`}>{name}</span>
      {detail && <span className="text-[9px] text-text-dim max-w-[100px] truncate">{detail}</span>}
    </div>
  )
}

// ── Knowledge Widget (WorldModel) ──────────────────────────────────────────

function KnowledgeWidget({ api }: { api: ReturnType<typeof import('@/hooks/useApi').useApi>['api'] }) {
  const [knowledge, setKnowledge] = useState<{ summary: Record<string, number>; hypotheses: Array<{ kind: string; text: string }>; target: string } | null>(null)
  const [open, setOpen] = useState(false)

  const load = async () => {
    setOpen(!open)
    if (!open) {
      const res = await api('GET', '/api/session/knowledge')
      if (res.status === 200) setKnowledge(res.data as { summary: Record<string, number>; hypotheses: []; target: string })
    }
  }

  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-3">
      <button onClick={load} className="flex items-center justify-between w-full text-left">
        <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
          <Brain size={13} className="text-phantom-green" /> WorldModel Knowledge
        </h2>
        <span className="text-[10px] text-text-dim">{open ? '▲' : '▼'}</span>
      </button>
      {open && knowledge && (
        <div className="mt-2 space-y-1 text-xs">
          <div className="text-text-dim">Target: <span className="text-text-primary">{knowledge.target || '—'}</span></div>
          {Object.entries(knowledge.summary).map(([k, v]) => (
            <div key={k} className="flex justify-between">
              <span className="text-text-secondary capitalize">{k}</span>
              <span className="text-text-primary font-mono">{v}</span>
            </div>
          ))}
          {knowledge.hypotheses.length > 0 && (
            <div className="mt-1 pt-1 border-t border-surface-border">
              <div className="text-phantom-green text-[10px] font-semibold mb-1">▶ Live Hypotheses</div>
              {knowledge.hypotheses.map((h, i) => (
                <div key={i} className="text-text-secondary text-[10px]">{h.kind}: {h.text}</div>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  )
}