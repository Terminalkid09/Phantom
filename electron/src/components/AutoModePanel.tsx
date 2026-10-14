import { useState, useRef, useEffect, useCallback } from 'react'
import { useStore, type AutoModeJob } from '@/store'
import { apiError, useApi } from '@/hooks/useApi'
import {
  automodeHandoff, automodePlan, automodeRun, automodeSetLlm, automodeStatus,
  automodeStop, automodeStream, deriveJobState, sessionSet,
  type JobState
} from '@/lib/api'
import LlmProposals from '@/components/LlmProposals'
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

// F-27: the run state the chip renders, in TWO vocabularies that must never be
// confused. The lowercase-local ones (`starting`, `active`, `done`) are the
// panel's own optimistic labels, used only until a status answer arrives; the
// `JobState` ones are the backend's, and once `backendSeen` is true they are
// the only thing on screen — which is the whole point of the strip. Where a
// run ended, `endReason` says WHY (stopped by operator / sequence complete).
const RUN_STATE_STYLE: Record<string, { label: string; cls: string }> = {
  // local, pre-confirmation
  starting: { label: 'Starting', cls: 'bg-phantom-cyan/10 text-phantom-cyan border-phantom-cyan/30' },
  active: { label: 'Running', cls: 'bg-phantom-magenta/10 text-phantom-magenta border-phantom-magenta/30' },
  done: { label: 'Completed', cls: 'bg-phantom-green/10 text-phantom-green border-phantom-green/30' },
  // backend lifecycle (JobState)
  idle: { label: 'Idle', cls: 'bg-surface text-text-dim border-surface-border' },
  planning: { label: 'Planning', cls: 'bg-phantom-cyan/10 text-phantom-cyan border-phantom-cyan/30' },
  running: { label: 'Running', cls: 'bg-phantom-magenta/10 text-phantom-magenta border-phantom-magenta/30' },
  awaiting_approval: { label: 'Awaiting approval', cls: 'bg-phantom-yellow/10 text-phantom-yellow border-phantom-yellow/30' },
  handoff_ready: { label: 'Handoff ready', cls: 'bg-phantom-green/10 text-phantom-green border-phantom-green/30' },
  stopping: { label: 'Stopping', cls: 'bg-phantom-yellow/10 text-phantom-yellow border-phantom-yellow/30' },
  cancelled: { label: 'Cancelled', cls: 'bg-surface text-text-secondary border-surface-border' },
  completed: { label: 'Completed', cls: 'bg-phantom-green/10 text-phantom-green border-phantom-green/30' },
  failed: { label: 'Failed', cls: 'bg-phantom-error/10 text-phantom-error border-phantom-error/30' }
}

/** A backend terminal/attention state → the panel's own run label, so the
 *  stream/status polls arm and disarm on the same vocabulary they always
 *  did while the CHIP shows the backend's state. */
const LOCAL_RUN_STATE: Partial<Record<JobState, 'idle' | 'active' | 'done' | 'failed'>> = {
  idle: 'idle',
  cancelled: 'idle',
  running: 'active',
  awaiting_approval: 'active',
  handoff_ready: 'done',
  completed: 'done',
  failed: 'failed'
}

/** Elapsed time of a live run. Rendered from the timestamp on every store
 *  update (the stream poll ticks well under a second while a run is live), so
 *  there is no second timer just to move the clock. */
function fmtElapsed(startedAt?: number): string {
  if (!startedAt) return '—'
  const total = Math.max(0, Math.floor((Date.now() - startedAt) / 1000))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  if (h > 0) return `${h}h ${String(m).padStart(2, '0')}m`
  if (m > 0) return `${m}m ${String(s).padStart(2, '0')}s`
  return `${s}s`
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

/**
 * OSINT scope for a username target. ONE wire value, sent to
 * `/api/automode/run` as `platform`:
 *
 *   ''         auto   — every platform is probed (legacy behaviour)
 *   <social>   pin    — the pass reads ONLY that network: the same handle on
 *                       another network is very often a different person,
 *                       and a namesake inside the identity graph sends the
 *                       whole chain (DM, follow, phish) at a stranger
 *   'other'    other  — the five top socials are EXCLUDED and the pass
 *                       searches everywhere else
 */
const IDENTITY_SCOPES = ['auto', 'instagram', 'tiktok', 'x', 'github',
  'telegram', 'other'] as const
type IdentityScope = typeof IDENTITY_SCOPES[number]

const SCOPE_LABELS: Record<IdentityScope, string> = {
  auto: 'Auto',
  instagram: 'instagram',
  tiktok: 'tiktok',
  x: 'x',
  github: 'github',
  telegram: 'telegram',
  other: 'Other'
}

/** `auto` travels as the empty string; every other choice is its own value. */
const scopeValue = (s: IdentityScope): string => (s === 'auto' ? '' : s)

/** What the run will ACTUALLY do, readable before Launch instead of after. */
const scopeHint = (s: IdentityScope): string =>
  s === 'auto'
    ? 'OSINT scope: auto — every platform is probed'
    : s === 'other'
      ? 'OSINT scope: everywhere except the 5 top socials'
      : `OSINT scope: ${s} only — other platforms are not probed`

const scopeAria = (s: IdentityScope): string =>
  s === 'auto'
    ? 'Probe every platform (auto OSINT scope)'
    : s === 'other'
      ? 'Search everywhere except the 5 top socials'
      : `Pin the OSINT to ${s} only`

/**
 * Does this look like a @handle rather than an address/machine?
 *
 * The scope control is only meaningful for an identity target, so it appears
 * when one is recognised instead of sitting there as a permanently visible
 * knob. This is a UI HINT that mirrors the backend's classifier — the run
 * itself always classifies the target server-side (`classify_target`), so a
 * wrong guess here changes nothing but what the panel shows.
 */
const identityLooksLikeUsername = (value: string): boolean =>
  /^@?[A-Za-z][A-Za-z0-9_.\-]{1,63}$/.test((value || '').trim())

export default function AutoModePanel() {
  const { autoMode, setAutoMode, job, setJob, appendReasoning, updateStep, ensureStep, session, addHandoff,
    handoffs, setHandoffStatus, beacons, setActiveBeacon, setActiveTab,
    pushToast
  } = useStore()
  const { api, pollC2 } = useApi()
  const [newTarget, setNewTarget] = useState('')
  const reasoningRef = useRef<HTMLDivElement>(null)
  // a DRY RUN sets `running` to lock the buttons, but nothing is executing:
  // the stream/status polls must not arm for it
  const [planning, setPlanning] = useState(false)

  // identity start-gate: precise username + platform -> preview card
  const [idUser, setIdUser] = useState('')
  // ONE source of truth for the scope: the store field the run reads. The
  // chips derive their pressed state from it, so the button the operator
  // sees and the value the backend receives cannot drift apart.
  const idScope: IdentityScope = autoMode.identityPlatform === ''
    ? 'auto'
    : (autoMode.identityPlatform as IdentityScope)
  const setIdScope = (s: IdentityScope) =>
    setAutoMode({ identityPlatform: scopeValue(s) })
  // the RUN scope and the PREVIEW platform are not the same thing: `auto`
  // and `other` are run scopes with no single profile page to preview, so
  // only a pinned social can be previewed (the endpoint rejects the rest).
  const idPlatform = idScope === 'auto' || idScope === 'other' ? '' : idScope
  const previewable = idPlatform !== ''
  // the scope control appears once an identity target is recognised — and
  // stays visible while a non-default scope is in force, so it can be undone.
  const showScopeChips = identityLooksLikeUsername(idUser)
    || autoMode.identityPlatform !== ''
  const [idPreview, setIdPreview] = useState<ProfilePreview | null>(null)

  // Handoffs this run produced and the operator has not acted on yet. The
  // card is the only thing that consumes them; once accepted or dismissed it
  // stops showing without any panel having to guess at the state.
  const pendingHandoffs = handoffs.filter((h) => h.status === 'ready')
  const [idLoading, setIdLoading] = useState(false)
  // mid-run ambiguity decisions (operator eyes on close candidates)
  const [idChecks, setIdChecks] = useState<IdentityCheck[]>([])

  // `useSerialPoll` owns every interval and every cleanup (unmount included),
  // so there is no manual interval to clear here any more.

  const handleClearLog = () => setAutoMode({ reasoning: [] })

  const handlePreview = async () => {
    const username = idUser.trim().replace(/^@/, '')
    if (!username || !previewable) return
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
    // a NEW run starts from a blank job record: the previous job's id/state/
    // error must not read as THIS run's state
    setJob({ id: null, state: 'planning', running: true, current_step: -1,
             cancel_requested: false, error: '', end_reason: '', started_at: 0,
             handoffs: [], handoff_state: 'none', last_status_at: 0 })

    // Make sure the backend session carries the same target (Suggest Next,
    // reports and the manual Run all read session.target server-side)
    if (!session.target && targets[0]) {
      await sessionSet('target', targets[0])
    }

    // Start the auto-mode engine. This call answers only after the engine has
    // accepted the job, which is why it is NOT raced against the 15s bridge
    // timeout (`@/lib/api` gives it the long one).
    const res = await automodeRun({
      targets,
      mode: autoMode.mode,
      engine: autoMode.engine,
      force_network: autoMode.forceNetwork,
      profile: autoMode.profile,
      goal: autoMode.goal,
      agents: autoMode.agents,
      llm: autoMode.llm,
      experience: autoMode.experience,
      verbose: autoMode.verbose,
      // where the operator says the handle belongs ('' = auto, a pinned
      // social, or 'other'): the OSINT pass must not widen to a namesake
      // on a network the operator did not name.
      platform: autoMode.identityPlatform
    })

    if (res.status === 200 && res.data) {
      // The job id is what a stop cancels, so record it NOW; the status poll
      // confirms the rest (the polling hooks arm themselves on `running`).
      setAutoMode({ run_state: 'active' })
      setJob({
        id: res.data.job_id || null,
        running: true,
        // the backend answered `planning`: the job exists and nothing has run
        state: 'planning',
        started_at: Date.now()
      })
    } else {
      setAutoMode({ running: false, run_state: 'failed' })
      setJob({ running: false, error: apiError(res) })
      appendReasoning(new Date().toLocaleTimeString(),
        `ERROR: Failed to start auto-mode — ${apiError(res)}`)
    }
  }

  // The stream is the run's timeline. It is armed by the run being LIVE and
  // every tick goes through `useSerialPoll`, whose busy-guard replaces the
  // hand-rolled `busy` flag (an in-flight poll is still never overlapped).
  const pollStream = useCallback(async () => {
    {
      const res = await automodeStream()
      if (res.status === 200 && res.data) {
        const d = res.data

        if (d.step_updates) {
          d.step_updates.forEach((u) => {
            // dynamic steps (deep goals): the backend allocates idx 8+
            // with a name — append before updating, or they vanish
            if (u.step >= 8 && u.name) ensureStep(u.step, u.name)
            updateStep(u.step, u.status, u.detail)
          })
        }
        if (d.current_step !== -1) {
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

        if (d.handoffs?.length) {
          d.handoffs.forEach((h) => {
            addHandoff({
              source: 'automode',
              kind: 'beacon_established',
              beaconId: h.beacon_id,
              target: h.target || undefined
            })
          })
        }

        if (d.done) {
          setAutoMode({ running: false, run_state: 'done' })
          setJob({ running: false, cancel_requested: false })
          appendReasoning(new Date().toLocaleTimeString(), '[■] Auto-mode complete')
          pollC2()
        }
      }
    }
  }, [setAutoMode, setJob, ensureStep, updateStep, appendReasoning, addHandoff, pollC2])

  // Status is the chip's source of truth (F-27): the job id, the backend's
  // own running flag and the LLM gate. It also resolves a run that ended
  // between stream polls — and a stop the backend has now honoured — instead
  // of leaving the optimistic label on screen forever.
  const pollStatus = useCallback(async () => {
    // Ask about OUR job when we know its id: a second run started elsewhere
    // must not be able to rewrite this panel's state (and a finished job is
    // still answerable by id for an hour).
    const res = await automodeStatus(job.id ?? undefined)
    if (res.status !== 200 || !res.data) return
    const s = res.data
    const state = deriveJobState(s)
    const patch: Partial<AutoModeJob> = {
      state,
      running: s.running,
      current_step: s.current_step,
      llm: s.llm,
      llm_pending: s.llm_pending,
      end_reason: s.end_reason,
      error: s.error,
      handoffs: s.handoffs.map((h) => ({
        beacon_id: h.beacon_id, target: h.target, status: h.status
      })),
      handoff_state: s.handoff_state,
      last_status_at: Date.now()
    }
    if (s.job_id) {
      patch.id = s.job_id
      patch.started_at = s.started_at
    }
    setJob(patch)
    // The backend's terminal state settles the panel — `cancelled` is NOT a
    // completion, and the reason travels with it instead of being guessed
    // from `cancel_requested`.
    if (!s.running && autoMode.running && !planning) {
      setAutoMode({ running: false, run_state: LOCAL_RUN_STATE[state] ?? 'done' })
      setJob({ cancel_requested: false })
    }
  }, [setJob, setAutoMode, autoMode.running, job.id, planning])

  const liveRun = !planning && (autoMode.run_state === 'starting'
    || autoMode.run_state === 'active' || autoMode.run_state === 'stopping')
  useSerialPoll(pollStream, 800, liveRun, [liveRun])
  useSerialPoll(pollStatus, 2000, liveRun, [liveRun])

  const handleLlmToggle = async (checked: boolean) => {
    setAutoMode({ llm: checked })
    // live mid-run approval (Fase 6): when a run is active the checkbox
    // flips the backend gate immediately, so a pending orchestrator
    // request fires on the next wave; at launch the flag pre-approves
    if (autoMode.running) {
      const res = await automodeSetLlm(checked)
      if (res.status !== 200) {
        appendReasoning(new Date().toLocaleTimeString(),
          `ERROR: LLM toggle failed — ${apiError(res)}`)
      }
    }
  }

  // Handoff -> C2. Selecting the beacon and switching tab is the whole
  // action: no task is queued here, because opening a C2 context must never
  // have a side effect on the target. `interact` is the operator's next,
  // explicit click.
  const openBeacon = async (beaconId: string | undefined, interact = false) => {
    if (!beaconId) return
    setActiveBeacon(beaconId)
    setActiveTab('c2')
    const record = handoffs.find((h) => h.beaconId === beaconId)
    if (record) setHandoffStatus(record.id, 'accepted')
    // Tell the BACKEND the operator accepted: the panel's own `handoffs` are
    // UI state, and a decision that only exists in the renderer is lost on
    // reload (and invisible to the CLI).
    const res = await automodeHandoff(beaconId, 'accept', job.id ?? undefined)
    if (res.status !== 200) {
      appendReasoning(new Date().toLocaleTimeString(),
        `ERROR: handoff not recorded — ${apiError(res)}`)
    }
    appendReasoning(
      new Date().toLocaleTimeString(),
      `[→ C2] ${beaconId} selected${interact ? ' — open Interact to send tasks' : ''}`
    )
    pushToast({
      title: interact ? `Beacon ${beaconId} ready` : `Opened C2 on ${beaconId}`,
      description: interact
        ? 'Use the Interact panel to send tasks. Nothing was queued.'
        : 'Beacon selected in the C2 dashboard.',
      type: 'success'
    })
  }

  // The stop is COOPERATIVE: the engine halts at its next iteration boundary
  // and a long scan already in flight finishes first, so the honest state is
  // "stopping" until the backend confirms. The old code declared the run
  // stopped, cancelled its own polling and never learned otherwise.
  const handleStop = async () => {
    setAutoMode({ run_state: 'stopping' })
    // `stopping` is the honest state from the click onwards: the request has
    // been made, the engine has not halted yet.
    setJob({ cancel_requested: true, state: 'stopping' })
    const res = await automodeStop()
    if (res.status !== 200) {
      setJob({ cancel_requested: false })
      setAutoMode({ run_state: 'active' })
      appendReasoning(new Date().toLocaleTimeString(),
        `ERROR: Stop failed — ${apiError(res)}`)
      return
    }
    if (res.data.note === 'no active run') {
      // there was nothing to cancel: settle now rather than showing a stop
      // that will never be confirmed
      setAutoMode({ running: false, run_state: 'idle' })
      setJob({ running: false, cancel_requested: false })
      return
    }
    void pollStatus()   // ask immediately; the 2s tick keeps checking
  }

  // "Keep AutoMode open": the operator decides NOT to move into the C2 now.
  // Recording it is what stops the card from coming back on the next poll.
  const dismissHandoff = async (beaconId: string | undefined, recordId: string) => {
    if (!beaconId) return
    setHandoffStatus(recordId, 'dismissed')
    const res = await automodeHandoff(beaconId, 'dismiss', job.id ?? undefined)
    if (res.status !== 200) {
      appendReasoning(new Date().toLocaleTimeString(),
        `ERROR: handoff not recorded — ${apiError(res)}`)
    }
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
    // locks the buttons without arming the run polls (nothing is executing)
    setPlanning(true)

    // The dry run must reflect the SAME posture the run would use: engine,
    // force_network and the worker count all change what gets planned, so
    // they are sent here too (the backend delegates to the engine's own
    // planner). The note the backend returns is shown with the plan so the
    // operator knows a dry run executes nothing.
    const res = await automodePlan({
      targets,
      mode: autoMode.mode,
      profile: autoMode.profile,
      goal: autoMode.goal,
      engine: autoMode.engine,
      force_network: autoMode.forceNetwork,
      agents: autoMode.agents,
      // the dry run carries the SAME scope the run will use, so the plan the
      // operator reads can never disagree with the pass that executes
      platform: autoMode.identityPlatform
    })

    setPlanning(false)
    if (res.status === 200 && res.data) {
      const d = res.data
      setAutoMode({
        plan: d.note ? [...d.plan, `- ${d.note}`] : d.plan,
        running: false
      })
    } else {
      setAutoMode({ running: false })
      appendReasoning(new Date().toLocaleTimeString(),
        `ERROR: Dry run failed — ${apiError(res)}`)
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

      {/* The model's own plan, and the reason a proposal was refused: the
          advisor never executes, so its commands wait here for a human. */}
      <LlmProposals />

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
                aria-label="Add a target (IP, domain, email, phone)"
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
                aria-label="Add target"
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
                    aria-label={`Remove target ${t}`}
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
            {showScopeChips && (
            <div className="flex flex-wrap gap-1 mb-2" role="group"
              aria-label="OSINT platform scope">
              {IDENTITY_SCOPES.map((s) => (
                <button
                  key={s}
                  type="button"
                  onClick={() => {
                    setIdScope(s)
                    setAutoMode({ identityPlatform: scopeValue(s) })
                    setIdPreview(null)
                  }}
                  disabled={autoMode.running}
                  aria-pressed={idScope === s}
                  aria-label={scopeAria(s)}
                  className={`px-2 py-1 rounded text-[10px] font-medium border
                    transition-colors disabled:opacity-30
                    ${idScope === s
                      ? 'bg-phantom-magenta/20 text-phantom-magenta border-phantom-magenta/50'
                      : 'bg-surface text-text-secondary border-surface-border hover:text-text-primary'
                    }`}
                >
                  {SCOPE_LABELS[s]}
                </button>
              ))}
            </div>
            )}
            {showScopeChips && (
              <p className="text-[10px] text-text-dim mb-2">
                {scopeHint(idScope)}
              </p>
            )}
            <div className="flex gap-1.5 mb-2">
              <input
                type="text"
                value={idUser}
                aria-label="Username to preview"
                onChange={(e) => setIdUser(e.target.value)}
                onKeyDown={(e) => { if (e.key === 'Enter') void handlePreview() }}
                placeholder="@username"
                className="flex-1 bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs font-mono text-text-primary placeholder-text-dim
                  focus:outline-none focus:border-phantom-magenta"
              />
              <button
                onClick={() => void handlePreview()}
                disabled={idLoading || !idUser.trim() || !previewable}
                aria-label={previewable
                  ? `Preview this identity on ${idPlatform}`
                  : 'Preview needs one pinned platform (pick a social, not Auto or Other)'}
                title={previewable ? '' : 'Preview needs one pinned platform'}
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
                  <img src={idPreview.avatar_url} alt={`Avatar of @${idPreview.username}`}
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
                    aria-pressed={autoMode.mode === m}
                    aria-label={MODE_LABELS[m]}
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

          {/* F-27: the run as the BACKEND sees it — job id, real state and
              the in-flight window of a stop — instead of an optimistic
              label nobody ever corrected */}
          {(liveRun || autoMode.run_state === 'done' || autoMode.run_state === 'failed'
            // a terminal state the operator must see (cancelled maps to the
            // local label `idle`, which would otherwise hide the strip)
            || (job.last_status_at > 0 && job.state !== 'idle')) && (
            <RunStateStrip
              state={job.last_status_at > 0 ? job.state : (autoMode.run_state ?? 'idle')}
              jobId={job.id}
              startedAt={job.last_status_at > 0 ? (job.started_at || undefined) : autoMode.startedAt}
              backendSeen={job.last_status_at > 0}
              llmPending={job.llm_pending}
              cancelRequested={job.cancel_requested}
              error={job.error}
              endReason={job.end_reason}
            />
          )}

          {/* what the run will do with the identity, readable before Launch.
              Only when a scope was actually chosen: `auto` is the default and
              does not need a standing warning. */}
          {autoMode.identityPlatform !== '' && (
            <p className="text-[10px] text-text-dim mb-1.5">
              {scopeHint(idScope)}
            </p>
          )}

          {/* Action buttons */}
          <div className="flex gap-2">
            <button
              onClick={handleLaunch}
              disabled={autoMode.running || (autoMode.targets.length === 0 && !session.target)}
              aria-label="Launch the auto-mode run"
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
              aria-label="Dry run — plan only, execute nothing"
              className={`px-3 py-2 rounded text-xs font-semibold flex items-center gap-1.5 transition-colors
                ${autoMode.running || (autoMode.targets.length === 0 && !session.target)
                  ? 'bg-surface-border text-text-dim cursor-not-allowed'
                  : 'bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30'
                }`}
            >
              <FileText size={13} /> Dry Run
            </button>
            {liveRun && (
              <button
                onClick={() => void handleStop()}
                aria-label="Stop the run"
                disabled={job.cancel_requested || job.state === 'stopping'
                  || !autoMode.running}
                title={job.cancel_requested || job.state === 'stopping'
                  ? 'Stop requested — the engine halts at its next iteration boundary'
                  : 'Stop the run (cooperative: the action in flight finishes first)'}
                className="px-3 py-2 rounded bg-phantom-error/20 text-phantom-error
                  text-xs font-semibold flex items-center gap-1.5 hover:bg-phantom-error/30
                  disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {job.cancel_requested || job.state === 'stopping'
                  ? <><Loader2 size={13} className="animate-spin" /> Stopping…</>
                  : <><Square size={13} /> Stop</>}
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
            <div role="group" aria-label="Kill chain steps" className="flex items-center gap-1 flex-wrap">
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
                            aria-label="Copy profile URL"
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
              <div role="progressbar" aria-label="Kill chain progress" aria-valuemin={0} aria-valuemax={Math.max(1, autoMode.steps.length - 1)} aria-valuenow={Math.max(0, autoMode.current_step)} className="absolute top-0 left-0 h-1 bg-phantom-magenta transition-all duration-500 rounded-tl-lg" 
                   style={{ width: `${Math.max(5, (autoMode.current_step / Math.max(1, autoMode.steps.length - 1)) * 100)}%` }} />
            )}
            <div className="px-3 py-2 border-b border-surface-border flex items-center justify-between">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider">
                Reasoning Stream
              </h2>
              <button onClick={handleClearLog} aria-label="Clear the reasoning stream" className="text-[10px] text-text-dim hover:text-text-primary transition-colors">
                Clear
              </button>
            </div>
            <div
              ref={reasoningRef}
              role="log"
              aria-live="polite"
              aria-label="Auto-mode reasoning stream"
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

          {/* Handoff: a beacon this run established, waiting to be taken into
              the C2 by hand. Before this the operator had to notice the beacon
              in the C2 dashboard on their own — the backend knew, the CLI
              offered `c2`, and this panel said nothing. */}
          {pendingHandoffs.length > 0 && (
            <div className="space-y-2">
              {pendingHandoffs.map((h) => {
                const beacon = beacons.find((b) => b.id === h.beaconId)
                return (
                  <div key={h.id}
                    role="region"
                    aria-labelledby={`handoff-title-${h.id}`}
                    aria-describedby={`handoff-detail-${h.id}`}
                    className="rounded-lg border border-phantom-green/40 bg-phantom-green/5 p-3">
                    <div className="flex items-start justify-between gap-3">
                      <div className="min-w-0">
                        <div id={`handoff-title-${h.id}`}
                          className="text-[13px] font-semibold text-phantom-green">
                          Beacon available — {h.beaconId}
                        </div>
                        <div id={`handoff-detail-${h.id}`}
                          className="text-[11px] text-text-dim mt-0.5">
                          {h.target && <span className="mr-2">Target: {h.target}</span>}
                          {beacon?.os && <span className="mr-2">OS: {beacon.os}</span>}
                          {beacon?.hostname && <span className="mr-2">Host: {beacon.hostname}</span>}
                          {beacon?.user && <span className="mr-2">User: {beacon.user}</span>}
                          {beacon?.status && (
                            <span className={beacon.status === 'LIVE'
                              ? 'text-phantom-green'
                              : 'text-text-dim'}>
                              {beacon.status}
                            </span>
                          )}
                        </div>
                      </div>
                    </div>
                    <div className="flex gap-2 mt-2.5">
                      <button onClick={() => void openBeacon(h.beaconId)}
                        className="px-2.5 py-1 text-[11px] rounded bg-phantom-cyan/20
                                   border border-phantom-cyan/40 text-phantom-cyan
                                   hover:bg-phantom-cyan/30">
                        Open C2
                      </button>
                      <button onClick={() => void openBeacon(h.beaconId, true)}
                        className="px-2.5 py-1 text-[11px] rounded bg-phantom-magenta/20
                                   border border-phantom-magenta/40 text-phantom-magenta
                                   hover:bg-phantom-magenta/30">
                        Interact
                      </button>
                      <button onClick={() => void dismissHandoff(h.beaconId, h.id)}
                        className="px-2.5 py-1 text-[11px] rounded bg-surface
                                   border border-surface-border text-text-dim
                                   hover:border-phantom-green/40">
                        Keep AutoMode open
                      </button>
                    </div>
                  </div>
                )
              })}
            </div>
          )}
        </div>
      </div>
    </div>
  )
}

// ── Run state (F-27) ────────────────────────────────────────────────────────

/**
 * One line that answers "what is this run actually doing?": the state, the
 * backend's job id, how long it has been going, whether a stop is still in
 * flight, and (when the backend reported one) the failure.
 *
 * `backendSeen` matters: until a status answer arrives the state is the
 * panel's own optimistic label, so the chip says `local` instead of letting
 * "Running" mean "we hoped so". It also surfaces the LLM gate, which used to
 * be invisible outside the reasoning log.
 */
function RunStateStrip({
  state, jobId, startedAt, backendSeen, llmPending, cancelRequested, error,
  endReason
}: {
  state: string
  jobId: string | null
  startedAt?: number
  backendSeen: boolean
  llmPending: number
  cancelRequested: boolean
  error: string
  endReason: string
}) {
  const style = RUN_STATE_STYLE[state] ?? RUN_STATE_STYLE.idle
  // The backend states that mean "work is in flight" (the elapsed clock only
  // makes sense for those) and the ones that mean "this run is over".
  const inFlight = state === 'starting' || state === 'active' ||
    state === 'planning' || state === 'running' || state === 'stopping'
  const over = state === 'cancelled' || state === 'completed' ||
    state === 'failed' || state === 'done'
  return (
    <div role="status" aria-live="polite" aria-label="Auto-mode run state"
      className="bg-surface-card border border-surface-border rounded-lg p-3">
      <div className="flex items-center gap-2 flex-wrap">
        <span className={`px-2 py-0.5 rounded border text-[11px] font-semibold uppercase tracking-wider ${style.cls}`}>
          {cancelRequested && state === 'running' ? 'Stopping' : style.label}
        </span>
        <span className="text-[11px] text-text-dim font-mono">
          {jobId ? `job ${jobId}` : 'no job id yet'}
        </span>
        {inFlight && (
          <span className="text-[11px] text-text-dim font-mono">
            {fmtElapsed(startedAt)}
          </span>
        )}
        {!backendSeen && liveRunHint(state) && (
          <span className="text-[10px] text-text-dim italic">
            local state — waiting for the backend to confirm
          </span>
        )}
        {state === 'awaiting_approval' && (
          <span className="text-[10px] text-phantom-yellow">
            the run is waiting for an LLM decision
          </span>
        )}
        {llmPending > 0 && (
          <span className="text-[10px] text-phantom-yellow">
            LLM: {llmPending} request{llmPending === 1 ? '' : 's'} waiting
          </span>
        )}
      </div>
      {state === 'failed' && error && (
        <p className="text-[11px] text-phantom-error mt-1.5 break-words flex items-start gap-1.5">
          <AlertTriangle size={12} className="mt-0.5 flex-shrink-0" />
          <span>{error}</span>
        </p>
      )}
      {over && endReason && state !== 'failed' && (
        <p className="text-[11px] text-text-dim mt-1.5 break-words">{endReason}</p>
      )}
    </div>
  )
}

function liveRunHint(state: string): boolean {
  return state === 'starting' || state === 'active' || state === 'stopping' ||
    state === 'planning' || state === 'running'
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
      <button onClick={load} aria-expanded={open} className="flex items-center justify-between w-full text-left">
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