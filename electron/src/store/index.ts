import { create } from 'zustand'

// ── Types ──────────────────────────────────────────────

export interface Capabilities {
  core: boolean
  c2: boolean
  automode: boolean
}

/** Which component owns each tab. The single Electron shell enables only
 *  the sections the backend announces via GET /api/capabilities, so a build
 *  shipping a subset (e.g. the manual core alone) simply hides the rest. */
const TAB_COMPONENT: Record<string, keyof Capabilities> = {
  c2: 'c2',
  recordings: 'c2',
  automode: 'automode'
}

export function componentForTab(id: string): keyof Capabilities {
  return TAB_COMPONENT[id] ?? 'core'
}

export interface Toast {
  id: string
  title: string
  description?: string
  type: 'info' | 'success' | 'warning' | 'error'
}

export interface Beacon {
  id: string
  source_ip: string
  user: string
  hostname: string
  os: string
  status: 'LIVE' | 'IDLE' | 'DEAD' | 'EXITED'
  last_seen: string
  last_seen_display: string
  tasks_pending: number
  session_resumed_at?: string
}

export interface C2Task {
  task_id: string
  command: string
  status: 'pending' | 'sent' | 'done'
  result?: string
  sent_at?: string
  done_at?: string
}

export interface ListenerState {
  active: boolean
  proto: 'HTTP' | 'HTTPS'
  host: string
  port: number
  mtls: boolean
  certs_present: boolean
}

export type SessionNote = string | { timestamp: string; text: string }

export interface SessionState {
  target: string
  scope: string[]
  lhost: string
  lport: number
  active_wordlist: string
  notes: SessionNote[]
  results: Record<string, unknown>
  history: string[]
}

export interface AutoModeState {
  running: boolean
  /** P1-14: explicit terminal-state machine — `running` alone cannot
   *  distinguish a stalled poll from an active run, a stop request in
   *  flight, or a finished/failed run. */
  run_state?: 'idle' | 'starting' | 'active' | 'stopping' | 'done' | 'failed'
  startedAt?: number
  plan: string[]
  current_step: number
  steps: Array<{
    name: string
    status: 'done' | 'running' | 'waiting' | 'failed'
    detail?: string
  }>
  reasoning: Array<{
    time: string
    text: string
    command?: string
    reason?: string
    stealth?: string
  }>
  agents: number
  mode: 'default' | 'stealth' | 'aggressive' | 'speed'
  engine: 'agent' | 'swarm'
  forceNetwork: boolean
  targets: string[]
  profile: string
  goal: string
  llm: boolean
  experience: boolean
  verbose: boolean
}

export interface SettingsState {
  backend_type: 'wsl2' | 'native' | 'ssh' | 'none'
  ssh_host: string
  ssh_port: number
  ssh_user: string
  wsl_distro: string
  /** When ON, finished screen recordings are auto-copied to the Desktop
   *  (folder "Phantom Recordings"). When OFF (default) they stay inside
   *  Electron / data/recordings and are only saved on demand. */
  save_recordings_to_disk: boolean
}

interface PhantomStore {
  // C2
  listener: ListenerState
  beacons: Beacon[]
  activeBeacon: string | null
  tasks: Record<string, C2Task[]>
  c2Connected: boolean
  // the LAST IPC/API failure, shown to the operator. `c2Connected:false`
  // alone cannot distinguish "the listener is down" from "the desktop
  // bridge never answered" (an IPC timeout), which is the failure the
  // operator actually needs to see.
  c2Error: string
  setListener: (l: Partial<ListenerState>) => void
  setBeacons: (b: Beacon[]) => void
  setActiveBeacon: (id: string | null) => void
  setTasks: (beaconId: string, tasks: C2Task[]) => void
  setC2Connected: (v: boolean) => void
  setC2Error: (e: string) => void

  // Session
  session: SessionState
  setSession: (s: Partial<SessionState>) => void
  addNote: (note: string) => void
  addHistory: (cmd: string) => void

  // Auto-mode
  autoMode: AutoModeState
  setAutoMode: (a: Partial<AutoModeState>) => void
  appendReasoning: (
    time: string,
    text: string,
    extra?: { command?: string; reason?: string; stealth?: string }
  ) => void
  updateStep: (index: number, status: string, detail?: string) => void
  ensureStep: (index: number, name: string) => void

  // Settings
  settings: SettingsState
  setSettings: (s: Partial<SettingsState>) => void

  // Capabilities (feature-gating): which components this build exposes
  capabilities: Capabilities
  setCapabilities: (c: Partial<Capabilities>) => void

  // App
  elapsed: string
  setElapsed: (e: string) => void
  activeTab: string
  setActiveTab: (t: string) => void
  toasts: Toast[]
  pushToast: (toast: Omit<Toast, 'id'>) => void
  removeToast: (id: string) => void
}

export const useStore = create<PhantomStore>((set, get) => ({
  // C2 defaults
  listener: {
    active: false,
    proto: 'HTTPS',
    host: '0.0.0.0',
    port: 8080,
    mtls: true,
    certs_present: false
  },
  beacons: [],
  activeBeacon: null,
  tasks: {},
  c2Connected: false,
  c2Error: '',
  setListener: (l) => set((s) => ({ listener: { ...s.listener, ...l } })),
  setBeacons: (b) => set({ beacons: b }),
  setActiveBeacon: (id) => set({ activeBeacon: id }),
  setTasks: (beaconId, tasks) =>
    set((s) => ({ tasks: { ...s.tasks, [beaconId]: tasks } })),
  setC2Connected: (v) => set({ c2Connected: v }),
  setC2Error: (e) => set({ c2Error: e }),

  // Session defaults
  session: {
    target: '',
    scope: [],
    lhost: '',
    lport: 0,
    active_wordlist: '',
    notes: [],
    results: {},
    history: []
  },
  setSession: (s) => set((st) => ({ session: { ...st.session, ...s } })),
  addNote: (note) =>
    set((st) => ({ session: { ...st.session, notes: [...st.session.notes, note] } })),
  addHistory: (cmd) =>
    set((st) => ({ session: { ...st.session, history: [...st.session.history, cmd] } })),

  // Auto-mode defaults
  autoMode: {
    running: false,
    plan: [],
    current_step: 0,
    steps: [],
    reasoning: [],
    agents: 0,
    mode: 'default',
    engine: 'agent',
    forceNetwork: false,
    targets: [],
    profile: 'enterprise',
    goal: 'deliver',
    llm: false,
    experience: true,
    verbose: false
  },
  setAutoMode: (a) => set((s) => ({ autoMode: { ...s.autoMode, ...a } })),
  appendReasoning: (
    time: string,
    text: string,
    extra?: { command?: string; reason?: string; stealth?: string }
  ) =>
    set((s) => ({
      autoMode: {
        ...s.autoMode,
        reasoning: [...s.autoMode.reasoning, { time, text, ...extra }]
      }
    })),
  updateStep: (index, status, detail) =>
    set((s) => {
      const steps = [...s.autoMode.steps]
      if (steps[index]) {
        steps[index] = { ...steps[index], status: status as 'done' | 'running' | 'waiting' | 'failed', detail }
      }
      return { autoMode: { ...s.autoMode, steps } }
    }),
  // dynamic steps (deep goals: LATERAL/AD/CRACK/HUNT...): the backend
  // allocates indices from 8 up — append once, then updateStep works
  ensureStep: (index, name) =>
    set((s) => {
      if (s.autoMode.steps[index]) return s
      const steps = [...s.autoMode.steps]
      while (steps.length < index) steps.push({ name: '···', status: 'waiting' as const })
      steps[index] = { name, status: 'waiting' as const }
      return { autoMode: { ...s.autoMode, steps } }
    }),

  // Settings
  settings: {
    backend_type: 'none',
    ssh_host: '',
    ssh_port: 22,
    ssh_user: 'root',
    wsl_distro: 'kali-linux',
    // persisted in localStorage so the preference survives a restart
    save_recordings_to_disk:
      typeof localStorage !== 'undefined'
        ? localStorage.getItem('phantom.saveRecordingsToDisk') === '1'
        : false
  },
  setSettings: (s) => set((st) => ({ settings: { ...st.settings, ...s } })),

  // Capabilities: optimistic default (all on) so a failed/absent probe never
  // hides a section; GET /api/capabilities narrows it once the backend answers
  capabilities: { core: true, c2: true, automode: true },
  setCapabilities: (c) =>
    set((st) => ({ capabilities: { ...st.capabilities, ...c } })),

  // App
  elapsed: '0s',
  setElapsed: (e) => set({ elapsed: e }),
  activeTab: 'c2',
  setActiveTab: (t) => set({ activeTab: t }),
  toasts: [],
  pushToast: (t) => {
    const id = Math.random().toString(36).substring(2, 9)
    set((s) => ({ toasts: [...s.toasts, { ...t, id }] }))
    setTimeout(() => {
      set((s) => ({ toasts: s.toasts.filter(toast => toast.id !== id) }))
    }, 5000)
  },
  removeToast: (id) => set((s) => ({ toasts: s.toasts.filter((t) => t.id !== id) }))
}))