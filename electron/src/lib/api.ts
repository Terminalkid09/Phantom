/**
 * api.ts — the renderer's TYPED operations for the auto-mode job (F-25).
 *
 * Every panel used to speak the raw IPC bridge, handing it a path string and
 * casting the answer to an inline object literal
 * (`res.data as { done: boolean }`). Two costs came with that. The compiler
 * could not check a single field — a renamed backend field is a silent
 * `undefined` at runtime — and the shape of the answer was re-invented at
 * every call site, so the same payload was read three different ways in one
 * panel.
 *
 * Here each operation the auto-mode panel performs is ONE function with a
 * declared request type, a declared response type, and a PARSER that narrows
 * the untrusted payload into that type (a cast asserts; a parser checks and
 * falls back). The parsers follow the contracts in `phantom/api/server.py`:
 * the six `automode` routes between lines 932 and 1210, whose request and
 * response shapes are quoted on each payload type below.
 *
 * Two deliberate implementation notes:
 *
 * 1. The one-call primitive below is called `request`, and every endpoint
 *    literal sits INLINE in the call that uses it, exactly as the panels
 *    spell it. The IPC
 *    contract test (`tests/test_electron_allowlist_sync.py`) re-derives the
 *    UI's endpoint set by scanning `electron/src` for exactly the spellings
 *    `api('METHOD', …)`, `requestApi('METHOD', …)` and `request('METHOD', …)`.
 *    Moving an endpoint into a differently named helper would silently remove
 *    it from that scan — the drift the test exists to catch — so the name and
 *    the literal stay together on purpose. Do not rename it, and do not wrap
 *    the literal in a constant.
 *
 * 2. A timeout is per operation, not global. `useApi`'s generic bridge races
 *    every call against 15s, which is right for a read and wrong for a run:
 *    `/api/automode/run` and `/api/automode/plan` legitimately execute a whole
 *    dry-run plan before answering (the main process allows 2h for the same
 *    reason). Racing them at 15s returned status 0 while the backend kept
 *    working, so the panel reported "Failed to start auto-mode" for a run that
 *    had in fact started.
 */

/** One decoded HTTP answer. `data` is a parsed payload on 200, the raw error
 *  envelope otherwise (so `apiError()` can quote what the backend said). */
export interface ApiResponse<T> {
  status: number
  data: T
}

type Method = 'GET' | 'POST'

/** Cheap reads and single mutations. */
const FAST_MS = 15_000
/** A run/plan answers after the engine has actually planned or started. */
const LONG_MS = 7_200_000

async function request<T>(
  method: Method,
  endpoint: string,
  body?: unknown,
  timeoutMs: number = FAST_MS,
  parse?: (raw: unknown) => T,
): Promise<ApiResponse<T>> {
  const bridge = typeof window !== 'undefined' ? window.phantom : undefined
  if (!bridge?.request) {
    return { status: 0, data: { error: 'IPC not available' } as unknown as T }
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    const res = await Promise.race([
      bridge.request(method, endpoint, body),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`IPC timeout after ${timeoutMs}ms`)),
          timeoutMs,
        )
      }),
    ])
    if (res.status === 200 && parse) {
      return { status: res.status, data: parse(res.data) }
    }
    // A non-200 body is an ERROR envelope, not a payload of type T: keep it
    // verbatim (apiError reads it) and never dress it up as a valid T.
    return { status: res.status, data: res.data as unknown as T }
  } catch (err) {
    return {
      status: 0,
      data: { error: err instanceof Error ? err.message : String(err) } as unknown as T,
    }
  } finally {
    if (timer) clearTimeout(timer)
  }
}

// ── narrowing helpers (no `any`: every field is checked, then defaulted) ────

function asRecord(v: unknown): Record<string, unknown> {
  return v !== null && typeof v === 'object' && !Array.isArray(v)
    ? (v as Record<string, unknown>)
    : {}
}

function str(v: unknown, fallback = ''): string {
  return typeof v === 'string' ? v : fallback
}

function num(v: unknown, fallback = 0): number {
  return typeof v === 'number' && Number.isFinite(v) ? v : fallback
}

function bool(v: unknown, fallback = false): boolean {
  return typeof v === 'boolean' ? v : fallback
}

function asList<T>(v: unknown): T[] {
  return Array.isArray(v) ? (v as T[]) : []
}

// ── payload types, mirrored from phantom/api/server.py ─────────────────────

/** `POST /api/automode/run` (server.py:1040) */
export interface AutomodeRunRequest {
  targets: string[]
  mode: string
  engine: string
  force_network: boolean
  profile: string
  goal: string
  agents: number
  llm: boolean
  experience: boolean
  verbose: boolean
  resume?: string
}

export interface AutomodeRunResult {
  status: string
  /** the handle the backend gave this run; a stop cancels THAT job */
  job_id: string
  targets: string[]
  mode: string
  engine: string
  guardrails: Record<string, unknown> | null
}

/**
 * `GET /api/automode/status` — the job as the BACKEND sees it.
 *
 * F-27: ONE shape for every answer, `state: 'idle'` included (the server's
 * `_IDLE_STATUS` mirrors `AutoJob.snapshot()` key for key), so the renderer
 * narrows a single payload instead of a union of "job" and "no job" answers.
 */
export interface AutomodeStatus {
  job_id: string | null
  /** `idle` = no job at all; the rest is the run's real lifecycle */
  state: JobState
  /** every transition this run made, oldest first (bounded tail) */
  state_history: Array<{ state: string; at: number; detail: string }>
  running: boolean
  done: boolean
  /** WHY it ended: "stopped by operator", "sequence complete", the crash */
  end_reason: string
  error: string
  current_step: number
  started_at: number
  elapsed: number
  targets: string[]
  mode: string
  profile: string
  goal: string
  llm: string
  llm_pending: number
  handoffs: AutomodeHandoffRecord[]
  handoff_state: 'none' | 'ready' | 'accepted' | 'dismissed'
}

/**
 * F-27: the run states the operator can see, as ONE union instead of the old
 * boolean. `running: false` could not distinguish `stopping` (we asked and the
 * engine has not halted yet) from `cancelled` (it did) or `failed` (it died) —
 * all three were simply "not running".
 *
 * The backend states are `planning | running | stopping | cancelled |
 * completed | failed` (plus `idle` when there is no job); `handoff_ready` and
 * `awaiting_approval` are the two operator-facing states DERIVED from the
 * snapshot. Deliberately absent: `paused` and `timed_out` — the backend has no
 * pause control and no wall-clock deadline on a run, so a UI showing them
 * would be inventing a state nothing can reach (docs/ManusOpenCode.md §3.3A is
 * the wish-list; this union is what the backend can assert).
 */
export type JobState =
  | 'idle'
  | 'planning'
  | 'running'
  | 'awaiting_approval'
  | 'handoff_ready'
  | 'stopping'
  | 'cancelled'
  | 'completed'
  | 'failed'

const JOB_STATES: readonly string[] = [
  'idle', 'planning', 'running', 'awaiting_approval', 'handoff_ready',
  'stopping', 'cancelled', 'completed', 'failed',
]

function asJobState(v: unknown): JobState {
  const s = str(v)
  return JOB_STATES.includes(s) ? (s as JobState) : 'idle'
}

/**
 * The operator-facing state of a job. Pure, so it is the one place to test.
 *
 * Order matters: a crash and an operator stop outrank everything (the run's
 * history is what tells the story), then an un-acted handoff — a run that
 * produced a beacon is WAITING for the operator's decision, not "completed" —
 * then a stop in flight, then the LLM gate the operator has to resolve.
 */
export function deriveJobState(status: AutomodeStatus): JobState {
  const backend = status.state
  if (backend === 'failed') return 'failed'
  if (backend === 'cancelled') return 'cancelled'
  if (status.handoff_state === 'ready') return 'handoff_ready'
  if (backend === 'stopping') return 'stopping'
  if (status.llm_pending > 0) return 'awaiting_approval'
  if (backend === 'completed') return 'completed'
  if (backend === 'planning') return 'planning'
  return backend === 'running' ? 'running' : 'idle'
}

function parseAutomodeStatus(raw: unknown): AutomodeStatus {
  const d = asRecord(raw)
  return {
    job_id: d.job_id === null || d.job_id === undefined ? null : str(d.job_id),
    state: asJobState(d.state),
    state_history: asList<Record<string, unknown>>(d.state_history).map((h) => ({
      state: str(h.state),
      at: num(h.at),
      detail: str(h.detail),
    })),
    running: bool(d.running),
    done: bool(d.done),
    end_reason: str(d.end_reason),
    error: str(d.error),
    current_step: num(d.current_step, -1),
    started_at: num(d.started_at),
    elapsed: num(d.elapsed),
    targets: asList<string>(d.targets),
    mode: str(d.mode),
    profile: str(d.profile),
    goal: str(d.goal),
    llm: str(d.llm, 'denied'),
    llm_pending: num(d.llm_pending),
    handoffs: parseHandoffs(d.handoffs),
    handoff_state: (['none', 'ready', 'accepted', 'dismissed'] as const)
      .includes(str(d.handoff_state) as 'none')
      ? (str(d.handoff_state) as AutomodeStatus['handoff_state'])
      : 'none',
  }
}

function parseHandoffs(v: unknown): AutomodeHandoffRecord[] {
  return asList<Record<string, unknown>>(v).map((h) => ({
    beacon_id: str(h.beacon_id),
    kind: str(h.kind),
    target: h.target === undefined ? undefined : str(h.target),
    created_at: num(h.created_at),
    status: h.status === undefined ? undefined : str(h.status),
    resolved_at: h.resolved_at === undefined ? undefined : num(h.resolved_at),
  }))
}

/** `GET /api/automode/stream` (server.py:1010) */
export interface AutomodeStepUpdate {
  step: number
  status: string
  detail: string
  name?: string
}

export interface AutomodeLogLine {
  time: string
  text: string
  level?: 'info' | 'success' | 'warn' | 'error' | 'dim'
  command?: string
  reason?: string
  stealth?: string
}

export interface AutomodeHandoffRecord {
  beacon_id: string
  kind: string
  target?: string
  created_at: number
  /** the operator's decision: ready | accepted | dismissed */
  status?: string
  resolved_at?: number
}

export interface AutomodeStreamPayload {
  done: boolean
  step_updates: AutomodeStepUpdate[]
  current_step: number
  log: AutomodeLogLine[]
  handoffs: AutomodeHandoffRecord[]
}

/** `POST /api/automode/stop` */
export interface AutomodeStopResult {
  status: string
  job_id?: string
  /** set when there was nothing to stop: "no active run" */
  note?: string
  /** `stopping` — cooperative: the engine halts at its next boundary, and
   *  only the status poll can report the terminal `cancelled` */
  state?: JobState
  job?: AutomodeStatus
}

/** `POST /api/automode/handoff` — accept or dismiss a beacon handoff. */
export interface AutomodeHandoffResult {
  status: string
  decision: 'accept' | 'dismiss'
  beacon_id: string
  job_id: string
  handoff_state: string
  job: AutomodeStatus
}

/** `POST /api/automode/plan` (server.py:1201) */
export interface AutomodePlanRequest {
  targets: string[]
  mode: string
  profile: string
  goal: string
  engine: string
  force_network: boolean
  agents: number
}

export interface AutomodePlanResult {
  plan: string[]
  note?: string
}

/** `POST /api/automode/llm` (server.py:1104) */
export interface AutomodeLlmResult {
  status: string
  llm: string
  job_id: string
}

// ── operations ─────────────────────────────────────────────────────────────

/** The active run's snapshot, or a specific (possibly finished) job's. The
 *  endpoint literals stay INLINE — the comment at the top of this file is the
 *  reason — so `?job_id=` is a second call, not a built variable. */
export function automodeStatus(
  jobId?: string,
): Promise<ApiResponse<AutomodeStatus>> {
  if (!jobId) {
    return request('GET', '/api/automode/status', undefined, FAST_MS,
      parseAutomodeStatus)
  }
  return request('GET', `/api/automode/status?job_id=${encodeURIComponent(jobId)}`,
    undefined, FAST_MS, parseAutomodeStatus)
}

/** Record the operator's decision on a handoff. `accept` is what "Open C2" and
 *  "Interact" send, `dismiss` is "Keep AutoMode open". The answer carries the
 *  job snapshot, so the caller does not re-poll to learn what its click did. */
export function automodeHandoff(
  beaconId: string,
  decision: 'accept' | 'dismiss',
  jobId?: string,
): Promise<ApiResponse<AutomodeHandoffResult>> {
  const body: Record<string, unknown> = { beacon_id: beaconId, decision }
  if (jobId) body.job_id = jobId
  return request('POST', '/api/automode/handoff', body, FAST_MS,
    (raw): AutomodeHandoffResult => {
      const d = asRecord(raw)
      return {
        status: str(d.status),
        decision: str(d.decision) === 'dismiss' ? 'dismiss' : 'accept',
        beacon_id: str(d.beacon_id),
        job_id: str(d.job_id),
        handoff_state: str(d.handoff_state),
        job: parseAutomodeStatus(d.job),
      }
    })
}

export function automodeRun(
  cfg: AutomodeRunRequest,
): Promise<ApiResponse<AutomodeRunResult>> {
  return request('POST', '/api/automode/run', cfg, LONG_MS,
    (raw): AutomodeRunResult => {
      const d = asRecord(raw)
      return {
        status: str(d.status),
        job_id: str(d.job_id),
        targets: asList<string>(d.targets),
        mode: str(d.mode),
        engine: str(d.engine),
        guardrails: (d.guardrails === null || d.guardrails === undefined
          ? null : asRecord(d.guardrails)),
      }
    })
}

/** Request a cooperative stop. The backend halts at the next iteration
 *  boundary, so the run is NOT finished when this returns: the status poll
 *  decides when it is. A `note` of "no active run" means there was nothing to
 *  stop and the UI can settle immediately. */
export function automodeStop(): Promise<ApiResponse<AutomodeStopResult>> {
  return request('POST', '/api/automode/stop', undefined, FAST_MS,
    (raw): AutomodeStopResult => {
      const d = asRecord(raw)
      return {
        status: str(d.status),
        job_id: d.job_id === undefined ? undefined : str(d.job_id),
        note: d.note === undefined ? undefined : str(d.note),
      }
    })
}

export function automodePlan(
  cfg: AutomodePlanRequest,
): Promise<ApiResponse<AutomodePlanResult>> {
  return request('POST', '/api/automode/plan', cfg, LONG_MS,
    (raw): AutomodePlanResult => {
      const d = asRecord(raw)
      return {
        plan: asList<string>(d.plan),
        note: d.note === undefined ? undefined : str(d.note),
      }
    })
}

/** Live LLM approval: true = approve for the session, 'once' = single
 *  consult, false = deny (server.py:1104). */
export function automodeSetLlm(
  allow: boolean | 'once',
): Promise<ApiResponse<AutomodeLlmResult>> {
  return request('POST', '/api/automode/llm', { allow }, FAST_MS,
    (raw): AutomodeLlmResult => {
      const d = asRecord(raw)
      return {
        status: str(d.status),
        llm: str(d.llm),
        job_id: str(d.job_id),
      }
    })
}

export function automodeStream(): Promise<ApiResponse<AutomodeStreamPayload>> {
  return request('GET', '/api/automode/stream', undefined, FAST_MS,
    (raw): AutomodeStreamPayload => {
      const d = asRecord(raw)
      return {
        done: bool(d.done),
        step_updates: asList<Record<string, unknown>>(d.step_updates).map((u) => ({
          step: num(u.step),
          status: str(u.status),
          detail: str(u.detail),
          name: u.name === undefined ? undefined : str(u.name),
        })),
        current_step: num(d.current_step, -1),
        log: asList<Record<string, unknown>>(d.log).map((l) => ({
          time: str(l.time),
          text: str(l.text),
          level: l.level === undefined
            ? undefined
            : (str(l.level) as AutomodeLogLine['level']),
          command: l.command === undefined ? undefined : str(l.command),
          reason: l.reason === undefined ? undefined : str(l.reason),
          stealth: l.stealth === undefined ? undefined : str(l.stealth),
        })),
        handoffs: parseHandoffs(d.handoffs),
      }
    })
}

/**
 * Point the backend session at a value (the run's target #1 must be the
 * Session panel's target, or the manual panels work on a different host).
 */
export function sessionSet(
  key: string,
  value: unknown,
): Promise<ApiResponse<Record<string, unknown>>> {
  return request('POST', '/api/session/set', { key, value }, FAST_MS)
}
