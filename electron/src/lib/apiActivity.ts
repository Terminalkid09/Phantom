/**
 * One global answer to "is the app working?" — framework-free.
 *
 * The store lives in `lib/` so `api.ts` can import it without pulling React
 * into an isolated compile; the React binding is `hooks/apiActivity.ts`.
 *
 * Panel-local spinners only cover the panels that remembered to add one. The
 * operator still clicked buttons that did nothing visible while the IPC call
 * was in flight, so the whole shell now shows an activity pill for EVERY
 * non-background API request. A short minimum-visible window keeps a fast
 * localhost answer from flashing so briefly that it looks like nothing
 * happened (and gives the E2E feedback test something to observe).
 */
export interface ApiActivity {
  visible: boolean
  pending: number
  label: string
}

const MIN_VISIBLE_MS = 700

let pending = 0
let label = ''
let visible = false
let backgroundDepth = 0
let hideTimer: ReturnType<typeof setTimeout> | undefined
let snapshot: ApiActivity = { visible: false, pending: 0, label: '' }
const listeners = new Set<() => void>()

function emit(): void {
  snapshot = { visible, pending, label }
  listeners.forEach((listener) => listener())
}

export function subscribe(listener: () => void): () => void {
  listeners.add(listener)
  return () => listeners.delete(listener)
}

export function getSnapshot(): ApiActivity {
  return snapshot
}

/** True while a request is inside a `runAsBackgroundRequest` scope. */
export function isBackgroundRequest(): boolean {
  return backgroundDepth > 0
}

/**
 * Run a poll (or any automatic refresh) without lighting the global pill.
 *
 * The scope is deliberately SYNCHRONOUS: the poll's first `requestApi` call
 * starts inside it and is classified as background, but the scope ends before
 * the request resolves. A long poll must never suppress the feedback of a
 * real click that happens while it is in flight.
 */
export function runAsBackgroundRequest<T>(fn: () => T): T {
  backgroundDepth += 1
  try {
    return fn()
  } finally {
    backgroundDepth = Math.max(0, backgroundDepth - 1)
  }
}

/** Mark an API request as started. Returns the matching `finish` callback. */
export function beginApiActivity(requestLabel: string): () => void {
  pending += 1
  label = requestLabel
  visible = true
  if (hideTimer) {
    clearTimeout(hideTimer)
    hideTimer = undefined
  }
  emit()

  let finished = false
  return () => {
    if (finished) return
    finished = true
    pending = Math.max(0, pending - 1)
    if (pending > 0) {
      emit()
      return
    }
    // Keep the pill up long enough to be perceived (and asserted) even when
    // the backend answers in a few milliseconds.
    hideTimer = setTimeout(() => {
      hideTimer = undefined
      visible = false
      label = ''
      emit()
    }, MIN_VISIBLE_MS)
  }
}

/** Test-only reset; never called by the app. */
export function _resetApiActivity(): void {
  if (hideTimer) clearTimeout(hideTimer)
  hideTimer = undefined
  pending = 0
  label = ''
  visible = false
  emit()
}
