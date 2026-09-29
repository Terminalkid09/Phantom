import { useCallback } from 'react'
import { useStore, type Beacon, type C2Task } from '@/store'
import { useSerialPoll } from '@/hooks/useSerialPoll'

// A backend that never answers must not hang an IPC call forever: the
// serial poll's busy-guard would then stay set and polling would STOP for
// the rest of the session. The race turns a hang into a structured error.
const API_TIMEOUT_MS = 15000

export interface ApiResponse<T = unknown> {
  status: number
  data: T
}

export async function requestApi<T = unknown>(
  method: string,
  endpoint: string,
  body?: unknown,
): Promise<ApiResponse<T>> {
  if (!window.phantom?.request) {
    return { status: 0, data: { error: 'IPC not available' } } as ApiResponse<T>
  }
  let timer: ReturnType<typeof setTimeout> | undefined
  try {
    return await Promise.race([
      window.phantom.request(method, endpoint, body),
      new Promise<never>((_, reject) => {
        timer = setTimeout(
          () => reject(new Error(`IPC timeout after ${API_TIMEOUT_MS}ms`)),
          API_TIMEOUT_MS,
        )
      }),
    ]) as ApiResponse<T>
  } catch (err) {
    // an IPC rejection/timeout degrades to a structured error instead of an
    // unhandled rejection that leaves the UI on a stale spinner
    return {
      status: 0,
      data: { error: err instanceof Error ? err.message : String(err) },
    } as ApiResponse<T>
  } finally {
    if (timer) clearTimeout(timer)
  }
}

/**
 * One human reason for a failed call, whatever the shape.
 *
 * The panels used to each invent their own: some printed
 * `String(res.data.error)` — which renders the literal "undefined" when the
 * backend sent no error field — some said "failed", some said nothing at
 * all. Every failure now reads the same way, and a status 0 (the desktop
 * bridge itself failing or timing out, not the backend refusing) says so
 * instead of blaming the feature.
 */
export function apiError(res: ApiResponse<unknown> | undefined): string {
  const body = res?.data as { error?: unknown } | undefined
  const detail = typeof body?.error === 'string' ? body.error.trim() : ''
  if (detail) return detail
  if (!res || res.status === 0) {
    return 'desktop bridge unavailable (IPC error or timeout)'
  }
  return `request failed (status ${res.status})`
}

/** Uniform error toast: title is what the operator tried to do. */
export function useApiError() {
  const pushToast = useStore((s) => s.pushToast)
  return useCallback(
    (res: ApiResponse<unknown> | undefined, title: string) => {
      pushToast({ title, description: apiError(res), type: 'error' })
    },
    [pushToast],
  )
}

export function useApi(enablePolling = false) {
  const {
    setListener, setBeacons, setTasks,
    setC2Connected, setC2Error, setSession
  } = useStore()

  const api = useCallback((method: string, endpoint: string, body?: unknown) =>
    requestApi(method, endpoint, body), [])

  const pollC2 = useCallback(async () => {
    const res = await requestApi<{
      listener: { active: boolean; proto: 'HTTP' | 'HTTPS'; host: string; port: number; mtls: boolean; certs_present: boolean }
      beacons: Beacon[]
      tasks: Record<string, C2Task[]>
    }>('GET', '/api/c2/state')
    if (res.status === 200 && res.data) {
      const d = res.data
      setC2Connected(true)
      setC2Error('')
      setListener(d.listener)
      setBeacons(d.beacons)
      Object.entries(d.tasks || {}).forEach(([bid, tasks]) => setTasks(bid, tasks))
    } else {
      setC2Connected(false)
      // show WHY, not just "disconnected": a status 0 is the desktop
      // bridge failing/timing out, not the listener being down
      const err = (res.data as { error?: string } | undefined)?.error
      setC2Error(err || `C2 state unavailable (status ${res.status})`)
    }
  }, [setListener, setBeacons, setTasks, setC2Connected, setC2Error])

  const pollSession = useCallback(async () => {
    const res = await requestApi<Parameters<typeof setSession>[0]>(
      'GET', '/api/session')
    if (res.status === 200 && res.data) setSession(res.data)
  }, [setSession])

  const intervalFn = useCallback(async () => {
    await pollC2()
    await pollSession()
  }, [pollC2, pollSession])
  // serial: an in-flight poll is never overlapped by the next tick
  useSerialPoll(intervalFn, 2000, enablePolling, [enablePolling])

  return { api, pollC2, pollSession }
}
