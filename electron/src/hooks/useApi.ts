import { useCallback, useEffect, useRef } from 'react'
import { useStore, type Beacon, type C2Task } from '@/store'

export async function requestApi(method: string, endpoint: string, body?: unknown) {
  if (!window.phantom) return { status: 0, data: { error: 'IPC not available' } }
  return window.phantom.request(method, endpoint, body)
}

export function useApi(enablePolling = false) {
  const {
    setListener, setBeacons, setTasks,
    setC2Connected, setSession
  } = useStore()

  const api = useCallback((method: string, endpoint: string, body?: unknown) =>
    requestApi(method, endpoint, body), [])

  const pollC2 = useCallback(async () => {
    const res = await requestApi('GET', '/api/c2/state')
    if (res.status === 200 && res.data) {
      const d = res.data as {
        listener: { active: boolean; proto: 'HTTP' | 'HTTPS'; host: string; port: number; mtls: boolean; certs_present: boolean }
        beacons: Beacon[]
        tasks: Record<string, C2Task[]>
      }
      setC2Connected(true)
      setListener(d.listener)
      setBeacons(d.beacons)
      Object.entries(d.tasks || {}).forEach(([bid, tasks]) => setTasks(bid, tasks))
    } else {
      setC2Connected(false)
    }
  }, [setListener, setBeacons, setTasks, setC2Connected])

  const pollSession = useCallback(async () => {
    const res = await requestApi('GET', '/api/session')
    if (res.status === 200 && res.data) setSession(res.data as Parameters<typeof setSession>[0])
  }, [setSession])

  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null)
  useEffect(() => {
    if (!enablePolling) return
    void pollC2()
    void pollSession()
    intervalRef.current = setInterval(() => {
      void pollC2()
      void pollSession()
    }, 2000)
    return () => {
      if (intervalRef.current) clearInterval(intervalRef.current)
    }
  }, [enablePolling, pollC2, pollSession])

  return { api, pollC2, pollSession }
}
