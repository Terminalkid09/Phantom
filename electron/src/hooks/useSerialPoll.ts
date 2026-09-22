import { useEffect, useRef } from 'react'

/**
 * Serial background polling: fire immediately, then every `ms`, but
 * NEVER overlap an in-flight request (busy-guard) and always clean up
 * on unmount / re-arm. Replaces raw setInterval(fetch), which stacked
 * concurrent fetches when the backend answered slowly — with every
 * panel mounted at once that multiplied into a request storm on the
 * single-process localhost API.
 */
export function useSerialPoll(
  fn: () => Promise<unknown> | unknown,
  ms: number,
  active: boolean = true,
  deps: unknown[] = [],
) {
  const fnRef = useRef(fn)
  fnRef.current = fn
  const busyRef = useRef(false)
  useEffect(() => {
    if (!active) return
    let alive = true
    const tick = async () => {
      if (busyRef.current || !alive) return
      busyRef.current = true
      try {
        await fnRef.current()
      } catch {
        // transient backend hiccup — the next tick retries
      } finally {
        busyRef.current = false
      }
    }
    void tick()
    const h = setInterval(tick, ms)
    return () => {
      alive = false
      clearInterval(h)
      busyRef.current = false
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [ms, active, ...deps])
}
