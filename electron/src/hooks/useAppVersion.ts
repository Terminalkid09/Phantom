import { useEffect, useState } from 'react'

/**
 * The application version, from the ONE place that knows it: `package.json`,
 * through the Electron main process.
 *
 * The header and the sidebar footer each carried their own hardcoded literal
 * and they disagreed on screen at the same time — the title bar said `v3.0.0`
 * while the footer said `v3.7.3`, a version nothing in the tree declares.
 * Two numbers for one app is a bug in its own right: whichever one an operator
 * quotes in a report is wrong half the time.
 *
 * The IPC call is best-effort: if the bridge is unavailable the version is
 * simply not shown, because a wrong number is worse than no number.
 */
export function useAppVersion(): string {
  const [version, setVersion] = useState('')
  useEffect(() => {
    let alive = true
    window.phantom?.getVersion?.()
      ?.then((v) => { if (alive) setVersion(v || '') })
      ?.catch(() => { /* bridge unavailable: show nothing */ })
    return () => { alive = false }
  }, [])
  return version
}
