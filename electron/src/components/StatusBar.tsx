import { useStore } from '@/store'
import { Wrench } from 'lucide-react'

export default function StatusBar() {
  const { elapsed, listener, beacons, session, autoMode } = useStore()
  const liveCount = beacons.filter((b) => b.status === 'LIVE').length
  const proto = listener.proto
  const mtlsStatus = listener.mtls ? 'ON' : 'OFF'
  const target = session.target || '—'

  return (
    <div
      role="contentinfo"
      aria-label="Session status"
      className="h-7 flex-shrink-0 bg-surface-card border-t border-surface-border
      flex items-center justify-between px-3 text-[11px] text-text-secondary"
    >
      <div className="flex items-center gap-4">
        {/* The timer ticks every second: announcing it would flood a screen
            reader, so it is readable but not a live region. */}
        <span
          title="Time since this window opened — not the engagement clock (that one starts when a run does)"
          aria-label={`Window open for ${elapsed}`}
        >⏱ {elapsed}</span>

        {autoMode.running && autoMode.steps[autoMode.current_step] && (
          <span
            role="status"
            aria-live="polite"
            className="flex items-center gap-1.5 text-phantom-magenta font-mono bg-phantom-magenta/10 px-2 py-0.5 rounded"
          >
            <span className="w-1.5 h-1.5 rounded-full bg-phantom-magenta animate-pulse" aria-hidden="true" />
            Auto-Mode: {autoMode.steps[autoMode.current_step].name}
          </span>
        )}

        {/* The run's POSTURE, not just its current step. The profile and goal
            decide which chain executes — a `mobile` profile and an `identity`
            goal run a different kill chain than `enterprise`/`deliver` — and
            from any panel other than Auto-Mode they were shown nowhere, so
            the same run appeared to differ by tab. */}
        {autoMode.running && (
          <span
            role="status"
            aria-live="polite"
            aria-label={`Auto-Mode posture: profile ${autoMode.profile}, goal ${autoMode.goal}, engine ${autoMode.engine}, mode ${autoMode.mode}`}
            className="flex items-center gap-1.5"
          >
            <span className="text-text-dim">profile</span>
            <span className="text-phantom-cyan">{autoMode.profile}</span>
            <span className="text-text-dim">goal</span>
            <span className="text-phantom-cyan">{autoMode.goal}</span>
            <span className="text-text-dim">{autoMode.mode} · {autoMode.engine}</span>
            {autoMode.forceNetwork && (
              <span
                className="text-phantom-yellow"
                title="Force network: the whole range is engaged, not only discovered"
              >force-network</span>
            )}
          </span>
        )}

        {liveCount > 0 ? (
          <span className="flex items-center gap-1" role="status" aria-live="polite">
            <span className="w-2 h-2 rounded-full bg-phantom-green animate-pulse-beacon" aria-hidden="true" />
            <span className="text-phantom-green">{liveCount} beacon{liveCount > 1 ? 's' : ''}</span>
          </span>
        ) : (
          <span className="flex items-center gap-1" role="status" aria-live="polite">
            <span className="w-2 h-2 rounded-full bg-text-dim" aria-hidden="true" />
            <span>○ no beacon</span>
          </span>
        )}

        <span>target: <span className="text-phantom-cyan">{target}</span></span>
      </div>

      <div className="flex items-center gap-4">
        <span
          className="flex items-center gap-1"
          role="status"
          aria-live="polite"
          aria-label={listener.active
            ? `C2 listener up on ${proto} ${listener.host}:${listener.port}`
            : 'C2 listener not running'}
        >
          <span className={`w-2 h-2 rounded-full ${listener.active ? 'bg-phantom-green' : 'bg-phantom-error'}`} aria-hidden="true" />
          <span>{listener.active ? `${proto} ${listener.host}:${listener.port}` : 'no listener'}</span>
        </span>

        <span>mTLS: <span
          className={mtlsStatus === 'ON' ? 'text-phantom-green' : 'text-phantom-yellow'}
          aria-label={`Mutual TLS ${mtlsStatus === 'ON' ? 'enabled' : 'disabled'}`}
        >{mtlsStatus}</span></span>

        <span className="flex items-center gap-1 text-text-dim">
          <Wrench size={11} aria-hidden="true" />
          <span>backend: auto-detect</span>
        </span>
      </div>
    </div>
  )
}