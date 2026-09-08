import { useStore } from '@/store'
import { Wrench } from 'lucide-react'

export default function StatusBar() {
  const { elapsed, listener, beacons, session, autoMode } = useStore()
  const liveCount = beacons.filter((b) => b.status === 'LIVE').length
  const proto = listener.proto
  const mtlsStatus = listener.mtls ? 'ON' : 'OFF'
  const target = session.target || '—'

  return (
    <div className="h-7 flex-shrink-0 bg-surface-card border-t border-surface-border
      flex items-center justify-between px-3 text-[11px] text-text-secondary">
      <div className="flex items-center gap-4">
        <span>⏱ {elapsed}</span>

        {autoMode.running && autoMode.steps[autoMode.current_step] && (
          <span className="flex items-center gap-1.5 text-phantom-magenta font-mono bg-phantom-magenta/10 px-2 py-0.5 rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-phantom-magenta animate-pulse" />
            Auto-Mode: {autoMode.steps[autoMode.current_step].name}
          </span>
        )}

        {liveCount > 0 ? (
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-phantom-green animate-pulse-beacon" />
            <span className="text-phantom-green">{liveCount} beacon{liveCount > 1 ? 's' : ''}</span>
          </span>
        ) : (
          <span className="flex items-center gap-1">
            <span className="w-2 h-2 rounded-full bg-text-dim" />
            <span>○ no beacon</span>
          </span>
        )}

        <span>target: <span className="text-phantom-cyan">{target}</span></span>
      </div>

      <div className="flex items-center gap-4">
        <span className="flex items-center gap-1">
          <span className={`w-2 h-2 rounded-full ${listener.active ? 'bg-phantom-green' : 'bg-phantom-error'}`} />
          <span>{listener.active ? `${proto} ${listener.host}:${listener.port}` : 'no listener'}</span>
        </span>

        <span>mTLS: <span className={mtlsStatus === 'ON' ? 'text-phantom-green' : 'text-phantom-yellow'}>{mtlsStatus}</span></span>

        <span className="flex items-center gap-1 text-text-dim">
          <Wrench size={11} />
          <span>backend: auto-detect</span>
        </span>
      </div>
    </div>
  )
}