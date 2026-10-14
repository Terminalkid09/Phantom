import { useState, useEffect, useRef } from 'react'
import { useApi } from '@/hooks/useApi'
import { useSerialPoll } from '@/hooks/useSerialPoll'
import { Clock, Plus, RefreshCw, Layers } from 'lucide-react'

interface TimelineEvent {
  time: string
  source: string
  type: string
  detail: string
}

export default function TimelinePanel({ standalone }: { standalone?: boolean }) {
  const { api } = useApi()
  const [events, setEvents] = useState<TimelineEvent[]>([])
  const [newDetail, setNewDetail] = useState('')
  const ref = useRef<HTMLDivElement>(null)

  const load = async () => {
    const res = await api('GET', '/api/timeline')
    if (res.status === 200) setEvents((res.data as { events: TimelineEvent[] }).events || [])
  }

  useSerialPoll(load, 5000)

  useEffect(() => {
    if (ref.current && standalone) ref.current.scrollTop = ref.current.scrollHeight
  }, [events, standalone])

  const push = async () => {
    if (!newDetail.trim()) return
    await api('POST', '/api/timeline', { source: 'operator', type: 'note', detail: newDetail })
    setNewDetail('')
    load()
  }

  const sourceColor = (s: string) => {
    if (s === 'c2') return 'text-phantom-magenta'
    if (s === 'exploit') return 'text-phantom-red'
    if (s === 'scan') return 'text-phantom-cyan'
    if (s === 'beacon') return 'text-phantom-green'
    if (s === 'operator') return 'text-phantom-yellow'
    return 'text-text-dim'
  }

  const sourceIcon = (t: string) => {
    if (t === 'beacon') return '★'
    if (t === 'command') return '▶'
    if (t === 'found') return '✓'
    if (t === 'failed') return '✗'
    if (t === 'note') return '•'
    return '·'
  }

  return (
    <div className={`flex flex-col gap-3 ${standalone ? 'h-full p-4' : ''}`}>
      {standalone && (
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <Clock size={19} aria-hidden="true" className="text-phantom-yellow" /> Campaign Timeline
          </h1>
          <button onClick={load} aria-label="Reload the timeline" className="p-2 rounded text-text-secondary hover:text-text-primary hover:bg-surface-hover">
            <RefreshCw size={14} aria-hidden="true" />
          </button>
        </div>
      )}

      {!standalone && (
        <div className="flex items-center justify-between px-3 py-2 border-b border-surface-border">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
            <Clock size={13} aria-hidden="true" className="text-phantom-yellow" /> Timeline
          </h2>
          <button onClick={load} aria-label="Reload the timeline" className="text-text-dim hover:text-text-primary"><RefreshCw size={13} aria-hidden="true" /></button>
        </div>
      )}

      <div
        ref={ref}
        role="log"
        aria-live="polite"
        aria-label="Campaign timeline events"
        className="flex-1 overflow-auto space-y-1 px-1"
      >
        {events.length === 0 ? (
          <div className={`text-xs text-text-dim ${standalone ? 'p-8 text-center' : 'p-4 text-center'}`}>
            <p>Campaign events appear here as actions are performed.</p>
            <p className="mt-1 text-text-dim">Run scans, exploits, or deploy beacons to populate the timeline.</p>
          </div>
        ) : (
          events.map((e, i) => (
            <div key={i} className="flex gap-3 text-xs py-1.5 px-2 rounded hover:bg-surface-hover/50 transition-colors">
              <span className={`font-mono text-text-dim flex-shrink-0 w-12`}>{e.time}</span>
              <span className={`font-medium w-14 flex-shrink-0 ${sourceColor(e.source)}`} aria-label={`source ${e.source}`}>
                <span aria-hidden="true" className="mr-1">{sourceIcon(e.type)}</span>
                {e.source.toUpperCase()}
              </span>
              <span className="text-text-primary break-words flex-1">{e.detail}</span>
            </div>
          ))
        )}
      </div>

      {standalone && (
        <div className="flex gap-2 pt-2 border-t border-surface-border">
          <input
            type="text" value={newDetail} onChange={(e) => setNewDetail(e.target.value)}
            onKeyDown={(e) => e.key === 'Enter' && push()}
            placeholder="Add manual event..."
            aria-label="Add a manual timeline event"
            className="flex-1 bg-surface border border-surface-border rounded px-3 py-2 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-yellow"
          />
          <button onClick={push} aria-label="Add the timeline event"
            className="px-3 py-2 rounded bg-phantom-yellow/20 text-phantom-yellow text-xs font-medium flex items-center gap-1.5 hover:bg-phantom-yellow/30">
            <Plus size={12} aria-hidden="true" /> Add
          </button>
        </div>
      )}
    </div>
  )
}