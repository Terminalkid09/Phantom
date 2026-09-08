import { useState, useEffect, useCallback } from 'react'
import { useApi } from '@/hooks/useApi'
import {
  ScrollText, RefreshCw, ShieldCheck, ShieldX, Fingerprint,
  Radio, Send, Inbox, Lock, Unlock, Ban, LogOut, Activity,
} from 'lucide-react'

interface AuditEntry {
  seq: number
  ts: string
  event: string
  [k: string]: unknown
}

interface AuditData {
  verified: boolean
  records: number
  first_bad: { seq: number } | null
  entries: AuditEntry[]
}

const EVENT_ICON: Record<string, typeof Radio> = {
  beacon_registered: Radio,
  task_queued: Send,
  task_result: Inbox,
  beacon_exited: LogOut,
  auth_rejected: Ban,
}

const EVENT_COLOR: Record<string, string> = {
  beacon_registered: 'text-phantom-green',
  task_queued: 'text-phantom-cyan',
  task_result: 'text-text-secondary',
  beacon_exited: 'text-phantom-yellow',
  auth_rejected: 'text-phantom-red',
}

function payloadFor(e: AuditEntry): string {
  const skip = new Set(['seq', 'ts', 'event', 'prev_hash', 'hash'])
  return Object.entries(e)
    .filter(([k, v]) => !skip.has(k) && v !== null && v !== undefined && v !== '')
    .map(([k, v]) => `${k}=${String(v).slice(0, 60)}`)
    .join('  ')
}

export default function AuditViewer({ standalone }: { standalone?: boolean }) {
  const { api } = useApi()
  const [data, setData] = useState<AuditData | null>(null)
  const [tail, setTail] = useState(50)

  const load = useCallback(async () => {
    const res = await api('GET', `/api/c2/audit?tail=${tail}`)
    if (res.status === 200 && res.data) setData(res.data as AuditData)
  }, [api, tail])

  useEffect(() => {
    load()
    const t = setInterval(load, 5000)
    return () => clearInterval(t)
  }, [load])

  if (!data) {
    return (
      <div className="h-full flex flex-col items-center justify-center text-text-dim">
        <ScrollText size={30} className="mb-2" />
        <p className="text-xs">Loading audit log…</p>
      </div>
    )
  }

  return (
    <div className={`flex flex-col h-full ${standalone ? 'p-4' : ''}`}>
      {standalone && (
        <div className="flex items-center justify-between mb-3">
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <ScrollText size={19} className="text-phantom-cyan" /> C2 Audit Log
          </h1>
          <div className="flex items-center gap-2">
            <select
              value={tail}
              onChange={(e) => setTail(Number(e.target.value))}
              className="bg-surface border border-surface-border rounded px-2 py-1.5 text-xs text-text-secondary"
            >
              {[50, 100, 250, 500].map((n) => (
                <option key={n} value={n}>last {n}</option>
              ))}
            </select>
            <button onClick={load} className="p-2 rounded text-text-secondary hover:text-text-primary hover:bg-surface-hover">
              <RefreshCw size={14} />
            </button>
          </div>
        </div>
      )}

      {/* Tamper-evidence verdict */}
      <div className={`flex items-center gap-3 px-3 py-2.5 rounded-lg border mb-3 flex-shrink-0
        ${data.verified
          ? 'bg-phantom-green/10 border-phantom-green/30'
          : 'bg-phantom-red/10 border-phantom-red/40'}`}>
        {data.verified ? (
          <ShieldCheck size={18} className="text-phantom-green flex-shrink-0" />
        ) : (
          <ShieldX size={18} className="text-phantom-red flex-shrink-0" />
        )}
        <div className="min-w-0">
          <p className={`text-xs font-semibold ${data.verified ? 'text-phantom-green' : 'text-phantom-red'}`}>
            {data.verified
              ? `Chain intact — ${data.records} record${data.records === 1 ? '' : 's'} verified`
              : `CHAIN BROKEN at record #${data.first_bad?.seq ?? '?'}`}
          </p>
          <p className="text-[10px] text-text-dim flex items-center gap-1 mt-0.5">
            <Fingerprint size={9} />
            SHA-256 hash chain (append-only) — edit or delete any record and verification fails
          </p>
        </div>
        <span className={`ml-auto text-[10px] font-mono px-2 py-1 rounded flex-shrink-0 flex items-center gap-1
          ${data.verified ? 'bg-phantom-green/15 text-phantom-green' : 'bg-phantom-red/15 text-phantom-red'}`}>
          {data.verified ? <Lock size={10} /> : <Unlock size={10} />}
          {data.verified ? 'TAMPER-EVIDENT' : 'COMPROMISED'}
        </span>
      </div>

      {/* Record feed */}
      <div className="flex-1 min-h-0 overflow-auto bg-surface-card border border-surface-border rounded-lg">
        {data.entries.length === 0 ? (
          <div className="h-full flex flex-col items-center justify-center text-text-dim">
            <Activity size={26} className="mb-2" />
            <p className="text-xs">No audit records yet.</p>
            <p className="text-[10px] mt-1">Start the C2 listener — registrations, tasks and results appear here.</p>
          </div>
        ) : (
          <div className="divide-y divide-surface-border">
            {[...data.entries].reverse().map((e) => {
              const Icon = EVENT_ICON[e.event] ?? Activity
              const color = EVENT_COLOR[e.event] ?? 'text-text-secondary'
              return (
                <div key={e.seq} className="flex items-start gap-3 px-3 py-2 hover:bg-surface-hover/50">
                  <span className="text-[10px] font-mono text-text-dim w-10 flex-shrink-0 text-right mt-0.5">
                    #{e.seq}
                  </span>
                  <Icon size={13} className={`mt-0.5 flex-shrink-0 ${color}`} />
                  <div className="min-w-0 flex-1">
                    <p className={`text-xs font-medium ${color}`}>{e.event}</p>
                    <p className="text-[10px] font-mono text-text-dim truncate">{payloadFor(e)}</p>
                  </div>
                  <span className="text-[10px] font-mono text-text-dim flex-shrink-0 mt-0.5">{e.ts}</span>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
