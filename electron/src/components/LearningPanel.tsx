import { useEffect, useMemo, useState } from 'react'
import { Brain, RefreshCw, Trash2, TrendingUp, TrendingDown, Database } from 'lucide-react'
import { useApi } from '@/hooks/useApi'

interface Episode {
  sig: { cls?: string; product?: string; services?: string[]; defenses?: string[] }
  phase: string
  technique: string
  ok: boolean
  cause: string
  repair: string
  detail: string
  ts: number
}

interface Stats {
  enabled?: boolean
  path?: string
  episodes?: number
  learnable?: number
  successes?: number
  failures?: number
  by_cause?: Record<string, number>
  by_phase?: Record<string, number>
  top_repairs?: Record<string, number>
}

interface LearningData {
  stats: Stats
  patterns: Record<string, { runs: number; wins: number; rate: number }>
  causes?: { total_failures?: number; by_cause?: Record<string, number> }
  recent: Episode[]
  labels?: Record<string, string>
}

const EMPTY: LearningData = { stats: {}, patterns: {}, recent: [] }

/**
 * LearningPanel — what Phantom has LEARNED (not what it is doing now).
 *
 * The experience engine records, for every attempt: the situation, the
 * technique, the outcome, WHY it failed and which move actually unblocked
 * it. This panel is the operator's window into that memory: which
 * cause->repair patterns are established, how often each wall is hit, and
 * the raw episodes behind the numbers. Reset is deliberate and explicit —
 * forgetting a client's engagement is a conscious action, never a surprise.
 */
export default function LearningPanel() {
  const { api } = useApi()
  const [data, setData] = useState<LearningData>(EMPTY)
  const [loading, setLoading] = useState(false)
  const [notice, setNotice] = useState('')
  const [filter, setFilter] = useState<'all' | 'repairs' | 'failures'>('all')

  const load = async () => {
    setLoading(true)
    try {
      const res = await api('GET', '/api/learning')
      if (res.status === 200) setData({ ...EMPTY, ...(res.data as LearningData) })
    } finally {
      setLoading(false)
    }
  }

  useEffect(() => { load() }, [])

  const reset = async () => {
    const res = await api('POST', '/api/learning/reset', {})
    if (res.status === 200) {
      setNotice('Learning memory cleared.')
      load()
    } else {
      setNotice('Could not clear the learning memory.')
    }
    setTimeout(() => setNotice(''), 4000)
  }

  const causes = data.causes?.by_cause || data.stats.by_cause || {}
  const totalCause = useMemo(
    () => Object.values(causes).reduce((a, b) => a + b, 0) || 1, [causes])

  const repairs = Object.entries(data.patterns || {})
    .filter(([k, v]) => v.rate >= 0.5 && k.includes('@'))
    .sort((a, b) => b[1].rate - a[1].rate)
    .slice(0, 12)

  const struggles = Object.entries(data.patterns || {})
    .filter(([, v]) => v.rate <= 0.5)
    .sort((a, b) => a[1].rate - b[1].rate)
    .slice(0, 8)

  const episodes = (data.recent || []).filter((e) => {
    if (filter === 'repairs') return !!e.repair
    if (filter === 'failures') return !e.ok
    return true
  })

  const label = (c: string) => data.labels?.[c] || c

  return (
    <div className="flex-1 flex flex-col min-h-0 h-full bg-surface-base">
      <div className="flex items-center justify-between px-3 py-2 border-b border-surface-border">
        <div className="flex items-center gap-2">
          <Brain size={15} className="text-phantom-magenta" />
          <span className="text-sm font-semibold text-text-primary">Learning Memory</span>
          <span className="text-[11px] text-text-dim">
            cross-engagement experience · {data.stats.enabled ? 'persistent' : 'run-only'}
          </span>
        </div>
        <div className="flex items-center gap-2">
          <button onClick={load}
            className="flex items-center gap-1 text-xs px-2 py-1 rounded border border-surface-border hover:bg-surface-hover">
            <RefreshCw size={12} className={loading ? 'animate-spin' : ''} /> Refresh
          </button>
          <button onClick={reset}
            className="flex items-center gap-1 text-xs px-2 py-1 rounded border border-phantom-red/40 text-phantom-red hover:bg-phantom-red/10">
            <Trash2 size={12} /> Reset
          </button>
        </div>
      </div>
      {notice && (
        <div className="px-3 py-1 text-[11px] text-phantom-magenta border-b border-surface-border">
          {notice}
        </div>
      )}

      <div className="grid grid-cols-4 gap-2 p-3">
        <Stat label="Episodes" value={data.stats.episodes ?? 0} icon={<Database size={12} />} />
        <Stat label="Learnable" value={data.stats.learnable ?? 0} />
        <Stat label="Successes" value={data.stats.successes ?? 0}
          icon={<TrendingUp size={12} />} tone="text-phantom-green" />
        <Stat label="Failures" value={data.stats.failures ?? 0}
          icon={<TrendingDown size={12} />} tone="text-phantom-red" />
      </div>

      <div className="flex-1 overflow-auto px-3 pb-3 grid grid-cols-1 xl:grid-cols-2 gap-3 min-h-0">
        <section className="rounded border border-surface-border bg-surface-card p-3">
          <h3 className="text-xs font-semibold text-text-primary mb-2">
            Failure causes — where engagements get stuck
          </h3>
          {Object.keys(causes).length === 0 ? (
            <p className="text-[11px] text-text-dim">No failures recorded yet.</p>
          ) : (
            <div className="space-y-1.5">
              {Object.entries(causes).sort((a, b) => b[1] - a[1]).map(([cause, n]) => (
                <div key={cause}>
                  <div className="flex justify-between text-[11px]">
                    <span className="text-text-secondary">{label(cause)}</span>
                    <span className="text-text-dim">{n}</span>
                  </div>
                  <div className="h-1.5 rounded bg-surface-base overflow-hidden">
                    <div className="h-full bg-phantom-red/70"
                      style={{ width: `${Math.round((n / totalCause) * 100)}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </section>

        <section className="rounded border border-surface-border bg-surface-card p-3">
          <h3 className="text-xs font-semibold text-text-primary mb-2">
            Learned patterns <span className="text-text-dim font-normal">(rate · runs)</span>
          </h3>
          {repairs.length === 0 && struggles.length === 0 ? (
            <p className="text-[11px] text-text-dim">
              Nothing learned yet — run an engagement and the memory fills itself.
            </p>
          ) : (
            <div className="space-y-3">
              {repairs.length > 0 && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-phantom-green mb-1">
                    Reliable
                  </div>
                  <ul className="space-y-1">
                    {repairs.map(([k, v]) => (
                      <li key={k} className="flex justify-between text-[11px]">
                        <span className="text-text-secondary truncate">{k}</span>
                        <span className="text-phantom-green ml-2 shrink-0">
                          {Math.round(v.rate * 100)}% · {v.runs}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
              {struggles.length > 0 && (
                <div>
                  <div className="text-[10px] uppercase tracking-wide text-phantom-red mb-1">
                    Deprioritised
                  </div>
                  <ul className="space-y-1">
                    {struggles.map(([k, v]) => (
                      <li key={k} className="flex justify-between text-[11px]">
                        <span className="text-text-secondary truncate">{k}</span>
                        <span className="text-phantom-red ml-2 shrink-0">
                          {Math.round(v.rate * 100)}% · {v.runs}
                        </span>
                      </li>
                    ))}
                  </ul>
                </div>
              )}
            </div>
          )}
        </section>

        <section className="xl:col-span-2 rounded border border-surface-border bg-surface-card p-3">
          <div className="flex items-center justify-between mb-2">
            <h3 className="text-xs font-semibold text-text-primary">Recent episodes</h3>
            <div className="flex gap-1">
              {(['all', 'repairs', 'failures'] as const).map((f) => (
                <button key={f} onClick={() => setFilter(f)}
                  className={`text-[10px] px-2 py-0.5 rounded border ${
                    filter === f
                      ? 'border-phantom-magenta/50 text-phantom-magenta'
                      : 'border-surface-border text-text-dim hover:bg-surface-hover'}`}>
                  {f}
                </button>
              ))}
            </div>
          </div>
          {episodes.length === 0 ? (
            <p className="text-[11px] text-text-dim">No episodes match this filter.</p>
          ) : (
            <div className="space-y-1">
              {episodes.map((e, i) => (
                <div key={`${e.technique}-${e.ts}-${i}`}
                  className="flex items-start gap-2 text-[11px] border-b border-surface-border/50 pb-1">
                  <span className={e.ok ? 'text-phantom-green' : 'text-phantom-red'}>
                    {e.ok ? '✔' : '✘'}
                  </span>
                  <span className="text-text-secondary w-40 shrink-0 truncate">
                    {e.phase}/{e.technique}
                  </span>
                  <span className="text-text-dim w-32 shrink-0">
                    {e.sig?.cls}{e.sig?.product ? ` · ${e.sig.product}` : ''}
                  </span>
                  <span className="flex-1 text-text-primary truncate">
                    {e.ok ? 'worked'
                      : `${label(e.cause)}${e.repair ? ` → repaired by ${e.repair}` : ''}`}
                  </span>
                </div>
              ))}
            </div>
          )}
        </section>
      </div>
    </div>
  )
}

function Stat({ label, value, icon, tone }: {
  label: string; value: number; icon?: JSX.Element; tone?: string
}) {
  return (
    <div className="rounded border border-surface-border bg-surface-card px-3 py-2">
      <div className="flex items-center gap-1 text-[10px] uppercase tracking-wide text-text-dim">
        {icon}{label}
      </div>
      <div className={`text-lg font-semibold ${tone || 'text-text-primary'}`}>{value}</div>
    </div>
  )
}
