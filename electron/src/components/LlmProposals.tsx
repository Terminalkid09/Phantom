import { useCallback, useEffect, useState } from 'react'
import { Brain, ChevronDown, ChevronRight, Play, RefreshCw, X } from 'lucide-react'
import { requestApi } from '@/hooks/useApi'

/**
 * What the model WANTED to do, and what the deterministic layer did with it.
 *
 * The advisor is deliberately non-gating for capability preferences, but a
 * concrete command is a different object: it executes. So this card is a review
 * surface, not an automation surface — the model's proposals arrive PENDING,
 * `Accept` runs one through the same gate as any operator command (scope, the
 * hosts named inside the command, tool availability) and `Reject` records why.
 * The journal tab answers the other question: "did we refuse something the
 * model got right?" — every dropped proposal keeps its reason.
 */

type Proposal = {
  id: number; ts: string; command: string; why: string; state: string
  decided_by: string; decision_reason: string; executed: boolean
  result_ok: boolean | null; result_excerpt: string
}
type JournalEntry = {
  seq: number; ts: string; kind: string
  proposals: Array<{ capability_id?: string; command?: string; reason?: string; verdict?: string; drop_reason?: string }>
  dropped: string[]; error: string
}

export default function LlmProposals() {
  const [open, setOpen] = useState(false)
  const [tab, setTab] = useState<'proposals' | 'journal'>('proposals')
  const [proposals, setProposals] = useState<Proposal[]>([])
  const [stats, setStats] = useState<Record<string, number>>({})
  const [journal, setJournal] = useState<JournalEntry[]>([])
  const [busy, setBusy] = useState(0)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    const res = await requestApi('GET', '/api/llm/proposals')
    const d = (res?.data ?? {}) as { proposals?: Proposal[]; stats?: Record<string, number> }
    setProposals(d.proposals ?? [])
    setStats(d.stats ?? {})
    const j = await requestApi('GET', '/api/llm/journal?limit=25')
    const jd = (j?.data ?? {}) as { entries?: JournalEntry[] }
    setJournal(jd.entries ?? [])
  }, [])

  useEffect(() => { if (open) load() }, [open, load])

  const decide = async (proposal: Proposal, action: 'accept' | 'reject') => {
    setBusy(proposal.id)
    setMsg('')
    try {
      const res = await requestApi('POST', '/api/llm/proposals', {
        action,
        id: proposal.id,
        reason: action === 'reject' ? 'refused from the UI' : undefined,
      })
      const d = (res?.data ?? {}) as { ok?: boolean; message?: string; output?: string }
      if (!d.ok) {
        // A refusal here is informative: out of scope, no target set, or the
        // executor's own gate. Show it instead of a silent no-op.
        setMsg(d.message || 'refused')
      } else {
        setMsg(action === 'accept' ? `#${proposal.id} executed` : `#${proposal.id} refused`)
      }
      await load()
    } finally {
      setBusy(0)
    }
  }

  const pending = proposals.filter(p => p.state === 'pending').length

  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-3">
      <button onClick={() => setOpen(!open)}
        className="w-full flex items-center gap-1.5 text-xs font-semibold text-text-secondary
          uppercase tracking-wider hover:text-text-primary">
        {open ? <ChevronDown size={13} /> : <ChevronRight size={13} />}
        <Brain size={13} className="text-phantom-magenta" />
        Model proposals
        {pending > 0 && (
          <span className="ml-1 px-1.5 py-0.5 rounded text-[9px] normal-case
            bg-amber-500/20 text-amber-400 border border-amber-500/40">
            {pending} pending
          </span>
        )}
        <span className="ml-auto text-[9px] text-text-dim normal-case">
          {stats.calls ? `${stats.calls} call(s) · ${stats.dropped ?? 0} refused` : ''}
        </span>
      </button>

      {open && (
        <div className="mt-2 space-y-2">
          <div className="flex items-center gap-2">
            <div className="flex rounded border border-surface-border overflow-hidden">
              {(['proposals', 'journal'] as const).map(t => (
                <button key={t} onClick={() => { setTab(t); load() }}
                  className={`px-2 py-0.5 text-[10px] ${tab === t
                    ? 'bg-phantom-magenta/20 text-phantom-magenta'
                    : 'text-text-dim hover:bg-surface-hover'}`}>
                  {t === 'proposals' ? 'queue' : 'reasoning'}
                </button>
              ))}
            </div>
            <button onClick={load}
              className="text-[10px] text-text-dim hover:text-phantom-cyan flex items-center gap-1">
              <RefreshCw size={10} /> Refresh
            </button>
          </div>

          {tab === 'proposals' && proposals.length === 0 && (
            <p className="text-[10px] text-text-dim">
              Nothing proposed yet. The advisor asks for commands only when it is
              enabled (<span className="font-mono">llm propose</span> in the CLI
              does the same thing), and every proposal lands here pending.
            </p>
          )}

          {tab === 'proposals' && proposals.map(p => (
            <div key={p.id} className="border border-surface-border rounded p-2 space-y-1">
              <div className="flex items-start justify-between gap-2">
                <div className="min-w-0">
                  <p className="text-[11px] font-mono text-text-primary break-all">$ {p.command}</p>
                  {p.why && <p className="text-[10px] text-text-dim mt-0.5">model: {p.why}</p>}
                </div>
                <span className={`shrink-0 text-[9px] px-1.5 py-0.5 rounded border ${
                  p.state === 'pending' ? 'border-amber-500/40 text-amber-400'
                  : p.state === 'accepted' ? 'border-phantom-green/40 text-phantom-green'
                  : 'border-surface-border text-text-dim'}`}>
                  {p.state}
                </span>
              </div>
              {p.state === 'pending' ? (
                <div className="flex items-center gap-2">
                  <button onClick={() => decide(p, 'accept')} disabled={busy === p.id}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px]
                      bg-phantom-magenta/20 text-phantom-magenta hover:bg-phantom-magenta/30
                      disabled:opacity-40">
                    <Play size={10} /> Accept &amp; run
                  </button>
                  <button onClick={() => decide(p, 'reject')} disabled={busy === p.id}
                    className="flex items-center gap-1 px-2 py-0.5 rounded text-[10px]
                      border border-surface-border text-text-dim hover:bg-surface-hover
                      disabled:opacity-40">
                    <X size={10} /> Reject
                  </button>
                  <span className="text-[9px] text-text-dim">
                    it runs through the engagement scope, not around it
                  </span>
                </div>
              ) : (
                <p className="text-[9px] text-text-dim">
                  {p.state} by {p.decided_by || 'operator'}
                  {p.decision_reason && ` — ${p.decision_reason}`}
                  {p.executed && (p.result_ok ? ' · ran' : ' · did not run')}
                </p>
              )}
              {p.executed && p.result_excerpt && (
                <pre className="text-[9px] text-text-dim font-mono whitespace-pre-wrap
                  max-h-24 overflow-auto bg-black/20 rounded p-1">{p.result_excerpt}</pre>
              )}
            </div>
          ))}

          {tab === 'journal' && journal.length === 0 && (
            <p className="text-[10px] text-text-dim">No model call recorded yet.</p>
          )}

          {tab === 'journal' && journal.map(entry => (
            <div key={entry.seq} className="border border-surface-border rounded p-2">
              <p className="text-[10px] text-text-secondary">
                #{entry.seq} {entry.ts} <span className="font-mono">{entry.kind}</span>
              </p>
              {entry.error && <p className="text-[10px] text-phantom-error">{entry.error}</p>}
              {entry.proposals.map((prop, i) => (
                <p key={i} className="text-[10px] font-mono">
                  <span className={
                    prop.verdict === 'accepted' ? 'text-phantom-green'
                    : prop.verdict === 'pending' ? 'text-amber-400'
                    : 'text-text-dim'}>
                    [{prop.verdict}]
                  </span>{' '}
                  <span className="text-text-primary">{prop.command || prop.capability_id}</span>
                  {prop.drop_reason && <span className="text-text-dim"> — {prop.drop_reason}</span>}
                </p>
              ))}
              {entry.proposals.length === 0 && (
                <p className="text-[10px] text-text-dim">no valid proposal in the output</p>
              )}
            </div>
          ))}

          {msg && <p className="text-[10px] text-text-secondary">{msg}</p>}
        </div>
      )}
    </div>
  )
}
