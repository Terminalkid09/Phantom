import { useCallback, useEffect, useMemo, useState } from 'react'
import {
  Download, Fingerprint, HelpCircle, Mail, RefreshCw, Share2, Shield,
  UserCheck, Users,
} from 'lucide-react'
import { requestApi } from '@/hooks/useApi'

/**
 * The identity graph: who is in the target's circle, which handles are PROVEN
 * to be one person, and whether an address is registered on a service.
 *
 * The desktop is the right surface for this — a graph read as text loses the
 * structure that matters (clusters, convergent proofs, the pivot worth the
 * next run) — while the enumeration half is deliberately two-step: the panel
 * first shows the PLAN (which services, which URLs) and asks for an explicit
 * confirmation, because opening a tab must never contact a third party.
 */

type Node = {
  id: string; kind: string; label: string; platform?: string
  confidence: number; sources: string[]; attrs: Record<string, unknown>
}
type Edge = {
  source: string; target: string; kind: string; evidence?: string
  confidence: number; sources: string[]; strong?: boolean
}
type GraphPayload = {
  graph: {
    nodes: Node[]
    edges: Edge[]
    stats: {
      nodes: number; edges: number; clusters: number
      node_kinds: Record<string, number>
      same_person_groups: string[][]
      dropped_nodes?: number; dropped_edges?: number
    }
  }
  text: string
  graphml: string
  pivots: Node[]
  topics: Record<string, (string | number)[][]>
}

type PlanRow = { service: string; url: string; reset_url?: string }
type Verdict = { service: string; verdict: string; evidence: string; source: string; proven: boolean }

const KIND_STYLE: Record<string, string> = {
  handle: 'border-cyan-500/50 text-cyan-200',
  email: 'border-amber-500/50 text-amber-200',
  person: 'border-purple-500/50 text-purple-200',
  domain: 'border-emerald-500/50 text-emerald-200',
  hashtag: 'border-pink-500/50 text-pink-200',
  place: 'border-orange-500/50 text-orange-200',
  post: 'border-white/20 text-text-dim',
  url: 'border-white/20 text-text-dim',
  phone: 'border-blue-500/50 text-blue-200',
}

const VERDICT_STYLE: Record<string, string> = {
  exists: 'text-emerald-300',
  absent: 'text-text-dim',
  unknown: 'text-amber-300',
}

export default function SocialGraphPanel() {
  const [payload, setPayload] = useState<GraphPayload | null>(null)
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState<string>('')
  const [address, setAddress] = useState('')
  const [plan, setPlan] = useState<PlanRow[] | null>(null)
  const [masked, setMasked] = useState('')
  const [confirmed, setConfirmed] = useState(false)
  const [useReset, setUseReset] = useState(false)
  const [verdicts, setVerdicts] = useState<Verdict[] | null>(null)
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await requestApi('GET', '/api/social/graph')
      setPayload((res?.data ?? null) as GraphPayload | null)
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const graph = payload?.graph
  const nodes = graph?.nodes ?? []
  const edges = graph?.edges ?? []
  const stats = graph?.stats

  const byId = useMemo(() => {
    const map = new Map<string, Node>()
    for (const n of nodes) map.set(n.id, n)
    return map
  }, [nodes])

  // Clusters are what the operator reads first: the target's circle, then the
  // pockets of its own. Layout is deterministic (no physics), so the picture
  // does not reshuffle every refresh — the nodes that MOVED are the news.
  const clusters = useMemo(() => {
    const seen = new Set<string>()
    const groups: Node[][] = []
    const adjacency = new Map<string, string[]>()
    for (const e of edges) {
      adjacency.set(e.source, [...(adjacency.get(e.source) ?? []), e.target])
      adjacency.set(e.target, [...(adjacency.get(e.target) ?? []), e.source])
    }
    for (const node of nodes) {
      if (seen.has(node.id)) continue
      const group: Node[] = []
      const queue = [node.id]
      seen.add(node.id)
      while (queue.length) {
        const current = queue.shift() as string
        const found = byId.get(current)
        if (found) group.push(found)
        for (const next of adjacency.get(current) ?? []) {
          if (!seen.has(next)) { seen.add(next); queue.push(next) }
        }
      }
      groups.push(group)
    }
    return groups.sort((a, b) => b.length - a.length)
  }, [nodes, edges, byId])

  const selectedEdges = edges.filter(
    e => e.source === selected || e.target === selected,
  )

  const askPlan = async () => {
    setMsg(''); setVerdicts(null); setPlan(null); setConfirmed(false)
    const res = await requestApi('GET', `/api/social/emails/plan?email=${encodeURIComponent(address)}`)
    const data = (res?.data ?? {}) as { ok?: boolean; masked?: string; plan?: PlanRow[]; message?: string }
    if (!data.ok) { setMsg(data.message || 'that is not a valid address'); return }
    setMasked(data.masked || '')
    setPlan(data.plan ?? [])
    setMsg('Nothing has been sent. Review the services, then confirm.')
  }

  const runEnumeration = async () => {
    setMsg('')
    const res = await requestApi('POST', '/api/social/emails', {
      email: address, confirm: true, reset: useReset,
    })
    const data = (res?.data ?? {}) as {
      ok?: boolean; report?: { verdicts: Verdict[] }; message?: string
    }
    setVerdicts(data.report?.verdicts ?? [])
    setMsg(data.ok ? 'Done. Only proven results are marked.' : (data.message || 'failed'))
    load()
  }

  const exportGraphml = () => {
    if (!payload?.graphml) return
    const blob = new Blob([payload.graphml], { type: 'application/xml' })
    const url = URL.createObjectURL(blob)
    const anchor = document.createElement('a')
    anchor.href = url
    anchor.download = 'phantom-social-graph.graphml'
    anchor.click()
    URL.revokeObjectURL(url)
  }

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/10">
        <Share2 size={14} className="text-cyan-300" />
        <span className="text-xs font-semibold text-text">Identity Graph</span>
        {stats && (
          <span className="text-[10px] text-text-dim">
            {stats.nodes} nodes · {stats.edges} edges · {stats.clusters} cluster(s)
            {stats.same_person_groups.length > 0 && ` · ${stats.same_person_groups.length} confirmed identity group(s)`}
          </span>
        )}
        <div className="flex-1" />
        <button onClick={exportGraphml} disabled={!payload?.graphml}
          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-white/15 hover:bg-white/10 disabled:opacity-40">
          <Download size={11} /> GraphML
        </button>
        <button onClick={load} disabled={loading}
          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-white/15 hover:bg-white/10">
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      <div className="flex-1 overflow-auto p-3 space-y-3">
        {(stats?.same_person_groups.length ?? 0) > 0 && (
          <section className="rounded border border-emerald-500/30 bg-emerald-500/5 p-2">
            <div className="flex items-center gap-1 text-[11px] text-emerald-200">
              <UserCheck size={12} /> Same person, proven
              <span className="text-text-dim">— converging proofs, not co-occurrence</span>
            </div>
            <ul className="mt-1 space-y-0.5">
              {stats?.same_person_groups.map((group, i) => (
                <li key={i} className="text-[11px] font-mono text-emerald-100/90">
                  {group.map(id => id.split(':').slice(1).join(':')).join('  ==  ')}
                </li>
              ))}
            </ul>
          </section>
        )}

        {nodes.length === 0 && (
          <p className="text-[11px] text-text-dim">
            No identity findings yet. Run a deep recon (auto-mode
            `deep_recon`, or <code className="text-phantom-cyan">social graph --run</code> in
            the CLI) and this view fills from the engagement's own findings —
            the API never fetches anything to render it.
          </p>
        )}

        {clusters.map((group, index) => (
          <section key={index} className="rounded border border-white/10 p-2">
            <div className="flex items-center gap-1 text-[10px] text-text-dim mb-1">
              <Users size={11} /> cluster {index + 1} — {group.length} node(s)
            </div>
            <div className="flex flex-wrap gap-1">
              {group.map(node => (
                <button key={node.id} onClick={() => setSelected(node.id)}
                  className={`text-[10px] font-mono px-2 py-1 rounded border hover:bg-white/10 ${KIND_STYLE[node.kind] ?? 'border-white/20 text-text'} ${selected === node.id ? 'ring-1 ring-cyan-400' : ''}`}
                  title={`${node.id}\nconfidence ${node.confidence}\nsources: ${node.sources.join(', ')}`}>
                  {node.label || node.id}
                  <span className="text-text-dim"> {Math.round(node.confidence * 100)}%</span>
                </button>
              ))}
            </div>
          </section>
        ))}

        {selected && (
          <section className="rounded border border-cyan-500/30 p-2">
            <div className="flex items-center gap-1 text-[11px] text-cyan-200">
              <Fingerprint size={12} /> {byId.get(selected)?.label || selected}
              <span className="text-text-dim">{selectedEdges.length} proof(s)</span>
            </div>
            <ul className="mt-1 space-y-0.5">
              {selectedEdges.map((edge, i) => {
                const other = edge.source === selected ? edge.target : edge.source
                const outgoing = edge.source === selected
                return (
                  <li key={i} className="text-[11px] font-mono">
                    <span className={edge.strong ? 'text-emerald-300' : 'text-text-secondary'}>
                      {outgoing ? '→' : '←'} {edge.kind}
                    </span>
                    {' '}
                    <span className="text-text">{byId.get(other)?.label || other}</span>
                    <span className="text-text-dim"> {Math.round(edge.confidence * 100)}%</span>
                    {edge.evidence && <span className="text-text-dim"> [{edge.evidence}]</span>}
                  </li>
                )
              })}
              {selectedEdges.length === 0 && (
                <li className="text-[11px] text-text-dim">no edge recorded (isolated node)</li>
              )}
            </ul>
          </section>
        )}

        {(payload?.pivots.length ?? 0) > 0 && (
          <section className="rounded border border-white/10 p-2">
            <div className="text-[11px] text-text-secondary">Widening order (confidence, then proofs)</div>
            <ul className="mt-1 space-y-0.5">
              {payload?.pivots.slice(0, 8).map(node => (
                <li key={node.id} className="text-[11px] font-mono text-text">
                  {node.kind} <span className="text-cyan-200">{node.label}</span>
                  <span className="text-text-dim"> {Math.round(node.confidence * 100)}%</span>
                  {node.platform && <span className="text-text-dim"> · {node.platform}</span>}
                </li>
              ))}
            </ul>
          </section>
        )}

        {nodes.some(n => n.kind === 'hashtag' || n.kind === 'place') && (
          <section className="rounded border border-white/10 p-2">
            <div className="text-[11px] text-text-secondary">Topics mined from posts (pretext material)</div>
            <div className="mt-1 flex flex-wrap gap-1">
              {nodes.filter(n => n.kind === 'hashtag' || n.kind === 'place').slice(0, 40).map(n => (
                <span key={n.id} className="text-[10px] px-2 py-0.5 rounded border border-pink-500/40 text-pink-200">
                  {n.label}
                </span>
              ))}
            </div>
          </section>
        )}

        <section className="rounded border border-white/10 p-2 space-y-2">
          <div className="flex items-center gap-1 text-[11px] text-text-secondary">
            <Mail size={12} /> Account existence (gated)
          </div>
          <div className="flex items-center gap-2">
            <input value={address} onChange={e => setAddress(e.target.value)}
              placeholder="address to check"
              className="text-[11px] px-2 py-1 rounded bg-black/30 border border-white/15 flex-1 font-mono" />
            <button onClick={askPlan} disabled={!address.includes('@')}
              className="text-[10px] px-2 py-1 rounded border border-white/15 hover:bg-white/10 disabled:opacity-40">
              Show plan
            </button>
          </div>
          {masked && <div className="text-[10px] text-text-dim">target: {masked}</div>}
          {plan && (
            <>
              <ul className="space-y-0.5 max-h-40 overflow-auto">
                {plan.map(row => (
                  <li key={row.service} className="text-[10px] font-mono text-text-dim">
                    <span className="text-text-secondary">{row.service}</span> {row.url}
                  </li>
                ))}
              </ul>
              <label className="flex items-center gap-2 text-[10px] text-text-secondary">
                <input type="checkbox" checked={confirmed}
                  onChange={e => setConfirmed(e.target.checked)} />
                I confirm: ask these services about this address
              </label>
              <label className="flex items-center gap-2 text-[10px] text-text-secondary">
                <input type="checkbox" checked={useReset}
                  onChange={e => setUseReset(e.target.checked)} />
                use the password-reset oracle (strongest proof, own request per service)
              </label>
              <button onClick={runEnumeration} disabled={!confirmed}
                className="text-[10px] px-2 py-1 rounded border border-amber-500/40 text-amber-200 hover:bg-amber-500/10 disabled:opacity-40">
                <Shield size={10} className="inline mr-1" /> Ask services
              </button>
            </>
          )}
          {verdicts && (
            <ul className="space-y-0.5">
              {verdicts.map((v, i) => (
                <li key={i} className="text-[10px] font-mono">
                  <span className="text-text-secondary">{v.service}</span>{' '}
                  <span className={VERDICT_STYLE[v.verdict] ?? 'text-text-dim'}>{v.verdict}</span>
                  <span className="text-text-dim"> [{v.evidence}]</span>
                  {v.proven && <span className="text-emerald-300"> reset-oracle PROVEN</span>}
                  {v.source === 'reset-oracle' && !v.proven && <span className="text-text-dim"> (oracle)</span>}
                </li>
              ))}
              {verdicts.length === 0 && <li className="text-[10px] text-text-dim">no verdict returned</li>}
            </ul>
          )}
          {msg && (
            <p className="text-[10px] text-text-dim flex items-center gap-1">
              <HelpCircle size={10} /> {msg}
            </p>
          )}
        </section>
      </div>
    </div>
  )
}
