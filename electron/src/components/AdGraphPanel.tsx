import { useCallback, useEffect, useState } from 'react'
import { Network, Plus, RefreshCw, ShieldAlert, Trash2 } from 'lucide-react'
import { requestApi } from '@/hooks/useApi'

type Node = { id: string; type: string; label?: string; kerberoastable?: boolean; as_rep_roastable?: boolean; cracked?: boolean }
type Edge = { src: string; dst: string; type: string; note?: string }
type Path = { src: string; edge: string; dst: string }[]
type Graph = { domain: string; nodes: Node[]; edges: Edge[]; paths: Path[]; error?: string }

const TYPE_COLOR: Record<string, string> = {
  domain: 'border-purple-500/60 text-purple-300',
  dc: 'border-red-500/60 text-red-300',
  user: 'border-cyan-500/60 text-cyan-200',
  group: 'border-amber-500/60 text-amber-300',
  computer: 'border-emerald-500/60 text-emerald-300',
}

export default function AdGraphPanel() {
  const [graph, setGraph] = useState<Graph>({ domain: '', nodes: [], edges: [], paths: [] })
  const [loading, setLoading] = useState(false)
  const [showForm, setShowForm] = useState(false)
  const [form, setForm] = useState({ user: '', kerberoastable: false, as_rep: false, cracked: false, admin_to: '', session_on: '', groups: '' })
  const [msg, setMsg] = useState('')

  const load = useCallback(async () => {
    setLoading(true)
    try {
      const res = await requestApi('GET', '/api/ad/graph')
      const g = (res?.data ?? {}) as Partial<Graph>
      setGraph({ domain: '', nodes: [], edges: [], paths: [], ...g })
    } finally {
      setLoading(false)
    }
  }, [])

  useEffect(() => { load() }, [load])

  const submit = async () => {
    if (!form.user.trim()) { setMsg('user required'); return }
    await requestApi('POST', '/api/ad/mutate', {
      op: 'add-user', user: form.user.trim(),
      kerberoastable: form.kerberoastable, as_rep: form.as_rep, cracked: form.cracked,
      admin_to: form.admin_to.split(',').map(s => s.trim()).filter(Boolean),
      session_on: form.session_on.split(',').map(s => s.trim()).filter(Boolean),
      groups: form.groups.split(',').map(s => s.trim()).filter(Boolean),
    })
    setMsg(`user ${form.user} recorded`)
    setForm({ user: '', kerberoastable: false, as_rep: false, cracked: false, admin_to: '', session_on: '', groups: '' })
    setShowForm(false)
    load()
  }

  const usersOn = (host: string, kind: string) =>
    graph.edges.filter(e => e.dst === host && e.type === kind).map(e => e.src)

  return (
    <div className="flex-1 flex flex-col overflow-hidden">
      <div className="flex items-center gap-2 px-3 py-2 border-b border-white/10">
        <Network size={14} className="text-cyan-300" />
        <span className="text-xs font-semibold text-text">
          AD Attack Graph {graph.domain ? `— ${graph.domain}` : ''}
        </span>
        <div className="flex-1" />
        <button onClick={() => setShowForm(s => !s)}
          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-white/15 hover:bg-white/10">
          <Plus size={11} /> Add
        </button>
        <button onClick={load} disabled={loading}
          className="flex items-center gap-1 text-[10px] px-2 py-1 rounded border border-white/15 hover:bg-white/10">
          <RefreshCw size={11} className={loading ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {showForm && (
        <div className="px-3 py-2 border-b border-white/10 space-y-2 text-xs">
          <div className="flex gap-2">
            <input value={form.user} onChange={e => setForm(f => ({ ...f, user: e.target.value }))}
              placeholder="username" className="flex-1 bg-black/40 rounded px-2 py-1 border border-white/10" />
            <label className="flex items-center gap-1"><input type="checkbox" checked={form.kerberoastable}
              onChange={e => setForm(f => ({ ...f, kerberoastable: e.target.checked }))} /> kerberoastable</label>
            <label className="flex items-center gap-1"><input type="checkbox" checked={form.as_rep}
              onChange={e => setForm(f => ({ ...f, as_rep: e.target.checked }))} /> AS-REP</label>
            <label className="flex items-center gap-1"><input type="checkbox" checked={form.cracked}
              onChange={e => setForm(f => ({ ...f, cracked: e.target.checked }))} /> cracked</label>
          </div>
          <div className="flex gap-2">
            <input value={form.admin_to} onChange={e => setForm(f => ({ ...f, admin_to: e.target.value }))}
              placeholder="admin_to hosts (comma sep)" className="flex-1 bg-black/40 rounded px-2 py-1 border border-white/10" />
            <input value={form.session_on} onChange={e => setForm(f => ({ ...f, session_on: e.target.value }))}
              placeholder="sessions on hosts" className="flex-1 bg-black/40 rounded px-2 py-1 border border-white/10" />
            <input value={form.groups} onChange={e => setForm(f => ({ ...f, groups: e.target.value }))}
              placeholder="member of groups" className="flex-1 bg-black/40 rounded px-2 py-1 border border-white/10" />
          </div>
          <div className="flex gap-2 items-center">
            <button onClick={submit} className="px-3 py-1 rounded bg-cyan-600/80 hover:bg-cyan-500">Save</button>
            {msg && <span className="text-[10px] text-text-dim">{msg}</span>}
          </div>
        </div>
      )}

      <div className="flex-1 overflow-auto p-3 space-y-3 text-xs">
        {graph.error && <div className="text-red-300">{graph.error}</div>}
        {graph.nodes.length === 0 && !graph.error && (
          <div className="text-text-dim p-4 text-center">
            No AD data yet. Collect with <code>use ad</code>, an auto-mode run, or add users above —
            the graph mirrors the CLI's <code>ad</code> command.
          </div>
        )}

        {/* domain controllers and hosts first */}
        {graph.nodes.filter(n => ['dc', 'computer'].includes(n.type)).map(n => (
          <div key={n.id} className={`border rounded p-2 ${TYPE_COLOR[n.type] ?? 'border-white/15'}`}>
            <div className="flex items-center gap-2">
              {n.type === 'dc' ? <ShieldAlert size={12} /> : null}
              <span className="font-semibold">{n.id}</span>
              <span className="text-[10px] uppercase opacity-60">{n.type}</span>
            </div>
            <div className="mt-1 ml-4 space-y-0.5">
              {usersOn(n.id, 'session').map(u => (
                <div key={u} className="text-cyan-200/80">↳ session: {u}
                  {graph.nodes.find(x => x.id === u)?.kerberoastable && <span className="ml-1 text-amber-300">[KERBEROASTABLE]</span>}
                  {graph.nodes.find(x => x.id === u)?.cracked && <span className="ml-1 text-emerald-300">[CREDS]</span>}
                </div>
              ))}
              {usersOn(n.id, 'admin_to').map(u => (
                <div key={u} className="text-red-200/80">↳ admin: {u}</div>
              ))}
            </div>
          </div>
        ))}

        {/* users without sessions */}
        <div className="space-y-1">
          {graph.nodes.filter(n => n.type === 'user' &&
            !graph.edges.some(e => e.dst === n.id && (e.type === 'session' || e.type === 'admin_to'))).map(n => (
            <div key={n.id} className="flex items-center gap-2">
              <span className="text-cyan-200">{n.id}</span>
              {n.kerberoastable && <span className="text-[10px] px-1 rounded bg-amber-500/20 text-amber-300">KERBEROASTABLE</span>}
              {n.as_rep_roastable && <span className="text-[10px] px-1 rounded bg-orange-500/20 text-orange-300">AS-REP</span>}
              {n.cracked && <span className="text-[10px] px-1 rounded bg-emerald-500/20 text-emerald-300">CREDS</span>}
              {graph.edges.filter(e => e.src === n.id && e.type === 'member_of').map(e => (
                <span key={e.dst} className="text-[10px] text-amber-300/70">member_of {e.dst}</span>
              ))}
            </div>
          ))}
        </div>

        {/* attack paths */}
        {graph.paths.length > 0 && (
          <div className="border border-red-500/40 rounded p-2">
            <div className="text-red-300 font-semibold mb-1">Attack paths to Domain Admin ({graph.paths.length})</div>
            {graph.paths.map((p, i) => (
              <div key={i} className="text-red-200/90 font-mono text-[10px]">
                [{i + 1}] {p.map(s => `${s.src} [${s.edge}] `).join('→ ')}{p[p.length - 1]?.dst}
              </div>
            ))}
          </div>
        )}
      </div>
    </div>
  )
}
