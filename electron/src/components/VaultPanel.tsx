import { useState, useEffect } from 'react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'
import {
  Key, Plus, Search, Trash2, Copy, Lock,
  Shield, RefreshCw, Eye, EyeOff, Hash
} from 'lucide-react'

interface VaultEntry {
  id: string
  time: string
  target: string
  type: string
  username: string
  password: string
  hash: string
  service: string
  source: string
  notes: string
}

export default function VaultPanel({ standalone }: { standalone?: boolean }) {
  const { session } = useStore()
  const { api } = useApi()
  const [entries, setEntries] = useState<VaultEntry[]>([])
  const [search, setSearch] = useState('')
  const [showPassword, setShowPassword] = useState<Record<string, boolean>>({})
  const [adding, setAdding] = useState(false)
  const [form, setForm] = useState({ username: '', password: '', hash: '', service: '', notes: '' })

  const load = async () => {
    const res = await api('GET', `/api/vault${search ? `?q=${encodeURIComponent(search)}` : ''}`)
    if (res.status === 200) setEntries((res.data as { entries: VaultEntry[] }).entries || [])
  }

  useEffect(() => { load() }, [search])

  const add = async () => {
    if (!form.username && !form.password && !form.hash) return
    await api('POST', '/api/vault', {
      ...form,
      type: form.hash ? 'hash' : 'credential',
      target: session.target,
    })
    setForm({ username: '', password: '', hash: '', service: '', notes: '' })
    setAdding(false)
    load()
  }

  const toggleShow = (id: string) => setShowPassword((s) => ({ ...s, [id]: !s[id] }))

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text).catch(() => {})
  }

  const typeBadge = (t: string) => {
    if (t === 'hash') return { bg: 'bg-phantom-yellow/20', text: 'text-phantom-yellow', label: 'HASH' }
    if (t === 'token') return { bg: 'bg-phantom-magenta/20', text: 'text-phantom-magenta', label: 'TOKEN' }
    return { bg: 'bg-phantom-cyan/20', text: 'text-phantom-cyan', label: 'CRED' }
  }

  return (
    <div className={`flex flex-col gap-3 ${standalone ? 'h-full p-4' : ''}`}>
      {standalone && (
        <div className="flex items-center justify-between">
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <Key size={19} className="text-phantom-yellow" /> Credential Vault
          </h1>
          <div className="flex gap-1.5">
            <button onClick={() => setAdding(!adding)}
              className="px-3 py-1.5 rounded bg-phantom-yellow/20 text-phantom-yellow text-xs font-medium flex items-center gap-1.5 hover:bg-phantom-yellow/30">
              <Plus size={12} /> Add Entry
            </button>
            <button onClick={load} className="p-1.5 rounded text-text-secondary hover:text-text-primary hover:bg-surface-hover">
              <RefreshCw size={14} />
            </button>
          </div>
        </div>
      )}

      {!standalone && (
        <div className="flex items-center justify-between px-3 py-2 border-b border-surface-border">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
            <Key size={13} className="text-phantom-yellow" /> Credential Vault
          </h2>
          <div className="flex gap-1">
            <button onClick={() => setAdding(!adding)}
              className="text-[10px] px-2 py-0.5 rounded bg-phantom-yellow/20 text-phantom-yellow hover:bg-phantom-yellow/30">
              <Plus size={10} className="inline mr-0.5" />Add
            </button>
            <button onClick={load} className="text-text-dim hover:text-text-primary"><RefreshCw size={13} /></button>
          </div>
        </div>
      )}

      {/* Search */}
      <div className="flex gap-2">
        <div className="flex-1 relative">
          <Search size={13} className="absolute left-2.5 top-1/2 -translate-y-1/2 text-text-dim" />
          <input type="text" value={search} onChange={(e) => setSearch(e.target.value)}
            placeholder="Filter by target, username, service..."
            className="w-full bg-surface border border-surface-border rounded pl-8 pr-3 py-2 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-yellow" />
        </div>
      </div>

      {/* Add form */}
      {adding && (
        <div className="bg-surface border border-phantom-yellow/30 rounded-lg p-3 space-y-2">
          <div className="flex gap-2">
            <input type="text" value={form.username} onChange={(e) => setForm({ ...form, username: e.target.value })}
              placeholder="Username" className="flex-1 bg-surface-card border border-surface-border rounded px-2.5 py-1.5 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-yellow" />
            <input type="text" value={form.service} onChange={(e) => setForm({ ...form, service: e.target.value })}
              placeholder="Service (ssh, smb, http...)" className="w-40 bg-surface-card border border-surface-border rounded px-2.5 py-1.5 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-yellow" />
          </div>
          <div className="flex gap-2">
            <input type="text" value={form.password} onChange={(e) => setForm({ ...form, password: e.target.value })}
              placeholder="Password" className="flex-1 bg-surface-card border border-surface-border rounded px-2.5 py-1.5 text-xs font-mono text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-yellow" />
            <input type="text" value={form.hash} onChange={(e) => setForm({ ...form, hash: e.target.value })}
              placeholder="Hash (NTLM, SHA256...)" className="flex-1 bg-surface-card border border-surface-border rounded px-2.5 py-1.5 text-xs font-mono text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-yellow" />
          </div>
          <input type="text" value={form.notes} onChange={(e) => setForm({ ...form, notes: e.target.value })}
            placeholder="Notes (pivot, domain admin...)" className="w-full bg-surface-card border border-surface-border rounded px-2.5 py-1.5 text-xs text-text-primary placeholder-text-dim focus:outline-none focus:border-phantom-yellow" />
          <div className="flex gap-2">
            <button onClick={add} className="flex-1 py-1.5 rounded bg-phantom-yellow/20 text-phantom-yellow text-xs font-medium hover:bg-phantom-yellow/30">Save to Vault</button>
            <button onClick={() => setAdding(false)} className="px-4 py-1.5 rounded bg-surface-border text-text-secondary text-xs">Cancel</button>
          </div>
        </div>
      )}

      {/* Entries */}
      <div className="flex-1 overflow-auto space-y-2">
        {entries.length === 0 ? (
          <div className={`text-xs text-text-dim ${standalone ? 'p-8 text-center' : 'p-4 text-center'}`}>
            <Lock size={28} className="mx-auto mb-2 text-text-dim" />
            <p>No credentials stored yet.</p>
            <p className="mt-1">Add entries manually or they will auto-populate from successful exploits.</p>
          </div>
        ) : (
          entries.map((e) => {
            const badge = typeBadge(e.type)
            return (
              <div key={e.id} className="bg-surface border border-surface-border rounded-lg p-3">
                <div className="flex items-center justify-between mb-2">
                  <div className="flex items-center gap-2">
                    <span className={`text-[10px] px-1.5 py-0.5 rounded font-medium ${badge.bg} ${badge.text}`}>{badge.label}</span>
                    <span className="text-xs text-text-primary font-medium">{e.username || e.hash?.slice(0, 16) + '...' || '—'}</span>
                    {e.service && <span className="text-[10px] text-text-dim">@{e.service}</span>}
                  </div>
                  <div className="flex items-center gap-1">
                    {e.target && <span className="text-[10px] text-text-dim">{e.target}</span>}
                    <span className="text-[10px] text-text-dim">·</span>
                    <span className="text-[10px] text-text-dim">{e.time}</span>
                  </div>
                </div>

                {e.password && (
                  <div className="flex items-center gap-2 mt-1">
                    <span className="text-[10px] text-text-dim">Pass:</span>
                    <code className="text-xs font-mono text-text-primary bg-surface-card px-2 py-0.5 rounded">
                      {showPassword[e.id] ? e.password : '••••••••'}
                    </code>
                    <button onClick={() => toggleShow(e.id)} className="text-text-dim hover:text-text-primary">
                      {showPassword[e.id] ? <EyeOff size={12} /> : <Eye size={12} />}
                    </button>
                    <button onClick={() => copyToClipboard(e.password)} className="text-text-dim hover:text-phantom-cyan" title="Copy">
                      <Copy size={12} />
                    </button>
                  </div>
                )}

                {e.hash && (
                  <div className="flex items-center gap-2 mt-1">
                    <Hash size={12} className="text-text-dim" />
                    <code className="text-[10px] font-mono text-text-secondary truncate flex-1">{e.hash}</code>
                    <button onClick={() => copyToClipboard(e.hash)} className="text-text-dim hover:text-phantom-cyan" title="Copy hash">
                      <Copy size={12} />
                    </button>
                  </div>
                )}

                {e.notes && (
                  <div className="mt-1.5 text-[10px] text-text-dim">{e.notes}</div>
                )}

                <div className="mt-1.5 text-[10px] text-text-dim">
                  Source: {e.source}
                </div>
              </div>
            )
          })
        )}
      </div>
    </div>
  )
}