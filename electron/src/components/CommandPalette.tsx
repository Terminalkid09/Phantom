import { useState, useEffect, useRef, useCallback } from 'react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'
import { Search, Command, CornerDownLeft, Zap } from 'lucide-react'

interface SearchResult {
  source: string
  type: string
  module?: string
  label: string
  group?: string
  action: string
  command?: string
}

export default function CommandPalette() {
  const { setActiveTab, activeBeacon, setActiveBeacon } = useStore()
  const { api } = useApi()
  const [open, setOpen] = useState(false)
  const [query, setQuery] = useState('')
  const [results, setResults] = useState<SearchResult[]>([])
  const [loading, setLoading] = useState(false)
  const [selected, setSelected] = useState(0)
  const inputRef = useRef<HTMLInputElement>(null)
  const overlayRef = useRef<HTMLDivElement>(null)

  // Global Ctrl+K listener
  const onKeyDown = useCallback((e: KeyboardEvent) => {
    if ((e.key === 'k' || e.key === 'K') && (e.ctrlKey || e.metaKey)) {
      e.preventDefault()
      setOpen((prev) => !prev)
    }
    if (e.key === 'Escape' && open) {
      setOpen(false)
    }
  }, [open])

  useEffect(() => {
    window.addEventListener('keydown', onKeyDown)
    return () => window.removeEventListener('keydown', onKeyDown)
  }, [onKeyDown])

  useEffect(() => {
    if (open) { inputRef.current?.focus(); setQuery(''); setSelected(0) }
  }, [open])

  // Search on query change (debounced)
  useEffect(() => {
    if (!open || query.length < 2) { setResults([]); return }
    const timer = setTimeout(async () => {
      setLoading(true)
      const res = await api('POST', '/api/search', { query })
      setLoading(false)
      setResults((res.data as { results: SearchResult[] })?.results || [])
      setSelected(0)
    }, 150)
    return () => clearTimeout(timer)
  }, [query, open])

  const execute = (result: SearchResult) => {
    setOpen(false)
    if (result.source === 'module') {
      setActiveTab(result.module!)
      // Store the selected command in localStorage so ModulePanel picks it up
      localStorage.setItem(`phantom:${result.module}:selected`, result.command || '')
    } else if (result.action === 'c2') {
      setActiveTab('c2')
      if (result.type === 'beacon') {
        // Extract beacon ID from label
        const id = result.label.match(/([a-f0-9]+)/i)
        if (id) setActiveBeacon(id[1])
      }
    } else if (result.action === 'session') {
      setActiveTab('session')
    }
  }

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === 'ArrowDown') { e.preventDefault(); setSelected((s) => Math.min(s + 1, results.length - 1)) }
    if (e.key === 'ArrowUp') { e.preventDefault(); setSelected((s) => Math.max(s - 1, 0)) }
    if (e.key === 'Enter' && results[selected]) {
      e.preventDefault()
      execute(results[selected])
    }
    if (e.key === 'Escape') setOpen(false)
  }

  if (!open) return null

  return (
    <div
      ref={overlayRef}
      className="fixed inset-0 z-50 bg-black/60 flex items-start justify-center pt-[15vh]"
      onClick={(e) => { if (e.target === overlayRef.current) setOpen(false) }}
    >
      <div
        role="dialog"
        aria-modal="true"
        aria-labelledby="command-palette-title"
        className="w-[600px] max-h-[480px] bg-surface-card border border-surface-border rounded-xl shadow-2xl overflow-hidden"
      >
        <h2 id="command-palette-title" className="sr-only">Command palette</h2>
        {/* Search input */}
        <div className="flex items-center gap-3 px-4 py-3 border-b border-surface-border">
          <Search size={17} aria-hidden="true" className="text-text-dim flex-shrink-0" />
          <label htmlFor="command-palette-input" className="sr-only">
            Search commands, beacons, services and credentials
          </label>
          <input
            id="command-palette-input"
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            onKeyDown={handleKeyDown}
            placeholder="Search commands, beacons, services, creds..."
            aria-label="Search commands, beacons, services and credentials"
            aria-controls="command-palette-results"
            aria-expanded={results.length > 0}
            aria-activedescendant={results[selected] ? `command-palette-option-${selected}` : undefined}
            className="flex-1 bg-transparent text-sm text-text-primary placeholder-text-dim outline-none"
            autoComplete="off"
            spellCheck={false}
          />
          <kbd className="text-[10px] px-1.5 py-0.5 rounded bg-surface border border-surface-border text-text-dim font-mono">
            <Command size={10} aria-hidden="true" className="inline mr-0.5" />K
          </kbd>
        </div>

        {/* Results */}
        <div
          id="command-palette-results"
          role="listbox"
          aria-label="Search results"
          className="overflow-auto max-h-[360px]"
        >
          {query.length < 2 ? (
            <div role="status" aria-live="polite" className="p-6 text-center text-xs text-text-dim">
              <Zap size={24} aria-hidden="true" className="mx-auto mb-2 text-text-dim" />
              <p>Type to search across all modules, beacons, and session data.</p>
              <p className="mt-1 text-text-dim">Try "nmap", "445", "beacon", "creds"...</p>
            </div>
          ) : loading ? (
            <div role="status" aria-live="polite" className="p-6 text-center text-xs text-text-dim animate-pulse">Searching...</div>
          ) : results.length === 0 ? (
            <div role="status" aria-live="polite" className="p-6 text-center text-xs text-text-dim">No results for "{query}"</div>
          ) : (
            results.map((r, i) => (
              <button
                key={i}
                id={`command-palette-option-${i}`}
                role="option"
                aria-selected={i === selected}
                aria-label={`${r.label} — ${r.source === 'module' ? `use ${r.action}` :
                   r.source === 'c2' ? 'C2 Dashboard' : 'Session'}`}
                onClick={() => execute(r)}
                className={`w-full text-left px-4 py-2.5 flex items-center gap-3 transition-colors text-sm
                  ${i === selected ? 'bg-phantom-magenta/10' : 'hover:bg-surface-hover'}`}
              >
                <SourceBadge source={r.source} type={r.type} />
                <span className="flex-1 text-text-primary truncate">{r.label}</span>
                <span aria-hidden="true" className="text-[10px] text-text-dim flex-shrink-0">
                  {r.source === 'module' ? `use ${r.action}` :
                   r.source === 'c2' ? 'C2 Dashboard' :
                   'Session'}
                </span>
                {i === selected && <CornerDownLeft size={13} aria-hidden="true" className="text-phantom-magenta flex-shrink-0" />}
              </button>
            ))
          )}
        </div>

        {/* Footer hint */}
        <div className="px-4 py-2 border-t border-surface-border flex items-center gap-4 text-[10px] text-text-dim">
          <span>↑↓ navigate</span>
          <span>↵ execute</span>
          <span>esc close</span>
        </div>
      </div>
    </div>
  )
}

function SourceBadge({ source, type }: { source: string; type: string }) {
  const colors: Record<string, string> = {
    module: 'bg-phantom-cyan/20 text-phantom-cyan border-phantom-cyan/30',
    c2: 'bg-phantom-magenta/20 text-phantom-magenta border-phantom-magenta/30',
    session: 'bg-phantom-green/20 text-phantom-green border-phantom-green/30',
  }
  const labels: Record<string, string> = {
    module: 'module', c2: 'C2', session: 'session',
    command: 'cmd', beacon: 'beacon', target: 'target', note: 'note',
    result: 'result', mode: 'mode',
  }
  return (
    <span aria-label={`source ${source}`} className={`text-[10px] px-1.5 py-0.5 rounded border font-medium flex-shrink-0 ${colors[source] || 'bg-surface-border text-text-dim'}`}>
      {labels[type] || type}
    </span>
  )
}