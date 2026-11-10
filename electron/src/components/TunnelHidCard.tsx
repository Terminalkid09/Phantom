import { useEffect, useState } from 'react'
import { apiError, type ApiResponse } from '@/hooks/useApi'
import { Globe, Zap, Cpu, RefreshCw, Usb, ShieldOff } from 'lucide-react'

type Api = (method: 'GET' | 'POST', path: string, body?: unknown) =>
  Promise<ApiResponse<unknown>>

interface TunnelState {
  running: boolean
  public_url: string
  front: string
  error: string
  binary: string
  listener_alive: boolean
  endpoint?: { url?: string; via_front?: boolean; warnings?: string[] }
}

interface HidState {
  boards: { port?: string; address?: string; name?: string; fqbn?: string;
            description?: string }[]
  arduino_cli: string
  endpoint?: { url?: string; via_front?: boolean }
  hint?: string
}

/**
 * The two delivery settings the desktop used to have NO surface for.
 *
 * `tunnel` (the public hop — i.e. whether a delivered artefact carries this
 * box's address) and `hid` (prepare + flash a keyboard board) were CLI-only.
 * A parity gap in exactly the place where two operators watching the same
 * screen would otherwise get different answers about what was delivered.
 */
export default function TunnelHidCard({ api, listenerActive }: { api: Api; listenerActive: boolean }) {
  const [tunnel, setTunnel] = useState<TunnelState | null>(null)
  const [hid, setHid] = useState<HidState | null>(null)
  const [busy, setBusy] = useState('')
  const [note, setNote] = useState('')
  const [port, setPort] = useState('')

  const refresh = async () => {
    const [t, h] = await Promise.all([
      api('GET', '/api/c2/tunnel'),
      api('GET', '/api/c2/hid'),
    ])
    if (t.status === 200) setTunnel(t.data as TunnelState)
    if (h.status === 200) setHid(h.data as HidState)
  }

  // The endpoint warning depends on whether the listener is alive. This card
  // is mounted before the first listener start, so a one-shot read left the
  // red "no listener is running" warning on screen after Start succeeded.
  // Re-read when the listener transitions, not on every render.
  useEffect(() => { refresh().catch(() => undefined) }, [listenerActive]) // eslint-disable-line react-hooks/exhaustive-deps

  const run = async (action: string, body?: unknown) => {
    setBusy(action)
    setNote('')
    try {
      const res = await api('POST', '/api/c2/hid', { action, port, ...(body || {}) })
      if (res.status === 200 && res.data) {
        const d = res.data as { built?: { path?: string; chars?: number };
                                summary?: string; note?: string; ok?: boolean }
        setNote(action === 'flash'
          ? `${d.summary || 'flashed'} — ${d.note || ''}`
          : `sketch built (${d.built?.chars ?? '?'} chars typed): ${d.built?.path || ''}`)
        if (action === 'flash' && d.ok) refresh().catch(() => undefined)
      } else {
        setNote(apiError(res))
      }
    } catch (e) {
      setNote(apiError({ status: 0, data: { error: String(e) } }))
    } finally {
      setBusy('')
    }
  }

  const tunnelAction = async (action: string) => {
    setBusy(`tunnel:${action}`)
    setNote('')
    try {
      const res = await api('POST', '/api/c2/tunnel', action === 'start' ? { action } : { action })
      if (res.status === 200) {
        const d = res.data as { front?: string; public_url?: string; messages?: string[] }
        setNote(d.front ? `c2.front = ${d.front}` : (d.messages || []).join(' · '))
      } else {
        setNote(apiError(res))
      }
      await refresh()
    } catch (e) {
      setNote(apiError({ status: 0, data: { error: String(e) } }))
    } finally {
      setBusy('')
    }
  }

  const boards = hid?.boards || []
  const boardPort = boards[0]?.port || boards[0]?.address || ''

  return (
    <div className="bg-surface-card border border-surface-border rounded-lg p-3 flex flex-col gap-3">
      {/* ── Tunnel ── */}
      <div>
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
            <Globe size={13} className="text-phantom-cyan" /> Tunnel
            <span className={`w-1.5 h-1.5 rounded-full ${tunnel?.running ? 'bg-phantom-green' : 'bg-text-dim'}`}
                  aria-label={tunnel?.running ? 'tunnel running' : 'tunnel down'} />
          </h2>
          <div className="flex gap-1.5">
            <button
              onClick={() => tunnelAction('start')}
              disabled={busy !== ''}
              title="Publish the listener on a throwaway public hostname"
              className="px-2 py-1 rounded text-[10px] font-medium bg-phantom-green/20 text-phantom-green
                         hover:bg-phantom-green/30 disabled:opacity-40"
            >
              <Zap size={10} className="inline mr-1" />Publish
            </button>
            <button
              onClick={() => tunnelAction('stop')}
              disabled={busy !== ''}
              className="px-2 py-1 rounded text-[10px] font-medium bg-phantom-error/20 text-phantom-error
                         hover:bg-phantom-error/30 disabled:opacity-40"
            >
              Stop
            </button>
          </div>
        </div>
        <div className="space-y-1 text-xs">
          <Row label="Front" value={tunnel?.front || '— (artefacts carry this box\'s address)'} />
          <Row label="Dial" value={tunnel?.endpoint?.url || '—'}
               warn={Boolean(tunnel?.endpoint?.warnings?.length)} />
          {tunnel?.endpoint?.warnings?.length ? (
            <p className="text-[10px] text-phantom-error leading-snug">
              {tunnel.endpoint.warnings[0]}
            </p>
          ) : null}
        </div>
      </div>

      {/* ── HID ── */}
      <div className="border-t border-surface-border pt-3">
        <div className="flex items-center justify-between mb-2">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
            <Usb size={13} className="text-phantom-magenta" /> HID
          </h2>
          <button onClick={() => refresh()} aria-label="Refresh board list"
                  className="text-text-dim hover:text-text-primary transition-colors">
            <RefreshCw size={12} />
          </button>
        </div>

        <div className="space-y-1 text-xs mb-2">
          <Row label="arduino-cli" value={hid?.arduino_cli ? '✓' : 'not found'} active={Boolean(hid?.arduino_cli)} />
          <Row label="Board" value={boardPort || 'none enumerated'}
               warn={!boardPort} />
          <Row label="Dial" value={hid?.endpoint?.url || '—'} />
        </div>
        {!boardPort && hid?.hint ? (
          <p className="text-[10px] text-text-dim leading-snug mb-2">{hid.hint}</p>
        ) : null}

        <div className="flex gap-1.5 items-center">
          <input
            value={port}
            onChange={(e) => setPort(e.target.value)}
            placeholder={boardPort || 'auto'}
            className="flex-1 min-w-0 bg-surface-raised border border-surface-border rounded px-2 py-1
                       text-[10px] text-text-primary placeholder:text-text-dim focus:outline-none"
            aria-label="Serial port (auto)"
          />
          <button
            onClick={() => run('build')}
            disabled={busy !== ''}
            title="Build the sketch (writes it under data/vectors)"
            className="px-2 py-1 rounded text-[10px] font-medium bg-phantom-cyan/20 text-phantom-cyan
                       hover:bg-phantom-cyan/30 disabled:opacity-40"
          >
            <Cpu size={10} className="inline mr-1" />Build
          </button>
          <button
            onClick={() => run('flash')}
            disabled={busy !== ''}
            title="Build and upload to the board"
            className="px-2 py-1 rounded text-[10px] font-medium bg-phantom-magenta/20 text-phantom-magenta
                       hover:bg-phantom-magenta/30 disabled:opacity-40"
          >
            {busy === 'flash' ? 'flashing…' : 'Flash'}
          </button>
        </div>
        {!hid?.arduino_cli && (
          <p className="text-[10px] text-phantom-error mt-1.5 flex items-center gap-1">
            <ShieldOff size={10} /> arduino-cli missing — flash is unavailable
          </p>
        )}
      </div>

      {note && (
        <p className="text-[10px] text-text-secondary bg-surface-raised border border-surface-border
                      rounded px-2 py-1 break-words" role="status">
          {note}
        </p>
      )}
    </div>
  )
}

function Row({ label, value, active, warn }: {
  label: string; value: string; active?: boolean; warn?: boolean
}) {
  return (
    <div className="flex items-center justify-between gap-2">
      <span className="text-text-dim">{label}</span>
      <span className={`truncate text-right ${warn ? 'text-phantom-error' : active ? 'text-phantom-green' : 'text-text-secondary'}`}
            title={value}>
        {value}
      </span>
    </div>
  )
}
