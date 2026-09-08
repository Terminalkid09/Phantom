import { useState, useEffect, useRef, useCallback } from 'react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'
import { Network, RefreshCw, Globe, Monitor, Server, Radio, Route, Bug, KeyRound, ShieldAlert, Wifi, Target, Copy, Check, Smartphone, Router, HardDrive, HelpCircle, Maximize2, Move } from 'lucide-react'

interface NodeMeta {
  ip?: string
  mac?: string
  vendor?: string
  hostname?: string
  os?: string
  services?: string
  ports?: number[]
  source?: string
  is_target?: boolean
}

interface MapNode {
  id: string
  label: string
  type: 'attacker' | 'host' | 'service' | 'beacon' | 'vuln' | 'creds'
  color: string
  detail?: string
  meta?: NodeMeta
}

interface MapEdge {
  from: string
  to: string
  label: string
}

interface NetworkMapData {
  nodes: MapNode[]
  edges: MapEdge[]
  target: string
  services: number
  beacons: number
  topology?: { kind?: string; gateway?: string; confidence?: number; note?: string }
}

interface AttackChain {
  steps: string[]
  score: number
  technique: string
  summary: string
}

interface VulnPort { port: number; service: string; weight: number }
interface VulnRank {
  ip: string
  hostname?: string
  vendor?: string
  mac?: string
  score: number
  risk: string
  open_ports: VulnPort[]
  port_count: number
  banner?: string
}
interface VulnReport {
  ranked: VulnRank[]
  recommended: VulnRank | null
  reason: string
}

const RISK_COLOR: Record<string, string> = {
  CRITICAL: 'text-red-400 border-red-500/40 bg-red-500/10',
  HIGH: 'text-orange-400 border-orange-500/40 bg-orange-500/10',
  MEDIUM: 'text-phantom-yellow border-phantom-yellow/40 bg-phantom-yellow/10',
  LOW: 'text-phantom-green border-phantom-green/40 bg-phantom-green/10',
}

const TYPE_ICON: Record<string, typeof Globe> = {
  vuln: Bug,
  creds: KeyRound,
}

/** Guess a device kind from hostname/vendor — drives the card icon. */
function deviceIcon(n: MapNode): typeof Globe {
  const t = `${n.label} ${n.meta?.vendor || ''} ${n.meta?.hostname || ''}`.toLowerCase()
  if (t.includes('modem') || t.includes('router') || t.includes('gateway') || t.includes('ap-')) return Router
  if (t.includes('samsung') || t.includes('iphone') || t.includes('android') || t.includes('pixel') || t.includes('-di-') || t.includes('phone')) return Smartphone
  if (t.includes('vmware') || t.includes('virtualbox') || t.includes('qemu') || t.includes('hyper-v')) return HardDrive
  return Monitor
}

function deviceKind(n: MapNode): string {
  const t = `${n.label} ${n.meta?.vendor || ''} ${n.meta?.hostname || ''}`.toLowerCase()
  if (t.includes('modem') || t.includes('router') || t.includes('gateway') || t.includes('ap-')) return 'Gateway / Router'
  if (t.includes('randomized')) return 'Mobile device (randomized MAC)'
  if (t.includes('vmware') || t.includes('virtualbox') || t.includes('qemu') || t.includes('hyper-v')) return 'Virtual machine'
  if (t.includes('roomba') || t.includes('bosch') || t.includes('petkit') || t.includes('amazon') || t.includes('hue')) return 'IoT device'
  if (t.includes('samsung') || t.includes('iphone') || t.includes('android') || t.includes('phone')) return 'Mobile device'
  return 'Host'
}

const MIN_K = 0.35
const MAX_K = 4

export default function NetworkMap({ standalone }: { standalone?: boolean }) {
  const { session, setSession } = useStore()
  const { api } = useApi()
  const [data, setData] = useState<NetworkMapData | null>(null)
  const [chains, setChains] = useState<AttackChain[]>([])
  const [showPaths, setShowPaths] = useState(true)
  const [hoveredNode, setHoveredNode] = useState<string | null>(null)
  const [selected, setSelected] = useState<MapNode | null>(null)
  const [settingTarget, setSettingTarget] = useState(false)
  const [targetMsg, setTargetMsg] = useState('')
  const [copied, setCopied] = useState('')
  const containerRef = useRef<HTMLDivElement>(null)
  const svgRef = useRef<SVGSVGElement>(null)

  // ── Pan & zoom viewport state ─────────────────────────────────────────────
  // The whole graph lives in a large world coordinate space; the <g> below
  // applies translate(x,y) scale(k). Drag = pan, wheel = zoom-to-cursor.
  const [view, setView] = useState({ x: 0, y: 0, k: 1 })
  const [dragging, setDragging] = useState(false)
  const dragStart = useRef<{ cx: number; cy: number; vx: number; vy: number } | null>(null)
  const didPan = useRef(false)

  const clientToSvg = useCallback((cx: number, cy: number) => {
    const svg = svgRef.current
    if (!svg) return null
    const m = svg.getScreenCTM()
    if (!m) return null
    const pt = svg.createSVGPoint()
    pt.x = cx
    pt.y = cy
    const p = pt.matrixTransform(m.inverse())
    return { x: p.x, y: p.y }
  }, [])

  const zoomAt = useCallback((clientX: number, clientY: number, factor: number) => {
    const loc = clientToSvg(clientX, clientY)
    if (!loc) return
    setView((v) => {
      const k2 = Math.min(MAX_K, Math.max(MIN_K, v.k * factor))
      if (k2 === v.k) return v
      // keep the world point under the cursor fixed while scaling
      return {
        k: k2,
        x: loc.x - ((loc.x - v.x) * k2) / v.k,
        y: loc.y - ((loc.y - v.y) * k2) / v.k,
      }
    })
  }, [clientToSvg])

  // Native (non-passive) wheel listener so preventDefault works inside the map
  useEffect(() => {
    const svg = svgRef.current
    if (!svg) return
    const onWheel = (e: WheelEvent) => {
      e.preventDefault()
      zoomAt(e.clientX, e.clientY, e.deltaY < 0 ? 1.15 : 1 / 1.15)
    }
    svg.addEventListener('wheel', onWheel, { passive: false })
    return () => svg.removeEventListener('wheel', onWheel)
  }, [zoomAt, data !== null])

  const onPointerDown = (e: React.PointerEvent<SVGSVGElement>) => {
    if (e.button !== 0) return
    didPan.current = false
    dragStart.current = { cx: e.clientX, cy: e.clientY, vx: view.x, vy: view.y }
    setDragging(true)
    ;(e.target as Element).setPointerCapture?.(e.pointerId)
  }

  const onPointerMove = (e: React.PointerEvent<SVGSVGElement>) => {
    const st = dragStart.current
    if (!st) return
    const now = clientToSvg(e.clientX, e.clientY)
    const origin = clientToSvg(st.cx, st.cy)
    if (!now || !origin) return
    const dx = now.x - origin.x
    const dy = now.y - origin.y
    if (Math.abs(dx) > 2 || Math.abs(dy) > 2) didPan.current = true
    setView((v) => ({ ...v, x: st.vx + dx, y: st.vy + dy }))
  }

  const onPointerUp = () => {
    dragStart.current = null
    setDragging(false)
    // let the click handler see didPan, then clear it on the next tick
    setTimeout(() => { didPan.current = false }, 0)
  }

  const resetView = () => setView({ x: 0, y: 0, k: 1 })

  const load = async () => {
    const res = await api('GET', '/api/network-map')
    if (res.status === 200) {
      const d = res.data as NetworkMapData
      setData(d)
      // keep the selected node fresh across reloads
      if (selected) {
        const fresh = d.nodes.find((n) => n.id === selected.id)
        setSelected(fresh || null)
      }
    }
    const ag = await api('GET', '/api/attack-graph')
    if (ag.status === 200 && ag.data) {
      const d = ag.data as { chains?: AttackChain[] }
      setChains(d.chains || [])
    }
  }

  const [scanning, setScanning] = useState(false)
  const [scanMsg, setScanMsg] = useState('')
  const handleScan = async () => {
    setScanning(true)
    setScanMsg('Mapping network…')
    const res = await api('POST', '/api/network/scan', {})
    setScanning(false)
    if (res.status === 200 && res.data) {
      const d = res.data as { hosts?: unknown[]; method?: string; seeded?: number }
      const hosts = (d.hosts || []) as Array<Record<string, string>>
      const named = hosts.filter((h) => h.hostname || h.vendor).length
      setScanMsg(`Found ${hosts.length} device(s) via ${d.method || '?'} — ${named} identified, added to the map`)
      await load()
    } else {
      setScanMsg('Scan failed — see console')
    }
  }

  const [vuln, setVuln] = useState<VulnReport | null>(null)
  const [probing, setProbing] = useState(false)
  const handleProbe = async () => {
    setProbing(true)
    const res = await api('POST', '/api/network/vulnerable', {})
    setProbing(false)
    if (res.status === 200 && res.data) {
      setVuln(res.data as VulnReport)
    } else {
      setVuln({ ranked: [], recommended: null, reason: 'Probe failed — see console' })
    }
  }

  useEffect(() => { load(); const t = setInterval(load, 8000); return () => clearInterval(t) }, [])

  const copy = (text: string) => {
    navigator.clipboard?.writeText(text)
    setCopied(text)
    setTimeout(() => setCopied(''), 1500)
  }

  const setAsTarget = async (n: MapNode) => {
    const ip = n.meta?.ip || n.label
    if (!ip || ip === session.target) return
    setSettingTarget(true)
    setTargetMsg('')
    const res = await api('POST', '/api/session/set', { key: 'target', value: ip })
    setSettingTarget(false)
    if (res.status === 200) {
      setSession({ target: ip })
      setTargetMsg(`${ip} is now the session target — run a scan or launch auto-mode against it`)
      await load()
    } else {
      const err = (res.data as { error?: string })?.error || 'failed to set target'
      setTargetMsg(`✗ ${err}`)
    }
  }

  if (!data || data.nodes.length === 0) {
    return (
      <div className={`flex flex-col items-center justify-center text-text-dim ${standalone ? 'h-full' : 'h-full'}`}>
        <Globe size={32} className="mb-2 text-text-dim" />
        <p className="text-xs">No network data yet.</p>
        <p className="text-xs text-text-dim mt-1">Scan the local network to discover every live device, or set a target and run a scan.</p>
        <div className="flex gap-2 mt-3">
          <button onClick={handleScan} disabled={scanning}
            className="px-3 py-1.5 rounded bg-phantom-cyan/20 text-phantom-cyan text-xs font-semibold hover:bg-phantom-cyan/30 transition-colors">
            {scanning ? 'Scanning...' : 'Scan Network'}
          </button>
          <button onClick={load} className="px-3 py-1.5 rounded bg-surface border border-surface-border text-xs text-text-secondary hover:text-text-primary">
            <RefreshCw size={12} className="inline mr-1" /> Refresh
          </button>
        </div>
        {scanMsg && <p className="text-[10px] text-text-dim mt-2">{scanMsg}</p>}
      </div>
    )
  }

  // ── World layout: a large canvas meant to be panned and zoomed ────────────
  // The layout mirrors the REAL network shape reported by the scan:
  // star → devices hang off the gateway hub; tree → tiered rows under the
  // gateway; broadcast → wide flat row (host-to-host). The session target
  // keeps its red aura where it actually lives — no phantom bubble.
  const hasPaths = showPaths && chains.length > 0
  const nodeList = data.nodes
  const svcNodes = nodeList.filter((n) => n.type === 'service')
  const vulnNodes = nodeList.filter((n) => n.type === 'vuln')
  const credNodes = nodeList.filter((n) => n.type === 'creds')
  const beaconNodes = nodeList.filter((n) => n.type === 'beacon')
  const extraHosts = nodeList.filter((n) => n.type === 'host')

  const hostCols = 3
  const hostRows = Math.max(1, Math.ceil(extraHosts.length / hostCols))
  const width = 1560
  const gridTop = 300
  const rowH = 96
  const height = Math.max(860, 470 + Math.ceil(Math.max(0, extraHosts.length - 1) / 4) * 150 + 260)

  // Layout positions — all nodes (beacons included) get a position so
  // nothing is dropped by the renderer when edges reference it.
  const positions: Record<string, { x: number; y: number }> = {}
  const topo = data.topology || {}
  const topoKind = (topo.kind || 'star').toLowerCase()

  // gateway node: prefer the detected gateway IP, else the device whose
  // hostname/vendor smells like a router
  const gwIp = topo.gateway || ''
  const gwNode = extraHosts.find((h) => (h.meta?.ip || '') === gwIp)
    || extraHosts.find((h) => /modem|router|gateway|fibra/i.test(`${h.label} ${h.meta?.vendor || ''}`))

  // session target lives wherever its real device lives (aura binds to it);
  // fall back to the single session node the server emits for an
  // undiscovered/external target
  const targetNode = data.nodes.find((n) => n.meta?.is_target && n.type === 'host')
  const hubId = gwNode?.id || extraHosts[0]?.id || ''

  const gwX = 620, gwY = 210
  if (hubId) positions[hubId] = { x: gwX, y: gwY }

  // devices that are neither gateway nor target get placed by topology kind
  const spokes = extraHosts.filter((h) => h.id !== hubId)
  const perRow = topoKind === 'broadcast' ? 5 : 4
  const fanX = topoKind === 'broadcast' ? 240 : 200
  spokes.forEach((h, i) => {
    const row = Math.floor(i / perRow)
    const col = i % perRow
    const rowCount = Math.min(perRow, spokes.length - row * perRow)
    const rowW = (rowCount - 1) * fanX
    positions[h.id] = {
      x: topoKind === 'tree'
        ? 420 + col * fanX + (row % 2) * 90
        : 300 + col * fanX - (topoKind === 'broadcast' ? 0 : rowW / 4),
      y: 470 + row * 150 + (topoKind === 'broadcast' ? (row % 2) * 40 : 0),
    }
  })

  // attacker connects from the left edge of the canvas
  positions['attacker'] = { x: 120, y: gwY }

  // findings belong to the session target's world model — fan them around
  // the TARGET device's position (fallback: gateway) instead of a fixed
  // offset that had nothing to do with where the device actually sits
  const anchorNode = targetNode || gwNode
  const ax = positions[anchorNode?.id || '']?.x ?? gwX
  const ay = positions[anchorNode?.id || '']?.y ?? gwY
  const svcStartY = ay - ((svcNodes.length - 1) * 42) / 2
  svcNodes.forEach((s, i) => {
    positions[s.id] = { x: ax + 320, y: Math.max(80, svcStartY + i * 42) }
  })
  vulnNodes.forEach((v, i) => {
    positions[v.id] = { x: ax - 260 + (i % 3) * 100, y: ay + 60 + Math.floor(i / 3) * 52 }
  })
  credNodes.forEach((c, i) => {
    positions[c.id] = { x: ax + 290, y: Math.max(80, svcStartY + svcNodes.length * 42 + 56 + i * 46) }
  })
  beaconNodes.forEach((b, i) => {
    positions[b.id] = { x: ax + (i * 150 - (beaconNodes.length - 1) * 75), y: ay + 250 }
  })
  // any node without a computed position (late beacon, stray finding):
  // park it on the parking row so edges never reference a missing position
  nodeList.forEach((n, i) => {
    if (!positions[n.id]) positions[n.id] = { x: 130 + (i % 6) * 210, y: height - 60 }
  })

  const nodeRadius = (t: string) => (t === 'attacker' ? 26 : t === 'host' ? 21 : t === 'beacon' ? 16 : 13)

  // gateway devices get a distinct badge so the hub reads as infrastructure
  const isGatewayNode = (n: MapNode) => n.id === gwNode?.id

  const renderNode = (n: MapNode) => {
    const pos = positions[n.id]
    if (!pos) return null
    const r = nodeRadius(n.type)
    const isHovered = hoveredNode === n.id
    const isSelected = selected?.id === n.id
    const isSessionTarget = !!n.meta?.is_target
    const Icon = TYPE_ICON[n.type]
    return (
      <g key={n.id}
        onMouseEnter={() => setHoveredNode(n.id)}
        onMouseLeave={() => setHoveredNode(null)}
        onClick={(e) => { e.stopPropagation(); if (!didPan.current) setSelected(n) }}
        style={{ cursor: 'pointer' }}
      >
        {/* red aura marks the session target — bound to THIS node, so it
            moves with the device when the target changes */}
        {isSessionTarget && (
          <>
            <circle cx={pos.x} cy={pos.y} r={r + 14} fill="#FF3333" opacity={0.10} />
            <circle cx={pos.x} cy={pos.y} r={r + 9} fill="none" stroke="#FF3333"
              strokeWidth={2.2} />
          </>
        )}
        {isGatewayNode(n) && !isSessionTarget && (
          <circle cx={pos.x} cy={pos.y} r={r + 7} fill="none" stroke="#58A6FF"
            strokeWidth={1} strokeDasharray="2,4" opacity={0.55} />
        )}
        {isSelected && (
          <circle cx={pos.x} cy={pos.y} r={r + 6} fill="none" stroke="#E6EDF3"
            strokeWidth={1.5} strokeDasharray="4,3" />
        )}
        <circle cx={pos.x} cy={pos.y} r={r} fill={n.color} opacity={0.15}
          stroke={n.color} strokeWidth={2} />
        <circle cx={pos.x} cy={pos.y} r={r} fill={n.color} opacity={isHovered ? 0.3 : 0.1} />
        {Icon ? (
          <g transform={`translate(${pos.x - 8},${pos.y - 8})`}>
            <Icon size={16} color={n.color} />
          </g>
        ) : (
          <text x={pos.x} y={pos.y + 4} textAnchor="middle" fill={n.color}
            fontSize={n.type === 'attacker' ? 9 : 8} fontWeight={700} fontFamily="Inter, sans-serif">
            {n.type === 'attacker' ? 'C2' : n.type === 'host' ? 'T' : n.type === 'beacon' ? 'B' : ''}
          </text>
        )}
        <text x={pos.x} y={pos.y - r - 6} textAnchor="middle" fill="#E6EDF3"
          fontSize={11.5} fontWeight={600} fontFamily="Inter, sans-serif">
          {n.label}
        </text>
        {n.type === 'host' && n.meta?.ip && (
          <>
            <text x={pos.x} y={pos.y + r + 13} textAnchor="middle" fill="#8B949E"
              fontSize={9} fontFamily="JetBrains Mono, monospace">
              {n.meta.ip}
            </text>
            {n.meta.os && (
              <text x={pos.x} y={pos.y + r + 25} textAnchor="middle" fill="#6E7681"
                fontSize={8} fontFamily="JetBrains Mono, monospace">
                {n.meta.os.slice(0, 24)}
              </text>
            )}
          </>
        )}
        {isHovered && n.detail && (
          <>
            <rect x={pos.x - 84} y={pos.y + r + 18} width={168} height={18} rx={4}
              fill="#161B22" stroke="#30363D" strokeWidth={0.5} />
            <text x={pos.x} y={pos.y + r + 31} textAnchor="middle" fill="#8B949E"
              fontSize={8} fontFamily="JetBrains Mono, monospace">
              {n.detail.slice(0, 36)}
            </text>
          </>
        )}
      </g>
    )
  }

  // ── Device detail panel (click a card or a node) ──────────────────────────
  const renderDetail = () => {
    if (!selected) return null
    const ip = selected.meta?.ip || (selected.type === 'host' && selected.id !== 'target' ? selected.label : '')
    const isSettable = selected.type === 'host' && selected.id !== 'target' && !!ip && ip !== session.target
    return (
      <div className="rounded-lg border border-surface-border bg-surface-card p-3">
        <div className="flex items-start justify-between gap-3">
          <div className="min-w-0">
            <div className="flex items-center gap-2">
              {(() => { const DI = deviceIcon(selected); return <DI size={15} className="text-phantom-cyan flex-shrink-0" /> })()}
              <span className="text-sm font-semibold text-text-primary truncate">{selected.label}</span>
              <span className="text-[10px] px-1.5 py-0.5 rounded bg-surface text-text-dim border border-surface-border flex-shrink-0">
                {selected.type === 'host' ? deviceKind(selected) : selected.type}
              </span>
            </div>
            <div className="mt-2 grid grid-cols-[auto_1fr] gap-x-3 gap-y-1 text-[11px]">
              {ip && (
                <>
                  <span className="text-text-dim">IP</span>
                  <button onClick={() => copy(ip)} className="text-left font-mono text-text-primary hover:text-phantom-cyan flex items-center gap-1 w-fit">
                    {ip} {copied === ip ? <Check size={10} className="text-phantom-green" /> : <Copy size={10} className="opacity-40" />}
                  </button>
                </>
              )}
              {selected.meta?.hostname && (
                <>
                  <span className="text-text-dim">Hostname</span>
                  <span className="font-mono text-text-secondary truncate">{selected.meta.hostname}</span>
                </>
              )}
              {selected.meta?.mac && (
                <>
                  <span className="text-text-dim">MAC</span>
                  <span className="font-mono text-text-secondary">{selected.meta.mac}</span>
                </>
              )}
              {selected.meta?.vendor && (
                <>
                  <span className="text-text-dim">Vendor</span>
                  <span className="text-text-secondary">{selected.meta.vendor}</span>
                </>
              )}
              {selected.meta?.os && (
                <>
                  <span className="text-text-dim">OS guess</span>
                  <span className="text-phantom-yellow">{selected.meta.os}</span>
                </>
              )}
              {selected.meta?.services && (
                <>
                  <span className="text-text-dim">Services</span>
                  <span className="font-mono text-[10px] text-phantom-cyan">{selected.meta.services}</span>
                </>
              )}
              {selected.detail && (
                <>
                  <span className="text-text-dim">Info</span>
                  <span className="text-text-secondary font-mono text-[10px] break-all">{selected.detail}</span>
                </>
              )}
              {selected.meta?.source && (
                <>
                  <span className="text-text-dim">Source</span>
                  <span className="text-text-dim font-mono">{selected.meta.source}</span>
                </>
              )}
            </div>
          </div>
          <div className="flex flex-col gap-1.5 flex-shrink-0">
            {isSettable && (
              <button
                onClick={() => setAsTarget(selected)}
                disabled={settingTarget}
                className="px-2.5 py-1.5 rounded text-[11px] font-semibold bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30 disabled:opacity-50 transition-colors flex items-center gap-1.5 whitespace-nowrap"
              >
                <Target size={12} /> {settingTarget ? 'Setting…' : 'Set as Session Target'}
              </button>
            )}
            {ip && ip === session.target && (
              <span className="px-2 py-1 rounded text-[10px] bg-phantom-green/15 text-phantom-green border border-phantom-green/30 flex items-center gap-1 whitespace-nowrap">
                <Check size={10} /> Active target
              </span>
            )}
            <button onClick={() => setSelected(null)}
              className="px-2 py-1 rounded text-[10px] text-text-dim hover:text-text-primary border border-surface-border">
              Close
            </button>
          </div>
        </div>
        {targetMsg && <p className="mt-2 text-[11px] text-phantom-green">{targetMsg}</p>}
      </div>
    )
  }

  // ── Device cards grid ─────────────────────────────────────────────────────
  const vulnByIp = new Map((vuln?.ranked || []).map((r) => [r.ip, r]))
  const recommendedIp = vuln?.recommended?.ip
  const renderDeviceGrid = () => {
    if (extraHosts.length === 0) return null
    return (
      <div>
        <h3 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2 flex items-center gap-1.5">
          <Monitor size={13} className="text-phantom-cyan" /> Discovered Devices
          <span className="text-text-dim normal-case font-normal">({extraHosts.length}) — click for details, set as target, or probe for the weakest</span>
        </h3>
        <p className="text-[10px] text-text-dim mb-2">
          Ranking criterion: risky services (SMB · RDP · telnet · DB · docker) weigh more than plain ports, then version banners; &quot;no risk shown&quot; = no open port among the ~60 probed.
        </p>
        {vuln?.recommended && (
          <div className="mb-2.5 rounded-lg border border-phantom-yellow/40 bg-phantom-yellow/10 p-2.5 flex items-start gap-2.5">
            <ShieldAlert size={15} className="text-phantom-yellow flex-shrink-0 mt-0.5" />
            <div className="min-w-0">
              <div className="text-xs font-semibold text-phantom-yellow">
                Recommended starting target — {vuln.recommended.hostname || vuln.recommended.ip}
                <span className="ml-1.5 font-mono text-[10px]">{vuln.recommended.ip}</span>
              </div>
              <div className="text-[11px] text-text-secondary mt-0.5">{vuln.reason}</div>
              <button
                onClick={() => {
                  const n = extraHosts.find((x) => (x.meta?.ip || '') === recommendedIp)
                  if (n) setAsTarget(n)
                }}
                disabled={settingTarget || !recommendedIp}
                className="mt-1.5 px-2 py-1 rounded text-[10px] font-semibold bg-phantom-yellow/20 text-phantom-yellow hover:bg-phantom-yellow/30 disabled:opacity-50 transition-colors flex items-center gap-1"
              >
                <Target size={10} /> Start here
              </button>
            </div>
          </div>
        )}
        <div className="grid grid-cols-2 lg:grid-cols-3 gap-2.5">
          {extraHosts.map((n) => {
            const DI = deviceIcon(n)
            const isTarget = (n.meta?.ip || '') === session.target
            const r = vulnByIp.get(n.meta?.ip || '')
            const isRec = (n.meta?.ip || '') === recommendedIp
            return (
              <div key={n.id} role="button" tabIndex={0}
                onClick={() => setSelected(n)}
                onKeyDown={(e) => { if (e.key === 'Enter') setSelected(n) }}
                className={`text-left rounded-lg border p-3 transition-colors group relative cursor-pointer
                  ${isRec ? 'border-phantom-yellow/50 bg-phantom-yellow/5' : selected?.id === n.id ? 'border-phantom-cyan/60 bg-phantom-cyan/10' : 'border-surface-border bg-surface-card hover:border-surface-hover hover:bg-surface'}`}>
                {isRec && (
                  <span className="absolute -top-2 right-2 px-1.5 py-0.5 rounded text-[9px] font-bold bg-phantom-yellow text-black">
                    WEAKEST
                  </span>
                )}
                <div className="flex items-center gap-2">
                  <DI size={16} className={isTarget ? 'text-phantom-green flex-shrink-0' : 'text-text-secondary flex-shrink-0'} />
                  <span className="text-xs font-semibold text-text-primary truncate">{n.label}</span>
                  {isTarget && <Check size={11} className="text-phantom-green flex-shrink-0 ml-auto" />}
                </div>
                <div className="mt-1.5 font-mono text-[10px] text-phantom-cyan">{n.meta?.ip || '—'}</div>
                <div className="text-[10px] text-text-dim truncate">
                  {n.meta?.vendor || deviceKind(n)}
                  {n.meta?.os && <span className="text-phantom-yellow/70"> · {n.meta.os}</span>}
                </div>
                {n.meta?.services && (
                  <div className="mt-1 font-mono text-[9px] text-phantom-cyan/70 truncate" title={n.meta.services}>
                    {n.meta.services}
                  </div>
                )}
                {r ? (
                  <div className="mt-1.5 flex flex-col gap-1">
                    <div className="flex items-center gap-1.5">
                      <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold border ${RISK_COLOR[r.risk] || RISK_COLOR.LOW}`}>
                        {r.risk} {r.score}
                      </span>
                      <span className="font-mono text-[10px] text-text-secondary">
                        {r.open_ports.slice(0, 4).map((p) => `${p.port}/${p.service}`).join(' ')}
                        {r.port_count > 4 && ` +${r.port_count - 4}`}
                      </span>
                    </div>
                    {r.banner && (
                      <div className="font-mono text-[9px] text-phantom-yellow/80 truncate" title={r.banner}>
                        {r.banner}
                      </div>
                    )}
                  </div>
                ) : isTarget ? (
                  <div className="mt-1.5 text-[10px] flex items-center gap-1 text-phantom-green">
                    Active target
                  </div>
                ) : (
                  <button
                    onClick={(e) => { e.stopPropagation(); setAsTarget(n) }}
                    disabled={settingTarget}
                    className="mt-1.5 text-[10px] flex items-center gap-1 px-1.5 py-0.5 rounded border border-surface-border text-text-dim group-hover:text-phantom-cyan group-hover:border-phantom-cyan/40 hover:!text-phantom-cyan hover:!border-phantom-cyan/60 disabled:opacity-50 transition-colors"
                  >
                    <Target size={10} /> {settingTarget ? 'Setting…' : 'Use as target'}
                  </button>
                )}
              </div>
            )
          })}
        </div>
      </div>
    )
  }

  return (
    <div className={`flex flex-col ${standalone ? 'h-full p-4' : 'h-full'}`}>
      {standalone && (
        <div className="flex items-center justify-between mb-3">
          <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
            <Network size={19} className="text-phantom-cyan" /> Network Map
          </h1>
          <div className="flex items-center gap-2">
            <button
              onClick={handleProbe}
              disabled={probing || (data?.nodes.length || 0) === 0}
              className={`px-2.5 py-1.5 rounded text-xs flex items-center gap-1.5 transition-colors
                ${vuln?.recommended ? 'bg-phantom-yellow/20 text-phantom-yellow hover:bg-phantom-yellow/30' : 'bg-surface text-text-secondary border border-surface-border hover:border-phantom-yellow/50 hover:text-phantom-yellow'}`}
            >
              <ShieldAlert size={12} /> {probing ? 'Probing…' : vuln?.recommended ? 'Weak spot ranked' : 'Find weak spot'}
            </button>
            <button
              onClick={handleScan}
              disabled={scanning}
              className={`px-2.5 py-1.5 rounded text-xs flex items-center gap-1.5 transition-colors
                bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30`}
            >
              <Wifi size={12} /> {scanning ? 'Scanning...' : 'Scan Network'}
            </button>
            <button
              onClick={() => setShowPaths((v) => !v)}
              className={`px-2.5 py-1.5 rounded text-xs flex items-center gap-1.5 transition-colors
                ${showPaths ? 'bg-phantom-yellow/15 text-phantom-yellow' : 'bg-surface text-text-secondary border border-surface-border'}`}
            >
              <Route size={13} /> Attack Paths {chains.length > 0 && `(${chains.length})`}
            </button>
            <button onClick={load} className="p-2 rounded text-text-secondary hover:text-text-primary hover:bg-surface-hover">
              <RefreshCw size={14} />
            </button>
          </div>
        </div>
      )}

      {!standalone && (
        <div className="flex items-center justify-between px-3 py-2 border-b border-surface-border">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
            <Network size={13} className="text-phantom-cyan" /> Network Map
          </h2>
          <button onClick={load} className="text-text-dim hover:text-text-primary"><RefreshCw size={13} /></button>
        </div>
      )}

      <div className={standalone ? 'flex-1 flex flex-col gap-3 min-h-0 overflow-auto' : 'flex-1 min-h-0 flex flex-col'}>
        {standalone && data.topology && data.topology.kind && data.topology.kind !== 'unknown' && (
          <div className="flex items-center gap-2 text-[11px] text-text-secondary px-1">
            <Route size={12} className="text-phantom-cyan flex-shrink-0" />
            <span className="font-semibold text-text-primary capitalize">{data.topology.kind}</span>
            <span className="text-text-dim">topology · {data.topology.gateway ? `gateway ${data.topology.gateway}` : 'gateway unknown'} · {(100 * (data.topology.confidence ?? 0)).toFixed(0)}% confidence</span>
            <span className="text-text-dim truncate hidden xl:inline">— {data.topology.note}</span>
          </div>
        )}
        <div ref={containerRef} className={`relative overflow-hidden bg-surface rounded-lg border border-surface-border flex-shrink-0 ${standalone ? 'min-h-[420px] h-[52%]' : 'flex-1'}`}>
          <svg
            ref={svgRef}
            width="100%" height="100%" viewBox={`0 0 ${width} ${height}`}
            className="w-full h-full select-none"
            style={{ cursor: dragging ? 'grabbing' : 'grab' }}
            onPointerDown={onPointerDown}
            onPointerMove={onPointerMove}
            onPointerUp={onPointerUp}
            onPointerLeave={onPointerUp}
          >
            <g transform={`translate(${view.x},${view.y}) scale(${view.k})`}>
              {/* world background grid — gives the pannable canvas depth */}
              <defs>
                <pattern id="map-grid" width="60" height="60" patternUnits="userSpaceOnUse">
                  <path d="M 60 0 L 0 0 0 60" fill="none" stroke="#161B22" strokeWidth="0.5" />
                </pattern>
              </defs>
              <rect x={-width} y={-height} width={width * 3} height={height * 3} fill="url(#map-grid)" opacity={0.5} />

              {/* Attack-path overlay */}
              {hasPaths && chains[0].steps.length > 1 && (() => {
                const steps = chains[0].steps
                const pts = steps.map((s) =>
                  positions[s] || positions[targetNode?.id || ''] || positions['attacker'])
                const d = pts.map((p, i) => `${i === 0 ? 'M' : 'L'}${p.x},${p.y}`).join(' ')
                return (
                  <g key="attack-path-overlay">
                    <path d={d} fill="none" stroke="#D29922" strokeWidth={7} opacity={0.15} strokeLinecap="round" strokeLinejoin="round" />
                    <path d={d} fill="none" stroke="#D29922" strokeWidth={2.5} strokeDasharray="7,5" opacity={0.9} strokeLinecap="round" strokeLinejoin="round" className="attack-path-flow">
                      <animate attributeName="stroke-dashoffset" from="24" to="0" dur="1.2s" repeatCount="indefinite" />
                    </path>
                    {pts.map((p, i) => (
                      <circle key={i} cx={p.x} cy={p.y} r={4} fill="#D29922" opacity={0.95} />
                    ))}
                  </g>
                )
              })()}

              {/* Edges — always rendered; the connection lines ARE the map */}
              {data.edges.map((e, i) => {
                const from = positions[e.from]
                const to = positions[e.to]
                if (!from || !to) return null
                const isFinding = e.label === 'finding' || e.label === 'credentials'
                return (
                  <g key={`edge-${i}`}>
                    <line x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                      stroke={isFinding ? '#D29922' : e.label === 'beacon' ? '#BD34FE' : '#30363D'}
                      strokeWidth={1.5}
                      strokeDasharray={e.label === 'discovered' ? '5,3' : 'none'} />
                    {e.label !== 'discovered' && (
                      <>
                        <rect x={(from.x + to.x) / 2 - 22} y={(from.y + to.y) / 2 - 9} width={44} height={16} rx={4} fill="#0D1117" stroke="#30363D" strokeWidth={0.5} />
                        <text x={(from.x + to.x) / 2} y={(from.y + to.y) / 2 + 1} textAnchor="middle" fill="#8B949E" fontSize={9} fontFamily="JetBrains Mono, monospace">
                          {e.label}
                        </text>
                      </>
                    )}
                  </g>
                )
              })}

              {/* star/tree spokes: hub → every device (the real topology) */}
              {extraHosts.filter((h) => h.id !== hubId).map((h) => {
                const from = positions[hubId]
                const to = positions[h.id]
                if (!from || !to) return null
                const already = data.edges.some((e) =>
                  (e.from === h.id && e.to === hubId) || (e.from === hubId && e.to === h.id))
                if (already) return null
                return (
                  <line key={`spoke-${h.id}`} x1={from.x} y1={from.y} x2={to.x} y2={to.y}
                    stroke="#1C2430" strokeWidth={1.2} strokeDasharray="2,5" opacity={0.9} />
                )
              })}
              {hubId && positions['attacker'] && positions[hubId] && (
                <line x1={positions['attacker'].x} y1={positions['attacker'].y}
                  x2={positions[hubId].x} y2={positions[hubId].y}
                  stroke="#FF3333" strokeWidth={1.6} strokeDasharray="6,4" opacity={0.55} />
              )}

              {/* Nodes */}
              {data.nodes.map(renderNode)}
            </g>
          </svg>

          {/* Legend + pan/zoom hints */}
          <div className="absolute bottom-3 left-3 flex flex-col gap-1.5 pointer-events-none">
            <div className="flex flex-wrap gap-3 text-[10px] max-w-[520px]">
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#FF3333]" /> Attacker</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#58A6FF]" /> Host</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#3FB950]" /> Service</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#D29922]" /> Finding</span>
              <span className="flex items-center gap-1"><span className="w-2.5 h-2.5 rounded-full bg-[#BD34FE]" /> Beacon</span>
            </div>
            <div className="flex items-center gap-1 text-[9.5px] text-text-dim">
              <Move size={9} /> drag to pan · scroll to zoom · {(view.k * 100).toFixed(0)}%
            </div>
          </div>

          {/* Zoom controls */}
          <div className="absolute top-3 right-3 flex flex-col gap-1">
            <button title="Zoom in" onClick={(e) => {
              const rect = svgRef.current?.getBoundingClientRect()
              if (rect) zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 1.25)
            }} className="w-7 h-7 rounded bg-surface border border-surface-border text-text-secondary hover:text-text-primary text-sm leading-none">+</button>
            <button title="Zoom out" onClick={(e) => {
              const rect = svgRef.current?.getBoundingClientRect()
              if (rect) zoomAt(rect.left + rect.width / 2, rect.top + rect.height / 2, 1 / 1.25)
            }} className="w-7 h-7 rounded bg-surface border border-surface-border text-text-secondary hover:text-text-primary text-sm leading-none">−</button>
            <button title="Reset view" onClick={resetView} className="w-7 h-7 rounded bg-surface border border-surface-border text-text-secondary hover:text-text-primary flex items-center justify-center">
              <Maximize2 size={11} />
            </button>
          </div>

          {/* Stats */}
          <div className="absolute top-3 left-3 flex gap-3 text-[10px] text-text-dim pointer-events-none">
            <span className="flex items-center gap-1"><Server size={10} /> {data.services} svc</span>
            <span className="flex items-center gap-1"><Radio size={10} /> {data.beacons} beacons</span>
          </div>
        </div>

        {/* Selected device detail */}
        <div className="flex-shrink-0">
          {vuln && !vuln.recommended && (
            <p className="mb-1 text-[11px] text-text-dim">{vuln.reason}</p>
          )}
          {renderDetail()}
        </div>

        {/* Discovered device cards */}
        {standalone && <div className="flex-shrink-0">{renderDeviceGrid()}</div>}

        {/* Attack paths list */}
        {standalone && showPaths && (
          <div className="bg-surface-card border border-surface-border rounded-lg p-3 flex-shrink-0">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2 flex items-center gap-1.5">
              <Route size={13} className="text-phantom-yellow" /> Attack Paths to Beacon
              <span className="text-text-dim normal-case font-normal">— same graph the auto-mode planner reasons on</span>
            </h2>
            {chains.length === 0 ? (
              <p className="text-xs text-text-dim">
                No complete chains yet. The graph shows what's missing as findings accumulate.
              </p>
            ) : (
              <div className="space-y-1.5">
                {chains.map((c, i) => (
                  <div key={i} className="flex items-start gap-2 text-xs">
                    <span className="text-[10px] font-mono text-phantom-yellow mt-0.5 w-14 flex-shrink-0">
                      {(c.score * 100).toFixed(0)}%
                    </span>
                    <span className="font-mono text-text-primary">{c.summary}</span>
                    {c.technique && (
                      <span className="ml-auto text-[10px] text-text-dim font-mono flex-shrink-0 flex items-center gap-1">
                        <ShieldAlert size={10} /> {c.technique}
                      </span>
                    )}
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    </div>
  )
}
