import { useEffect, useState } from 'react'
import { useStore } from '@/store'
import { useApi, useApiError } from '@/hooks/useApi'
import ExternalTools from '@/components/ExternalTools'
import {
  Settings, Cpu, Server, Shield, Key, Eye, EyeOff,
  RotateCw, CheckCircle2, AlertTriangle, Film, Globe
} from 'lucide-react'

interface KeyInfo {
  label: string
  hint: string
  env: string
  configured: boolean
  source: string
  masked: string
}

export default function SettingsPanel() {
  const { settings, setSettings, listener, pushToast } = useStore()
  const { api, pollC2 } = useApi()
  const apiError = useApiError()
  const [apiToken, setApiToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [saved, setSaved] = useState(false)
  const [apiKeys, setApiKeys] = useState<Record<string, KeyInfo>>({})
  const [keyDrafts, setKeyDrafts] = useState<Record<string, string>>({})
  const [keySaved, setKeySaved] = useState('')

  const loadKeys = async () => {
    const res = await api('GET', '/api/config/keys')
    if (res.status === 200 && res.data) {
      const d = res.data as { keys: Record<string, KeyInfo> }
      setApiKeys(d.keys || {})
    }
  }

// eslint-disable-next-line react-hooks/exhaustive-deps
useEffect(() => { loadKeys(); loadGuardrails() }, [])

  const saveKey = async (name: string) => {
    const value = keyDrafts[name] ?? ''
    const res = await api('POST', '/api/config/keys', { name, value })
    if (res.status === 200 && res.data) {
      const d = res.data as { keys: Record<string, KeyInfo> }
      setApiKeys(d.keys || {})
      setKeyDrafts((s) => ({ ...s, [name]: '' }))
      setKeySaved(name)
      setTimeout(() => setKeySaved(''), 2500)
    } else {
      apiError(res, `Save ${name} key`)
    }
  }

  const handleRotateApiToken = async () => {
    const res = await api('POST', '/api/c2/config/rotate-api-token')
    if (res.status === 200 && res.data) {
      const d = res.data as { token: string }
      setApiToken(d.token)
      setSaved(true)
      setTimeout(() => setSaved(false), 3000)
    }
  }

  const handleToggleMtls = async () => {
    const res = await api('POST', '/api/c2/config/mtls-toggle')
    pollC2()
  }

  // ── guardrails ────────────────────────────────────────────────────────
  // The manifest is a read; flipping one is a deliberate operator action that
  // the backend also writes to the audit log. Nothing here is a silent write.
  type Guardrail = {
    key: string
    label: string
    enabled: boolean
    overridden: boolean
    detail: string
    source: string
    remedy: string
  }
  type GuardrailManifest = {
    guards: Guardrail[]
    summary: string
    digest: string
    overrides: string[]
    toggleable: string[]
  }

  const [guardrails, setGuardrails] = useState<GuardrailManifest | null>(null)

  const loadGuardrails = async () => {
    const res = await api('GET', '/api/guardrails')
    if (res.status === 200 && res.data) {
      setGuardrails(res.data as GuardrailManifest)
    }
  }

  const toggleGuardrail = async (key: string, enabled: boolean) => {
    const res = await api('POST', '/api/guardrails', { key, enabled })
    if (res.status === 200 && res.data) {
      const d = res.data as { manifest: GuardrailManifest }
      setGuardrails(d.manifest)
    } else if (res.status !== 200) {
      pushToast({
        title: 'Guardrail not changed',
        description: 'That control is not operator-toggleable.',
        type: 'warning'
      })
      loadGuardrails()
    }
  }

  const handleBackendDetect = async () => {
    const res = await api('GET', '/api/backend/detect')
    if (res.status === 200 && res.data) {
      const d = res.data as { kind: string; details: string }
      setSettings({ backend_type: (d.kind || 'none') as typeof settings.backend_type })
    }
  }

  const saveBackend = async () => {
    await api('POST', '/api/backend/config', {
      kind: settings.backend_type,
      distro: settings.wsl_distro,
      host: settings.ssh_host,
      port: settings.ssh_port,
      user: settings.ssh_user,
    })
    setSaved(true)
    setTimeout(() => setSaved(false), 2500)
  }

  const toggleSaveRecordings = () => {
    const next = !settings.save_recordings_to_disk
    setSettings({ save_recordings_to_disk: next })
    try {
      localStorage.setItem('phantom.saveRecordingsToDisk', next ? '1' : '0')
    } catch { /* localStorage can be unavailable — preference stays session-only */ }
  }

  return (
    <div className="p-4 flex flex-col gap-4 h-full">
      <div>
        <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
          <Settings size={19} className="text-text-secondary" /> Settings
        </h1>
        <p className="text-xs text-text-dim mt-0.5">Backend configuration, security, and preferences</p>
      </div>

      <div className="grid grid-cols-2 gap-4 max-w-[700px]">
        {/* Backend */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-3">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <Cpu size={13} /> Backend
          </h2>
          <div className="space-y-2.5">
            <div>
              <label className="text-[10px] text-text-dim block mb-1">Type</label>
              <select
                value={settings.backend_type}
                onChange={(e) => setSettings({ backend_type: e.target.value as typeof settings.backend_type })}
                className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5
                  text-xs text-text-primary focus:outline-none focus:border-phantom-cyan"
              >
                <option value="none">Auto-detect</option>
                <option value="wsl2">WSL2 (Windows)</option>
                <option value="native">Native (Linux)</option>
                <option value="ssh">SSH Remote</option>
              </select>
            </div>

            <div className="flex gap-2">
              <button
                onClick={handleBackendDetect}
                className="flex-1 py-1.5 rounded text-xs font-medium
                  bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30
                  transition-colors"
              >
                Auto-Detect Backend
              </button>
              <button
                onClick={saveBackend}
                className="px-3 py-1.5 rounded text-xs font-medium
                  bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30
                  transition-colors"
              >
                Save
              </button>
            </div>
            {saved && <p className="text-[10px] text-phantom-green">Backend configuration saved.</p>}

            {settings.backend_type === 'ssh' && (
              <div className="space-y-2">
                <InputGroup label="SSH Host" value={settings.ssh_host}
                  onChange={(v) => setSettings({ ssh_host: v })} placeholder="kali.local" />
                <div className="flex gap-2">
                  <InputGroup label="SSH Port" value={String(settings.ssh_port)}
                    onChange={(v) => { const n = parseInt(v); if (!isNaN(n)) setSettings({ ssh_port: n }) }}
                    placeholder="22" />
                  <InputGroup label="User" value={settings.ssh_user}
                    onChange={(v) => setSettings({ ssh_user: v })} placeholder="root" />
                </div>
              </div>
            )}

            {settings.backend_type === 'wsl2' && (
              <InputGroup label="WSL Distro" value={settings.wsl_distro}
                onChange={(v) => setSettings({ wsl_distro: v })} placeholder="kali-linux" />
            )}
          </div>
        </div>

        {/* Engagement guardrails: every safety control, its state, and which layer
            decided it. Overridden controls are called out because an override
            the operator cannot see is how an engagement runs with less
            protection than it was sold with — and it is what ends up in the
            report. */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-3">
          <div className="flex items-center justify-between mb-3">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
              <Shield size={13} /> Engagement guardrails
            </h2>
            {guardrails && (
              <span className={`text-[10px] px-1.5 py-0.5 rounded ${
                guardrails.overrides.length
                  ? 'bg-amber-500/20 text-amber-400 border border-amber-500/40'
                  : 'bg-phantom-green/10 text-phantom-green border border-phantom-green/30'}`}>
                {guardrails.overrides.length
                  ? `${guardrails.overrides.length} override${guardrails.overrides.length > 1 ? 's' : ''}`
                  : 'all on'}
              </span>
            )}
          </div>
          <button onClick={loadGuardrails}
            className="text-[10px] text-text-dim hover:text-phantom-cyan mb-2">
            Refresh
          </button>
          <div className="space-y-2">
            {!guardrails && (
              <p className="text-[10px] text-text-dim">Loading the manifest…</p>
            )}
            {guardrails?.guards.map((g) => {
              const toggleable = guardrails.toggleable.includes(g.key)
              const off = !g.enabled
              const overridden = guardrails.overrides.includes(g.key)
              // Only the ON/OFF control is a button. Wrapping the whole row in
              // one would nest a button inside a button: invalid HTML, and the
              // click fires twice.
              return (
                <div key={g.key} className="flex items-start justify-between gap-3">
                  <div className="min-w-0">
                    <p className="text-xs font-medium text-text-primary">
                      {g.label}
                      {overridden && (
                        <span className="ml-1.5 text-[9px] px-1 py-0.5 rounded
                          bg-amber-500/20 text-amber-400 border border-amber-500/40">
                          operator override
                        </span>
                      )}
                    </p>
                    <p className="text-[10px] text-text-dim">{g.detail}</p>
                    <p className="text-[9px] text-text-dim/70 mt-0.5">
                      set by <span className="font-mono">{g.source}</span>
                      {g.remedy && <> · restore: {g.remedy}</>}
                    </p>
                  </div>
                  {toggleable ? (
                    <button
                      onClick={() => toggleGuardrail(g.key, !g.enabled)}
                      className={`shrink-0 px-3 py-1 rounded text-xs font-medium transition-colors
                        ${g.enabled
                          ? 'bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30'
                          : 'bg-surface-border text-text-dim hover:bg-surface-hover'}`}>
                      {g.enabled ? 'ON' : 'OFF'}
                    </button>
                  ) : (
                    <span className={`shrink-0 px-3 py-1 rounded text-xs font-medium
                      ${g.enabled
                        ? 'bg-phantom-green/10 text-phantom-green border border-phantom-green/30'
                        : 'bg-surface-border text-text-dim'}`}>
                      {g.enabled ? 'ON' : 'OFF'}
                    </span>
                  )}
                </div>
              )
            })}
            {guardrails && guardrails.overrides.length > 0 && (
              <p className="text-[10px] text-amber-400/90 pt-1 border-t border-surface-border">
                This engagement runs with {guardrails.overrides.length} control(s)
                disabled. The override is recorded in the next report and in the
                audit log.
              </p>
            )}
            {guardrails && (
              <p className="text-[9px] text-text-dim/70">
                manifest digest <span className="font-mono">{guardrails.digest}</span>
                {' — '}appears in the report as &quot;Guardrails&quot;.
              </p>
            )}
          </div>
        </div>

        {/* External tools: what this machine is missing and the install command
            for THIS platform. The Electron half of `deps` — the backend asks the
            package manager only when the request carries confirm=true. */}
        <ExternalTools />

        {/* Security */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-3">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <Shield size={13} /> Security
          </h2>
          <div className="space-y-3">
            {/* mTLS */}
            <div className="flex items-center justify-between">
              <div>
                <p className="text-xs font-medium text-text-primary">mTLS</p>
                <p className="text-[10px] text-text-dim">
                  Mutual TLS for beacon channel
                </p>
              </div>
              <button
                onClick={handleToggleMtls}
                className={`px-3 py-1 rounded text-xs font-medium transition-colors
                  ${listener.mtls
                    ? 'bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30'
                    : 'bg-surface-border text-text-dim hover:bg-surface-hover'
                  }`}
              >
                {listener.mtls ? 'ON' : 'OFF'}
              </button>
            </div>

            {/* API Token */}
            <div className="space-y-1.5">
              <div className="flex items-center justify-between">
                <div>
                  <p className="text-xs font-medium text-text-primary">API Token</p>
                  <p className="text-[10px] text-text-dim">
                    REST endpoint authentication
                  </p>
                </div>
                <button
                  onClick={handleRotateApiToken}
                  className="flex items-center gap-1 px-2 py-1 rounded text-xs
                    bg-phantom-yellow/20 text-phantom-yellow hover:bg-phantom-yellow/30
                    transition-colors"
                >
                  <RotateCw size={11} /> Rotate
                </button>
              </div>
              {apiToken && (
                <div className="flex items-center gap-1.5 bg-surface rounded px-2 py-1.5 border border-surface-border">
                  <Key size={11} className="text-text-dim" />
                  <span className="text-xs font-mono text-text-primary flex-1 truncate">
                    {showToken ? apiToken : '●●●●●●●●●●●●●●●●●●●●'}
                  </span>
                  <button onClick={() => setShowToken(!showToken)} className="text-text-dim hover:text-text-primary">
                    {showToken ? <EyeOff size={13} /> : <Eye size={13} />}
                  </button>
                </div>
              )}
              {saved && (
                <div className="flex items-center gap-1 text-phantom-green text-[10px]">
                  <CheckCircle2 size={11} /> Token rotated
                </div>
              )}
            </div>

            {/* Certs status */}
            <div className="flex items-center justify-between">
              <p className="text-xs text-text-primary">TLS Certs</p>
              <span className={`text-xs ${listener.certs_present ? 'text-phantom-green' : 'text-phantom-yellow'}`}>
                {listener.certs_present ? '✓ Present' : '⚠ Missing'}
              </span>
            </div>
          </div>
        </div>

        {/* External services (API keys) */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-3 col-span-2">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-1 flex items-center gap-1.5">
            <Globe size={13} /> External services
          </h2>
          <p className="text-[10px] text-text-dim mb-3">
            API keys are stored in data/config.json — no .env editing needed.
            A legacy PHANTOM_* environment variable, when set, still overrides
            the value here.
          </p>
          <div className="space-y-3">
            {Object.entries(apiKeys).map(([name, info]) => (
              <div key={name} className="border-t border-surface-border pt-3 first:border-t-0 first:pt-0">
                <div className="flex items-center justify-between mb-1">
                  <div>
                    <p className="text-xs font-medium text-text-primary flex items-center gap-1.5">
                      {info.label}
                      <span className={`text-[9px] px-1.5 py-0.5 rounded ${
                        info.configured
                          ? 'bg-phantom-green/20 text-phantom-green'
                          : 'bg-surface-border text-text-dim'
                      }`}>
                        {info.configured
                          ? (info.source === 'env' ? 'set · env' : 'set')
                          : 'not set'}
                      </span>
                    </p>
                    <p className="text-[10px] text-text-dim mt-0.5">{info.hint}</p>
                  </div>
                  {info.configured && info.masked && (
                    <span className="text-[10px] font-mono text-text-dim">{info.masked}</span>
                  )}
                </div>
                <div className="flex gap-2 mt-1.5">
                  <input
                    type="password"
                    value={keyDrafts[name] ?? ''}
                    onChange={(e) => setKeyDrafts((s) => ({ ...s, [name]: e.target.value }))}
                    placeholder={info.env}
                    className="flex-1 bg-surface border border-surface-border rounded px-2.5 py-1.5
                      text-xs font-mono text-text-primary placeholder-text-dim
                      focus:outline-none focus:border-phantom-cyan"
                  />
                  <button
                    onClick={() => saveKey(name)}
                    className="px-3 py-1.5 rounded text-xs font-medium
                      bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30
                      transition-colors"
                  >
                    Save
                  </button>
                </div>
                {keySaved === name && (
                  <div className="flex items-center gap-1 text-phantom-green text-[10px] mt-1">
                    <CheckCircle2 size={11} /> Saved
                  </div>
                )}
              </div>
            ))}
            {Object.keys(apiKeys).length === 0 && (
              <p className="text-[10px] text-text-dim">
                No key registry available (backend offline or older build).
              </p>
            )}
          </div>
        </div>

        {/* Preferences */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-3 col-span-2">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3 flex items-center gap-1.5">
            <Film size={13} /> Preferences
          </h2>
          <div className="flex items-center justify-between">
            <div>
              <p className="text-xs font-medium text-text-primary">Save recordings to disk</p>
              <p className="text-[10px] text-text-dim">
                Auto-copy every finished screen recording to your Desktop
                (folder &quot;Phantom Recordings&quot;). When OFF, recordings stay
                inside Electron and are saved only on demand.
              </p>
            </div>
            <button
              onClick={toggleSaveRecordings}
              className={`px-3 py-1 rounded text-xs font-medium transition-colors
                ${settings.save_recordings_to_disk
                  ? 'bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30'
                  : 'bg-surface-border text-text-dim hover:bg-surface-hover'
                }`}
            >
              {settings.save_recordings_to_disk ? 'ON' : 'OFF'}
            </button>
          </div>
        </div>

        {/* About */}
        <div className="bg-surface-card border border-surface-border rounded-lg p-3 col-span-2">
          <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
            About
          </h2>
          <div className="grid grid-cols-3 gap-2 text-xs">
            <div>
              <span className="text-text-dim">Version:</span>{' '}
              <span className="text-text-primary font-mono">3.7.3</span>
            </div>
            <div>
              <span className="text-text-dim">Platform:</span>{' '}
              <span className="text-text-primary">{navigator.platform}</span>
            </div>
            <div>
              <span className="text-text-dim">Electron:</span>{' '}
              <span className="text-text-primary font-mono">31.x</span>
            </div>
            <div className="col-span-3 mt-2">
              <span className="text-text-dim">PHANTOM — Offensive Security Framework</span>
            </div>
          </div>
        </div>
      </div>
    </div>
  )
}

function InputGroup({
  label, value, onChange, placeholder
}: {
  label: string
  value: string
  onChange: (v: string) => void
  placeholder: string
}) {
  return (
    <div className={label.length < 6 ? 'flex-1' : ''}>
      <label className="text-[10px] text-text-dim block mb-1">{label}</label>
      <input
        type="text"
        value={value}
        onChange={(e) => onChange(e.target.value)}
        placeholder={placeholder}
        className="w-full bg-surface border border-surface-border rounded px-2.5 py-1.5
          text-xs font-mono text-text-primary placeholder-text-dim
          focus:outline-none focus:border-phantom-cyan"
      />
    </div>
  )
}