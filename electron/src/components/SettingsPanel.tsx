import { useState } from 'react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'
import {
  Settings, Cpu, Server, Shield, Key, Eye, EyeOff,
  RotateCw, CheckCircle2, AlertTriangle
} from 'lucide-react'

export default function SettingsPanel() {
  const { settings, setSettings, listener } = useStore()
  const { api, pollC2 } = useApi()
  const [apiToken, setApiToken] = useState('')
  const [showToken, setShowToken] = useState(false)
  const [saved, setSaved] = useState(false)

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