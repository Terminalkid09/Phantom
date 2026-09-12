import { useState } from 'react'
import { useStore } from '@/store'
import {
  Radio, Target, Bot, FileText, Settings, Terminal,
  Globe, Wifi, Search, Shield, AlertTriangle,
  Wrench, Monitor, Key, Layers, MapPin, Clock, ScrollText,
  Radar, BookOpen, PieChart, Film, Package, Brain, Network
} from 'lucide-react'

const SECTIONS = [
  {
    label: 'OPERATIONS',
    items: [
      { id: 'c2', icon: Radio, label: 'C2 Dashboard' },
      { id: 'session', icon: Target, label: 'Session' },
      { id: 'automode', icon: Bot, label: 'Auto-Mode' },
      { id: 'adgraph', icon: Network, label: 'AD Graph' },
    ],
  },
  {
    label: 'INTEL',
    items: [
      { id: 'timeline', icon: Clock, label: 'Timeline' },
      { id: 'vault', icon: Key, label: 'Vault' },
      { id: 'network', icon: MapPin, label: 'Network Map' },
      { id: 'audit', icon: ScrollText, label: 'Audit Log' },
      { id: 'recordings', icon: Film, label: 'Recordings' },
      { id: 'bundles', icon: Package, label: 'Bundles' },
      { id: 'learning', icon: Brain, label: 'Learning' },
    ],
  },
  {
    label: 'MODULES',
    items: [
      { id: 'scan', icon: Radar, label: 'Scan' },
      { id: 'osint', icon: Search, label: 'OSINT' },
      { id: 'web', icon: Globe, label: 'Web' },
      { id: 'exploit', icon: Shield, label: 'Exploit' },
      { id: 'brute', icon: AlertTriangle, label: 'Brute' },
      { id: 'payload', icon: Wrench, label: 'Payload' },
      { id: 'wifi', icon: Wifi, label: 'WiFi' },
      { id: 'pivot', icon: Layers, label: 'Pivot' },
      { id: 'handler', icon: Monitor, label: 'Handler' },
      { id: 'analyzer', icon: Terminal, label: 'Analyzer' },
      { id: 'wordlist', icon: BookOpen, label: 'Wordlist' },
    ],
  },
  {
    label: 'OUTPUT',
    items: [
      { id: 'reports', icon: PieChart, label: 'Reports' },
      { id: 'settings', icon: Settings, label: 'Settings' },
    ],
  },
]

export default function Sidebar() {
  const { activeTab, setActiveTab, beacons, autoMode } = useStore()
  const nLive = beacons.filter((b) => b.status === 'LIVE').length

  return (
    <div className="w-[218px] flex-shrink-0 bg-surface-card border-r border-surface-border flex flex-col h-full">
      {/* Logo area */}
      <div className="h-12 flex items-center px-4 border-b border-surface-border flex-shrink-0">
        <span className="text-sm font-bold tracking-widest text-phantom-red">PHANTOM</span>
        {nLive > 0 && (
          <span className="ml-auto text-[10px] px-1.5 py-0.5 rounded bg-phantom-green/20 text-phantom-green font-medium">
            {nLive} live
          </span>
        )}
      </div>

      {/* Navigation sections */}
      <div className="flex-1 overflow-auto py-2">
        {SECTIONS.map((section) => (
          <div key={section.label}>
            <div className="px-4 py-1.5 text-[9px] font-semibold text-text-dim uppercase tracking-[0.15em]">
              {section.label}
            </div>
            {section.items.map((item) => {
              const Icon = item.icon
              const isActive = activeTab === item.id
              return (
                <button
                  key={item.id}
                  onClick={() => setActiveTab(item.id)}
                  className={`w-full text-left flex items-center justify-between px-4 py-1.5 text-[12px] transition-colors
                    ${isActive
                      ? 'bg-phantom-magenta/10 text-phantom-magenta border-r-2 border-phantom-magenta'
                      : 'text-text-secondary hover:text-text-primary hover:bg-surface-hover border-r-2 border-transparent'
                    }`}
                >
                  <div className="flex items-center gap-2.5 min-w-0">
                    <Icon size={14} className={isActive ? 'text-phantom-magenta' : 'text-text-dim flex-shrink-0'} />
                    <span className="truncate">{item.label}</span>
                  </div>
                  {item.id === 'automode' && autoMode.running && (
                    <span className="flex-shrink-0 relative flex h-2 w-2 ml-2">
                      <span className="animate-ping absolute inline-flex h-full w-full rounded-full bg-phantom-magenta opacity-75"></span>
                      <span className="relative inline-flex rounded-full h-2 w-2 bg-phantom-magenta"></span>
                    </span>
                  )}
                </button>
              )
            })}
          </div>
        ))}
      </div>

      {/* Footer */}
      <div className="px-4 py-2 border-t border-surface-border flex-shrink-0">
        <span className="text-[9px] text-text-dim">v3.7.3 · Electron</span>
      </div>
    </div>
  )
}