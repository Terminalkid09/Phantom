import { useState } from 'react'
import { useStore } from '@/store'
import { useApi } from '@/hooks/useApi'
import {
  FileText, Download, Eye, FileJson, FileCode,
  FileType, Shield, UserCheck, Clock, Layers, Archive
} from 'lucide-react'

interface ReportStatus {
  raw: string | null
  client: string | null
  raw_path: string | null
  client_path: string | null
  generated_at: string | null
}

export default function ReportsPanel() {
  const { session } = useStore()
  const { api } = useApi()
  const [report, setReport] = useState<ReportStatus>({
    raw: null, client: null, raw_path: null, client_path: null, generated_at: null
  })
  const [generating, setGenerating] = useState(false)
  const [format, setFormat] = useState<'json' | 'html' | 'pdf'>('html')

  const handleGenerate = async () => {
    setGenerating(true)
    const res = await api('POST', '/api/reports/generate', {
      format
    })
    setGenerating(false)

    if (res.status === 200 && res.data) {
      const d = res.data as ReportStatus
      setReport(d)
    }
  }

  const handleExport = async (type: 'raw' | 'client') => {
    const path = type === 'raw' ? report.raw_path : report.client_path
    if (!path) return
    await api('POST', '/api/reports/export', { path, type })
  }

  const handleExportAll = async () => {
    setGenerating(true)
    const res = await api('POST', '/api/reports/export-all', { format })
    setGenerating(false)
    if (res.status === 200 && res.data) {
      setReport({
        raw: null, client: null,
        raw_path: (res.data as { raw_path: string }).raw_path,
        client_path: (res.data as { client_path: string }).client_path,
        generated_at: (res.data as { generated_at: string }).generated_at
      })
    }
  }

  const handleExportCampaign = async () => {
    setGenerating(true)
    const res = await api('POST', '/api/export-campaign')
    setGenerating(false)
    if (res.status === 200 && res.data) {
      const d = res.data as { path: string; size: number }
      setReport({
        raw: null, client: null,
        raw_path: d.path, client_path: '',
        generated_at: new Date().toISOString()
      })
    }
  }

  return (
    <div className="p-4 flex flex-col gap-4 h-full">
      <div>
        <h1 className="text-lg font-bold text-text-primary flex items-center gap-2">
          <FileText size={19} className="text-phantom-green" /> Reports
        </h1>
        <p className="text-xs text-text-dim mt-0.5">Generate professional audit and client reports</p>
      </div>

      <div className="flex gap-4 flex-1 min-h-0">
        {/* Left — controls */}
        <div className="w-[320px] flex-shrink-0 flex flex-col gap-3">
          {/* Generate */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-3">
              Generate Report
            </h2>
            <div className="space-y-2.5">
              <div>
                <label className="text-[10px] text-text-dim block mb-1">Format</label>
                <div className="flex gap-1.5">
                  {(['json', 'html', 'pdf'] as const).map((f) => (
                    <button
                      key={f}
                      onClick={() => setFormat(f)}
                      className={`flex-1 py-1.5 rounded text-xs font-medium transition-colors
                        ${format === f
                          ? 'bg-phantom-green/20 text-phantom-green border border-phantom-green/50'
                          : 'bg-surface text-text-secondary hover:bg-surface-hover border border-surface-border'
                        }`}
                    >
                      {f.toUpperCase()}
                    </button>
                  ))}
                </div>
              </div>

              <button
                onClick={handleGenerate}
                disabled={generating}
                className={`w-full py-2 rounded text-xs font-semibold uppercase tracking-wider
                  flex items-center justify-center gap-2 transition-colors
                  ${generating
                    ? 'bg-surface-border text-text-dim cursor-not-allowed'
                    : 'bg-phantom-green/20 text-phantom-green hover:bg-phantom-green/30'
                  }`}
              >
                {generating ? (
                  <span className="animate-pulse">Generating...</span>
                ) : (
                  <><FileText size={13} /> Generate Report</>
                )}
              </button>

              <button
                onClick={handleExportAll}
                disabled={generating}
                className={`w-full py-2 rounded text-xs font-semibold uppercase tracking-wider
                  flex items-center justify-center gap-2 transition-colors
                  ${generating
                    ? 'bg-surface-border text-text-dim cursor-not-allowed'
                    : 'bg-phantom-magenta/20 text-phantom-magenta hover:bg-phantom-magenta/30'
                  }`}
              >
                <Layers size={13} /> Export All (Raw + Client)
              </button>

              <button
                onClick={handleExportCampaign}
                disabled={generating}
                className={`w-full py-2 rounded text-xs font-semibold uppercase tracking-wider
                  flex items-center justify-center gap-2 transition-colors
                  ${generating
                    ? 'bg-surface-border text-text-dim cursor-not-allowed'
                    : 'bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30'
                  }`}
              >
                <Archive size={13} /> Export Campaign ZIP
              </button>
            </div>
          </div>

          {/* Report types info */}
          <div className="bg-surface-card border border-surface-border rounded-lg p-3">
            <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider mb-2">
              Report Types
            </h2>
            <div className="space-y-2.5">
              <div className="flex items-start gap-2">
                <Shield size={14} className="text-phantom-red mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-xs font-medium text-text-primary">Raw Audit Report</p>
                  <p className="text-[10px] text-text-dim">
                    Full technical details — vulnerabilities, exploited CVEs, beacon logs, credentials found.
                    For the red teamer.
                  </p>
                </div>
              </div>
              <div className="flex items-start gap-2">
                <UserCheck size={14} className="text-phantom-cyan mt-0.5 flex-shrink-0" />
                <div>
                  <p className="text-xs font-medium text-text-primary">Client Report</p>
                  <p className="text-[10px] text-text-dim">
                    Sanitized executive summary — business impact, risk scores, remediation steps.
                    Ready for the client.
                  </p>
                </div>
              </div>
            </div>
          </div>
        </div>

        {/* Right — preview */}
        <div className="flex-1 flex flex-col gap-3 min-w-0">
          {/* Raw report preview */}
          <div className="bg-surface-card border border-surface-border rounded-lg flex-1 flex flex-col min-h-0">
            <div className="px-3 py-2 border-b border-surface-border flex items-center justify-between">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <Shield size={13} className="text-phantom-red" /> Raw Audit Report
              </h2>
              {report.raw_path && (
                <button
                  onClick={() => handleExport('raw')}
                  className="flex items-center gap-1 px-2 py-1 rounded text-[10px]
                    bg-phantom-red/20 text-phantom-red hover:bg-phantom-red/30 transition-colors"
                >
                  <Download size={11} /> Export
                </button>
              )}
            </div>
            <div className="flex-1 overflow-auto p-3">
              {report.raw ? (
                <pre className="text-xs font-mono text-text-primary whitespace-pre-wrap">{report.raw}</pre>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-text-dim gap-2">
                  <Shield size={32} className="text-text-dim" />
                  <p className="text-xs">No raw report generated yet</p>
                  <p className="text-[10px] text-text-dim">Click "Generate Report" to create one</p>
                </div>
              )}
            </div>
          </div>

          {/* Client report preview */}
          <div className="bg-surface-card border border-surface-border rounded-lg flex-1 flex flex-col min-h-0">
            <div className="px-3 py-2 border-b border-surface-border flex items-center justify-between">
              <h2 className="text-xs font-semibold text-text-secondary uppercase tracking-wider flex items-center gap-1.5">
                <UserCheck size={13} className="text-phantom-cyan" /> Client Report
              </h2>
              {report.client_path && (
                <button
                  onClick={() => handleExport('client')}
                  className="flex items-center gap-1 px-2 py-1 rounded text-[10px]
                    bg-phantom-cyan/20 text-phantom-cyan hover:bg-phantom-cyan/30 transition-colors"
                >
                  <Download size={11} /> Export
                </button>
              )}
            </div>
            <div className="flex-1 overflow-auto p-3">
              {report.client ? (
                <pre className="text-xs font-mono text-text-primary whitespace-pre-wrap">{report.client}</pre>
              ) : (
                <div className="flex flex-col items-center justify-center h-full text-text-dim gap-2">
                  <UserCheck size={32} className="text-text-dim" />
                  <p className="text-xs">No client report generated yet</p>
                  <p className="text-[10px] text-text-dim">Click "Generate Report" to create one</p>
                </div>
              )}
            </div>
          </div>

          {/* Info footer */}
          {report.generated_at && (
            <div className="flex items-center gap-2 text-[10px] text-text-dim px-1">
              <Clock size={11} />
              <span>Generated: {report.generated_at}</span>
              <span className="text-text-dim">·</span>
              <span>{format.toUpperCase()}</span>
            </div>
          )}
        </div>
      </div>
    </div>
  )
}