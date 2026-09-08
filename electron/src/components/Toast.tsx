import React from 'react'
import { Toast as ToastType, useStore } from '../store'
import { AlertCircle, CheckCircle, Info, XCircle, X } from 'lucide-react'

const icons = {
  info: <Info className="w-5 h-5 text-phantom-cyan" />,
  success: <CheckCircle className="w-5 h-5 text-phantom-green" />,
  warning: <AlertCircle className="w-5 h-5 text-phantom-yellow" />,
  error: <XCircle className="w-5 h-5 text-phantom-error" />
}

const borderColors = {
  info: 'border-phantom-cyan',
  success: 'border-phantom-green',
  warning: 'border-phantom-yellow',
  error: 'border-phantom-error'
}

const glowColors = {
  info: 'shadow-[0_0_10px_rgba(0,240,255,0.2)]',
  success: 'shadow-[0_0_10px_rgba(0,255,157,0.2)]',
  warning: 'shadow-[0_0_10px_rgba(255,214,0,0.2)]',
  error: 'shadow-[0_0_10px_rgba(255,51,51,0.2)]'
}

export function Toast({ toast }: { toast: ToastType }) {
  const removeToast = useStore((s) => s.removeToast)

  return (
    <div
      className={`relative flex w-80 flex-col gap-1 rounded-lg border bg-surface-card p-4 text-sm ${borderColors[toast.type]} ${glowColors[toast.type]} animate-step-enter`}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="mt-0.5">{icons[toast.type]}</div>
        <div className="flex-1">
          <h3 className="font-medium text-text-primary">{toast.title}</h3>
          {toast.description && (
            <p className="mt-1 text-xs text-text-secondary">{toast.description}</p>
          )}
        </div>
        <button
          onClick={() => removeToast(toast.id)}
          className="text-text-secondary hover:text-text-primary transition-colors"
        >
          <X className="h-4 w-4" />
        </button>
      </div>
    </div>
  )
}

export function ToastContainer() {
  const toasts = useStore((s) => s.toasts)

  return (
    <div className="fixed bottom-4 right-4 z-50 flex flex-col gap-3 pointer-events-none">
      {toasts.map((toast) => (
        <div key={toast.id} className="pointer-events-auto">
          <Toast toast={toast} />
        </div>
      ))}
    </div>
  )
}
