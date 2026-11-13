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
  const card = `relative flex w-80 flex-col gap-1 rounded-lg border bg-surface-card p-4 text-sm ${borderColors[toast.type]} ${glowColors[toast.type]} animate-step-enter`
  const body = (
    <div className="flex items-start justify-between gap-3">
      <div className="mt-0.5" aria-hidden="true">{icons[toast.type]}</div>
      <div className="flex-1">
        <h3 className="font-medium text-text-primary">{toast.title}</h3>
        {toast.description && (
          <p className="mt-1 text-xs text-text-secondary">{toast.description}</p>
        )}
      </div>
      <button
        onClick={() => removeToast(toast.id)}
        aria-label={`Dismiss notification: ${toast.title}`}
        className="text-text-secondary hover:text-text-primary transition-colors"
      >
        <X className="h-4 w-4" aria-hidden="true" />
      </button>
    </div>
  )

  // An error interrupts (role=alert); anything else waits its turn (status).
  // Spelled out as two branches rather than a computed attribute so the live
  // semantics stay visible in the source — the a11y contract test reads them.
  return toast.type === 'error' ? (
    <div role="alert" aria-live="assertive" aria-atomic="true" className={card}>
      {body}
    </div>
  ) : (
    <div role="status" aria-live="polite" aria-atomic="true" className={card}>
      {body}
    </div>
  )
}

export function ToastContainer() {
  const toasts = useStore((s) => s.toasts)

  return (
    <div
      role="region"
      aria-label="Notifications"
      className="fixed bottom-4 right-4 z-50 flex flex-col gap-3 pointer-events-none"
    >
      {toasts.map((toast) => (
        <div key={toast.id} className="pointer-events-auto">
          <Toast toast={toast} />
        </div>
      ))}
    </div>
  )
}
