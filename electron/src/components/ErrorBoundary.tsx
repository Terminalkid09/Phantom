import { Component, Fragment, type ErrorInfo, type ReactNode } from 'react'

interface Props {
  /** Panel name, shown in the fallback so the operator knows WHICH panel failed. */
  label: string
  children: ReactNode
}

interface State {
  error: Error | null
  /** Bumped by Retry to force a fresh mount of the subtree. */
  attempt: number
}

/**
 * Per-panel error boundary.
 *
 * Every panel is mounted at boot (see App.tsx) so switching tabs never wipes
 * local state — a scan, a craft output, an auto-mode view all survive
 * navigation. The cost of that trade is that an exception in ANY panel
 * unmounts the WHOLE tree: the operator gets a blank window and no clue which
 * feature died.
 *
 * That is not hypothetical. `payload?.pivots.length` in the social panel —
 * an optional chain that guards `payload` but not `pivots` — threw the moment
 * the API answered anything other than the expected shape (a 404 body, an
 * error object), and the packaged app never rendered at all: `<div id="root">`
 * stayed empty and the only trace was a minified stack in the devtools
 * console.
 *
 * The contract here: a panel that throws loses ITSELF, not the shell. The
 * fallback names the panel and prints the message, because a blank window is
 * not a diagnosis. Retry re-mounts the subtree, which is the honest recovery
 * for a panel whose fault was a bad response that a refresh may fix.
 */
export default class ErrorBoundary extends Component<Props, State> {
  state: State = { error: null, attempt: 0 }

  static getDerivedStateFromError(error: Error): Partial<State> {
    return { error }
  }

  componentDidCatch(error: Error, info: ErrorInfo): void {
    // The message is on screen already; this is the console/devtools trail.
    console.error(`[panel:${this.props.label}] crashed`, error, info.componentStack)
  }

  render(): ReactNode {
    const { error, attempt } = this.state
    if (!error) {
      // key={attempt}: React treats a new key as a new subtree, so Retry
      // remounts the panel instead of re-rendering a broken state object.
      return <Fragment key={attempt}>{this.props.children}</Fragment>
    }
    return (
      <div className="h-full flex items-center justify-center p-6">
        <div className="max-w-lg w-full rounded border border-phantom-error/40 bg-phantom-error/5 p-4 space-y-2">
          <p className="text-sm font-semibold text-phantom-error">
            The {this.props.label} panel stopped
          </p>
          <p className="text-xs text-text-secondary">
            The rest of the app is unaffected. A panel-level fault means the
            data this panel renders did not arrive in the shape it expects —
            usually a backend that answered with an error body.
          </p>
          <pre className="text-[11px] font-mono text-text-dim whitespace-pre-wrap break-all">
            {error.message}
          </pre>
          <button
            onClick={() =>
              this.setState((s) => ({ error: null, attempt: s.attempt + 1 }))
            }
            className="px-2.5 py-1.5 rounded text-xs bg-surface text-text-secondary border border-surface-border hover:text-text-primary"
          >
            Retry
          </button>
        </div>
      </div>
    )
  }
}
