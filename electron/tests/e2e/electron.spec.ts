import { appendFileSync, mkdirSync } from 'node:fs'
import { test, expect, _electron as electron, type Locator, type Page } from '@playwright/test'

// Playwright wipes test-results/ at startup: keep the live progress log
// outside it or the file disappears under a running test.
const PROGRESS = 'pw-progress.log'
mkdirSync('test-results', { recursive: true })
function progress(message: string): void {
  appendFileSync(PROGRESS, `${new Date().toISOString()} ${message}\n`)
}

/**
 * The Electron shell contract: every advertised panel mounts, the sidebar
 * navigates to it, a panel-level crash is visible instead of blanking the
 * window, and every safe panel action shows visible "working" feedback while
 * its backend request is in flight.
 *
 * This runs the REAL main process, the REAL Python API and the REAL panel
 * components (no mocked renderer), so it also catches IPC/timeout regressions
 * that a component test would miss.
 */

type ActionSpec = {
  name: string | RegExp
  /** Optional operator-like setup that must happen before the action. */
  setup?: (panel: Locator) => Promise<void>
}

/**
 * One safe, read-only (or plan-only) action per panel. These are deliberately
 * actions an operator can click at any time: refresh/list, generate a report,
 * plan a dry run. Destructive controls (reset, kill, launch) are excluded.
 */
const PANEL_ACTIONS: Record<string, ActionSpec> = {
  c2: { name: 'Refresh beacon list' },
  session: {
    name: 'Refresh core knowledge',
    setup: async (panel) => {
      // Auto-mode's dry run is disabled until the shared session has a target.
      // Persist through the real input; the dry-run button becoming enabled is
      // the end-to-end proof that the backend accepted it. Do not assert the
      // transient inline "target saved" text: a second blur-triggered save can
      // legitimately replace it before the assertion polls.
      const target = panel.getByLabel('Target', { exact: true })
      await target.fill('192.0.2.10')
      await target.press('Enter')
      await expect(target).toHaveValue('192.0.2.10')
    },
  },
  automode: { name: /Dry run/ },
  reports: { name: /Generate Report/i },
  settings: { name: 'Reload the guardrail manifest' },
  timeline: { name: 'Reload the timeline' },
  vault: { name: 'Refresh vault entries' },
  network: { name: 'Reload the network map' },
  audit: { name: 'Refresh audit log' },
  recordings: { name: /^Refresh$/ },
  bundles: { name: 'Refresh the bundle list' },
  learning: { name: 'Refresh learning memory' },
  adgraph: { name: 'Refresh the AD graph' },
  social: { name: 'Refresh the identity graph' },
  scan: { name: /Refresh this module/ },
  web: { name: /Refresh this module/ },
  exploit: { name: /Refresh this module/ },
  brute: { name: /Refresh this module/ },
  osint: { name: /Refresh this module/ },
  wifi: { name: /Refresh this module/ },
  payload: { name: /Refresh this module/ },
  pivot: { name: /Refresh this module/ },
  handler: { name: /Refresh this module/ },
  analyzer: { name: /Refresh this module/ },
  wordlist: { name: /Refresh this module/ },
}

async function waitForIdle(page: Page): Promise<void> {
  await expect(page.getByTestId('global-activity')).toBeHidden({ timeout: 20_000 })
}

test('all 25 panels render, navigate, and show busy UX for safe actions', async () => {
  const app = await electron.launch({
    args: ['.'],
    env: {
      ...process.env,
      PHANTOM_E2E: '1',
      PHANTOM_DEV_PORT: '5199',
      NODE_ENV: 'development',
    },
  })
  const pageErrors: string[] = []
  const feedbackFailures: string[] = []
  try {
    // DevTools (when a real dev session leaves it open) is another window;
    // never assert against it. Under PHANTOM_E2E the app is the only window.
    const page = await app.firstWindow()
    expect(page.url()).toMatch(/^http:\/\/(localhost|127\.0\.0\.1):5199\//)
    page.on('pageerror', (error) => pageErrors.push(error.message))

    const nav = page.locator('nav[aria-label="Panels"]')
    await expect(nav).toBeVisible({ timeout: 60_000 })

    const buttons = nav.locator('button')
    await expect(buttons).toHaveCount(25)
    const count = await buttons.count()
    expect(count).toBe(25)
    // Snapshot the labels ONCE: reading each button lazily raced a backend
    // lifecycle re-render and turned a clear panel failure into a confusing
    // selector timeout.
    const labels = await buttons.allTextContents()

    const activity = page.getByTestId('global-activity')
    const main = page.locator('main[aria-label]')

    for (let i = 0; i < count; i += 1) {
      const button = buttons.nth(i)
      const label = labels[i]?.trim() || `panel-${i}`
      progress(`nav ${i} ${label}`)
      await button.click()
      await expect(button).toHaveAttribute('aria-current', 'page')
      await expect(main).toHaveAttribute('aria-label', /^Phantom panel: /)
      // A panel that throws is replaced by its ErrorBoundary, which names the
      // panel and says "stopped". The shell must never show that fallback.
      await expect(page.getByText(`The ${label} panel stopped`)).toHaveCount(0)

      const activeLabel = await main.getAttribute('aria-label')
      const panelId = activeLabel?.replace('Phantom panel: ', '') ?? ''
      const panel = page.locator(`[data-panel="${panelId}"]`)
      await expect(panel).toBeVisible()
      const spec = PANEL_ACTIONS[panelId]
      if (!spec) {
        feedbackFailures.push(`${panelId}: no safe UX action declared`)
        continue
      }

      try {
        progress(`  idle-before ${panelId}`)
        await waitForIdle(page)
        if (spec.setup) {
          progress(`  setup ${panelId}`)
          await spec.setup(panel)
          await waitForIdle(page)
        }
        const action = panel.getByRole('button', { name: spec.name }).first()
        await expect(action).toBeVisible({ timeout: 10_000 })
        await expect(action).toBeEnabled({ timeout: 15_000 })
        progress(`  click ${panelId}`)
        await action.click({ timeout: 15_000 })

        // The UX promise: the click is acknowledged immediately, not only
        // when the answer arrives. The global pill is the shell-wide
        // guarantee; aria-busy on <main> exposes the same state to AT.
        await expect(activity).toBeVisible({ timeout: 5_000 })
        await expect(activity).toHaveAttribute('aria-busy', 'true')
        await expect(main).toHaveAttribute('aria-busy', 'true')
        await expect(activity).toContainText(/Working/)
        // The generic IPC race is 30 s; let the pill finish before calling
        // it stuck. A poll that exceeds it is a separate backend defect.
        await expect(activity).toBeHidden({ timeout: 40_000 })
        await expect(main).toHaveAttribute('aria-busy', 'false')
        progress(`  ok ${panelId}`)
      } catch (error) {
        progress(`  FAIL ${panelId}: ${(error as Error).message.split('\n')[0]}`)
        feedbackFailures.push(
          `${panelId}: ${(error as Error).message.split('\n')[0]}`,
        )
      }
    }

    expect(
      feedbackFailures,
      `panels without measurable busy feedback:\n${feedbackFailures.join('\n')}`,
    ).toEqual([])
    expect(pageErrors, `uncaught renderer errors: ${pageErrors.join('\n')}`).toEqual([])
  } finally {
    // A dev Electron app can hold its Python backend (and the test process)
    // after the assertions are done. Force the Electron main process to exit;
    // `app.close()` waits for a graceful quit that can take minutes.
    try {
      await Promise.race([
        app.evaluate(({ app }) => app.exit(0)).catch(() => undefined),
        new Promise<void>((resolve) => setTimeout(resolve, 5_000)),
      ])
    } catch {
      /* already gone */
    }
    try {
      if (app.process().exitCode === null) app.process().kill('SIGKILL')
    } catch {
      /* already gone */
    }
  }
})
