import { defineConfig } from '@playwright/test'

export default defineConfig({
  testDir: './tests/e2e',
  // One test walks all 25 panels, runs a safe action in each and waits for
  // the busy pill to settle: app boot + 25 real backend round trips.
  timeout: 240_000,
  expect: { timeout: 20_000 },
  fullyParallel: false,
  workers: 1,
  reporter: process.env.CI ? 'list' : 'line',
  use: {
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
  },
  webServer: {
    command: 'npm run dev',
    // A dedicated E2E port: an orphan Vite from a previous run (or the
    // developer's own dev server) must not be mistaken for this test's app.
    url: 'http://127.0.0.1:5199',
    reuseExistingServer: false,
    timeout: 120_000,
    env: { ...process.env, PHANTOM_DEV_PORT: '5199' },
  },
})
