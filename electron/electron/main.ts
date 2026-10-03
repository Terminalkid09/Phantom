import { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage, dialog, session } from 'electron'
import { spawn, ChildProcess } from 'child_process'
import path from 'path'
import fs from 'fs'
import { checkEndpoint } from './endpoint_allowlist'
const { existsSync } = fs
let mainWindow: BrowserWindow | null = null
let apiProcess: ChildProcess | null = null
let tray: Tray | null = null
let pmSavedOnQuit = false

const API_PORT = 9876
const isDev = !app.isPackaged || process.env.NODE_ENV === 'development'

/** App icon path: works in dev (electron/assets) and packaged (asar —
 *  electron-builder ships electron/assets/icon256.png per the files list,
 *  and __dirname/../assets resolves inside the archive). */
function iconPath(): string | undefined {
  const candidates = [
    // Packaged: electron-builder ships electron/assets/* into resources/
    path.join(process.resourcesPath || '', 'assets', 'icon256.png'),
    path.join(__dirname, '..', 'assets', 'icon256.png'),
    path.join(__dirname, 'assets', 'icon256.png'),
  ]
  for (const p of candidates) {
    try { if (p && existsSync(p)) return p } catch { /* ignore */ }
  }
  return undefined
}

function getApiUrl(): string {
  return `http://127.0.0.1:${API_PORT}`
}

// Content-Security-Policy for the renderer. The UI is a single local
// document that talks ONLY to the loopback API; it must never load remote
// script/font/style. Self-hosted fonts (public/ + @fontsource) mean no
// fonts.gstatic.com exception is needed. Vite's dev server injects the React
// refresh preamble as an inline script, so `script-src` loosens to
// 'unsafe-inline' in dev only — the packaged build stays strict. The same
// policy is emitted as a <meta> tag for the packaged build by the custom
// Vite plugin (vite.config.ts), because webRequest.onHeadersReceived does
// not fire for the file:// document load.
function buildCsp(): string {
  const scriptSrc = isDev ? "'self' 'unsafe-inline'" : "'self'"
  const connectSrc = isDev
    ? "'self' http://127.0.0.1:9876 http://localhost:5173 ws://localhost:5173"
    : "'self' http://127.0.0.1:9876"
  return [
    "default-src 'self'",
    `script-src ${scriptSrc}`,
    "style-src 'self' 'unsafe-inline'",
    "img-src 'self' data: blob:",
    "font-src 'self' data:",
    "media-src 'self' blob: data:",
    `connect-src ${connectSrc}`,
    "object-src 'none'",
    "base-uri 'self'",
    "form-action 'none'",
    "frame-ancestors 'none'",
  ].join('; ')
}

/** Read the auto-generated API token (state file → env override).
 *
 * The state file is the SOURCE OF TRUTH: the Electron-spawned backend resolves
 * its token from the same per-user file (PHANTOM_DATA_DIR points there), so
 * both sides always agree. Inheriting a stray PHANTOM_API_TOKEN from the
 * parent shell (a common footgun when launching from a terminal that ran
 * tests) must NOT desync the two processes — that mismatch was producing 401
 * on every renderer fetch. The env var remains honored only as a last-resort
 * fallback for custom deployments.
 */
function getApiToken(): string {
  try {
    const statePath = path.join(app.getPath('userData'), 'data', 'phantom_state.json')
    const state = JSON.parse(fs.readFileSync(statePath, 'utf-8'))
    const fromState = state.PHANTOM_API_TOKEN
    if (fromState) return fromState
  } catch { /* fall through to env */ }
  return process.env.PHANTOM_API_TOKEN || ''
}

// C-1: append-only audit of mutating IPC calls. Kept in main (the renderer
// never sees it) and best-effort — an audit write must never break the UI.
function auditIpc(method: string, endpoint: string): void {
  try {
    const line = `${new Date().toISOString()} ${method.toUpperCase()} ${endpoint}\n`
    const dir = app.getPath('userData')
    if (!existsSync(dir)) return
    fs.appendFileSync(path.join(dir, 'ipc_audit.log'), line)
  } catch { /* best-effort */ }
}

// Backend readiness gate: the renderer fires its first fetches while the
// Python backend is still bootstrapping (2-4s) — without this gate every
// panel starts with "TypeError: fetch failed" until the user refreshes.
let apiReadyPromise: Promise<boolean> | null = null

function waitForApiReady(timeoutMs = 20000): Promise<boolean> {
  if (apiReadyPromise) return apiReadyPromise
  apiReadyPromise = (async () => {
    const deadline = Date.now() + timeoutMs
    while (Date.now() < deadline) {
      if (!apiProcess) return false
      try {
        const controller = new AbortController()
        const t = setTimeout(() => controller.abort(), 1200)
        const res = await fetch(`${getApiUrl()}/api/session`, {
          signal: controller.signal,
        })
        clearTimeout(t)
        // ANY http answer (even 401) means the server is up — auth is
        // applied by the caller; readiness only needs a listener.
        if (res.status > 0) return true
      } catch { /* not up yet */ }
      await new Promise((r) => setTimeout(r, 350))
    }
    return false
  })()
  return apiReadyPromise
}

function startApiServer(): void {
  const projectRoot = path.resolve(__dirname, '..', '..')
  const dataDir = path.join(app.getPath('userData'), 'data')
  const packagedBackend = path.join(
    process.resourcesPath,
    'backend',
    process.platform === 'win32' ? 'phantom-backend.exe' : 'phantom-backend',
  )

  const command = isDev ? (process.platform === 'win32' ? 'python' : 'python3') : packagedBackend
  const args = isDev
    ? ['-u', path.join(projectRoot, 'phantom', 'api', 'launcher.py'), '--port', String(API_PORT)]
    : ['--port', String(API_PORT)]
  const cwd = isDev ? projectRoot : path.dirname(packagedBackend)

  console.log(`[main] Starting API server: ${command} ${args.join(' ')}`)
  console.log(`[main] backend exists: ${existsSync(command)} (packaged=${!isDev})`)

  try {
    apiProcess = spawn(command, args, {
      cwd,
      env: {
        ...process.env,
        PYTHONUNBUFFERED: '1',
        PHANTOM_DATA_DIR: dataDir,
      },
      stdio: ['pipe', 'pipe', 'pipe'],
    })
  } catch (err) {
    console.error('[main] API spawn FAILED:', err)
    mainWindow?.webContents.send('api-status', { state: 'error', detail: String(err) })
    return
  }

  // spawn() errors arrive ASYNC (ENOENT etc.) — surface them instead of
  // leaving the UI talking to a server that will never exist.
  apiProcess.on('error', (err) => {
    console.error('[main] API process error:', err)
    mainWindow?.webContents.send('api-status', { state: 'error', detail: String(err) })
  })

  apiProcess.stdout?.on('data', (data: Buffer) => {
    console.log(`[api] ${data.toString().trim()}`)
  })

  apiProcess.stderr?.on('data', (data: Buffer) => {
    console.error(`[api:err] ${data.toString().trim()}`)
  })

  apiProcess.on('close', (code: number | null) => {
    console.log(`[main] API server exited with code ${code}`)
    apiProcess = null
    apiReadyPromise = null
    mainWindow?.webContents.send('api-status', { state: 'exited', code })
  })
}

function stopApiServer(): void {
  if (apiProcess) {
    console.log('[main] Stopping API server...')
    apiProcess.kill('SIGTERM')
    apiProcess = null
  }
}

function createWindow(): void {
  mainWindow = new BrowserWindow({
    width: 1400,
    height: 900,
    minWidth: 1100,
    minHeight: 700,
    title: 'Phantom',
    backgroundColor: '#0D1117',
    icon: iconPath(),
    webPreferences: {
      preload: path.join(__dirname, 'preload.js'),
      nodeIntegration: false,
      contextIsolation: true,
      // A-3: the preload is CJS and imports ONLY `electron`
      // (contextBridge + ipcRenderer), both available in a sandboxed
      // preload — so the renderer can run inside the OS sandbox like any
      // other browser process. Set PHANTOM_ELECTRON_NO_SANDBOX=1 if a
      // future preload needs Node APIs (then the IPC allowlist in
      // endpoint_allowlist.ts stays the compensating control).
      sandbox: process.env.PHANTOM_ELECTRON_NO_SANDBOX !== '1'
    },
    // NATIVE window frame on every platform: standard minimize / maximize /
    // close buttons + OS resize snapping. (The old frame:false + hiddenInset
    // removed all window controls — the "app without an X button" bug.)
    titleBarStyle: 'default',
    frame: true,
  })

  // A-3: the renderer never opens windows and never navigates away — the
  // UI is a single local document. Any attempt is dropped (defense in
  // depth for a compromised renderer: no phishing window, no remote page
  // inheriting this window's privileges).
  mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }))
  mainWindow.webContents.on('will-navigate', (event, url) => {
    const allowed = isDev ? url.startsWith('http://localhost:5173') : false
    if (!allowed) {
      event.preventDefault()
    }
  })

  if (isDev) {
    mainWindow.loadURL('http://localhost:5173')
    mainWindow.webContents.openDevTools({ mode: 'detach' })
  } else {
    mainWindow.loadFile(path.join(__dirname, '..', 'dist', 'index.html'))
  }

  mainWindow.on('closed', () => {
    mainWindow = null
  })
}

function createTray(): void {
  // Real app icon (also used for the window + installer): falls back to a
  // transparent stub when the asset is missing (dev without assets).
  const p = iconPath()
  const icon = p
    ? nativeImage.createFromPath(p)
    : nativeImage.createEmpty()
  tray = new Tray(icon.resize({ width: 16, height: 16 }))
  const contextMenu = Menu.buildFromTemplate([
    { label: 'Show Phantom', click: () => mainWindow?.show() },
    { type: 'separator' },
    { label: 'Quit', click: () => app.quit() }
  ])
  tray.setToolTip('Phantom Framework')
  tray.setContextMenu(contextMenu)
  tray.on('double-click', () => mainWindow?.show())
}

app.whenReady().then(() => {
  // CSP on every response of the default session (dev http server + any
  // fetch). Packaged file:// loads are covered by the <meta> tag in the
  // built index.html; this header keeps dev honest against the same policy.
  session.defaultSession.webRequest.onHeadersReceived((details, callback) => {
    const headers = details.responseHeaders ?? {}
    const existing = Object.keys(headers).find((k) => k.toLowerCase() === 'content-security-policy')
    if (existing) {
      callback({ responseHeaders: headers })
      return
    }
    callback({ responseHeaders: { ...headers, 'Content-Security-Policy': [buildCsp()] } })
  })

  startApiServer()
  createWindow()
  createTray()

  ipcMain.handle('get-api-url', () => getApiUrl())

  ipcMain.handle('api-request', async (_event, method: string, endpoint: string, body?: unknown) => {
    // P1-13: the renderer can only reach endpoints on the explicit
    // allowlist — a compromised renderer/dependency cannot fan out to
    // arbitrary backend routes (the bearer token never left main, but
    // authorization-by-network-position is not a boundary)
    const verdict = checkEndpoint(method, endpoint)
    if (!verdict.allowed) {
      return { status: 403, data: { error: verdict.reason ?? 'endpoint not allowlisted' } }
    }
    // C-1: the allowlist already told us whether this is a read or a write.
    // Mutating calls get an audit line; DESTRUCTIVE ones additionally need
    // an operator confirmation, so a compromised renderer cannot burn the
    // engagement (kill the listener, revoke identities, rotate secrets)
    // without a human in the loop.
    if (verdict.group === 'mutating') {
      auditIpc(method, endpoint)
    }
    if (verdict.confirm) {
      const parent = BrowserWindow.getFocusedWindow() ?? mainWindow
      const opts = {
        type: 'warning' as const,
        buttons: ['Cancel', 'Proceed'],
        defaultId: 0,
        cancelId: 0,
        title: 'Confirm destructive action',
        message: `${method} ${endpoint}`,
        detail: 'This changes C2/session state and may be irreversible.'
      }
      const choice = parent
        ? dialog.showMessageBoxSync(parent, opts)
        : dialog.showMessageBoxSync(opts)
      if (choice !== 1) {
        return { status: 499, data: { error: 'cancelled by operator' } }
      }
    }
    const url = `${getApiUrl()}${endpoint}`
    const options: RequestInit = {
      method,
      headers: { 'Content-Type': 'application/json' },
    }
    // First requests of the session wait for the backend to come up
    // instead of failing instantly (the "open app → everything fetch
    // failed → must refresh" bug). After readiness this await is a no-op.
    if (!(await waitForApiReady())) {
      return { status: 0, data: { error: 'backend not reachable (startup timeout)' } }
    }
    // The localhost API is bearer-protected; the token lives in the main
    // process only (the renderer never sees it). Retry once briefly in case
    // the backend has not finished bootstrapping its state file yet.
    let token = getApiToken()
    if (!token) {
      await new Promise((resolve) => setTimeout(resolve, 400))
      token = getApiToken()
    }
    if (token) {
      options.headers = { ...options.headers, Authorization: `Bearer ${token}` }
    }
    if (body && method !== 'GET') {
      options.body = JSON.stringify(body)
    }

    // Long-running module runs (network scans, run-group batches, the
    // automode plan endpoint) legitimately take many minutes. Aborting at
    // 120s surfaced as "AbortError: This operation was aborted" on every
    // panel — give long calls room instead.
    const controller = new AbortController()
    const timeout = setTimeout(() => controller.abort(), 7_200_000)
    options.signal = controller.signal

    try {
      const response = await fetch(url, options)
      clearTimeout(timeout)
      const data = await response.json()
      return { status: response.status, data }
    } catch (err) {
      clearTimeout(timeout)
      return { status: 0, data: { error: String(err) } }
    }
  })

  ipcMain.handle('get-version', () => app.getVersion())

  // ── Save artifact to disk (Recordings / screenshots) ──────────────────
  // The renderer asks WHERE to save; the main process writes the bytes so
  // the renderer never touches fs directly (contextIsolation stays intact).
  ipcMain.handle('save-artifact', async (_event, payload: { name: string; data: string }, dir?: string) => {
    try {
      const win = BrowserWindow.getFocusedWindow() ?? mainWindow
      if (!win) return { saved: false, error: 'no window' }
      const ext = (payload.name.match(/\.[a-z0-9]+$/i) || [''])[0]
      const res = await dialog.showSaveDialog(win, {
        title: 'Save artifact',
        defaultPath: path.join(app.getPath('videos'), payload.name),
        filters: [
          { name: ext === '.mp4' ? 'Video' : 'All files', extensions: [ext.replace('.', '') || '*'] },
        ],
      })
      if (res.canceled || !res.filePath) return { saved: false }
      // dir is an API-relative subdir (recordings, recordings/live, ...);
      // only names coming straight from the artifacts list are accepted.
      // raw=1: WITHOUT it the backend answers the base64 JSON envelope and we
      // would write that JSON into an .mp4 — the artifact must be fetched as
      // raw bytes.
      let url = `/api/c2/artifact?raw=1&name=${encodeURIComponent(payload.name)}`
      if (dir) url += `&dir=${encodeURIComponent(dir)}`
      const token = getApiToken()
      const r = await fetch(`${getApiUrl()}${url}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!r.ok) return { saved: false, error: `fetch ${r.status}` }
      const buf = Buffer.from(await r.arrayBuffer())
      fs.writeFileSync(res.filePath, buf)
      return { saved: true, path: res.filePath }
    } catch (err) {
      return { saved: false, error: String(err) }
    }
  })

  // ── Auto-save artifact to the Desktop (setting-driven) ────────────────
  // Same byte path as save-artifact, but with NO dialog: the renderer only
  // calls this when the "Save recordings to disk" preference is ON, so a
  // finished recording lands in ~/Desktop/Phantom Recordings.
  ipcMain.handle('save-artifact-auto', async (_event, payload: { name: string; data: string }, dir?: string) => {
    try {
      if (!payload?.name || payload.name.includes('/') || payload.name.includes('\\')) {
        return { saved: false, error: 'invalid name' }
      }
      const destDir = path.join(app.getPath('desktop'), 'Phantom Recordings')
      fs.mkdirSync(destDir, { recursive: true })
      // raw=1: save the artifact BYTES, not the base64 JSON envelope.
      let url = `/api/c2/artifact?raw=1&name=${encodeURIComponent(payload.name)}`
      if (dir) url += `&dir=${encodeURIComponent(dir)}`
      const token = getApiToken()
      const r = await fetch(`${getApiUrl()}${url}`, {
        headers: token ? { Authorization: `Bearer ${token}` } : {},
      })
      if (!r.ok) return { saved: false, error: `fetch ${r.status}` }
      const buf = Buffer.from(await r.arrayBuffer())
      const filePath = path.join(destDir, payload.name)
      fs.writeFileSync(filePath, buf)
      return { saved: true, path: filePath }
    } catch (err) {
      return { saved: false, error: String(err) }
    }
  })

  app.on('activate', () => {
    if (BrowserWindow.getAllWindows().length === 0) createWindow()
  })
})

app.on('window-all-closed', () => {
  if (process.platform !== 'darwin') {
    stopApiServer()
    app.quit()
  }
})

app.on('before-quit', async (event) => {
  // Auto-save the engagement as a .pm bundle on close (fire-and-forget:
  // the backend mirrors the live session to _auto.json regardless, this
  // adds the full portable bundle on top).
  if (!pmSavedOnQuit) {
    pmSavedOnQuit = true
    try {
      const token = getApiToken()
      const controller = new AbortController()
      const t = setTimeout(() => controller.abort(), 2500)
      await fetch(`${getApiUrl()}/api/pm/export`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json',
          ...(token ? { Authorization: `Bearer ${token}` } : {}),
        },
        body: JSON.stringify({}),
        signal: controller.signal,
      })
      clearTimeout(t)
    } catch { /* best effort — quit anyway */ }
  }
  stopApiServer()
})