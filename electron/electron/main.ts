import { app, BrowserWindow, ipcMain, Tray, Menu, nativeImage } from 'electron'
import { spawn, ChildProcess } from 'child_process'
import path from 'path'
import fs from 'fs'
const { existsSync } = fs
let mainWindow: BrowserWindow | null = null
let apiProcess: ChildProcess | null = null
let tray: Tray | null = null

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
      sandbox: false
    },
    // NATIVE window frame on every platform: standard minimize / maximize /
    // close buttons + OS resize snapping. (The old frame:false + hiddenInset
    // removed all window controls — the "app without an X button" bug.)
    titleBarStyle: 'default',
    frame: true,
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
  startApiServer()
  createWindow()
  createTray()

  ipcMain.handle('get-api-url', () => getApiUrl())

  ipcMain.handle('api-request', async (_event, method: string, endpoint: string, body?: unknown) => {
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

app.on('before-quit', () => {
  stopApiServer()
})