import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import electron from 'vite-plugin-electron'
import path from 'path'

// Phantom's own dev-server port. 5173 is Vite's default and therefore the
// port every other project on the machine also tries to use; strictPort makes
// a collision fail loudly instead of serving the WRONG app in the Electron
// window.
const DEV_PORT = Number(process.env.PHANTOM_DEV_PORT || 5178)

// Packaged build: the renderer is loaded from file://, where
// webRequest.onHeadersReceived never fires — so the strict CSP must be baked
// into the document as a <meta> tag. Kept in sync with buildCsp() in
// electron/main.ts (which covers the dev http server).
const PACKAGED_CSP = [
  "default-src 'self'",
  "script-src 'self'",
  "style-src 'self' 'unsafe-inline'",
  "img-src 'self' data: blob:",
  "font-src 'self' data:",
  "media-src 'self' blob: data:",
  "connect-src 'self' http://127.0.0.1:9876",
  "object-src 'none'",
  "base-uri 'self'",
  "form-action 'none'",
].join('; ')

function cspMetaPlugin(): Plugin {
  return {
    name: 'phantom-csp-meta',
    apply: 'build',
    transformIndexHtml(html) {
      return html.replace(
        '</title>',
        `</title>\n    <meta http-equiv="Content-Security-Policy" content="${PACKAGED_CSP}" />`,
      )
    },
  }
}

export default defineConfig({
  plugins: [
    react(),
    cspMetaPlugin(),
    electron([
      {
        entry: 'electron/main.ts',
        // Vite must build the main process, NOT launch it. `electron:dev`
        // starts exactly one app after wait-on; the previous default also
        // started one from the plugin, so two backends fought for :9876 and
        // the visible window could be the orphaned instance.
        onstart() { /* started explicitly by electron:dev / Playwright */ },
        vite: {
          build: {
            outDir: 'dist-electron',
            rollupOptions: {
              external: ['electron']
            }
          }
        }
      },
      {
        entry: 'electron/preload.ts',
        onstart(args) {
          args.reload()
        },
        vite: {
          build: {
            outDir: 'dist-electron'
          }
        }
      }
    ])
  ],
  resolve: {
    alias: {
      '@': path.resolve(__dirname, 'src')
    }
  },
  server: {
    // Explicit IPv4: on Windows Vite otherwise binds [::1], while Electron
    // and Playwright may ask 127.0.0.1 — the server is up but unreachable
    // from the window that needs it.
    host: '127.0.0.1',
    port: DEV_PORT,
    strictPort: true
  }
})