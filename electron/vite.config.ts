import { defineConfig, type Plugin } from 'vite'
import react from '@vitejs/plugin-react'
import electron from 'vite-plugin-electron'
import path from 'path'

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
    port: 5173
  }
})