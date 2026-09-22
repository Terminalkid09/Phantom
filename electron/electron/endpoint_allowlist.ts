/**
 * endpoint_allowlist.ts — P1-13 (docs/ROADMAP.md).
 *
 * The `api-request` IPC handler used to forward ANY method+endpoint the
 * renderer sent. A compromised renderer (or a compromised dependency)
 * could reach every backend route — including destructive ones — even
 * though the bearer token never left the main process.
 *
 * The allowlist below is derived from the endpoints the UI actually
 * references (grep of src/), grouped read-only vs mutating. Unknown
 * endpoints are REFUSED in the main process; a missing group match on a
 * parameterized path falls back to exact/prefix rules below.
 */

export type EndpointGroup = 'readonly' | 'mutating'

interface Rule {
  /** exact match, or prefix match when the rule ends with '*' */
  pattern: string
  methods: readonly string[]
  group: EndpointGroup
}

const RULES: readonly Rule[] = [
  // ── reads (safe to repeat, no side effects) ────────────────────────────
  { pattern: '/api/capabilities', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/session', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/session/history', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/session/history', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/knowledge', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/session/preflight', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/session/preflight', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/wordlists', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/session/wordlists/use', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/wordlists/generate', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/state', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/c2/audit', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/c2/recordings/live', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/c2/artifacts', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/c2/beacon-help', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/c2/certs', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/modules', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/network-map', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/network/liveness', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/network/liveness', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/search', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/search', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/timeline', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/timeline', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/craft/hits', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/backend/detect', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/backend/detect', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/backend/config', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/backend/config', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/ad/graph', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/ad/mutate', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/ad/mutate', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/attack-graph', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/timeline', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/learning', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/pm/list', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/search', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/automode/stream', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/vault', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/launcher', methods: ['GET'], group: 'readonly' },

  // ── mutating (each one changes backend state — still operator-driven) ──
  { pattern: '/api/session/run', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/save', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/load', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/next', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/notes', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/knowledge/reset', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/profile/save', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/profile/load', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/session/set', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/listener/start', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/listener/stop', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/generate', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/beacon-auth', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/c2/beacon-auth', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/beacon-auth/revoke', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/beacon-auth/rotate', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/certs/uninstall', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/config/mtls-toggle', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/c2/config/rotate-api-token', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/network/scan', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/network/vulnerable', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/automode/plan', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/automode/run', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/automode/stop', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/automode/llm', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/osint/preview', methods: ['POST'], group: 'readonly' },
  { pattern: '/api/identity/checks', methods: ['GET'], group: 'readonly' },
  { pattern: '/api/identity/confirm', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/craft', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/backend/detect', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/backend/install-tool', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/backend/config', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/learning/reset', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/pm/export', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/pm/import', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/reports/generate', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/reports/export', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/reports/export-all', methods: ['POST'], group: 'mutating' },
  { pattern: '/api/export-campaign', methods: ['POST'], group: 'mutating' },
]

/** dynamic segments: /api/<area>/<id>[/<action>] — matched by first segment */
const PREFIX_GROUPS: readonly { prefix: string; methods: readonly string[]; group: EndpointGroup }[] = [
  { prefix: '/api/c2/artifact?', methods: ['GET'], group: 'readonly' },
  { prefix: '/api/c2/beacon/', methods: ['GET', 'POST'], group: 'mutating' },
  { prefix: '/api/modules/', methods: ['GET', 'POST'], group: 'mutating' },
  { prefix: '/api/session/notes/', methods: ['GET'], group: 'readonly' },
  { prefix: '/api/timeline/', methods: ['GET'], group: 'readonly' },
  { prefix: '/api/network-map/', methods: ['GET'], group: 'readonly' },
  { prefix: '/api/vault/', methods: ['GET', 'POST'], group: 'mutating' },
]

export interface CheckResult {
  allowed: boolean
  group?: EndpointGroup
  reason?: string
}

export function checkEndpoint(method: string, endpoint: string): CheckResult {
  if (typeof endpoint !== 'string' || !endpoint.startsWith('/api/')) {
    return { allowed: false, reason: 'endpoint must start with /api/' }
  }
  // path-only comparison: drop query string, normalize trailing slash
  const path = endpoint.split('?')[0].replace(/\/+$/, '') || '/'
  const m = (method || 'GET').toUpperCase()

  for (const r of RULES) {
    const pat = r.pattern.replace(/\/+$/, '')
    if (pat.endsWith('*')) {
      if (path.startsWith(pat.slice(0, -1)) && r.methods.includes(m)) {
        return { allowed: true, group: r.group }
      }
      continue
    }
    if (path === pat && r.methods.includes(m)) {
      return { allowed: true, group: r.group }
    }
  }

  for (const p of PREFIX_GROUPS) {
    const base = p.prefix.replace(/\?$/, '').replace(/\/+$/, '')
    if ((path + '/').startsWith(base + '/') && p.methods.includes(m)) {
      return { allowed: true, group: p.group }
    }
  }

  return {
    allowed: false,
    reason: `endpoint not allowlisted: ${m} ${path}`,
  }
}
