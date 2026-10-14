"""An unknown backend state must be REPORTED, not silently shown as `idle`.

`asJobState` folded every unrecognised backend state into `idle`. A backend
rename therefore degraded to "nothing is running" — the panel said the engine
was quiet while the contract was broken — and it said so nowhere. The audit
called this out as the class of regression the parsers exist to intercept.

This compiles the renderer's own `api.ts` with the project's tsc and runs it in
node against a STUBBED IPC bridge, driving `automodeStatus()` — the real public
path that parses a backend payload — so it checks behaviour (a warning was
emitted, the fallback is still safe, one report per unseen value) rather than
the presence of a string. Skips, with the reason, without node/electron deps.
"""
import json
import os
import shutil
import subprocess

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELECTRON = os.path.join(REPO_ROOT, "electron")
API_TS = os.path.join(ELECTRON, "src", "lib", "api.ts")
DTS = os.path.join(ELECTRON, "vite-env.d.ts")
TSC = os.path.join(ELECTRON, "node_modules", "typescript", "bin", "tsc")

NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    NODE is None or not os.path.isfile(TSC),
    reason="needs node and the project's typescript (electron/node_modules)")

_HARNESS = """// the harness runs under node; the renderer's lib has no node types
declare const process: {{ exit(code?: number): void }}

import {{ automodeStatus, deriveJobState, schemaMismatches }} from '{api}'

// A payload that a FUTURE backend could send: one state this renderer does not
// know. Everything else is a shape the parser accepts.
const payload = {{
  job_id: 'job-1', state: 'paused', state_history: [], running: true,
  done: false, end_reason: '', error: '', current_step: 1, started_at: 0,
  elapsed: 1, targets: ['10.0.0.5'], mode: 'auto', profile: 'enterprise',
  goal: 'deliver', llm: 'denied', llm_pending: 0, handoffs: [],
  handoff_state: 'none', outcome: 'not_started', outcome_label: '',
  targets_outcome: {{}},
}}

const warnings: string[] = []
const original = console.warn
console.warn = (...args: unknown[]) => {{ warnings.push(args.join(' ')) }}

async function main() {{
  const bridge = {{ request: async () => ({{ status: 200, data: payload }}) }}
  ;(globalThis as Record<string, unknown>).window = {{ phantom: bridge }}

  const first = await automodeStatus('job-1')
  const second = await automodeStatus('job-1')      // the poll loop again
  console.warn = original

  const raw = JSON.parse(JSON.stringify(first.data))
  const knownPayload = {{ ...payload, state: 'running' }}
  console.log(JSON.stringify({{
    parsed_state: raw.state,
    derived: deriveJobState(first.data),
    second_derived: deriveJobState(second.data),
    mismatches: schemaMismatches(),
    warnings,
    known: deriveJobState({{ ...first.data, state: 'running' }}),
    known_payload_state: knownPayload.state,
  }}))
}}

main().catch((err: unknown) => {{ console.error(String(err)); process.exit(1) }})
"""


def _run(tmp_path):
    shutil.copyfile(API_TS, str(tmp_path / "api.ts"))
    harness = tmp_path / "harness.ts"
    harness.write_text(_HARNESS.format(api="./api"), encoding="utf-8")
    out_dir = tmp_path / "out"
    compiled = subprocess.run(
        [NODE, TSC, str(harness), DTS, "--target", "es2019",
         "--module", "commonjs", "--lib", "dom,es2019", "--skipLibCheck",
         "--outDir", str(out_dir)],
        capture_output=True, text=True, cwd=str(tmp_path), timeout=180)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    run = subprocess.run([NODE, str(out_dir / "harness.js")],
                         capture_output=True, text=True, cwd=str(tmp_path),
                         timeout=120)
    assert run.returncode == 0, run.stdout + run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


def test_an_unknown_state_is_reported_but_still_degrades_safely(tmp_path):
    result = _run(tmp_path)
    assert result["parsed_state"] == "idle", "the display fallback must stay safe"
    assert result["derived"] == "idle"
    mismatches = result["mismatches"]
    assert mismatches, "an unknown backend state was not reported at all"
    assert mismatches[0]["field"] == "automode.state"
    assert mismatches[0]["value"] == "paused"
    assert "running" in mismatches[0]["known"]


def test_the_same_unknown_state_is_reported_only_once(tmp_path):
    """A poll loop must not turn one contract break into console spam."""
    result = _run(tmp_path)
    assert len(result["mismatches"]) == 1, result["mismatches"]
    assert len(result["warnings"]) == 1, result["warnings"]
    assert "schema mismatch" in result["warnings"][0]
    assert "paused" in result["warnings"][0]
    assert "falling back" in result["warnings"][0]


def test_a_known_state_stays_quiet(tmp_path):
    result = _run(tmp_path)
    assert result["known"] == "running"
    assert all("running" != m["value"] for m in result["mismatches"])


# ── the fields the type DECLARES are fields the parser fills ───────────────

_STOP_HARNESS = """
import { automodeStop } from './api'

async function main() {
  const payload = {
    status: 'stopped', job_id: 'job-7', state: 'stopping',
    job: {
      job_id: 'job-7', state: 'stopping', state_history: [], running: true,
      done: false, end_reason: '', error: '', current_step: 3, started_at: 0,
      elapsed: 12, targets: ['10.0.0.5'], mode: 'auto', profile: 'enterprise',
      goal: 'deliver', llm: 'denied', llm_pending: 0, handoffs: [],
      handoff_state: 'none', outcome: 'not_started', outcome_label: '',
      targets_outcome: {},
    },
  }
  ;(globalThis as Record<string, unknown>).window = {
    phantom: { request: async () => ({ status: 200, data: payload }) },
  }
  const res = await automodeStop()
  const out = JSON.parse(JSON.stringify(res.data))
  console.log(JSON.stringify({
    status: out.status,
    state: out.state,
    job_state: out.job && out.job.state,
    job_targets: out.job && out.job.targets,
  }))
}

main().catch((err: unknown) => {
  try { console.error(String(err)) } catch { /* no console */ }
})
"""


def test_the_stop_result_populates_the_fields_its_type_declares(tmp_path):
    """A declared-but-unfilled field hands the caller `undefined` forever.

    `/api/automode/stop` sends `state` and `job` (server.py:1441); both were
    dropped by the parser, so a component reading them rendered nothing while
    the type said they were there. This runs the real parser over a real
    payload shape.
    """
    shutil.copyfile(API_TS, str(tmp_path / "api.ts"))
    harness = tmp_path / "stop.ts"
    harness.write_text(_STOP_HARNESS, encoding="utf-8")
    out_dir = tmp_path / "out"
    compiled = subprocess.run(
        [NODE, TSC, str(harness), DTS, "--target", "es2019",
         "--module", "commonjs", "--lib", "dom,es2019", "--skipLibCheck",
         "--outDir", str(out_dir)],
        capture_output=True, text=True, cwd=str(tmp_path), timeout=180)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr
    run = subprocess.run([NODE, str(out_dir / "stop.js")],
                         capture_output=True, text=True, cwd=str(tmp_path),
                         timeout=120)
    assert run.returncode == 0, run.stdout + run.stderr
    result = json.loads(run.stdout.strip().splitlines()[-1])
    assert result["state"] == "stopping"
    assert result["job_state"] == "stopping"
    assert result["job_targets"] == ["10.0.0.5"]
