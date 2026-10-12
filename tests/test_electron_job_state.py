"""`deriveJobState`, executed for real: compiled by tsc, run by node.

Most of the Electron coverage in this repo asserts on SOURCE text, because no
JS test runner is installed. That limit is real — a source assertion cannot tell
you a function returns the WRONG value, only that a string is still present.

So this file tests the one piece of renderer logic that decides what the
operator sees, for real: the project's own TypeScript compiles
`electron/src/lib/api.ts`, node executes `deriveJobState` over a table of job
snapshots, and the answers are compared with what the backend's lifecycle
implies. If tsc or node is missing, the test SKIPS with that reason instead of
pretending to have checked.
"""
import json
import os
import shutil
import subprocess

import pytest

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ELECTRON = os.path.join(REPO_ROOT, "electron")
API_TS = os.path.join(ELECTRON, "src", "lib", "api.ts")
# The renderer's globals (`window.phantom`) live in this declaration file,
# which the project's tsconfig includes: an isolated compile needs it too.
DTS = os.path.join(ELECTRON, "vite-env.d.ts")
TSC = os.path.join(ELECTRON, "node_modules", "typescript", "bin", "tsc")

NODE = shutil.which("node")

pytestmark = pytest.mark.skipif(
    NODE is None or not os.path.isfile(TSC),
    reason="needs node and the project's typescript (electron/node_modules)")


# The snapshots the backend can actually produce (tests/test_automode_job_
# lifecycle.py drives the real AutoJob to prove they exist) and the state each
# one must render as.
CASES = [
    ("nothing has run", {"state": "idle", "done": True}, "idle"),
    ("job accepted", {"state": "planning", "running": True, "done": False},
     "planning"),
    ("an action went out", {"state": "running", "running": True, "done": False},
     "running"),
    ("stop requested, engine has not halted",
     {"state": "stopping", "running": True, "done": False}, "stopping"),
    ("the loop exited on the stop request",
     {"state": "cancelled", "end_reason": "stopped by operator"}, "cancelled"),
    ("the loop finished", {"state": "completed", "end_reason": "sequence complete"},
     "completed"),
    ("the loop raised", {"state": "failed", "error": "boom"}, "failed"),
    # a run waiting on the LLM gate: the operator has something to resolve
    ("running with a pending LLM request",
     {"state": "running", "running": True, "done": False, "llm_pending": 1},
     "awaiting_approval"),
    # HANDOFF_READY is the case the docs care about most: the autonomous part
    # is over and the operator has to decide whether to enter the C2
    ("a finished run with an un-acted handoff",
     {"state": "completed", "handoff_state": "ready"}, "handoff_ready"),
    ("a still-running run with an un-acted handoff",
     {"state": "running", "running": True, "done": False, "handoff_state": "ready"},
     "handoff_ready"),
    ("an ACCEPTED handoff is a plain completion",
     {"state": "completed", "handoff_state": "accepted"}, "completed"),
    ("a dismissed handoff is not an operator to-do",
     {"state": "completed", "handoff_state": "dismissed"}, "completed"),
    # the cause of the end outranks the card: the operator still gets the
    # handoff card (from `handoffs`), but the chip must not hide a crash
    ("a crash with a handoff ready",
     {"state": "failed", "error": "boom", "handoff_state": "ready"}, "failed"),
    ("an operator cancellation with a handoff ready",
     {"state": "cancelled", "handoff_state": "ready"}, "cancelled"),
]

_BASE = """{
  job_id: null, state: 'idle', state_history: [], running: false, done: true,
  end_reason: '', error: '', current_step: -1, started_at: 0, elapsed: 0,
  targets: [], mode: '', profile: '', goal: '', llm: 'denied',
  llm_pending: 0, handoffs: [], handoff_state: 'none',
}"""

_HARNESS = """import {{ deriveJobState, type AutomodeStatus }} from '{api}'

const base: AutomodeStatus = {base}

const cases: Array<{{ name: string; patch: Partial<AutomodeStatus> }}> = {cases}

const out: Record<string, string> = {{}}
for (const c of cases) {{
  out[c.name] = deriveJobState({{ ...base, ...c.patch }})
}}
console.log(JSON.stringify(out))
"""


def _run_node_harness(tmp_path):
    """Compile a harness against the renderer's module and run it in node.

    `api.ts` is COPIED next to the harness rather than imported across
    directories: tsc mirrors the input tree under `--outDir`, and a require
    written from the harness's depth would then point at the wrong place. The
    copy is byte-identical to the file the app compiles — that is the point.
    """
    shutil.copyfile(API_TS, str(tmp_path / "api.ts"))
    cases = ",\n  ".join(
        f"{{ name: {json.dumps(name)}, patch: {json.dumps(patch)} }}"
        for name, patch, _expected in CASES)
    harness = tmp_path / "harness.ts"
    harness.write_text(
        _HARNESS.format(api="./api", base=_BASE,
                        cases="[\n  " + cases + ",\n]"),
        encoding="utf-8")

    out_dir = tmp_path / "out"
    compiled = subprocess.run(
        [NODE, TSC, str(harness), DTS, "--target", "es2019",
         "--module", "commonjs", "--lib", "dom,es2019", "--skipLibCheck",
         "--outDir", str(out_dir)],
        capture_output=True, text=True, cwd=str(tmp_path), timeout=180)
    assert compiled.returncode == 0, compiled.stdout + compiled.stderr

    emitted = [os.path.join(out_dir, "harness.js"),
               os.path.join(out_dir, "api.js")]
    missing = [p for p in emitted if not os.path.isfile(p)]
    assert not missing, f"tsc emitted nothing at {missing}"
    run = subprocess.run([NODE, emitted[0]], capture_output=True, text=True,
                         cwd=str(tmp_path), timeout=120)
    assert run.returncode == 0, run.stdout + run.stderr
    return json.loads(run.stdout.strip().splitlines()[-1])


def test_derive_job_state_maps_every_real_snapshot(tmp_path):
    answers = _run_node_harness(tmp_path)
    assert len(answers) == len(CASES)
    wrong = []
    for name, _patch, expected in CASES:
        got = answers.get(name)
        if got != expected:
            wrong.append(f"{name}: expected {expected!r}, got {got!r}")
    assert not wrong, "deriveJobState disagreed with the lifecycle: " + "; ".join(wrong)


def test_the_union_has_no_state_the_backend_cannot_reach():
    """Every member of `JobState` must be derivable from a real snapshot.

    The other direction of the drift guard: adding `paused` to the union
    without adding a pause control to the backend would leave a state the UI
    can name but never truly show.
    """
    reached = {expected for _name, _patch, expected in CASES}
    source = open(API_TS, encoding="utf-8").read()
    union = source.split("export type JobState =", 1)[1].split("const ", 1)[0]
    declared = set(__import__("re").findall(r"'([a-z_]+)'", union))
    assert declared == reached, (
        f"declared but unreachable: {sorted(declared - reached)}; "
        f"reachable but undeclared: {sorted(reached - declared)}")
