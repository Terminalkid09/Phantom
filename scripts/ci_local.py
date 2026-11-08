#!/usr/bin/env python3
"""ci_local.py — run the GitHub CI jobs here, the way GitHub runs them.

Why this exists: three of the last four red runs were green on the developer's
machine and red on the runner (a bare `pytest` without xdist against a
`pytest.ini` that sets `-n auto`; sealed beacon artefacts read with `open()`;
a test that depended on an import-time snapshot). Running the SAME commands
locally is the only way to see those before the push.

What it mirrors, job by job, from `.github/workflows/ci.yml`:

  lint-and-test     py_compile, the full glob-collected suite (hermetic gate),
                    the tracked-assets check, the two import smoke blocks
  static-analysis   ruff + mypy (the ratchets)
  security-scan     bandit with the .bandit baseline, HIGH outside it fails
  security-sweep    the security test glob
  model-integrity   scripts/verify_model_integrity.py
  offline-sims      coverage_matrix_sim, hardened_target_sim, automode_benchmark
  c2-test           the C2 glob + the real end-to-end beacon smoke
  electron-build    npm ci, tsc --noEmit, vite build, renderer contracts
  beacon-lint       scripts/ci_beacon_lint.py
  beacon-smoke      the release-path build + grid verify FOR THIS OS only
  docker-test       skipped unless a daemon answers (with the reason)

`integration-tools` is reported as SKIP: it installs nmap on a Linux runner
and its tests are non-hermetic by design, so a local skip is honest here.

Exit code is 1 when any executed step fails. Nothing is swallowed: a skipped
job says why, a failed step prints the tail of its output.
"""

from __future__ import annotations

import argparse
import os
import platform as _platform
import shutil
import subprocess
import sys
import time
from pathlib import Path
from typing import Dict, List, Tuple

ROOT = Path(__file__).resolve().parents[1]
PY = sys.executable
#: GitHub's ubuntu-latest runner has 4 cores, so its `-n auto` resolves to 4
#: workers. On a 16-core box the same setting spawns 16, and a loaded 16-way
#: run turns legitimate ~100s agent tests into pytest-timeout worker kills
#: (measured 2026-11-08: 5 red tests and 3 worker crashes, all green serially).
#: Mirror the runner, not the developer's core count.
CI_WORKERS = ["-n", "4"]
# Job artefacts (bandit/model reports) land here, never in the tree: a local CI
# run must not leave untracked files behind that the next commit sweeps up.
ARTIFACTS = ROOT / ".ci-local"

PASS, FAIL, SKIP = "PASS", "FAIL", "SKIP"


def _resolve(cmd: List[str]) -> List[str]:
    """Find bare command names the way a shell would.

    On Windows `npm`, `npx` and `tsc` are `.cmd` shims: `CreateProcess` (what
    ``subprocess`` calls without a shell) cannot execute them, so the Electron
    job failed with ``WinError 2`` while the GitHub runner — a shell — worked.
    Absolute paths and ``python -m`` invocations are left untouched.
    """
    out: List[str] = []
    previous = ""
    for token in (str(c) for c in cmd):
        is_module = previous in ("-m", "-c")
        if (os.name == "nt" and not is_module and not os.path.dirname(token)
                and not token.lower().endswith(".exe")):
            token = shutil.which(token) or token
        out.append(token)
        previous = token
    return out


def _run(cmd: List[str], *, cwd: Path = ROOT, timeout: int = 2400,
         env: Dict[str, str] | None = None) -> Tuple[bool, str, float]:
    started = time.time()
    try:
        proc = subprocess.run(_resolve(cmd), cwd=str(cwd),
                              env={**os.environ, **(env or {})},
                              capture_output=True, text=True, timeout=timeout)
        out = (proc.stdout or "") + (proc.stderr or "")
        return proc.returncode == 0, out, time.time() - started
    except subprocess.TimeoutExpired:
        return False, f"TIMEOUT after {timeout}s", time.time() - started
    except FileNotFoundError as exc:
        return False, f"not found: {exc}", time.time() - started


def _tail(text: str, lines: int = 30) -> str:
    rows = [r for r in (text or "").strip().splitlines() if r.strip()]
    return "\n".join(rows[-lines:])


def _python_files() -> List[str]:
    """The file set `py_compile` checks in ci.yml (same directories)."""
    patterns = [
        "phantom/core/*.py", "phantom/modules/*.py", "phantom/utils/*.py",
        "phantom/automation/*.py", "phantom/automation/guidance/*.py",
        "phantom/automation/exploit/*.py",
        "phantom/automation/exploit/modules/*.py",
        "phantom/automation/social/*.py",
        "phantom/automation/fingerprint/*.py", "phantom/api/*.py",
    ]
    out: List[str] = []
    for pattern in patterns:
        out.extend(str(p.relative_to(ROOT)) for p in sorted(ROOT.glob(pattern)))
    return out


def _test_files() -> List[str]:
    skip = {"test_features_final.py", "test_real_deploy.py"}
    return [str(p.relative_to(ROOT)) for p in sorted((ROOT / "tests").glob("test_*.py"))
            if p.name not in skip]


def _security_tests() -> List[str]:
    out: List[str] = []
    patterns = ["tests/test_security*.py", "tests/test_p0_*.py",
                "tests/test_c2_token_rotation.py", "tests/test_remote_viewer.py",
                "tests/test_config_secret_perms.py",
                "tests/test_electron_allowlist_sync.py",
                "tests/test_endpoint_allowlist_drift.py"]
    for pattern in patterns:
        out.extend(str(p.relative_to(ROOT)) for p in sorted(ROOT.glob(pattern)))
    return sorted(set(out))


def _host_beacon() -> Tuple[str, str]:
    machine = _platform.machine().lower()
    if sys.platform.startswith("win"):
        return "windows", "x86_64"
    if sys.platform == "darwin":
        return "macos", ("aarch64" if machine in ("arm64", "aarch64")
                         else "x86_64")
    return "linux", ("aarch64" if machine in ("arm64", "aarch64") else "x86_64")


# --------------------------------------------------------------------- jobs
def job_lint_and_test() -> List[Tuple[str, str, str, str]]:
    rows: List[Tuple[str, str, str, str]] = []
    ok, out, dur = _run([PY, "-m", "py_compile", *_python_files()])
    rows.append(("py_compile", PASS if ok else FAIL, f"{dur:.1f}s",
                 "" if ok else _tail(out)))

    files = _test_files()
    ok, out, dur = _run([PY, "-m", "pytest", *files, *CI_WORKERS,
                         "-m", "not integration_tool", "-q", "--tb=short",
                         "--timeout=120", "--maxfail=25"])
    rows.append((f"pytest suite ({len(files)} files)",
                 PASS if ok else FAIL, f"{dur:.0f}s",
                 "" if ok else _tail(out, 40)))

    tracked = subprocess.run(["git", "ls-files", "phantom/data/templates"],
                             cwd=str(ROOT), capture_output=True, text=True)
    android = subprocess.run(
        ["git", "ls-files", "phantom/payloads/remote/android/app/src/main"],
        cwd=str(ROOT), capture_output=True, text=True)
    ok = bool(tracked.stdout.strip()) and ".xml" in android.stdout
    rows.append(("tracked assets", PASS if ok else FAIL, "0.1s",
                 "" if ok else "report templates or Android XML are not tracked"))

    core = (
        "from phantom.core.workflow import WorkflowManager, workflow_manager\n"
        "from phantom.core.persistence import persistence_manager, PersistenceManager\n"
        "from phantom.core.automode import run_auto_mode\n"
        "from phantom.modules.wordlist import WordlistModule\n"
        "print('core imports ok')")
    ok, out, dur = _run([PY, "-c", core])
    rows.append(("core imports", PASS if ok else FAIL, f"{dur:.1f}s",
                 "" if ok else _tail(out)))

    enterprise = (
        "from phantom.core.threatintel import threat_intel, ThreatIntelFeed\n"
        "from phantom.core.calibration import calibration_engine, CalibrationEngine\n"
        "from phantom.core.attack_mapping import attack_mapper, AttackMapper\n"
        "from phantom.core.risk_engine import risk_engine, RiskEngine\n"
        "from phantom.core.history import history_analyzer, HistoricalAnalyzer\n"
        "from phantom.automation.fingerprint.probes import FingerprintEngine, PROBE_MAP\n"
        "from phantom.automation.attack_chain import AttackGraph\n"
        "from phantom.automation.exploit.differential import DifferentialEngine\n"
        "from phantom.automation.ad_awareness import ADAwareness\n"
        "from phantom.automation.fallback import FallbackEngine, HistoricalLearner\n"
        "assert attack_mapper.get_enterprise_techniques()\n"
        "print('enterprise imports ok')")
    ok, out, dur = _run([PY, "-c", enterprise])
    rows.append(("enterprise imports", PASS if ok else FAIL, f"{dur:.1f}s",
                 "" if ok else _tail(out)))
    return rows


def job_static_analysis() -> List[Tuple[str, str, str, str]]:
    rows = []
    ok, out, dur = _run([PY, "-m", "ruff", "check", "."])
    rows.append(("ruff", PASS if ok else FAIL, f"{dur:.1f}s",
                 "" if ok else _tail(out, 25)))
    ok, out, dur = _run([PY, "-m", "mypy"])
    rows.append(("mypy", PASS if ok else FAIL, f"{dur:.1f}s",
                 "" if ok else _tail(out, 25)))
    return rows


def job_security_scan() -> List[Tuple[str, str, str, str]]:
    if not (ROOT / ".bandit").exists():
        return [("bandit", SKIP, "0s", ".bandit baseline missing")]
    ARTIFACTS.mkdir(exist_ok=True)
    report = ARTIFACTS / "bandit-results.json"
    ok, out, dur = _run([PY, "-m", "bandit", "-r", "phantom/", "scripts/",
                         "electron/", "-c", ".bandit", "-f", "json",
                         "-o", str(report), "-q"])
    # CI ignores bandit's exit code and reads the JSON: baselined findings
    # do not fail the run, unbaselined HIGHs do.
    if not report.exists():
        return [("bandit", FAIL, f"{dur:.0f}s", _tail(out, 15))]
    import json
    try:
        data = json.loads(report.read_text(encoding="utf-8"))
    except ValueError as exc:
        return [("bandit", FAIL, f"{dur:.0f}s", f"unreadable report: {exc}")]
    high = [r for r in data.get("results", [])
            if r.get("issue_severity") == "HIGH"]
    detail = "" if not high else "\n".join(
        f"{r.get('test_id')}: {r.get('issue_text')} @ {r.get('filename')}:"
        f"{r.get('line_number')}" for r in high[:10])
    return [("bandit (HIGH outside baseline)", PASS if not high else FAIL,
             f"{dur:.0f}s", detail)]


def job_security_sweep() -> List[Tuple[str, str, str, str]]:
    files = _security_tests()
    if not files:
        return [("security sweep", FAIL, "0s", "no security test file found")]
    ok, out, dur = _run([PY, "-m", "pytest", *files, *CI_WORKERS,
                         "-m", "not integration_tool", "-q", "--tb=short",
                         "--timeout=120"])
    return [(f"security sweep ({len(files)} files)",
             PASS if ok else FAIL, f"{dur:.0f}s", "" if ok else _tail(out, 30))]


def job_model_integrity() -> List[Tuple[str, str, str, str]]:
    ARTIFACTS.mkdir(exist_ok=True)
    ok, out, dur = _run([PY, "scripts/verify_model_integrity.py",
                         "--json", str(ARTIFACTS / "model-integrity.json")])
    return [("model digests", PASS if ok else FAIL, f"{dur:.1f}s",
             "" if ok else _tail(out, 20))]


def job_offline_sims() -> List[Tuple[str, str, str, str]]:
    rows = []
    for script in ("scripts/coverage_matrix_sim.py",
                   "scripts/hardened_target_sim.py"):
        ok, out, dur = _run([PY, script])
        rows.append((Path(script).stem, PASS if ok else FAIL, f"{dur:.0f}s",
                     "" if ok else _tail(out, 20)))
    ok, out, dur = _run([PY, "scripts/automode_benchmark.py"])
    rows.append(("automode benchmark", PASS if ok else FAIL, f"{dur:.0f}s",
                 "" if ok else _tail(out, 25)))
    return rows


def job_c2() -> List[Tuple[str, str, str, str]]:
    files = sorted(str(p.relative_to(ROOT)) for p in ROOT.glob("tests/test_c2*.py"))
    files += sorted(str(p.relative_to(ROOT)) for p in ROOT.glob("tests/test_beacon_auth*.py"))
    for extra in ("tests/test_state_store.py", "tests/test_manual_ux.py",
                  "tests/test_manual_core.py"):
        if (ROOT / extra).exists():
            files.append(extra)
    ok, out, dur = _run([PY, "-m", "pytest", *sorted(set(files)), *CI_WORKERS,
                         "-q", "--tb=short", "--timeout=60"])
    rows = [(f"c2 tests ({len(set(files))} files)", PASS if ok else FAIL,
             f"{dur:.0f}s", "" if ok else _tail(out, 30))]
    ok, out, dur = _run([PY, "scripts/e2e_c2_beacon_smoke.py"])
    rows.append(("c2 <-> beacon smoke", PASS if ok else FAIL, f"{dur:.0f}s",
                 "" if ok else _tail(out, 20)))
    return rows


def job_electron() -> List[Tuple[str, str, str, str]]:
    if not shutil.which("npm") or not shutil.which("node"):
        return [("electron", SKIP, "0s", "node/npm not installed")]
    root = ROOT / "electron"
    ok, out, dur = _run(["npm", "ci", "--no-audit", "--no-fund"], cwd=root,
                        timeout=1800)
    if not ok:
        return [("npm ci", FAIL, f"{dur:.0f}s", _tail(out, 20))]
    rows = [("npm ci", PASS, f"{dur:.0f}s", "")]
    ok, out, dur = _run(["npx", "tsc", "--noEmit"], cwd=root)
    rows.append(("tsc --noEmit", PASS if ok else FAIL, f"{dur:.0f}s",
                 "" if ok else _tail(out, 20)))
    ok, out, dur = _run(["npx", "vite", "build"], cwd=root)
    rows.append(("vite build", PASS if ok else FAIL, f"{dur:.0f}s",
                 "" if ok else _tail(out, 20)))
    ok, out, dur = _run([PY, "-m", "pytest",
                         "tests/test_electron_job_state.py",
                         "tests/test_electron_schema_mismatch.py", "-q"])
    rows.append(("renderer contracts", PASS if ok else FAIL, f"{dur:.0f}s",
                 "" if ok else _tail(out, 25)))
    return rows


def job_beacon_lint() -> List[Tuple[str, str, str, str]]:
    ok, out, dur = _run([PY, "scripts/ci_beacon_lint.py"])
    return [("beacon lint", PASS if ok else FAIL, f"{dur:.1f}s",
             "" if ok else _tail(out, 20))]


def job_beacon_smoke() -> List[Tuple[str, str, str, str]]:
    plat, arch = _host_beacon()
    rows = []
    ok, out, dur = _run([PY, "scripts/ci_beacon_smoke.py", "--platform", plat,
                         "--require"], timeout=1800)
    rows.append((f"beacon build ({plat})", PASS if ok else FAIL,
                 f"{dur:.0f}s", "" if ok else _tail(out, 25)))
    ok, out, dur = _run([PY, "scripts/beacon_matrix_verify.py",
                         "--platform", plat, "--arch", arch, "--require"])
    rows.append((f"beacon grid ({plat}/{arch})", PASS if ok else FAIL,
                 f"{dur:.1f}s", "" if ok else _tail(out, 20)))
    return rows


def job_docker() -> List[Tuple[str, str, str, str]]:
    if not shutil.which("docker"):
        return [("docker", SKIP, "0s", "docker CLI not installed")]
    ok, out, dur = _run(["docker", "info"], timeout=20)
    if not ok:
        return [("docker", SKIP, "0s",
                 "no daemon answers (Docker Desktop not running)")]
    if not shutil.which("hadolint"):
        return [("docker", SKIP, "0s",
                 "hadolint not installed (CI runs it from a container)")]
    ok, out, dur = _run(["docker", "build", "--target", "ci-smoke",
                         "-t", "phantom-ci-smoke", "."], timeout=1800)
    return [("docker ci-smoke build", PASS if ok else FAIL, f"{dur:.0f}s",
             "" if ok else _tail(out, 25))]


JOBS = {
    "lint-and-test": job_lint_and_test,
    "static-analysis": job_static_analysis,
    "security-scan": job_security_scan,
    "security-sweep": job_security_sweep,
    "model-integrity": job_model_integrity,
    "offline-sims": job_offline_sims,
    "c2-test": job_c2,
    "electron-build": job_electron,
    "beacon-lint": job_beacon_lint,
    "beacon-smoke": job_beacon_smoke,
    "docker-test": job_docker,
    "integration-tools": lambda: [
        ("integration-tools", SKIP, "0s",
         "non-hermetic: the CI job installs nmap on a Linux runner")],
}


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--job", action="append", default=[],
                        help="run only these jobs (repeatable)")
    parser.add_argument("--list", action="store_true", help="list the jobs")
    parser.add_argument("--no-tail", action="store_true",
                        help="do not print failing output")
    args = parser.parse_args(argv)
    if args.list:
        for name in JOBS:
            print(name)
        return 0
    chosen = args.job or list(JOBS)
    unknown = [n for n in chosen if n not in JOBS]
    if unknown:
        print(f"unknown job(s): {', '.join(unknown)}; --list shows them")
        return 2

    results: Dict[str, List[Tuple[str, str, str, str]]] = {}
    started = time.time()
    for name in chosen:
        print(f"\n=== {name} ===", flush=True)
        results[name] = JOBS[name]()
        for step, status, dur, detail in results[name]:
            print(f"  {status:4s} {step:42s} {dur:>8s}")
            if status == FAIL and detail and not args.no_tail:
                for line in detail.splitlines():
                    print(f"       {line}")

    print("\n" + "=" * 72)
    failed = [name for name, rows in results.items()
              if any(r[1] == FAIL for r in rows)]
    skipped = [name for name, rows in results.items()
               if rows and all(r[1] == SKIP for r in rows)]
    total = sum(len(rows) for rows in results.values())
    print(f"{len(results)} job(s), {total} step(s), "
          f"{len(failed)} failed, {len(skipped)} fully skipped "
          f"({time.time() - started:.0f}s)")
    for name in failed:
        bad = [r[0] for r in results[name] if r[1] == FAIL]
        print(f"  FAIL {name}: {', '.join(bad)}")
    for name in skipped:
        why = results[name][0][3]
        print(f"  SKIP {name}: {why}")
    return 1 if failed else 0


if __name__ == "__main__":
    raise SystemExit(main())
