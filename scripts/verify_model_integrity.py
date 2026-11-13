#!/usr/bin/env python3
"""verify_model_integrity.py — a promoted manifest must match its artifact.

The defect this closes (measured 2026-11-06): `models/exploit/
ranker-2026-11-03/manifest.json` declared `sha256: ba9023a2…` and the artifact
in git hashed `b7e3b978…`. Nothing computed either number, so a ranker edited
after its evaluation kept being served as the promoted model.

The registry now reproduces the digest on load, which protects a running
engagement. This script is the CI counterpart: it walks every promoted
manifest in `models/`, recomputes the digest of the named artifact (file or
adapter directory), and FAILS the build on a mismatch. A model that cannot be
proven is not a model the release may ship.

Exit codes: 0 = every promoted artifact matches (or none is promoted), 1 = at
least one mismatch or error.

Run locally:

    python scripts/verify_model_integrity.py

The JSON summary goes to stdout (and to `--json PATH` when given) — never into
`data/`, which is runtime state, not a place to drop build output.
"""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parents[1]


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Recompute the digest of every promoted ML artifact.")
    parser.add_argument("--json", default="",
                        help="also write the summary to this path")
    args = parser.parse_args(argv)

    sys.path.insert(0, str(ROOT))
    from phantom.automation.ai.registry import ModelRegistry, digest_problem

    registry = ModelRegistry(ROOT)
    models = ROOT / "models"
    if not models.is_dir():
        print("no models/ directory: nothing to verify")
        return 0

    checked = 0
    failures = []
    promoted_phases = set()
    for phase_dir in sorted(p for p in models.iterdir() if p.is_dir()):
        for manifest in registry.candidates(phase_dir.name):
            if manifest.get("promoted") is not True:
                continue
            checked += 1
            promoted_phases.add(phase_dir.name)
            phase = str(manifest.get("phase") or phase_dir.name)
            version = str(manifest.get("version") or "?")
            problem = digest_problem(manifest, ROOT)
            if problem:
                failures.append((phase, version, problem))
                print(f"FAIL {phase}/{version}: {problem}")
            else:
                artifact = manifest.get("ranker") or manifest.get("adapter")
                print(f"ok   {phase}/{version} ({artifact})")

    if not checked:
        print("no promoted model in models/: nothing to verify")
        return 0

    # A second, independent path: for every phase that claims a promoted
    # model, the registry's own gate must also agree it is servable. Two code
    # paths returning the same verdict is the point of a check that has to
    # survive a refactor of either one. A phase with NO promoted model is not
    # a failure — that is the honest state of finding/osint/social/evolution
    # today, and failing the build on it would make this check meaningless.
    for phase in sorted(promoted_phases):
        if registry.promoted(phase) is None:
            failures.append((phase, "-", "registry refuses the promoted model"))
            print(f"FAIL {phase}: registry.promoted() returned None")

    summary = {
        "checked": checked,
        "failures": [{"phase": p, "version": v, "problem": t}
                     for p, v, t in failures],
    }
    text = json.dumps(summary, indent=2)
    print(text)
    if args.json:
        out = Path(args.json)
        try:
            out.parent.mkdir(parents=True, exist_ok=True)
            out.write_text(text + "\n", encoding="utf-8", newline="\n")
        except OSError as e:
            print(f"could not write {out}: {e}")
    return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())
