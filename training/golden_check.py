"""golden_check.py — the golden set must speak the RUNTIME schema.

A golden expectation the runtime validator would refuse turns a CORRECT model
into a zero. Measured 2026-10-26: the 0.5B finding adapter answered
``finding-2`` with the schema-valid kind ``hunt_anomaly`` while the fixture
expected ``web_anomaly`` — a kind that exists nowhere in
``schemas.FINDING_KINDS`` — and exact_match scored 0 for an answer Phantom
accepts. The datum was wrong, not the model.

Every phase's golden ``expected`` is mapped into the payload its validator
takes and checked WITH that validator, so this file cannot drift from
``phantom.automation.ai.schemas`` either: it imports the same functions the
runtime uses.

    python -m training.golden_check            # every phase, exit 1 on error
    python -m training.golden_check --phase finding
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Dict, List, Optional

from phantom.automation.ai import schemas

from training.phases import PHASE_ORDER

GOLDEN_DIR = Path(__file__).resolve().parent / "golden"


def load_jsonl(path: str | Path) -> List[dict]:
    out: List[dict] = []
    with open(path, encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except ValueError:
                continue
    return out


def _payload(phase: str, record: dict) -> Optional[Dict[str, Any]]:
    """The validator-shaped payload for one golden expectation.

    ``None`` means the phase has no closed schema for its expectation (the
    rubric-graded phase), so there is nothing for the runtime to refuse.
    """
    expected = record.get("expected")
    if not isinstance(expected, dict):
        return None
    if phase == "exploit":
        ranking = expected.get("ranking")
        rows = [{"id": str(i)} for i in (ranking or [])]
        return {"ranked": rows}
    if phase == "finding":
        value = expected.get("value")
        return {"findings": [value] if isinstance(value, dict) else []}
    if phase == "osint":
        candidate = ((record.get("input") or {}).get("candidate") or {})
        return {"links": [{
            "handle": str(candidate.get("handle") or ""),
            "platform": str(candidate.get("platform") or ""),
            "confidence": expected.get("probability"),
        }]}
    if phase == "scan_parse":
        ports = expected.get("open_ports") or []
        return {"findings": [{"port": p} for p in ports]}
    if phase == "evolution":
        value = expected.get("value") or {}
        return {"summary": str(value.get("cause") or ""),
                "proposal": str(value.get("repair") or "")}
    if phase == "social":
        # A rubric row carries criteria, not an expected string: the check is
        # that every criterion is verifiable (see _rubric_problems).
        return None
    return None


def _rubric_problems(record: dict) -> List[str]:
    """Social rows are graded by ``training.rubric``; pin the two together."""
    from training.rubric import CHECKS

    expected = record.get("expected") or {}
    criteria = expected.get("criteria")
    if not isinstance(criteria, list) or not criteria:
        return ["no criteria to grade"]
    out = []
    for criterion in criteria:
        if not isinstance(criterion, str) or not criterion.strip():
            out.append(f"criterion is not a string: {criterion!r}")
            continue
        if criterion.strip().lower() not in CHECKS:
            out.append(f"no rubric check for criterion: {criterion!r}")
    return out


def errors(phase: str, golden: Optional[List[dict]] = None) -> List[str]:
    """Every golden row that the runtime schema would refuse, as text."""
    if golden is None:
        path = GOLDEN_DIR / f"{phase}.jsonl"
        golden = load_jsonl(path) if path.is_file() else []
    out: List[str] = []
    for record in golden:
        record_id = str(record.get("id") or "?")
        payload = _payload(phase, record)
        if payload is None:
            if not record.get("expected"):
                out.append(f"{record_id}: no expectation")
            elif phase == "social":
                out.extend(f"{record_id}: {p}" for p in _rubric_problems(record))
            continue
        for problem in schemas.validate(phase, payload):
            out.append(f"{record_id}: {problem}")
    return out


def all_errors() -> Dict[str, List[str]]:
    """Per-phase errors for every golden file that exists."""
    out: Dict[str, List[str]] = {}
    for phase in PHASE_ORDER:
        path = GOLDEN_DIR / f"{phase}.jsonl"
        if not path.is_file():
            out[phase] = [f"missing golden file: {path}"]
            continue
        rows = load_jsonl(path)
        out[phase] = (["no usable records"] if not rows else errors(phase, rows))
    return out


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="training.golden_check",
        description="Validate the golden set against the runtime schemas.")
    parser.add_argument("--phase", default="", choices=["", *PHASE_ORDER])
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    report = ({args.phase: errors(args.phase)} if args.phase
              else all_errors())
    bad = 0
    for phase, problems in report.items():
        state = "OK" if not problems else "INVALID"
        if not args.quiet:
            print(f"{phase:12} {state}")
        for problem in problems:
            bad += 1
            if not args.quiet:
                print(f"  - {problem}")
    return 1 if bad else 0


if __name__ == "__main__":
    sys.exit(main())
