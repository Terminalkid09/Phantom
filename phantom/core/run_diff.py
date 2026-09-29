"""run_diff.py — structured comparison of two Phantom runs.

A run writes a checkpoint after every wave (auto/agent), and each
checkpoint carries the full WorldModel: findings, hypotheses, the audit
trail and the dead-capability map. That means any two runs are
comparable — and the comparison answers the operator questions a score
never will:

  * what did the second run LEARN that the first did not (new findings)?
  * what did it LOSE (findings that vanished — a regression or an
    environment change)?
  * which walls got resolved, and which NEW walls appeared?
  * did the run actually go further, or just move sideways?

The diff is pure: no targets are touched, no tools are run. It reads two
checkpoint files (or two WorldModel JSON dumps — same shape) and returns
a RunDiff the CLI renders.
"""

from __future__ import annotations

import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple


# ── loading ──────────────────────────────────────────────────────────────

def load_run(path: str) -> Dict[str, Any]:
    """Normalize a run artifact (checkpoint or wm dump) to a plain dict.

    Accepts:
      * an agent checkpoint  ({"schema": 1, "wm": {...}, "failed_caps": …})
      * a bare WorldModel dump ({"target": …, "findings": …, "actions": …})

    Never raises on a readable-but-foreign JSON: returns what it finds so
    the diff degrades to "everything changed" instead of crashing.
    """
    with open(path, "r", encoding="utf-8") as fh:
        raw = json.load(fh)
    if not isinstance(raw, dict):
        raise ValueError(f"{path}: not a JSON object")
    wm = raw.get("wm") if isinstance(raw.get("wm"), dict) else raw
    failed = raw.get("failed_caps") if isinstance(raw, dict) else {}
    return {
        "path": path,
        "target": str(raw.get("target") or wm.get("target") or ""),
        "saved_at": float(raw.get("saved_at") or 0.0),
        "goal": str(raw.get("goal") or ""),
        "findings": _findings_of(wm),
        "failed_caps": {str(k): v for k, v in (failed or {}).items()},
        "actions": [a for a in (wm.get("actions") or [])
                    if isinstance(a, dict)],
    }


def _findings_of(wm: Dict[str, Any]) -> List[Dict[str, Any]]:
    out: List[Dict[str, Any]] = []
    for f in (wm.get("findings") or []):
        if not isinstance(f, dict):
            continue
        out.append({
            "kind": str(f.get("kind") or ""),
            "key": str(f.get("key") or ""),
            "confidence": float(f.get("confidence") or 0.0),
            "source": str(f.get("source") or ""),
        })
    return out


# ── diffing ──────────────────────────────────────────────────────────────

def _fkey(f: Dict[str, Any]) -> Tuple[str, str]:
    return (f.get("kind", ""), f.get("key", ""))


_CONF_EPSILON = 0.05


@dataclass
class RunDiff:
    path_a: str = ""
    path_b: str = ""
    target_a: str = ""
    target_b: str = ""
    new_findings: List[Dict[str, Any]] = field(default_factory=list)
    lost_findings: List[Dict[str, Any]] = field(default_factory=list)
    changed_findings: List[Dict[str, Any]] = field(default_factory=list)
    resolved_failures: List[str] = field(default_factory=list)
    new_failures: List[str] = field(default_factory=list)
    actions_a: int = 0
    actions_b: int = 0
    wins_a: int = 0
    wins_b: int = 0

    @property
    def progressed(self) -> bool:
        """B learned something A did not have, or unblocked a wall."""
        return bool(self.new_findings or self.resolved_failures)

    @property
    def regressed(self) -> bool:
        """B lost knowledge A had, or hit walls A had already cleared."""
        return bool(self.lost_findings or self.new_failures)


def diff_runs(a: Dict[str, Any], b: Dict[str, Any]) -> RunDiff:
    fa = {_fkey(f): f for f in a["findings"]}
    fb = {_fkey(f): f for f in b["findings"]}

    d = RunDiff(path_a=a.get("path", ""), path_b=b.get("path", ""),
                target_a=a.get("target", ""), target_b=b.get("target", ""),
                actions_a=len(a.get("actions", [])),
                actions_b=len(b.get("actions", [])),
                wins_a=sum(1 for x in a.get("actions", [])
                           if x.get("ok")),
                wins_b=sum(1 for x in b.get("actions", [])
                           if x.get("ok")))

    d.new_findings = sorted((f for k, f in fb.items() if k not in fa),
                            key=_fkey)
    d.lost_findings = sorted((f for k, f in fa.items() if k not in fb),
                             key=_fkey)
    for k in sorted(set(fa) & set(fb)):
        ca, cb = fa[k]["confidence"], fb[k]["confidence"]
        if abs(cb - ca) > _CONF_EPSILON or fa[k]["source"] != fb[k]["source"]:
            d.changed_findings.append({
                "kind": k[0], "key": k[1],
                "was": ca, "now": cb,
                "source_was": fa[k]["source"], "source_now": fb[k]["source"],
            })

    caps_a = set(a.get("failed_caps") or {})
    caps_b = set(b.get("failed_caps") or {})
    d.resolved_failures = sorted(caps_a - caps_b)
    d.new_failures = sorted(caps_b - caps_a)
    return d


def diff_files(path_a: str, path_b: str) -> RunDiff:
    return diff_runs(load_run(path_a), load_run(path_b))


# ── rendering ────────────────────────────────────────────────────────────

def format_report(d: RunDiff) -> str:
    """Plain-text report (rich renders it verbatim in the shell)."""
    lines: List[str] = []
    head = f"Run diff: {os.path.basename(d.path_b)} vs {os.path.basename(d.path_a)}"
    if d.target_a and d.target_b and d.target_a != d.target_b:
        head += f"  (targets differ: {d.target_b} vs {d.target_a}!)"
    lines.append(head)
    lines.append(
        f"actions {d.actions_b} vs {d.actions_a} "
        f"(wins {d.wins_b} vs {d.wins_a}) | findings "
        f"+{len(d.new_findings)} / -{len(d.lost_findings)} / "
        f"~{len(d.changed_findings)} | walls "
        f"-{len(d.resolved_failures)} resolved / +{len(d.new_failures)} new")

    def rows(title: str, items: List[Any], fmt) -> None:
        if not items:
            return
        lines.append(f"\n{title}:")
        for it in items[:25]:
            lines.append(f"  {fmt(it)}")
        if len(items) > 25:
            lines.append(f"  … and {len(items) - 25} more")

    rows("New findings", d.new_findings,
         lambda f: f"+ [{f['kind']}] {f['key']} "
                   f"(conf {f['confidence']:.2f}, {f['source']})")
    rows("Lost findings", d.lost_findings,
         lambda f: f"- [{f['kind']}] {f['key']} ({f['source']})")
    rows("Changed", d.changed_findings,
         lambda c: f"~ [{c['kind']}] {c['key']}: "
                   f"conf {c['was']:.2f}->{c['now']:.2f}"
                   + ("" if c["source_was"] == c["source_now"] else
                      f", source {c['source_was']}->{c['source_now']}"))
    rows("Walls resolved", d.resolved_failures, lambda s: f"✓ {s}")
    rows("New walls", d.new_failures, lambda s: f"✗ {s}")

    if d.progressed and not d.regressed:
        lines.append("\nVerdict: the second run went FURTHER.")
    elif d.progressed and d.regressed:
        lines.append("\nVerdict: mixed — new knowledge AND regressions "
                     "(read the lists above).")
    elif not d.progressed and d.regressed:
        lines.append("\nVerdict: REGRESSED — nothing new learned, "
                     "knowledge or ground lost.")
    else:
        lines.append("\nVerdict: sideways — same ground, no net change.")
    return "\n".join(lines)
