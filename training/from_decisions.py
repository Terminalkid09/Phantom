"""from_decisions.py — turn logged exploit decisions into ranker rows.

``phantom.automation.exploit.decision_log`` writes one JSONL row per attempted
candidate: its ``success``/``noise``/``complexity`` and what happened. That is
the raw material the ranker was missing; this module turns it into the SAME
corpus shape ``training.ranker`` already trains on — a payload (the candidate
table plus the engagement context) and a graded order.

The label is an OBSERVATION, never the deterministic score: an RCE outranks a
vulnerable-but-not-RCE, which outranks a candidate the engagement never reached,
which outranks one it tried and failed. Training on the planner's own ranking
would teach the model to copy the planner and make the gate measure nothing.

Grouping is by engagement identity — ``(target, goal, profile, mode)`` — because
that is the unit a candidate table belongs to: two different runs against the
same target are two different tables, and merging them would put a candidate
that was tried in run A into run B's table. Duplicate ids within a group keep
the LAST outcome (the most recent measurement wins), and a group with fewer
than two candidates is skipped: one row cannot teach an ORDER.

Nothing here is on the runtime path. Run:

    python -m training.from_decisions --write
    python -m training.ranker --cv
"""

from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

#: Outcome tier -> the position it earns in the label. Higher is better.
TIER_RCE = 3
TIER_VULN = 2
TIER_UNTRIED = 1
TIER_FAILED = 0


def _tier(entry: Dict[str, Any]) -> int:
    outcome = entry.get("outcome") or {}
    if outcome.get("rce"):
        return TIER_RCE
    if outcome.get("vulnerable"):
        return TIER_VULN
    if not outcome.get("attempted"):
        return TIER_UNTRIED
    return TIER_FAILED


def _engagement(entry: Dict[str, Any]) -> Tuple[str, str, str, str]:
    return (str(entry.get("target") or ""), str(entry.get("goal") or ""),
            str(entry.get("profile") or ""), str(entry.get("mode") or ""))


def build_rows(entries: Iterable[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """Corpus rows (``phase``/``input``/``expected``) from decision entries."""
    groups: Dict[Tuple[str, str, str, str], Dict[str, Dict[str, Any]]] = {}
    for entry in entries:
        if not isinstance(entry, dict):
            continue
        cand = entry.get("candidate") or {}
        cid = str(cand.get("id") or "").strip()
        if not cid:
            continue
        # Last outcome per id wins: a route retried later is a newer
        # measurement, and keeping both would let the older one vote twice.
        groups.setdefault(_engagement(entry), {})[cid] = entry

    rows: List[Dict[str, Any]] = []
    for (target, goal, profile, mode), table in sorted(groups.items()):
        if len(table) < 2:
            continue
        candidates = []
        services = {}
        cves = set()
        tried = []
        tiers: Dict[str, int] = {}
        for cid, entry in table.items():
            cand = entry.get("candidate") or {}
            row: Dict[str, Any] = {"id": cid}
            for key in ("success", "noise", "complexity"):
                if isinstance(cand.get(key), (int, float)):
                    row[key] = round(float(cand[key]), 4)
            candidates.append(row)
            port = str(cand.get("port") or "")
            service = str(cand.get("service") or "")
            if port or service:
                services[(port, service)] = {"port": port, "service": service}
            if cand.get("cve"):
                cves.add(str(cand["cve"]))
            if (entry.get("outcome") or {}).get("attempted"):
                tried.append(cid)
            tiers[cid] = _tier(entry)
        order = sorted(table, key=lambda cid: (-tiers[cid], cid))
        rows.append({
            "phase": "exploit",
            "input": {
                "candidates": candidates,
                "services": [services[k] for k in sorted(services)],
                "cves": sorted(cves),
                "goal": goal, "profile": profile, "mode": mode,
                "target": target,
                "already_tried": sorted(set(tried) - {order[0]}),
            },
            "expected": {"ranking": order},
            "source": "decision_log",
        })
    return rows


def write(rows: List[Dict[str, Any]], path: Path) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True) + "\n")
    return path


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(prog="training.from_decisions",
                                     description=__doc__)
    parser.add_argument("--decisions", default="",
                        help="JSONL from the decision log (default: data/)")
    parser.add_argument("--out",
                        default="training/data/exploit.decisions.jsonl")
    parser.add_argument("--write", action="store_true")
    args = parser.parse_args(argv)

    from phantom.automation.exploit import decision_log

    path = Path(args.decisions) if args.decisions else None
    entries = decision_log.read(path)
    rows = build_rows(entries)
    print(f"{len(entries)} decision row(s) -> {len(rows)} corpus row(s)")
    for row in rows[:3]:
        print(f"  {row['input'].get('target', '')} "
              f"{row['input']['candidates'][0]['id']} … "
              f"{len(row['input']['candidates'])} candidates")
    if args.write:
        target = write(rows, Path(args.out))
        print(f"written -> {target}")
    return 0 if rows else 1


if __name__ == "__main__":
    raise SystemExit(main())
