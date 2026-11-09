"""planner_vocab.py — a planner corpus in the vocabulary the planner emits.

The shipped ranker is fitted on ACCESS ids (``noncve:service:ssh:22``) and
capability ids (``web_rce``); the planner asks about CAPABILITY ids from the
registry (``scan_tcp``, ``beacon_via_rce``, ``web_creds``).  Nothing in the
training tree could express that question, so a promoted ``planner`` model was
impossible to produce honestly.

This module generates the missing corpus from the REAL capability table
(``phantom.automation.guidance.kit.CAPABILITIES``) and the REAL reverse index
(``phantom.automation.planner._FACT_SOURCES``); no capability id or fact is
invented.  A row is one decision: the eligible sources for one fact, in the
context of one goal/profile/target and the facts the run already holds.

The label is a DECLARED RUBRIC, not the deterministic ordering and not the
production ranker's output.  It encodes doctrine an operator can read:

* a move that grants control (beacon, foothold, privilege, domain takeover)
  outranks one that merely informs;
* an effect the run already holds is worth less than a new one;
* under ``stealth``/``paranoid`` a passive move outranks an active one, and
  detection risk/cost are penalised harder; a ``forceful`` move is last;
* with the noise breaker tripped the same de-escalation applies;
* the goal decides what "valuable" means (deliver prefers beacon/persistence,
  footprint prefers service/os/banner, web prefers web_app/hunt_anomaly ...).

The baseline recorded in every row is the static ``_FACT_SOURCES`` order — the
order the deterministic planner uses before any context is considered.  The
gate therefore measures the one thing a planner ranker is supposed to add:
context-dependent reordering of the same eligible set.

Limits, stated rather than hidden: this is a DECLARED corpus, not a log of
live engagements.  It measures whether a model can learn the doctrine above,
and it is comparable across checkouts; it does not prove field superiority.
``training.from_decisions`` remains the path for real exploit outcomes.

    python -m training.planner_vocab --write
    python -m training.planner_vocab --check
"""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any, Dict, List, Sequence, Tuple

PHASE = "planner"
METRIC = "ndcg"
RUBRIC_VERSION = "planner-vocab-rubric/1"
GOLDEN_PATH = (Path(__file__).resolve().parent / "golden"
               / "planner.jsonl")

#: What a grant is worth WHEN IT WORKS.  These are properties of the effect,
#: not estimates of whether this attempt succeeds, so the rubric never reads
#: ``opsec_cost``/``detection_risk`` as a label (it uses them only as a cost).
_IMPACT: Dict[str, float] = {
    "beacon": 6.0, "rce_foothold": 6.0, "shell_foothold": 6.0,
    "system_privilege": 5.5, "injection": 5.0, "persistence": 5.0,
    "ad_domain": 5.5, "ad_creds": 5.0, "cloud_access": 5.0,
    "pivot": 4.5, "mobile": 4.0, "mdm_vendor": 4.0,
    "creds": 4.0, "cracked": 4.0, "stolen_cookies": 3.5,
    "cloud_creds": 3.5, "cloud_lateral": 3.5, "web_app": 3.0,
    "hunt_anomaly": 3.0, "identity": 3.0, "victim_ip": 3.0,
    "email_verified": 2.5, "service_account": 2.5, "dossier": 2.0,
    "profile": 2.0, "account_link": 2.0, "email_candidate": 1.5,
    "domain_candidate": 1.5, "service": 1.5, "os": 1.5, "banner": 1.0,
    "version": 1.0, "web_header": 1.0, "fingerprint": 1.0,
}
DEFAULT_IMPACT = 0.5

#: Goal -> effects it is trying to reach.  A matching effect earns a bonus;
#: the rest of the rubric is goal-independent.
_GOAL_EFFECTS: Dict[str, set] = {
    "beacon": {"beacon", "rce_foothold", "persistence"},
    "complete_kill_chain": {"beacon", "persistence", "rce_foothold"},
    "deliver": {"beacon", "persistence", "creds", "rce_foothold"},
    "footprint": {"service", "os", "banner", "web_app", "version"},
    "creds": {"creds", "cracked", "email_verified"},
    "web": {"web_app", "hunt_anomaly", "rce_foothold", "xss_exfil"},
    "exploit": {"rce_foothold", "hunt_anomaly", "exploit_plan", "xss_exfil"},
    "post_exploit": {"beacon", "persistence", "system_privilege", "injection"},
    "harvest": {"stolen_cookies", "cdp_cookies", "socks_proxy", "bt_device"},
    "ad": {"ad_domain", "ad_creds"},
    "crack": {"ad_creds", "cracked"},
    "lateral": {"pivot"},
    "expand": {"internal_host", "internal_service"},
    "identity": {"identity", "victim_ip", "geolocation"},
    "enrich": {"identity", "profile", "account_link", "dossier",
               "email_candidate", "domain_candidate", "email_verified",
               "service_account", "phone", "geolocation"},
    "mobile": {"mobile", "mdm_vendor"},
    "cloud": {"cloud_creds", "cloud_access", "cloud_lateral"},
    "cloud_creds": {"cloud_creds"},
    "cloud_lateral": {"cloud_lateral", "cloud_access"},
    "evasion": {"defensive_gap"},
    "cleanup": {"cleanup"},
    "impact": {"ransom_sim"},
    "trojan": {"trojan_bundle"},
    "environment": {"environment"},
}

#: (goal, profile, target_type, noise_breaker, known facts, facts to ask).
#: A fact whose reverse index has fewer than two eligible sources is skipped
#: (one candidate is not an ordering), exactly as ``prod_vocab`` reports.
SCENARIOS: Sequence[Tuple[str, str, str, bool, Tuple[str, ...],
                          Tuple[str, ...]]] = (
    ("footprint", "enterprise", "ip", False, (), ("service", "os", "banner")),
    ("footprint", "stealth", "ip", False, (), ("service", "os", "banner")),
    ("footprint", "paranoid", "ip", False, (), ("service", "banner")),
    ("footprint", "enterprise", "ip", True, ("service",), ("service", "os")),
    ("footprint", "enterprise", "domain", False, (), ("service", "os")),
    ("deliver", "enterprise", "ip", False, ("service",),
     ("beacon", "creds", "persistence")),
    ("deliver", "stealth", "ip", False, ("service",),
     ("beacon", "creds", "persistence")),
    ("deliver", "paranoid", "ip", True, ("service", "os"),
     ("beacon", "creds")),
    ("deliver", "enterprise", "ip", True, ("service", "creds"),
     ("beacon", "persistence")),
    ("creds", "enterprise", "ip", False, ("service",), ("creds",)),
    ("creds", "stealth", "ip", False, ("service",), ("creds",)),
    ("creds", "paranoid", "ip", True, ("service",), ("creds",)),
    ("web", "enterprise", "ip", False, ("service",),
     ("web_app", "hunt_anomaly", "rce_foothold")),
    ("web", "stealth", "ip", False, ("service",),
     ("web_app", "hunt_anomaly", "rce_foothold")),
    ("web", "enterprise", "ip", True, ("service", "web_app"),
     ("hunt_anomaly", "rce_foothold")),
    ("exploit", "enterprise", "ip", False, ("service", "web_app"),
     ("rce_foothold", "hunt_anomaly")),
    ("exploit", "stealth", "ip", False, ("service",),
     ("rce_foothold", "hunt_anomaly")),
    ("post_exploit", "enterprise", "ip", False,
     ("service", "rce_foothold"), ("system_privilege", "injection", "beacon")),
    ("post_exploit", "stealth", "ip", False,
     ("service", "rce_foothold"), ("system_privilege", "injection")),
    ("post_exploit", "enterprise", "ip", True,
     ("service", "rce_foothold"), ("system_privilege", "beacon")),
    ("identity", "enterprise", "domain", False, (),
     ("identity", "victim_ip")),
    ("identity", "stealth", "domain", False, (), ("identity", "victim_ip")),
    ("enrich", "enterprise", "identity", False, (),
     ("identity", "profile", "account_link", "email_candidate")),
    ("enrich", "stealth", "identity", False, (),
     ("identity", "profile", "account_link")),
    ("mobile", "enterprise", "phone", False, (), ("mobile", "mdm_vendor")),
    ("mobile", "stealth", "phone", False, (), ("mobile", "mdm_vendor")),
    ("cloud", "enterprise", "ip", False, ("service", "creds"),
     ("cloud_creds", "cloud_access", "cloud_lateral")),
    ("cloud", "stealth", "ip", False, ("service",),
     ("cloud_creds", "cloud_access", "cloud_lateral")),
    ("cloud_lateral", "enterprise", "ip", False, ("cloud_creds",),
     ("cloud_lateral", "cloud_access")),
    ("ad", "enterprise", "ip", False, ("service",), ("ad_domain", "ad_creds")),
    ("crack", "enterprise", "ip", False, ("ad_domain",),
     ("ad_creds", "cracked")),
    ("lateral", "enterprise", "ip", False, ("service", "creds"),
     ("pivot",)),
    ("harvest", "enterprise", "ip", False, ("service",),
     ("stolen_cookies", "socks_proxy", "cdp_cookies")),
    ("expand", "enterprise", "ip", False, ("service", "beacon"),
     ("internal_host", "internal_service")),
    ("evasion", "stealth", "ip", False, ("service", "beacon"),
     ("defensive_gap",)),
)


def _capability_table() -> Dict[str, Any]:
    from phantom.automation.guidance.kit import CAPABILITIES

    return {str(c.id): c for c in CAPABILITIES}


def _fact_sources() -> Dict[str, List[str]]:
    from phantom.automation.planner import _FACT_SOURCES

    return {str(k): [str(x) for x in v] for k, v in _FACT_SOURCES.items()}


def _candidate_row(cap: Any) -> Dict[str, Any]:
    return {
        "id": str(cap.id),
        "category": str(cap.category),
        "stealth_level": str(cap.stealth_level),
        "opsec_cost": round(float(cap.opsec_cost or 0.0), 3),
        "detection_risk": round(float(cap.detection_risk or 0.0), 3),
        "forceful": bool(cap.forceful),
        "effects": sorted(str(e) for e in (cap.effects or ())),
    }


def utility(candidate: Dict[str, Any], *, goal: str, profile: str,
            noise_breaker: bool, known_facts: Sequence[str]) -> float:
    """The rubric's value for ONE candidate in ONE context.

    Pure and deterministic.  It reads the candidate's declared effects and its
    cost/risk — never the deterministic ordering and never a runtime outcome.
    """
    effects = {str(e) for e in candidate.get("effects") or ()}
    score = max((_IMPACT.get(e, DEFAULT_IMPACT) for e in effects),
                default=0.0)

    matching = effects & _GOAL_EFFECTS.get(str(goal), set())
    score += 2.0 * len(matching)
    score += 1.0 if effects else 0.0

    # A fact the run already holds is information it will not gain again.
    known = {str(x) for x in known_facts}
    score -= 0.75 * len(effects & known)

    stealthy = str(profile).lower() in ("stealth", "paranoid") or noise_breaker
    risk = float(candidate.get("detection_risk") or 0.0)
    cost = float(candidate.get("opsec_cost") or 0.0)
    level = str(candidate.get("stealth_level") or "").lower()
    if stealthy:
        score -= 4.0 * risk + 0.8 * cost
        if candidate.get("forceful"):
            score -= 3.0
        score += {"passive": 1.5, "stealth": 1.0}.get(level, 0.0)
        if level in ("active", "aggressive"):
            score -= 0.5
    else:
        score -= 1.2 * risk + 0.2 * cost
    return round(score, 6)


def _ranking(candidates: Sequence[Dict[str, Any]], *, goal: str,
             profile: str, noise_breaker: bool,
             known_facts: Sequence[str]) -> List[str]:
    """Rubric order; id breaks every tie so the label is total."""
    return [c["id"] for c in sorted(
        candidates,
        key=lambda c: (-utility(c, goal=goal, profile=profile,
                                noise_breaker=noise_breaker,
                                known_facts=known_facts),
                       str(c["id"])))]


def _baseline(fact: str, candidates: Sequence[Dict[str, Any]],
              sources: Sequence[str]) -> List[str]:
    """The static reverse-index order, filtered to the offered candidates."""
    offered = {c["id"] for c in candidates}
    order = [cid for cid in sources if cid in offered]
    # The reverse index is the planner's ordering; a candidate it does not
    # mention (a discovered driver) keeps the table's own order at the end.
    missing = [c["id"] for c in candidates if c["id"] not in order]
    return order + missing


def build_rows() -> List[Dict[str, Any]]:
    table = _capability_table()
    sources = _fact_sources()
    rows: List[Dict[str, Any]] = []
    for goal, profile, target_type, noise, known, facts in SCENARIOS:
        for fact in facts:
            ids = sources.get(str(fact)) or []
            candidates = [_candidate_row(table[cid]) for cid in ids
                          if cid in table]
            if len(candidates) < 2:
                continue
            expected = _ranking(candidates, goal=goal, profile=profile,
                                noise_breaker=noise, known_facts=known)
            baseline = _baseline(fact, candidates, ids)
            rows.append({
                "phase": PHASE,
                "rubric": RUBRIC_VERSION,
                "id": f"planner-{len(rows) + 1:03d}",
                "input": {
                    "fact": str(fact),
                    "goal": str(goal),
                    "profile": str(profile),
                    "target_type": str(target_type),
                    "noise_breaker": bool(noise),
                    "known_facts": sorted({str(x) for x in known}),
                    "candidates": candidates,
                },
                "expected": {"ranking": expected},
                "baseline": {"ranking": baseline},
            })
    return rows


def write(rows: Sequence[Dict[str, Any]], path: Path = GOLDEN_PATH) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for row in rows:
            handle.write(json.dumps(row, sort_keys=True, ensure_ascii=False)
                         + "\n")
    return path


def digest(rows: Sequence[Dict[str, Any]]) -> str:
    payload = "\n".join(json.dumps(row, sort_keys=True, ensure_ascii=False)
                        for row in rows)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def main(argv: Sequence[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="training.planner_vocab",
                                     description=__doc__)
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args(argv)

    rows = build_rows()
    print(f"{len(rows)} planner row(s), rubric {RUBRIC_VERSION}, "
          f"sha256 {digest(rows)[:16]}")
    for row in rows[:4]:
        print(f"  {row['input']['goal']:>13} {row['input']['fact']:>14} "
              f"{len(row['input']['candidates'])} candidates -> "
              f"{row['expected']['ranking'][0]}")
    if args.check:
        if not GOLDEN_PATH.is_file():
            print(f"missing {GOLDEN_PATH}; run --write")
            return 1
        existing = [json.loads(line) for line in
                    GOLDEN_PATH.read_text(encoding="utf-8").splitlines()
                    if line.strip()]
        if digest(existing) != digest(rows):
            print(f"drift: {GOLDEN_PATH} does not match the generator")
            return 1
        print("no drift")
    if args.write:
        print(f"written -> {write(rows)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
