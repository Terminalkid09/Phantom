"""build_dataset.py — turn run artefacts into per-phase SFT examples.

Inputs, all optional and all local:

* session checkpoints (``data/sessions/**/checkpoint.json`` and the flat
  JSON files): the WorldModel's actions, findings, identity edges and
  failures are the most honest labels Phantom has — they are what a run
  actually did and actually learned;
* ``data/exploit_packs.json``: CVE -> resolved weapon, a curated label for
  the exploit phase;
* ``data/experience_cases.json``: cross-engagement episodes, when present.

Every record is written as chat JSONL:

    {"phase": "...", "source": "...", "label": "...",
     "messages": [{"role": "system"|"user"|"assistant", "content": "..."}]}

Design rules:

* **No invented labels.** A record is emitted only when the artefact carries
  the assistant side (an action outcome, a stored finding, a pack, a failure
  with a named unblock). The rest is counted as ``skipped`` in the manifest.
* **Redaction before writing.** Passwords, tokens, private keys, e-mail
  addresses and Windows user paths are rewritten; the count is recorded so a
  dataset can be audited without printing the secrets.
* **Deterministic.** Files and records are processed in sorted order, so two
  builds of the same tree produce byte-identical output.

Nothing here imports torch or reaches the network.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import re
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Dict, Iterable, List, Optional, Tuple

from training.phases import PHASE_ORDER, PHASES

DEFAULT_SESSIONS = "data/sessions"
DEFAULT_EXPERIENCE = "data/experience_cases.json"
DEFAULT_PACKS = "data/exploit_packs.json"
DEFAULT_OUT = "training/data"

# A secret assignment, a bearer token, a private key block, an e-mail and a
# Windows user path. Order matters: key blocks before the generic assignment.
_KEY_BLOCK = re.compile(
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----",
    re.DOTALL)
_ASSIGN = re.compile(
    r"(?i)\b(password|passwd|pwd|token|api[_-]?key|secret|authorization|"
    r"cookie)\b[\"']?\s*[:=]\s*(\"[^\"]*\"|'[^']*'|[^\s,;]+)")
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-+/=]{6,}")
_EMAIL = re.compile(r"\b([A-Za-z0-9._%+-])[A-Za-z0-9._%+-]*@([A-Za-z0-9.-]+\.[A-Za-z]{2,})\b")
_WIN_USER = re.compile(r"(?i)\bC:\\Users\\[^\\\s\"]+")


def _mask_email(match: re.Match) -> str:
    return f"{match.group(1)}***@{match.group(2)}"


def redact(text: str) -> Tuple[str, int]:
    """Rewrite secrets/PII in one string. Returns (clean, substitutions)."""
    if not isinstance(text, str) or not text:
        return text, 0
    hits = 0

    def _sub(pattern: re.Pattern, repl, value: str) -> str:
        nonlocal hits
        value, count = pattern.subn(repl, value)
        hits += count
        return value

    text = _sub(_KEY_BLOCK, "<REDACTED KEY>", text)
    text = _sub(_ASSIGN, r"\1=<REDACTED>", text)
    text = _sub(_BEARER, "Bearer <REDACTED>", text)
    text = _sub(_EMAIL, _mask_email, text)
    text = _sub(_WIN_USER, r"C:\\Users\\<USER>", text)
    return text, hits


def redact_obj(value: Any) -> Tuple[Any, int]:
    """Recursively redact every string in a JSON-like value."""
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        out, hits = [], 0
        for item in value:
            clean, count = redact_obj(item)
            out.append(clean)
            hits += count
        return out, hits
    if isinstance(value, dict):
        out, hits = {}, 0
        for key, item in value.items():
            clean, count = redact_obj(item)
            out[key] = clean
            hits += count
        return out, hits
    return value, 0


# ── source loading ──────────────────────────────────────────────────────────

def _read_json(path: Path) -> Optional[Any]:
    try:
        return json.loads(path.read_text(encoding="utf-8", errors="replace"))
    except (OSError, ValueError):
        return None


def load_sessions(directory: str | Path) -> List[Tuple[str, dict]]:
    """Every session-shaped JSON under `directory`, sorted by path."""
    root = Path(directory)
    if not root.is_dir():
        return []
    paths = sorted(root.rglob("checkpoint.json")) + sorted(root.glob("*.json"))
    out: List[Tuple[str, dict]] = []
    seen = set()
    for path in paths:
        if path in seen:
            continue
        seen.add(path)
        data = _read_json(path)
        if isinstance(data, dict) and ("wm" in data or "goal" in data):
            out.append((str(path), data))
    return out


def _pack_examples(path: str | Path) -> List[dict]:
    data = _read_json(Path(path))
    packs = (data or {}).get("packs") if isinstance(data, dict) else None
    if not isinstance(packs, dict):
        return []
    out: List[dict] = []
    for cve in sorted(packs):
        pack = packs.get(cve)
        if not isinstance(pack, dict):
            continue
        module = str(pack.get("msf_module") or "")
        if not module and not pack.get("poc"):
            continue
        out.append({
            "cve": cve,
            "module": module,
            "status": str(pack.get("status") or "candidate"),
            "notes": str(pack.get("notes") or ""),
            "source": "packs",
        })
    return out


def _experience_examples(path: str | Path) -> List[dict]:
    data = _read_json(Path(path))
    rows = data if isinstance(data, list) else (
        data.get("cases") if isinstance(data, dict) else None)
    if not isinstance(rows, list):
        return []
    out = []
    for row in rows:
        if isinstance(row, dict) and row.get("phase") in PHASES:
            out.append(row)
    return out


# ── per-phase extraction ────────────────────────────────────────────────────

def _system(phase: str) -> str:
    return (f"You are Phantom's {phase} model. {PHASES[phase]['task']} "
            f"Answer with JSON matching the {PHASES[phase]['schema']} schema "
            f"only: no prose, no commands, no invented ids.")


def _messages(phase: str, payload: dict, answer: dict) -> dict:
    return {
        "phase": phase,
        "messages": [
            {"role": "system", "content": _system(phase)},
            {"role": "user", "content": json.dumps(payload, sort_keys=True,
                                                   ensure_ascii=False)},
            {"role": "assistant", "content": json.dumps(
                answer, sort_keys=True, ensure_ascii=False)},
        ],
    }


def _findings(wm: dict, kind: str) -> List[dict]:
    return [f for f in (wm.get("findings") or [])
            if isinstance(f, dict) and f.get("kind") == kind]


def _services(wm: dict) -> List[dict]:
    out = []
    for finding in _findings(wm, "service"):
        value = finding.get("value")
        if isinstance(value, dict):
            out.append({k: value.get(k) for k in
                        ("port", "service", "product", "version")
                        if value.get(k) not in (None, "")})
    return out


def _cves(wm: dict) -> List[dict]:
    out = []
    for finding in _findings(wm, "vulnerability") + _findings(wm, "cve"):
        value = finding.get("value")
        if isinstance(value, dict):
            out.append({"id": value.get("id") or value.get("cve"),
                        "cvss": value.get("cvss"),
                        "product": value.get("product")})
    return out


# The label is the RUNTIME schema, not a builder-private shape: a model
# trained on {"chosen": ...} would be rejected by validate_exploit on every
# call. Keep these in lockstep with phantom/automation/ai/schemas.py.
_FINDING_KIND = {
    "os_inferred": "os",
    "attack_path": "vuln_class",
    "rce_foothold": "vuln_class",
    "web_anomaly": "hunt_anomaly",
    "pivot_plan": "note",
    "service_role": "note",
    "beacon": "note",
    "persistence": "note",
    "web_header": "note",
}
_ALLOWED_FINDING_KINDS = {
    "service", "os", "creds", "vuln_class", "hunt_anomaly", "identity",
    "email_candidate", "email_verified", "web_app", "recon_verdict",
    "hostname", "origin", "note",
}


def _finding_kind(kind: str) -> str:
    mapped = _FINDING_KIND.get(kind, kind)
    return mapped if mapped in _ALLOWED_FINDING_KINDS else "note"


def _exploit_candidates(session: dict) -> List[dict]:
    """The candidate table the run actually had, in the runtime's shape.

    Built from the run's own record — the actions it executed and the
    hypotheses the planner was still holding. An id the run never saw is
    never invented, and the order is the run's, not a score's.
    """
    wm = session.get("wm") or {}
    rows: List[dict] = []
    seen = set()

    def _push(cid: Any, **extra: Any) -> None:
        cid = str(cid or "").strip()
        if not cid or cid in seen:
            return
        seen.add(cid)
        row: Dict[str, Any] = {"id": cid}
        row.update({k: v for k, v in extra.items() if v not in (None, "")})
        rows.append(row)

    for action in wm.get("actions") or []:
        if isinstance(action, dict):
            _push(action.get("capability"))
    for hypothesis in wm.get("hypotheses") or []:
        if isinstance(hypothesis, dict):
            _push(hypothesis.get("capability_id"),
                  priority=hypothesis.get("priority"))
    return rows


def _exploit_outcome_ranking(session: dict,
                             candidates: List[dict]) -> List[dict]:
    """Order the candidate table by what the RUN established.

    Tier 1 is an executed action that worked (in the order it worked); tier 2
    is the planner's pending hypotheses, best priority first; tier 3 is what
    the engagement already tried and failed, which a rerun must not read as a
    fresh idea. Every rank is an observation, so the label is a measured
    order instead of a restatement of the deterministic scorer — training on
    the scorer's own output would only teach the model to copy it.
    """
    wm = session.get("wm") or {}
    known = {row["id"] for row in candidates}
    priorities = {str(h.get("capability_id")): float(h.get("priority") or 0.0)
                  for h in (wm.get("hypotheses") or [])
                  if isinstance(h, dict)}
    failed = {str(f.get("capability")) for f in (wm.get("failures") or [])
              if isinstance(f, dict)}
    order: List[dict] = []
    seen = set()

    def _push(cid: Any, reason: str, success: float) -> None:
        cid = str(cid or "")
        if cid in known and cid not in seen:
            seen.add(cid)
            order.append({"id": cid, "reason": reason,
                          "expected_success": success})

    for action in wm.get("actions") or []:
        if isinstance(action, dict) and action.get("ok"):
            _push(action.get("capability"), "executed and successful", 0.7)
    for cid, _prio in sorted(priorities.items(), key=lambda kv: (-kv[1], kv[0])):
        _push(cid, "planner candidate, never executed", 0.5)
    for action in wm.get("actions") or []:
        if isinstance(action, dict) and not action.get("ok"):
            _push(action.get("capability"), "executed, failed", 0.2)
    for cid in sorted(failed):
        _push(cid, "already failed this engagement", 0.05)
    return order


def _exploit_examples(session: dict) -> List[dict]:
    """One graded example per executed step.

    The old label ranked exactly ONE id (the capability the run happened to
    pick), so the phase could never teach ORDER — and the golden set's NDCG
    was unwinnable against a heuristic that returns the whole table (measured
    2026-10-26: adapter 0.5068 vs baseline 0.9065). Each row now carries the
    run's real candidate table and a graded tail, so the ranking is a task
    with a measurable answer while the run's own decision stays first.
    """
    wm = session.get("wm") or {}
    services, cves = _services(wm), _cves(wm)
    actions = [a for a in (wm.get("actions") or [])
               if isinstance(a, dict) and a.get("capability")]
    candidates = _exploit_candidates(session)
    if not actions or not candidates or not (services or cves):
        return []
    graded = _exploit_outcome_ranking(session, candidates)
    failed = wm.get("failures") or []
    out = []
    for index, action in enumerate(actions):
        chosen = str(action.get("capability"))
        if chosen not in {row["id"] for row in candidates}:
            continue          # never rank an id the table does not carry
        was_failed = any(f.get("capability") == chosen for f in failed
                         if isinstance(f, dict))
        answer = {
            "ranked": [{
                "id": chosen,
                "reason": "recorded action outcome",
                "expected_success": 0.2 if was_failed else 0.7,
            }] + [row for row in graded if row["id"] != chosen],
            "notes": "",
        }
        out.append(_messages("exploit", {
            "mode": "balanced",
            "target": session.get("target", ""),
            "goal": session.get("goal", ""),
            "profile": session.get("profile", ""),
            "services": services,
            "cves": cves,
            "candidates": candidates,
            "already_tried": [a.get("capability") for a in actions[:index]],
        }, answer))
    return out


def _finding_examples(session: dict) -> List[dict]:
    out = []
    for finding in (session.get("wm") or {}).get("findings") or []:
        if not isinstance(finding, dict) or not finding.get("kind"):
            continue
        key = str(finding.get("key") or "").strip()
        if not key:
            continue
        raw = {k: finding.get(k) for k in
               ("kind", "key", "value", "confidence", "source", "evidence")
               if finding.get(k) not in (None, "")}
        row = {"kind": _finding_kind(str(finding.get("kind"))),
               "key": key[:200], "value": finding.get("value")}
        if isinstance(finding.get("confidence"), (int, float)):
            row["confidence"] = max(0.0, min(1.0,
                                             float(finding["confidence"])))
        out.append(_messages("finding", {"observation": raw},
                             {"findings": [row], "next": []}))
    return out


def _osint_examples(session: dict) -> List[dict]:
    identity = (session.get("wm") or {}).get("identity") or {}
    nodes = {n.get("key") or n.get("value"): n
             for n in identity.get("nodes") or [] if isinstance(n, dict)}
    out = []
    for edge in identity.get("edges") or []:
        if not isinstance(edge, dict):
            continue
        src, dst = edge.get("src"), edge.get("dst")
        if src not in nodes or dst not in nodes:
            continue
        candidate = nodes[dst]
        handle = str(candidate.get("handle") or candidate.get("key") or "")
        platform = str(candidate.get("platform") or "")
        if not handle or not platform:
            continue
        out.append(_messages("osint", {
            "primary": nodes[src], "candidate": candidate,
        }, {"links": [{
            "handle": handle,
            "platform": platform,
            "confidence": max(0.0, min(0.79, float(
                edge.get("confidence") or 0.5))),
            "signals": [str(edge.get("kind") or "graph_edge")],
        }], "notes": ""}))
    return out


def _scan_examples(session: dict) -> List[dict]:
    """Only a real tool OUTPUT teaches parsing; a command alone does not."""
    wm = session.get("wm") or {}
    services = []
    for row in _services(wm):
        port = row.get("port")
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            continue
        clean = {"port": port}
        for field in ("service", "product", "version"):
            if row.get(field):
                clean[field] = str(row[field])[:120]
        services.append(clean)
    out = []
    for action in wm.get("actions") or []:
        if not isinstance(action, dict):
            continue
        if action.get("capability") not in ("scan_tcp", "version_detect",
                                            "masscan"):
            continue
        output = str(action.get("output") or "")
        if not output.strip() or not services:
            continue
        out.append(_messages("scan_parse", {"tool": "nmap", "output": output},
                             {"findings": services, "notes": ""}))
    return out


def _evolution_examples(session: dict) -> List[dict]:
    out = []
    for failure in (session.get("wm") or {}).get("failures") or []:
        if not isinstance(failure, dict) or not failure.get("capability"):
            continue
        cause = str(failure.get("reason") or "unknown")
        unblock = str(failure.get("unblock") or "")
        answer = {
            "summary": cause[:400],
            "causes": [cause[:200]],
            "proposal": unblock[:400],
        }
        out.append(_messages("evolution", {
            "failure": failure,
            "target": session.get("target", ""),
            "goal": session.get("goal", ""),
        }, answer))
    return out


def _social_examples(session: dict) -> List[dict]:
    """Only real campaign artefacts; a run without one contributes nothing."""
    out = []
    for finding in (session.get("wm") or {}).get("findings") or []:
        if not isinstance(finding, dict):
            continue
        if finding.get("kind") not in ("campaign", "phish", "dm"):
            continue
        value = finding.get("value")
        if not isinstance(value, dict) or not value.get("body"):
            continue
        out.append(_messages("social", {
            "channel": value.get("channel", "dm"),
            "pretext": value.get("pretext", ""),
            "context": value.get("context", {}),
        }, {"text": str(value.get("body"))}))
    return out


_EXTRACTORS = {
    "exploit": _exploit_examples,
    "finding": _finding_examples,
    "osint": _osint_examples,
    "scan_parse": _scan_examples,
    "evolution": _evolution_examples,
    "social": _social_examples,
}


def _pack_messages(row: dict) -> dict:
    answer = {
        "ranked": [{
            "id": row["cve"],
            "reason": row["notes"] or "recorded weapon",
            "expected_success": 0.7 if row["status"] == "verified" else 0.5,
        }],
        "notes": "",
    }
    return _messages("exploit", {
        "target": "", "goal": "exploit",
        "cves": [{"id": row["cve"]}],
        "candidates": [{"id": row["cve"], "module": row["module"],
                        "status": row["status"]}],
    }, answer)


# ── build + write ───────────────────────────────────────────────────────────

def build(phase: str, sessions: List[Tuple[str, dict]],
          packs: List[dict], experience: List[dict],
          *, limit: int = 0) -> Tuple[List[dict], Dict[str, int]]:
    """(records, stats) for one phase. Pure; no I/O for the sources."""
    stats = {"skipped": 0, "dupes": 0, "redactions": 0, "sessions": 0}
    records: List[dict] = []
    seen = set()

    def add(record: dict, source: str, label: str) -> None:
        record = dict(record)
        record["source"] = source
        record["label"] = label
        clean, hits = redact_obj(record)
        stats["redactions"] += hits
        text = json.dumps(clean.get("messages"), sort_keys=True)
        digest = hashlib.sha256(text.encode("utf-8")).hexdigest()
        if digest in seen:
            stats["dupes"] += 1
            return
        seen.add(digest)
        records.append(clean)

    extractor = _EXTRACTORS.get(phase)
    for path, session in sessions:
        if extractor is None:
            break
        stats["sessions"] += 1
        for record in extractor(session):
            add(record, source=path, label="session")
        if limit and len(records) >= limit:
            break

    if phase == "exploit":
        for row in packs:
            add(_pack_messages(row), source="exploit_packs", label="pack")

    for row in experience:
        if row.get("phase") != phase:
            continue
        payload = row.get("input")
        answer = row.get("output")
        if isinstance(payload, dict) and isinstance(answer, dict):
            add(_messages(phase, payload, answer), source="experience",
                label="case")

    stats["skipped"] = max(0, len(sessions) - stats["sessions"])
    return records, stats


def write_jsonl(path: Path, records: Iterable[dict]) -> int:
    path.parent.mkdir(parents=True, exist_ok=True)
    count = 0
    with open(path, "w", encoding="utf-8", newline="\n") as handle:
        for record in records:
            handle.write(json.dumps(record, sort_keys=True,
                                    ensure_ascii=False) + "\n")
            count += 1
    return count


def main(argv: Optional[List[str]] = None) -> int:
    parser = argparse.ArgumentParser(
        prog="training.build_dataset",
        description="Build per-phase SFT JSONL from local run artefacts.")
    parser.add_argument("--phase", default="all",
                        choices=list(PHASE_ORDER) + ["all"])
    parser.add_argument("--sessions-dir", default=DEFAULT_SESSIONS)
    parser.add_argument("--experience", default=DEFAULT_EXPERIENCE)
    parser.add_argument("--packs", default=DEFAULT_PACKS)
    parser.add_argument("--out", default=DEFAULT_OUT,
                        help="output DIRECTORY (one file per phase)")
    parser.add_argument("--limit", type=int, default=0,
                        help="max records per phase (0 = no limit)")
    parser.add_argument("--quiet", action="store_true")
    args = parser.parse_args(argv)

    phases = list(PHASE_ORDER) if args.phase == "all" else [args.phase]
    sessions = load_sessions(args.sessions_dir)
    packs = _pack_examples(args.packs)
    experience = _experience_examples(args.experience)
    out_dir = Path(args.out)
    out_dir.mkdir(parents=True, exist_ok=True)

    for phase in phases:
        records, stats = build(phase, sessions, packs, experience,
                               limit=max(0, args.limit))
        out_path = out_dir / f"{phase}.jsonl"
        count = write_jsonl(out_path, records)
        manifest = {
            "phase": phase,
            "count": count,
            "sessions": len(sessions),
            "stats": stats,
            "sources": sorted({str(r.get("source")) for r in records}),
            "built_at": datetime.now(timezone.utc).strftime(
                "%Y-%m-%dT%H:%M:%SZ"),
            "sha256": hashlib.sha256(
                out_path.read_bytes()).hexdigest() if out_path.exists()
            else "",
        }
        (out_dir / f"{phase}.manifest.json").write_text(
            json.dumps(manifest, indent=2, sort_keys=True) + "\n",
            encoding="utf-8")
        if not args.quiet:
            print(f"{phase}: {count} record(s) -> {out_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
