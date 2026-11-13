"""
timeline.py — the engagement timeline.

A report answers "what did we find". A timeline answers "what happened,
in what order, and what did it lead to" — the question a client actually
asks first and the question an operator asks when a run stalls.

Everything the engine already records is timestamped:

    * ``wm.all_findings()``    -> Finding.ts
    * ``wm.actions_taken``     -> action["ts"]
    * ``wm.failures``          -> failure["ts"]
    * ``wm.noise_events``      -> event["ts"]
    * C2 evidence              -> beacon / task records

This module merges all of them into ONE ordered stream of
:class:`TimelineEntry`, tags each entry with its kill-chain phase (via the
canonical ``phases.phase_of`` index, so the timeline can never drift from
the registry) and a severity, and renders it two ways:

    * operator view — full detail, commands, raw evidence
    * client view   — no commands, no raw evidence, phase-level narrative

Pure functions over the world model: no network, no disk, no side effects.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, Iterable, List, Optional

_SEV_ORDER = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}

# finding kind -> (severity, human label). Kinds not listed fall back to
# "info"; the label is what the client report prints.
_KIND_RISK: Dict[str, tuple] = {
    "beacon": ("critical", "Beacon / implant established"),
    "rce_foothold": ("critical", "Remote code execution"),
    "cloud_creds": ("critical", "Cloud credentials exposed"),
    "cloud_iam": ("critical", "Cloud IAM principals enumerated"),
    "cloud_identity": ("critical", "Cloud identity hijack path"),
    "creds": ("high", "Valid credentials"),
    "creds_valid": ("high", "Valid credentials"),
    "exploit": ("high", "Exploited vulnerability"),
    "exploit_plan": ("high", "Exploitable vulnerability confirmed"),
    "vuln_class": ("high", "Vulnerability class detected"),
    "hunt_anomaly": ("high", "Behavioural anomaly confirmed"),
    "differential_anomaly": ("high", "Differential anomaly confirmed"),
    "persistence": ("high", "Persistence installed"),
    "privilege": ("high", "Privilege escalation"),
    "defensive_gap": ("high", "Defensive controls bypassed"),
    "stolen_cookies": ("high", "Session cookies stolen"),
    "cdp_cookies": ("high", "Browser session cookies harvested"),
    "ad_hint": ("medium", "Active Directory surface"),
    "ad_recon": ("medium", "AD enumeration"),
    "kerberoast": ("medium", "Kerberoastable service account"),
    "as_rep_roast": ("medium", "AS-REP roastable account"),
    "internal_host": ("medium", "Internal host discovered"),
    "internal_service": ("medium", "Internal service discovered"),
    "pivot": ("medium", "Lateral movement"),
    "k8s_escape": ("high", "Container escape path"),
    "mobile": ("medium", "Mobile device surface"),
    "mobile_platform": ("medium", "Mobile platform identified"),
    "mdm_vendor": ("medium", "MDM vendor identified"),
    "web_app": ("medium", "Web application"),
    "web_endpoint": ("low", "Web endpoint"),
    "vulnerability": ("high", "Vulnerability"),
    "service": ("info", "Exposed service"),
    "os": ("info", "Operating system"),
    "banner": ("info", "Service banner"),
    "web_header": ("info", "Web server header"),
    "fingerprint": ("info", "Service fingerprint"),
    "identity": ("info", "Identity"),
    "breach": ("high", "Breach exposure"),
    "campaign": ("medium", "Phishing campaign"),
    "phish_hit": ("high", "Lure interaction"),
    "ip_grab": ("high", "Victim geolocated via lure"),
    "report": ("info", "Report"),
    "note": ("info", "Note"),
    "host": ("info", "Network host"),
    "subnet": ("info", "Network segment"),
}

# finding kinds whose very EXISTENCE is secret material. The client
# report only ever states impact ("accounts compromised"), never names a
# credential finding — the timeline must respect the same invariant, or a
# sanitised report would leak it back through the chronology.
_CLIENT_HIDDEN_REFS = frozenset({
    "creds", "creds_valid", "cloud_creds", "ad_creds", "cracked",
    "stolen_cookies", "cdp_cookies", "hash", "ntlm",
})

# capability id fragment -> phase, used when a capability is not in the
# canonical phase index (defensive fallback so a new capability still lands
# somewhere sensible instead of "unknown").
_PHASE_HINTS = (
    ("scan", "recon"), ("nmap", "recon"), ("port", "recon"),
    ("osint", "osint"), ("breach", "osint"), ("persona", "osint"),
    ("dossier", "osint"), ("profile", "osint"), ("recon", "osint"),
    ("exploit", "exploit"), ("hunt", "exploit"), ("anomaly", "exploit"),
    ("foothold", "foothold"), ("rce", "foothold"), ("shell", "foothold"),
    ("beacon", "beacon"), ("payload", "beacon"), ("deliver", "beacon"),
    ("login", "foothold"), ("cred", "foothold"),
    ("privesc", "post"), ("persist", "post"), ("pivot", "post"),
    ("cloud", "post"), ("internal", "post"), ("loot", "post"),
    ("edr", "post"), ("k8s", "post"), ("ransom", "post"),
    ("report", "report"),
)


def _phase_for(capability_or_kind: str) -> str:
    """Resolve the kill-chain phase for a capability id or a finding kind."""
    cid = (capability_or_kind or "").strip()
    if not cid:
        return "other"
    try:
        from phantom.automation.phases import phase_of
        phase = phase_of(cid)
        if phase:
            return phase
    except Exception:
        pass
    low = cid.lower()
    for frag, phase in _PHASE_HINTS:
        if frag in low:
            return phase
    return "other"


def _iso(ts: float) -> str:
    try:
        return datetime.fromtimestamp(float(ts)).isoformat(timespec="seconds")
    except Exception:
        return ""


@dataclass
class TimelineEntry:
    """One thing that happened, at one moment, in one phase."""

    ts: float
    phase: str
    kind: str                     # finding | action | failure | noise | beacon
    summary: str
    actor: str = ""               # capability id / source
    detail: str = ""
    severity: str = "info"
    target: str = ""
    ok: Optional[bool] = None     # for actions: did it work
    ref: str = ""                 # finding kind / capability, for filtering

    @property
    def iso(self) -> str:
        return _iso(self.ts)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "ts": self.ts,
            "iso": self.iso,
            "phase": self.phase,
            "kind": self.kind,
            "actor": self.actor,
            "summary": self.summary,
            "detail": self.detail,
            "severity": self.severity,
            "target": self.target,
            "ok": self.ok,
            "ref": self.ref,
        }


# ── collection ──────────────────────────────────────────────────────────────


def _finding_entry(f) -> TimelineEntry:
    kind = str(getattr(f, "kind", "") or "")
    severity, label = _KIND_RISK.get(kind, ("info", kind or "finding"))
    value = getattr(f, "value", None)
    detail = ""
    if isinstance(value, dict):
        parts = []
        for k in ("port", "service", "product", "version", "name", "user",
                  "host", "ip", "path", "category", "class", "vendor",
                  "provider", "account", "role"):
            v = value.get(k)
            if v not in (None, "", []):
                parts.append(f"{k}={v}")
        detail = " · ".join(parts)
    elif value not in (None, "", []):
        detail = str(value)[:300]
    if detail:
        summary = f"{label}: {detail}"
    else:
        summary = label
    return TimelineEntry(
        ts=float(getattr(f, "ts", 0.0) or 0.0),
        phase=_phase_for(str(getattr(f, "source", "") or "")) if
        _phase_for(str(getattr(f, "source", "") or "")) != "other"
        else _phase_for(kind),
        kind="finding",
        summary=summary,
        actor=str(getattr(f, "source", "") or kind),
        detail=detail,
        severity=severity,
        target=str(getattr(f, "target", "") or ""),
        ref=kind,
    )


def _action_entry(a: Dict[str, Any]) -> TimelineEntry:
    cap = str(a.get("capability", "") or "")
    ok = a.get("ok")
    cmd = str(a.get("command", "") or "")
    note = str(a.get("note", "") or "")
    summary = f"{cap} — {'ok' if ok else 'failed'}"
    if note:
        summary += f" ({note[:120]})"
    return TimelineEntry(
        ts=float(a.get("ts", 0.0) or 0.0),
        phase=_phase_for(cap),
        kind="action",
        summary=summary,
        actor=cap,
        detail=cmd or note,
        severity="info",
        target=str(a.get("target", "") or ""),
        ok=bool(ok) if ok is not None else None,
        ref=cap,
    )


def _failure_entry(f: Dict[str, Any]) -> TimelineEntry:
    cap = str(f.get("capability", "") or "")
    reason = str(f.get("reason", "") or "")
    return TimelineEntry(
        ts=float(f.get("ts", 0.0) or 0.0),
        phase=_phase_for(cap),
        kind="failure",
        summary=f"{cap} — {reason[:200]}",
        actor=cap,
        detail=str(f.get("evidence", "") or ""),
        severity="low",
        ok=False,
        ref=cap,
    )


def _noise_entry(n: Dict[str, Any]) -> TimelineEntry:
    return TimelineEntry(
        ts=float(n.get("ts", 0.0) or 0.0),
        phase="opsec",
        kind="noise",
        summary=f"detection risk +{n.get('weight', 0)} "
                f"({n.get('event', '')}) → score {n.get('score', 0)}",
        actor=str(n.get("event", "") or "noise"),
        severity="info" if float(n.get("score", 0) or 0) < 8 else "medium",
    )


def _beacon_entries(evidence: Iterable[Dict[str, Any]]) -> List[TimelineEntry]:
    """C2 evidence has no epoch ts; keep source order and place the block
    at the end of the stream with a stable synthetic ordering."""
    out: List[TimelineEntry] = []
    base = 0.0
    for i, ev in enumerate(evidence or []):
        rec = ev if isinstance(ev, dict) else {}
        if "beacon_id" not in rec and "task_id" not in rec:
            continue
        task = rec.get("task_id")
        if task:
            summary = (f"beacon task {task} returned output "
                       f"({len(str(rec.get('output_tail', '')))} chars)")
            ok: Optional[bool] = True
        else:
            summary = (f"beacon {rec.get('beacon_id', '')} checked in from "
                       f"{rec.get('ip', '?')} ({rec.get('os', '?')})")
            ok = True
        out.append(TimelineEntry(
            ts=base + i * 1e-6,
            phase="beacon",
            kind="beacon",
            summary=summary,
            actor="c2",
            detail=str(rec.get("output_tail", "") or "")[:400],
            severity="critical" if not task else "high",
            target=str(rec.get("hostname", "") or ""),
            ok=ok,
            ref="beacon",
        ))
    return out


# ── public API ──────────────────────────────────────────────────────────────


def build_timeline(wm, c2_evidence: Optional[Iterable[Dict[str, Any]]] = None,
                   started: Optional[float] = None) -> List[TimelineEntry]:
    """Merge every recorded event into one ordered stream.

    Pure: reads the world model, never mutates it. Entries with a missing
    timestamp are dropped rather than silently sorted to the epoch.
    """
    entries: List[TimelineEntry] = []

    for f in (wm.all_findings() if wm is not None else []):
        entries.append(_finding_entry(f))
    for a in (getattr(wm, "actions_taken", []) or []):
        entries.append(_action_entry(a if isinstance(a, dict) else {}))
    for f in (getattr(wm, "failures", []) or []):
        entries.append(_failure_entry(f if isinstance(f, dict) else {}))
    for n in (getattr(wm, "noise_events", []) or []):
        entries.append(_noise_entry(n if isinstance(n, dict) else {}))

    beacon = _beacon_entries(c2_evidence or [])
    if beacon:
        offset = 0.0
        if started is not None:
            offset = float(started)
        # place C2 activity after the last recorded event
        last = max((e.ts for e in entries), default=offset)
        for i, e in enumerate(beacon):
            e.ts = last + 1.0 + i * 1e-3
        entries.extend(beacon)

    entries = [e for e in entries if e.ts > 0.0]
    entries.sort(key=lambda e: (e.ts, _SEV_ORDER.get(e.severity, 9)))
    return entries


def timeline_stats(entries: List[TimelineEntry]) -> Dict[str, Any]:
    """Phase/severity roll-up used by the report headers and the UI."""
    by_phase: Dict[str, int] = {}
    by_severity: Dict[str, int] = {}
    by_kind: Dict[str, int] = {}
    for e in entries:
        by_phase[e.phase] = by_phase.get(e.phase, 0) + 1
        by_severity[e.severity] = by_severity.get(e.severity, 0) + 1
        by_kind[e.kind] = by_kind.get(e.kind, 0) + 1
    return {
        "total": len(entries),
        "by_phase": by_phase,
        "by_severity": by_severity,
        "by_kind": by_kind,
        "first": entries[0].iso if entries else "",
        "last": entries[-1].iso if entries else "",
    }


_LEVEL_TAG = {"critical": "!!", "high": "!", "medium": "-", "low": ".",
              "info": ""}


def render_markdown(entries: List[TimelineEntry], client: bool = False,
                    max_entries: int = 400) -> List[str]:
    """Render the timeline as markdown lines.

    ``client=True`` hides commands, raw evidence and internal capability
    ids: the client sees WHAT happened and WHEN, not our tradecraft.
    """
    lines: List[str] = ["## Engagement Timeline", ""]
    if not entries:
        lines += ["_No recorded activity._", ""]
        return lines

    stats = timeline_stats(entries)
    lines.append(
        f"> {stats['total']} events · {stats['first']} → {stats['last']}")
    if stats["by_phase"]:
        order = ["recon", "osint", "exploit", "foothold", "beacon", "post",
                 "opsec", "report", "other"]
        parts = [f"{p}: {stats['by_phase'][p]}" for p in order
                 if p in stats["by_phase"]]
        lines.append("> " + " · ".join(parts))
    lines.append("")

    shown = entries[:max_entries]
    for e in shown:
        when = e.iso.replace("T", " ") if e.iso else "—"
        tag = _LEVEL_TAG.get(e.severity, "")
        phase = e.phase
        if client:
            # client view: phase + outcome, never the command
            if e.kind == "action":
                continue  # actions are operator tradecraft, not client data
            if e.ref in _CLIENT_HIDDEN_REFS:
                # a credential finding is secret material: the client report
                # states impact elsewhere, the timeline must not name it
                continue
            if e.kind == "failure":
                summary = f"{e.phase}: automated check did not apply"
            elif e.kind == "noise":
                summary = "detection surface touched"
            else:
                summary = e.summary
            lines.append(f"- `{when}` **[{phase}]** {summary}")
        else:
            head = f"- `{when}` **[{phase}]** {tag} " if tag else \
                   f"- `{when}` **[{phase}]** "
            lines.append(head + e.summary)
            if e.detail and e.kind in ("action", "beacon"):
                lines.append(f"  - `{e.detail[:300]}`")

    if len(entries) > len(shown):
        lines.append(f"- _… {len(entries) - len(shown)} more events "
                     f"(see raw_report.json)_")
    lines.append("")
    return lines


def to_dicts(entries: List[TimelineEntry]) -> List[Dict[str, Any]]:
    return [e.to_dict() for e in entries]


# ── in-memory store for live views (CLI/Electron) ───────────────────────────


@dataclass
class TimelineStore:
    """Holds the last built timeline so the CLI and the API can render it
    without rebuilding from the world model on every request."""

    entries: List[TimelineEntry] = field(default_factory=list)
    built_at: str = ""

    def update(self, entries: List[TimelineEntry]) -> None:
        self.entries = list(entries or [])
        self.built_at = datetime.now().isoformat(timespec="seconds")

    def stats(self) -> Dict[str, Any]:
        return timeline_stats(self.entries)

    def recent(self, n: int = 50) -> List[TimelineEntry]:
        return self.entries[-max(1, int(n)):]


_timeline_store = TimelineStore()


def store() -> TimelineStore:
    return _timeline_store
