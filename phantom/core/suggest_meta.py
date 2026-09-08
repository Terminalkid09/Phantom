"""suggest_meta.py — evidence-tagged, trust-earned suggestions.

The manual core's `suggest` becomes auditable: every suggestion carries

  * WHY      — the concrete findings that produced it
               ("tcp/445 open + anon share reachable + admin creds")
  * TRUST    — 0..1 confidence, blended from evidence strength and the
               historical success rate of this capability class
  * PREFLIGHT — whether the command's tools exist on THIS host, whether
               the target is in scope, and whether it already ran OK
               (dedup against engagement history)

An operator can verify the reasoning in two seconds — that is the only
way suggestion engines get used instead of abandoned.
"""

from __future__ import annotations

import re
import shutil
from dataclasses import dataclass, field
from typing import Dict, List, Optional

from phantom.core.session import session


@dataclass
class Evidence:
    kind: str          # finding kind: service / creds / web_app / os ...
    key: str           # e.g. "tcp/445"
    note: str = ""     # human detail ("anonymous session OK")


@dataclass
class TaggedSuggestion:
    command: str
    group: str
    why: str = ""                    # one-line reason (findings behind it)
    trust: float = 0.5               # 0..1
    tool: str = ""                   # first token (for preflight)
    tool_missing: bool = False       # preflight result
    already_ok: bool = False         # ran successfully before (dedup)
    out_of_scope: bool = False
    metadata: Dict = field(default_factory=dict)

    # ---- display -------------------------------------------------------
    def badge(self) -> str:
        marks = []
        if self.trust >= 0.75:
            marks.append("[green]●●●[/]")
        elif self.trust >= 0.5:
            marks.append("[yellow]●●○[/]")
        else:
            marks.append("[red]●○○[/]")
        if self.already_ok:
            marks.append("[dim]ran-ok[/]")
        if self.tool_missing:
            marks.append(f"[red]missing:{self.tool}[/]")
        if self.out_of_scope:
            marks.append("[red]out-of-scope[/]")
        return " ".join(marks)

    def line(self) -> str:
        why = f"  [dim]why: {self.why}[/]" if self.why else ""
        return f"{self.command}{why}  {self.badge()}"


# ---------------------------------------------------------------------------
# evidence extraction — the same WorldModel facts the auto-mode reasons on
# ---------------------------------------------------------------------------

def _wm_evidence() -> List[Evidence]:
    """Collect the operator's evidence from the live WorldModel (auto-mode
    checkpoint / manual findings) and the manual session knowledge base."""
    out: List[Evidence] = []
    try:
        from phantom.core.knowledge import session_wm
        wm = session_wm()
        for f in wm.all_findings():
            note = ""
            if isinstance(f.value, dict):
                note = str(f.value.get("product") or f.value.get("service")
                           or f.value.get("banner") or "")[:60]
            elif f.value is not None:
                note = str(f.value)[:60]
            out.append(Evidence(kind=f.kind, key=f.key, note=note))
    except Exception:
        pass
    # manual session knowledge base: services / creds found by modules
    try:
        for svc in (session.knowledge_base.get("services") or []):
            if isinstance(svc, dict):
                out.append(Evidence(
                    kind="service",
                    key=f"{svc.get('proto', 'tcp')}/{svc.get('port')}",
                    note=str(svc.get("service") or "")[:40]))
    except Exception:
        pass
    try:
        for c in (session.knowledge_base.get("creds_found") or []):
            if isinstance(c, dict):
                out.append(Evidence(
                    kind="creds",
                    key=str(c.get("service") or c.get("method") or "?"),
                    note=f"{c.get('username') or c.get('user') or '?'}@"
                         f"{c.get('host') or session.target or '?'}"))
    except Exception:
        pass
    return out


def _service_evidence(evidences: List[Evidence], svc_tokens: tuple) -> List[Evidence]:
    """Evidence entries for a service family (e.g. smb, ssh, http)."""
    hit = []
    for ev in evidences:
        k = ev.key.lower()
        if any(tok in k or tok in ev.note.lower() for tok in svc_tokens):
            hit.append(ev)
    return hit


# ---------------------------------------------------------------------------
# historical trust — same store as the fallback/learning engine
# ---------------------------------------------------------------------------

def _class_success(capability_class: str) -> Optional[float]:
    """Success rate for a capability class from the engagement history,
    or None when there is not enough data to judge."""
    try:
        from phantom.core.history import HistoricalAnalyzer
        records = HistoricalAnalyzer().records
    except Exception:
        return None
    wins = losses = 0
    for r in records:
        tech = str(r.get("technique") or "")
        if capability_class in tech or tech in capability_class:
            if r.get("success"):
                wins += 1
            else:
                losses += 1
    total = wins + losses
    if total < 3:
        return None   # not enough history: trust comes from evidence alone
    return wins / total


def score_trust(evidence_count: int, capability_class: str = "") -> float:
    """Blend evidence strength with historical success rate.

    Base trust rises with the number of independent corroborating
    findings (1 finding = 0.45, 2 = 0.6, 3+ = 0.75). When the history
    has >= 3 attempts for the class, the rate is blended 60/40.
    """
    base = min(0.45 + 0.15 * max(0, evidence_count - 1), 0.85)
    rate = _class_success(capability_class)
    if rate is None:
        return round(base, 2)
    return round(0.6 * base + 0.4 * rate, 2)


# ---------------------------------------------------------------------------
# preflight — tools / scope / dedup
# ---------------------------------------------------------------------------

def preflight(command: str) -> Dict:
    tool = command.split()[0] if command.split() else ""
    # strip sudo for the tool check — the sudo BINARY always exists
    bare = tool[5:] if tool.startswith("sudo ") else tool
    bare = command.split()[1] if tool == "sudo" and len(command.split()) > 1 else bare
    missing = bool(bare) and bare not in ("phantom",) and shutil.which(bare) is None \
        and shutil.which(tool) is None
    return {"tool": bare or tool, "missing": missing}


def in_scope(command: str) -> bool:
    """Crude scope check: an explicit scope list must contain the target."""
    scope = list(getattr(session, "scope", None) or [])
    if not scope:
        return True
    target = (session.target or "").lower()
    return any(target.endswith(s.lower()) or s.lower() in target
               for s in scope if s)


def already_ok(command: str) -> bool:
    """True when this exact command ran successfully in this session."""
    for entry in (session.results or {}).values():
        text = str(entry)
        if command[:80] in text and ("ok" in text.lower() or "✔" in text):
            return True
    return False


# ---------------------------------------------------------------------------
# the tagging engine — wraps a plain suggestions dict
# ---------------------------------------------------------------------------

# capability class per group prefix, for history-based trust
_CLASS_BY_TOKEN = (
    (("smb", "445", "enum4linux", "smbclient"), "smb"),
    (("ssh", "22", "sshpass"), "ssh"),
    (("http", "web", "curl", "80", "443", "sslscan", "nikto", "whatweb"),
     "web"),
    (("kerberoast", "as-rep", " GetUserSPNs", "ldap"), "kerberoast"),
    (("msf", "exploit/"), "exploit_cve_public"),
    (("hydra", "medusa", "brute"), "brute_force_passwords"),
)


def _class_for(group: str, command: str) -> str:
    text = f"{group} {command}".lower()
    for tokens, cls in _CLASS_BY_TOKEN:
        if any(tok in text for tok in tokens):
            return cls
    return ""


# findings keywords -> evidence tokens a suggestion depends on
_TOKEN_EVIDENCE = (
    (("smb", "445", "enum4linux", "smbclient", "rpcclient"), ("smb", "445")),
    (("ssh", "22", "sshpass"), ("ssh", "22")),
    (("http", "curl", "80", "443", "sslscan", "whatweb", "nikto"),
     ("http", "80", "443", "web")),
    (("kerberoast", "spn", "GetUserSPNs", "ldap", "389"), ("kerberos", "389", "88")),
    (("msf", "exploit/"), ()),
    (("hydra", "medusa"), ()),
)


def tag_suggestions(groups: Dict[str, List[str]]) -> List[TaggedSuggestion]:
    """Turn the plain groups dict from a module's suggest_commands() into
    tagged, preflighted, deduped suggestions sorted by trust."""
    evidences = _wm_evidence()
    evidence_keys = [e.key.lower() for e in evidences]
    evidence_notes = [e.note.lower() for e in evidences]

    tagged: List[TaggedSuggestion] = []
    for group, cmds in (groups or {}).items():
        if not cmds:
            continue
        for raw in cmds:
            cmd = raw.replace(" AGGRESSIVE", "").strip()
            if not cmd:
                continue
            # why: the findings this suggestion is derived from
            text = f"{group} {cmd}".lower()
            matching: List[str] = []
            for tokens, ev_tokens in _TOKEN_EVIDENCE:
                if not any(tok in text for tok in tokens):
                    continue
                for ev in evidences:
                    blob = f"{ev.kind} {ev.key} {ev.note}".lower()
                    if any(t in blob for t in ev_tokens):
                        matching.append(f"{ev.kind}:{ev.key}")
            # dedupe the why string
            seen: List[str] = []
            for m in matching:
                if m not in seen:
                    seen.append(m)
            why = " + ".join(seen[:4])

            cls = _class_for(group, cmd)
            trust = score_trust(len(seen), cls)
            pf = preflight(cmd)
            already = already_ok(cmd) if cmd.split() else False
            oos = not in_scope(cmd)
            tagged.append(TaggedSuggestion(
                command=cmd, group=group, why=why, trust=trust,
                tool=pf["tool"], tool_missing=pf["missing"],
                already_ok=already, out_of_scope=oos,
                metadata={"evidence_keys": evidence_keys[:8],
                          "evidence_notes": evidence_notes[:8],
                          "capability_class": cls}))

    # highest trust first; missing-tool and ran-ok sink to the bottom
    def sort_key(t: TaggedSuggestion):
        penalty = 0.5 if t.tool_missing else 0.0
        penalty += 0.4 if t.already_ok else 0.0
        penalty += 1.0 if t.out_of_scope else 0.0
        return -(t.trust - penalty)

    tagged.sort(key=sort_key)
    return tagged


def render_tagged(tagged: List[TaggedSuggestion], limit: int = 12) -> None:
    """Print the tagged suggestion list (the `suggest` front door)."""
    from rich.console import Console
    from phantom.utils.notifier import notifier
    console = Console()
    if not tagged:
        notifier.info("No suggestions yet — set a target and scan first.")
        return
    console.print("[bold cyan]── SUGGESTIONS (evidence-tagged, preflighted) ──[/]")
    for i, t in enumerate(tagged[:limit], 1):
        console.print(f"  [{i:2}] {t.line()}")
    console.print(
        "  [dim]●●● high trust · why = findings behind it · missing:<tool> = "
        "not installed · ran-ok = already succeeded · run <cmd> to execute[/]")
