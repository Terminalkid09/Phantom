"""schemas.py — the closed output contract of every AI phase.

A model may only ever return DATA in one of these shapes. There is no field
for a command, a tool call, or a file to write; a response that tries is
rejected wholesale by the validator (``ok=False``) and the deterministic
path continues. Validators are plain functions so the whole contract is
verifiable offline, with no model and no dependency.
"""

from __future__ import annotations

from typing import Any, Dict, List

# Keys that would smuggle an instruction into the runtime. Checked at every
# nesting level, because a nested "args" is exactly how a shell command
# would arrive.
EXECUTION_KEYS = frozenset({
    "command", "commands", "cmd", "shell", "exec", "execute", "run",
    "argv", "args", "script", "code", "bash", "powershell", "tool_call",
    "tool_calls", "function_call",
})

FINDING_KINDS = frozenset({
    "service", "os", "creds", "vuln_class", "hunt_anomaly", "identity",
    "email_candidate", "email_verified", "web_app", "recon_verdict",
    "hostname", "origin", "note",
})

PHASES = ("exploit", "finding", "osint", "social", "scan_parse",
          "evolution", "planner")


def _walk_keys(data: Any, seen: List[str]) -> None:
    if isinstance(data, dict):
        for key, value in data.items():
            seen.append(str(key).strip().lower())
            _walk_keys(value, seen)
    elif isinstance(data, list):
        for item in data:
            _walk_keys(item, seen)


def _no_exec(data: Any) -> List[str]:
    keys: List[str] = []
    _walk_keys(data, keys)
    bad = sorted({k for k in keys if k in EXECUTION_KEYS})
    return ([f"execution-shaped key refused: {', '.join(bad)}"] if bad else [])


def _num(value: Any, low: float, high: float) -> bool:
    return isinstance(value, (int, float)) and not isinstance(value, bool) \
        and low <= float(value) <= high


def validate_exploit(data: Dict[str, Any]) -> List[str]:
    """``{"ranked": [{"id", "reason", "expected_success"}], "notes": str}``.

    ``id`` is an ACCESS-CANDIDATE id from the table the caller supplied; the
    validator enforces shape and forbids execution keys, while the advisor
    filters ids against that table (a closed registry it owns). The model
    can only REORDER candidates, never add one.
    """
    errors: List[str] = _no_exec(data)
    if not isinstance(data, dict):
        return errors + ["payload must be an object"]
    ranked = data.get("ranked")
    if not isinstance(ranked, list):
        return errors + ["ranked must be a list"]
    if len(ranked) > 50:
        errors.append("ranked has more than 50 entries")
    for index, row in enumerate(ranked):
        if not isinstance(row, dict):
            errors.append(f"ranked[{index}] must be an object")
            continue
        cid = row.get("id")
        if not isinstance(cid, str) or not cid.strip():
            errors.append(f"ranked[{index}].id must be a non-empty string")
        reason = row.get("reason")
        if reason is not None and (not isinstance(reason, str)
                                   or len(reason) > 400):
            errors.append(f"ranked[{index}].reason must be a short string")
        if "expected_success" in row and not _num(
                row.get("expected_success"), 0.0, 1.0):
            errors.append(
                f"ranked[{index}].expected_success must be 0..1")
    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append("notes must be a string")
    extra = set(data) - {"ranked", "notes"}
    if extra:
        errors.append("unknown keys: " + ", ".join(sorted(extra)))
    return errors


def validate_planner(data: Dict[str, Any]) -> List[str]:
    """``{"ranked": [{"id", "confidence", "reason"}], "notes": str}``.

    A capability-level proposal: which move the planner should run next, with
    how strongly the model believes it. Shape only — membership in the
    eligible set is enforced by ``ai.arbiter.Arbiter``, which also applies the
    authority bound. Confidence is REQUIRED here (unlike the exploit schema):
    the arbiter's floor is the whole point, and an absent number would silently
    read as 0.0 and be refused with a misleading reason.
    """
    errors: List[str] = _no_exec(data)
    if not isinstance(data, dict):
        return errors + ["payload must be an object"]
    ranked = data.get("ranked")
    if not isinstance(ranked, list):
        return errors + ["ranked must be a list"]
    if len(ranked) > 30:
        errors.append("ranked has more than 30 entries")
    for index, row in enumerate(ranked):
        if not isinstance(row, dict):
            errors.append(f"ranked[{index}] must be an object")
            continue
        cid = row.get("id", row.get("capability_id"))
        if not isinstance(cid, str) or not cid.strip():
            errors.append(f"ranked[{index}].id must be a non-empty string")
        if not _num(row.get("confidence"), 0.0, 1.0):
            errors.append(f"ranked[{index}].confidence must be 0..1")
        reason = row.get("reason")
        if reason is not None and (not isinstance(reason, str)
                                   or len(reason) > 200):
            errors.append(f"ranked[{index}].reason must be a short string")
        extra = set(row) - {"id", "capability_id", "confidence", "reason"}
        if extra:
            errors.append("unknown keys: " + ", ".join(sorted(extra)))
    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append("notes must be a string")
    extra = set(data) - {"ranked", "notes"}
    if extra:
        errors.append("unknown keys: " + ", ".join(sorted(extra)))
    return errors


def validate_finding(data: Dict[str, Any]) -> List[str]:
    errors: List[str] = _no_exec(data)
    if not isinstance(data, dict):
        return errors + ["payload must be an object"]
    findings = data.get("findings")
    if not isinstance(findings, list):
        return errors + ["findings must be a list"]
    if len(findings) > 40:
        errors.append("findings has more than 40 entries")
    for index, row in enumerate(findings):
        if not isinstance(row, dict):
            errors.append(f"findings[{index}] must be an object")
            continue
        kind = row.get("kind")
        if kind not in FINDING_KINDS:
            errors.append(f"findings[{index}].kind not allowed: {kind!r}")
        if not isinstance(row.get("key"), str) or not row.get("key", "").strip():
            errors.append(f"findings[{index}].key must be a string")
        if "confidence" in row and not _num(row.get("confidence"), 0.0, 1.0):
            errors.append(f"findings[{index}].confidence must be 0..1")
        note = row.get("note")
        if note is not None and not isinstance(note, str):
            errors.append(f"findings[{index}].note must be a string")
    nxt = data.get("next")
    if nxt is not None and (not isinstance(nxt, list)
                            or any(not isinstance(x, str) for x in nxt)):
        errors.append("next must be a list of strings")
    extra = set(data) - {"findings", "next"}
    if extra:
        errors.append("unknown keys: " + ", ".join(sorted(extra)))
    return errors


def validate_osint(data: Dict[str, Any]) -> List[str]:
    """Cross-platform same-person PROPOSALS; confirmation stays elsewhere."""
    errors: List[str] = _no_exec(data)
    if not isinstance(data, dict):
        return errors + ["payload must be an object"]
    links = data.get("links")
    if not isinstance(links, list):
        return errors + ["links must be a list"]
    if len(links) > 30:
        errors.append("links has more than 30 entries")
    for index, row in enumerate(links):
        if not isinstance(row, dict):
            errors.append(f"links[{index}] must be an object")
            continue
        for field in ("handle", "platform"):
            value = row.get(field)
            if not isinstance(value, str) or not value.strip():
                errors.append(f"links[{index}].{field} must be a string")
        if "confidence" in row and not _num(row.get("confidence"), 0.0, 1.0):
            errors.append(f"links[{index}].confidence must be 0..1")
        signals = row.get("signals")
        if signals is not None and (
                not isinstance(signals, list)
                or any(not isinstance(s, str) for s in signals)):
            errors.append(f"links[{index}].signals must be a list of strings")
    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append("notes must be a string")
    extra = set(data) - {"links", "notes"}
    if extra:
        errors.append("unknown keys: " + ", ".join(sorted(extra)))
    return errors


def validate_social(data: Dict[str, Any]) -> List[str]:
    """Draft text only: the pretext scorer still gates the send."""
    errors: List[str] = _no_exec(data)
    if not isinstance(data, dict):
        return errors + ["payload must be an object"]
    text = data.get("text")
    if not isinstance(text, str) or not text.strip():
        errors.append("text must be a non-empty string")
    elif len(text) > 4000:
        errors.append("text exceeds 4000 characters")
    subject = data.get("subject")
    if subject is not None and (not isinstance(subject, str)
                                or len(subject) > 200):
        errors.append("subject must be a short string")
    extra = set(data) - {"text", "subject"}
    if extra:
        errors.append("unknown keys: " + ", ".join(sorted(extra)))
    return errors


def validate_scan_parse(data: Dict[str, Any]) -> List[str]:
    errors: List[str] = _no_exec(data)
    if not isinstance(data, dict):
        return errors + ["payload must be an object"]
    findings = data.get("findings")
    if not isinstance(findings, list):
        return errors + ["findings must be a list"]
    for index, row in enumerate(findings):
        if not isinstance(row, dict):
            errors.append(f"findings[{index}] must be an object")
            continue
        port = row.get("port")
        if isinstance(port, str) and port.isdigit():
            port = int(port)
        if not isinstance(port, int) or not 1 <= port <= 65535:
            errors.append(f"findings[{index}].port must be 1..65535")
        for field in ("service", "product", "version"):
            value = row.get(field)
            if value is not None and not isinstance(value, str):
                errors.append(f"findings[{index}].{field} must be a string")
    notes = data.get("notes")
    if notes is not None and not isinstance(notes, str):
        errors.append("notes must be a string")
    extra = set(data) - {"findings", "notes"}
    if extra:
        errors.append("unknown keys: " + ", ".join(sorted(extra)))
    return errors


def validate_evolution(data: Dict[str, Any]) -> List[str]:
    """Triage text for the evolution loop; never authored code."""
    errors: List[str] = _no_exec(data)
    if not isinstance(data, dict):
        return errors + ["payload must be an object"]
    summary = data.get("summary")
    if not isinstance(summary, str) or not summary.strip():
        errors.append("summary must be a non-empty string")
    causes = data.get("causes")
    if causes is not None and (not isinstance(causes, list)
                               or any(not isinstance(c, str) for c in causes)):
        errors.append("causes must be a list of strings")
    proposal = data.get("proposal")
    if proposal is not None and not isinstance(proposal, str):
        errors.append("proposal must be a string")
    extra = set(data) - {"summary", "causes", "proposal"}
    if extra:
        errors.append("unknown keys: " + ", ".join(sorted(extra)))
    return errors


SCHEMAS = {
    "exploit": validate_exploit,
    "planner": validate_planner,
    "finding": validate_finding,
    "osint": validate_osint,
    "social": validate_social,
    "scan_parse": validate_scan_parse,
    "evolution": validate_evolution,
}


def validate(phase: str, data: Any) -> List[str]:
    """Errors for one phase (unknown phase -> a typed error, never a raise)."""
    validator = SCHEMAS.get(str(phase or ""))
    if validator is None:
        return [f"no schema for phase: {phase!r}"]
    return validator(data)
