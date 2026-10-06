"""decision_audit.py — auditable telemetry of AutoMode decisions.

ManusReview §7.3.5 and AutoModeBrief §11.2 ask the same thing: when the agent
enables a capability, applies a policy, admits or refuses a target, or picks
one move over another, there must be a LOCAL, tamper-evident record of WHO
decided, UNDER WHICH policy and scope, and WHY. The report already shows the
outcome; what was missing is the decision trail that explains it.

This module is a thin, TYPED layer over the existing hash-chained
append-only log (:class:`phantom.utils.audit_log.AuditLog`), pointed at its
own file so decision traffic does not mix with C2 events. The chain gives
tamper evidence and the redaction the log already applies keeps credentials
out of the trail. The vocabulary is fixed so a reader can grep for one kind:

  * ``capability_approved`` / ``capability_enabled`` — a discovered capability
    crossed the approval gate (who approved it, under which policy);
  * ``policy_decision`` — a guard allowed or denied a move;
  * ``scope_decision`` — a target was admitted or refused, by which scope;
  * ``capability_chosen`` / ``capability_rejected`` — the arbiter's pick and
    the moves it passed over, with the reason;
  * ``llm_proposal`` — an advisory proposal and whether a policy accepted it.

Recording is best-effort: an audit write must NEVER take the planner down, so
every call is wrapped and a failure is swallowed (the decision still happens;
only its telemetry is lost). ``enabled()`` is the switch (``automation.
decision_audit``), default on.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

KIND_APPROVED = "capability_approved"
KIND_ENABLED = "capability_enabled"
KIND_POLICY = "policy_decision"
KIND_SCOPE = "scope_decision"
KIND_CHOSEN = "capability_chosen"
KIND_REJECTED = "capability_rejected"
KIND_LLM = "llm_proposal"

_DEFAULT_NAME = "decision_audit.log"


def _default_path() -> str:
    try:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), _DEFAULT_NAME)
    except Exception:
        return _DEFAULT_NAME


def enabled() -> bool:
    """Whether decision telemetry is on (config ``automation.decision_audit``)."""
    try:
        from phantom.utils import config as cfg
        return cfg.get_bool("automation.decision_audit", True,
                            env="PHANTOM_DECISION_AUDIT")
    except Exception:
        return True


class DecisionAudit:
    """Typed, hash-chained decision trail (one file)."""

    def __init__(self, path: Optional[str] = None, log: Any = None) -> None:
        if log is not None:
            self._log = log               # injected (tests / custom sink)
        else:
            from phantom.utils.audit_log import AuditLog
            self._log = AuditLog(path or _default_path())

    @property
    def path(self) -> str:
        return getattr(self._log, "path", "")

    # ------------------------------------------------------------- record

    def record(self, kind: str, **fields: Any) -> Optional[Dict[str, Any]]:
        """Append one decision event (never raises)."""
        if not enabled():
            return None
        try:
            return self._log.append(kind, subsystem="automation", **fields)
        except Exception:
            return None

    def capability_approved(self, capability: str, approver: str = "operator",
                            policy: str = "", **extra: Any):
        return self.record(KIND_APPROVED, capability=capability,
                           approver=approver, policy=policy, **extra)

    def capability_enabled(self, capability: str, approver: str = "operator",
                           policy: str = "", scope: str = "",
                           **extra: Any):
        """A capability crossed the approval gate into the planner."""
        return self.record(KIND_ENABLED, capability=capability,
                           approver=approver, policy=policy, scope=scope,
                           **extra)

    def policy_decision(self, subject: str, decision: str, policy: str = "",
                        reason: str = "", **extra: Any):
        return self.record(KIND_POLICY, subject=subject, decision=decision,
                           policy=policy, reason=reason, **extra)

    def scope_decision(self, target: str, decision: str, scope: str = "",
                       reason: str = "", **extra: Any):
        return self.record(KIND_SCOPE, target=target, decision=decision,
                           scope=scope, reason=reason, **extra)

    def chosen(self, capability: str, driver: str = "", value: float = 0.0,
               stage: str = "", reason: str = "", **extra: Any):
        return self.record(KIND_CHOSEN, capability=capability, driver=driver,
                           value=round(float(value), 4), stage=stage,
                           reason=reason, **extra)

    def rejected(self, capability: str, reason: str = "", stage: str = "",
                 **extra: Any):
        return self.record(KIND_REJECTED, capability=capability,
                           reason=reason, stage=stage, **extra)

    def llm_proposal(self, subject: str, accepted: bool, reason: str = "",
                     **extra: Any):
        return self.record(KIND_LLM, subject=subject,
                           accepted=bool(accepted), reason=reason, **extra)

    # -------------------------------------------------------------- reads

    def tail(self, n: int = 20) -> List[Dict[str, Any]]:
        try:
            return self._log.tail(n)
        except Exception:
            return []

    def verify(self):
        """(ok, records_checked, first_bad) for the underlying hash chain."""
        try:
            return self._log.verify()
        except Exception:
            return False, 0, None

    def explain(self, n: int = 20) -> List[str]:
        """Operator-readable lines for the last ``n`` decisions."""
        lines: List[str] = []
        for rec in self.tail(n):
            if not isinstance(rec, dict):
                continue
            kind = rec.get("event", "")
            subject = (rec.get("capability") or rec.get("target")
                       or rec.get("subject") or "")
            if kind == KIND_SCOPE:
                lines.append(f"[{rec.get('ts', '')}] scope {subject}: "
                             f"{rec.get('decision', '')} "
                             f"({rec.get('reason', '')})")
            elif kind == KIND_POLICY:
                lines.append(f"[{rec.get('ts', '')}] policy {subject}: "
                             f"{rec.get('decision', '')} "
                             f"({rec.get('reason', '')})")
            elif kind in (KIND_APPROVED, KIND_ENABLED):
                lines.append(f"[{rec.get('ts', '')}] {kind} {subject} "
                             f"by {rec.get('approver', '?')}")
            elif kind == KIND_CHOSEN:
                lines.append(f"[{rec.get('ts', '')}] chose {subject} "
                             f"(driver {rec.get('driver', '-')}, "
                             f"x{rec.get('value', 0)})")
            elif kind == KIND_REJECTED:
                lines.append(f"[{rec.get('ts', '')}] rejected {subject} "
                             f"({rec.get('reason', '')})")
            else:
                lines.append(f"[{rec.get('ts', '')}] {kind} {subject}")
        return lines


# lazy singleton: the file is created on first use, never at import
_singleton: Optional[DecisionAudit] = None


def instance() -> DecisionAudit:
    global _singleton
    if _singleton is None:
        _singleton = DecisionAudit()
    return _singleton


def set_instance(log: Optional[DecisionAudit]) -> None:
    """Swap the singleton (tests / custom sink); ``None`` resets it."""
    global _singleton
    _singleton = log


def record(kind: str, **fields: Any):
    """Convenience: record via the singleton (never raises)."""
    return instance().record(kind, **fields)
