"""approval.py — the policy that decides how a driver may be approved.

AutoModeBrief §13.4: not every capability deserves the same gate. A passive,
read-only, argv-driven tool in a lab can be auto-approved; a network-active or
shell-pipeline tool needs an operator; a learned/unknown driver stays disabled
until reviewed. The rule used to live implicitly in a comment; here it is a
single, testable function.

``decide`` returns an :class:`ApprovalDecision`:

  * ``action`` — ``auto`` (may be enabled without a human), ``operator``
    (needs an explicit approval), or ``deny`` (must be reviewed first);
  * ``reason`` — the human-readable why;
  * ``requirements`` — the concrete steps the caller must satisfy.

It reads only declarative fields (mode, category, stealth, risk, source), so
it is deterministic and offline.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, List

ACTION_AUTO = "auto"
ACTION_OPERATOR = "operator"
ACTION_DENY = "deny"

# detection risk above which a move stops being auto-approvable
RISK_THRESHOLD = 0.5
# categories that CHANGE the target (not just observe it)
STATE_CHANGING_CATEGORIES = frozenset({
    "exploit", "lateral", "persistence", "beacon", "exfil", "creds",
    "post", "ad",
})
# sources whose drivers are not operator-vetted
UNTRUSTED_SOURCES = frozenset({"learned", "unknown"})
_LOUD_LEVELS = frozenset({"active", "noisy", "loud"})


@dataclass
class ApprovalDecision:
    action: str
    reason: str
    requirements: List[str] = field(default_factory=list)

    @property
    def auto(self) -> bool:
        return self.action == ACTION_AUTO

    @property
    def denied(self) -> bool:
        return self.action == ACTION_DENY

    def to_dict(self) -> dict:
        return {"action": self.action, "reason": self.reason,
                "requirements": list(self.requirements)}


def mode_of(driver: Any) -> str:
    """``argv`` when the driver carries an explicit argument vector."""
    return "argv" if getattr(driver, "argv", ()) else "shell"


def decide(driver: Any, source: str = "operator-local",
           lab: bool = False) -> ApprovalDecision:
    """Map a driver manifest to an approval decision."""
    mode = mode_of(driver)
    category = str(getattr(driver, "category", "") or "").lower()
    level = str(getattr(driver, "stealth_level", "") or "").lower()
    try:
        risk = float(getattr(driver, "detection_risk", 0.0) or 0.0)
    except (TypeError, ValueError):
        risk = 0.0

    if source in UNTRUSTED_SOURCES:
        return ApprovalDecision(
            ACTION_DENY,
            f"{source} driver is not operator-vetted",
            ["review the manifest", "approve explicitly per engagement"])

    if category in STATE_CHANGING_CATEGORIES:
        return ApprovalDecision(
            ACTION_OPERATOR, f"{category} is state-changing",
            ["operator approval per run"])

    if mode == "shell":
        return ApprovalDecision(
            ACTION_OPERATOR, "shell-pipeline driver",
            ["operator approval", "prefer an argv manifest"])

    if risk > RISK_THRESHOLD or level in _LOUD_LEVELS:
        return ApprovalDecision(
            ACTION_OPERATOR,
            f"detection risk {risk:.2f} / level {level or 'unknown'}",
            ["operator approval"])

    if lab:
        return ApprovalDecision(
            ACTION_AUTO, "passive, argv, read-only driver in lab", [])

    return ApprovalDecision(
        ACTION_OPERATOR, "passive driver outside a lab",
        ["operator approval", "or run with --lab to auto-approve"])


def needs_approval(driver: Any, source: str = "operator-local",
                   lab: bool = False) -> bool:
    """True when the driver may NOT run without an explicit approval."""
    return decide(driver, source=source, lab=lab).action != ACTION_AUTO
