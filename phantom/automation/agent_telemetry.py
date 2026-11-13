"""agent_telemetry.py — best-effort telemetry helpers for the agent loop.

Extracted from ``automation/agent.py`` (2026-11-05) for the same reason
``agent_support.py`` exists: agent.py is ~5.2k lines and every edit pays for
reading it. These three helpers share one contract — a telemetry sink must
NEVER take the planner down, so each one swallows its own failure — and that
contract is easier to keep true when it lives in one small file.

Behaviour is unchanged; ``agent.py`` re-exports the names.
"""

from __future__ import annotations

from typing import Any


def _audit_decision(kind: str, **fields: Any) -> None:
    """Best-effort decision telemetry (never takes the planner down)."""
    try:
        from phantom.automation import decision_audit as _audit
        _audit.record(kind, **fields)
    except Exception:
        pass


def _health_enabled() -> bool:
    try:
        from phantom.utils import config as cfg
        return cfg.get_bool("automation.capability_health", True,
                            env="PHANTOM_CAPABILITY_HEALTH")
    except Exception:
        return True


def _record_health(cap_id: str, ok: bool, reason: str = "") -> None:
    """Best-effort per-capability health ledger update (never fatal)."""
    if not _health_enabled():
        return
    try:
        from phantom.automation import capability_health as _ch
        _ch.instance().record(cap_id, ok, reason)
    except Exception:
        pass
