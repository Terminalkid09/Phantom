"""Building the arbiter for one engagement (the agent-facing factory).

Kept next to the policy so the AUTHORITY RULE lives in one place:

* the scope's trust ladder decides by default (``trust.trust_for``);
* when the ladder has no measurement (``observe``) but the operator EXPLICITLY
  enabled the plane (``--ai local|cloud|integrated``), the arbiter runs at
  ``nudge`` and says so — the same rule the LLM advisor already uses. Asking
  for a model and then refusing to let it move anything by two positions is
  the "AI on == AI off" behaviour this replaces;
* an operator override (``--ai-authority``) still wins, and is announced by
  ``trust.apply_authority``.
"""

from __future__ import annotations

from typing import Any, Optional


def for_engagement(wm: Any, *, goal: str = "", phase: str = "planner",
                   authority: Optional[str] = None,
                   audit: bool = True) -> Any:
    """An ``Arbiter`` wired to the planner-phase proposer for this world."""
    from phantom.automation.ai import config as ai_config
    from phantom.automation.ai.advisors import planning
    from phantom.automation.ai.arbiter import Arbiter
    from phantom.automation.ai.trust import apply_authority, trust_for

    level = authority
    if not level:
        trust = apply_authority(trust_for(phase))
        level = str(getattr(trust, "level", "observe") or "observe")
        if level == "observe" and ai_config.mode(phase) != "off":
            level = "nudge"
            try:
                from phantom.utils.notifier import notifier
                notifier.info(
                    f"AI arbiter: no measured advantage for phase {phase!r}, "
                    "so it runs at the 'nudge' profile (at most 2 positions) "
                    "because the operator enabled the plane explicitly.")
            except Exception:
                pass

    def proposer(fact, capabilities):
        return planning.propose(wm, fact, capabilities, goal)

    return Arbiter(authority=level, proposer=proposer, audit=audit)
