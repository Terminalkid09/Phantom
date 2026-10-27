"""Per-phase AI layer: optional, closed-contract, off by default.

Public surface (stable for the advisors and for tests):

    from phantom.automation.ai import ask, ai_enabled, AIResult
    from phantom.automation.ai import ModelRegistry, SCHEMAS, MODES, PHASES

``ask`` never raises and never executes model output; a caller that gets
``ok=False`` must fall back to its deterministic path.
"""

from __future__ import annotations

from .client import AIError, AIClient, CloudClient, LocalClient, MockClient
from .config import MODES, PHASES, mode, set_mode
from .registry import ModelRegistry, manifest_errors
from .router import AIResult, ai_enabled, ask
from .schemas import SCHEMAS, validate

__all__ = [
    "AIError", "AIClient", "AIResult", "CloudClient", "LocalClient",
    "MockClient", "ModelRegistry", "MODES", "PHASES", "SCHEMAS",
    "ai_enabled", "ask", "manifest_errors", "mode", "set_mode", "validate",
]
