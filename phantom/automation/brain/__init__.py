"""
phantom.automation.brain — shared reasoning engines.

The brain package holds the cross-phase engines every kill-chain phase
uses. Phase-specific logic stays in guidance/kit.py + the strategy/fallback
modules; everything that must survive a phase refactor lives here.

Modules:
    toolbelt — capability -> ranked tool selection per OS/host.
"""
