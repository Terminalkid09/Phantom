"""
Phantom Autonomous Agent — red-team grade automation.

Entry point: run_autonomous(target, stealth=True, aggressive=False)

Design:
  - Agents reason over a structured WorldModel (beliefs => findings),
    never over raw command strings.
  - Every operation is a Capability in a Knowledge Model: prereqs, effects,
    adapter (synthesizes commands from facts at execution time) and an
    interpreter (parses output back into beliefs).
  - The OPSEC engine assigns costs to actions as a prioritization signal
    (cheap + quiet first). There is no budget: termination is governed by
    never repeating failed moves unless new facts make them viable again.
  - A sandboxed pre-flight validates droppers/exploits before real deploy.
  - An orchestrator runs an elastic pool of agents (1..N) like a red team.
"""
from __future__ import annotations


def __getattr__(name: str):
    # Lazy import so subpackages can be imported before the full agent exists.
    if name == "run_autonomous":
        from phantom.automation.agent import run_autonomous
        return run_autonomous
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")


__all__ = ["run_autonomous"]
