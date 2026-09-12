"""
commands.py — the Command Knowledge Model.

A Capability is the atomic unit of action. It describes WHAT an action
needs (preconditions), WHAT it produces (effects), HOW the command string
is synthesized (adapter, the ONLY place commands exist), and HOW output
is turned back into beliefs (interpreter). The planner reasons over
Capabilities + WorldModel, never over raw strings.
"""

from __future__ import annotations

import re
import time
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from phantom.automation.belief import WorldModel, Finding


@dataclass
class InputSlot:
    """Typed input a capability consumes."""
    name: str
    type: str  # ip | port | host | url | username | password | path | wordlist | target | command | choice
    required: bool = True
    description: str = ""

    def accepts(self, value: Any) -> bool:
        if value is None:
            return not self.required
        t = self.type
        if t == "ip":
            return isinstance(value, str) and bool(re.match(r"^[\d\.]+$", value))
        if t == "port":
            return isinstance(value, str) and value.isdigit() or (isinstance(value, int) and 0 < value < 65536)
        if t in ("host", "url"):
            return isinstance(value, str) and len(value) > 0
        if t in ("username", "password", "path", "wordlist", "command", "choice"):
            return isinstance(value, str) and len(value) > 0
        if t == "target":
            return isinstance(value, str) and len(value) > 0
        return False


@dataclass
class Capability:
    """One atomic red-team action."""

    id: str
    category: str  # recon | osint | service | creds | exploit | lateral | persistence | beacon | exfil | social
    description: str
    inputs: List[InputSlot] = field(default_factory=list)
    preconditions: List[Callable[[WorldModel], bool]] = field(default_factory=list)
    effects: List[str] = field(default_factory=list)  # fact kinds produced, e.g. ["service"]
    adapter: Optional[Callable[[WorldModel, Dict[str, Any]], str]] = None
    interpreter: Optional[Callable[[str, WorldModel, Dict[str, Any]], List[Finding]]] = None
    opsec_cost: float = 1.0
    detection_risk: float = 0.1  # probability of tripping blue team, 0..1
    stealth_level: str = "passive"  # passive | active | aggressive
    forceful: bool = False  # loud by nature (mass brute, auto-exploit, AD
                            # attacks, lateral movement) — refused in paranoid
                            # mode even when stealth_level is aggressive, while
                            # PRECISE access moves (single ssh_login with a
                            # known pair, beacon deploy, persistence) stay
                            # available or the kill chain can never complete.
    timeout: int = 30
    banner: str = ""  # one-line label shown in the decision stream
    tools: List[str] = field(default_factory=list)  # binaries needed on operator box

    def make_command(self, wm: WorldModel, slot_values: Dict[str, Any]) -> str:
        if self.adapter is None:
            raise ValueError(f"capability {self.id} has no adapter")
        for slot in self.inputs:
            if slot.required and (slot.name not in slot_values or not slot.accepts(slot_values[slot.name])):
                raise ValueError(f"capability {self.id}: missing/invalid input '{slot.name}' ({slot.type})")
        cmd = self.adapter(wm, slot_values)
        return cmd

    def interpret(self, output: str, wm: WorldModel, slot_values: Dict[str, Any]) -> List[Finding]:
        if self.interpreter is None:
            return []
        return self.interpreter(output, wm, slot_values)


class Registry:
    """Capability registry with planner-friendly lookup."""

    def __init__(self) -> None:
        self._caps: Dict[str, Capability] = {}

    def register(self, cap: Capability) -> None:
        self._caps[cap.id] = cap

    def get(self, cap_id: str) -> Optional[Capability]:
        return self._caps.get(cap_id)

    def all(self) -> List[Capability]:
        return list(self._caps.values())

    def by_category(self, category: str) -> List[Capability]:
        return [c for c in self._caps.values() if c.category == category]

    def usable(self, wm: WorldModel) -> List[Capability]:
        """Capabilities whose preconditions are satisfied by current beliefs."""
        return [c for c in self._caps.values() if self._ok(c, wm)]

    def _ok(self, cap: Capability, wm: WorldModel) -> bool:
        return all(p(wm) for p in cap.preconditions)

    def find(self, wm: WorldModel, goal_fact: str, budget: float) -> Optional[Capability]:
        """First capability that can produce `goal_fact` and fits the opsec budget."""
        best = None
        for cap in self.usable(wm):
            if goal_fact in cap.effects and cap.opsec_cost <= budget:
                if best is None or cap.opsec_cost < best.opsec_cost:
                    best = cap
        return best


def make_registry() -> Registry:
    """Instantiate the built-in capability set plus any machine-authored
    capabilities living in guidance/learned/ (the evolution loop's
    production location — see phantom/automation/evolution).

    Learned capabilities import AFTER built-ins: a learned id colliding
    with a built-in id would silently shadow it, which must never happen,
    so collisions are refused loudly.
    """
    from phantom.automation.guidance import kit as _kit
    reg = Registry()
    for cap in _kit.CAPABILITIES:
        reg.register(cap)
    try:
        from phantom.automation.guidance.learned import load_learned
        for cap in load_learned():
            if reg.get(cap.id) is not None:
                raise ValueError(
                    f"learned capability {cap.id!r} collides with an "
                    "existing capability id — refusing to shadow it")
            reg.register(cap)
    except ImportError:
        pass  # learned/ package absent (trimmed install)
    try:
        from phantom.automation.evolution import beta as _beta
        for cap in _beta.pending():   # --beta staged in this process
            if reg.get(cap.id) is None:
                reg.register(cap)
    except ImportError:
        pass
    return reg
