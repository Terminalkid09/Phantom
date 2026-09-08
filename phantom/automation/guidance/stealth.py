"""
stealth.py — OPSEC engine.

There is NO budget: the agent must reach beacon injection in every case,
so cost is only a prioritization signal (cheap + quiet first) that the
planner weighs. The real anti-hammering guard is the agent's own behavior:
it never repeats a failed move and it reasons about detection risk before
acting. This engine humanizes timing (random jitter between steps) and
hard-gates noisy operations (online brute force) behind `--aggressive`.
"""

from __future__ import annotations

import random
from dataclasses import dataclass
from typing import Optional

from phantom.automation.belief import WorldModel
from phantom.automation.guidance.threatmodel import BlueTeamModel


@dataclass
class StealthConfig:
    aggressive: bool = False  # unlocks online brute (hydra); fast + noisy
    paranoid: bool = False    # max-OPSEC: slower cadence, skips loud tools
    speed: bool = False       # opportunistic: faster cadence WITHOUT raising noise
    min_delay: float = 0.5
    max_delay: float = 3.5
    profile: str = "enterprise"
    targets_blue_team: bool = True  # assume Google/Meta-level defenders by default


class StealthEngine:
    """Central OPSEC decision point for the agent."""

    def __init__(self, wm: WorldModel, config: Optional[StealthConfig] = None,
                 blue_team: Optional[BlueTeamModel] = None) -> None:
        self.wm = wm
        self.config = config or StealthConfig()
        self.blue_team = blue_team or BlueTeamModel.for_profile(self.config.profile)

    # -- decisions --------------------------------------------------------

    def online_brute_allowed(self) -> bool:
        """Online brute force (hydra etc.) only in --aggressive mode."""
        return self.config.aggressive

    def would_be_loud(self, category: str, stealth_level: str, opsec_cost: float) -> bool:
        return self.blue_team.risk(category, stealth_level, opsec_cost) > 0.6

    def allowed(self, category: str, stealth_level: str, opsec_cost: float,
                is_online_brute: bool = False, forceful: bool = False) -> bool:
        """Cost is a prioritization signal, never a block: the agent must
        reach beacon injection in every case. Online brute force stays
        hard-gated behind --aggressive.

        paranoid refuses FORCEFUL capabilities (mass brute, auto-exploit,
        AD attacks, lateral movement) outright — they are loud by nature.
        PRECISE access moves that happen to carry stealth_level="aggressive"
        (a single ssh_login with a known pair, beacon deploy, persistence)
        stay available: refusing them would make the kill chain impossible
        in paranoid mode (verified: empty plan, halt before creds)."""
        if is_online_brute and not self.online_brute_allowed():
            return False
        if self.config.paranoid and forceful:
            return False
        return True

    # -- timing ------------------------------------------------------------

    def human_delay(self) -> float:
        """Random jitter between actions so the cadence looks human.

        aggressive: fast + noisy (0.5x-0.7x).  speed: faster but quiet-ish
        (0.65x-0.85x).  paranoid: slow and deliberate (2x-3x)."""
        lo, hi = self.config.min_delay, self.config.max_delay
        if self.config.aggressive:
            lo, hi = lo * 0.5, hi * 0.7
        elif self.config.speed:
            lo, hi = lo * 0.65, hi * 0.85
        elif self.config.paranoid:
            lo, hi = lo * 2.0, hi * 3.0
        return random.uniform(lo, hi)

    def consume(self, cost: float) -> bool:
        """Records the OPSEC cost in the audit ledger. Never blocks."""
        return self.wm.spend_opsec(cost)
