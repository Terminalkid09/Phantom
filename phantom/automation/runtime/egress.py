"""
egress.py — egress discipline for the agent pool.

The approved design: ONE device, ONE egress. This module enforces that
discipline (a single active egress identity) and is ready to scale to a
pool of egress boxes without changing the caller's API.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import List, Optional


@dataclass
class Egress:
    name: str
    device: str  # local | docker_vpn | remote_box
    status: str = "idle"  # idle | in_use
    in_use_by: str = ""


class EgressManager:
    """Lease-based egress control: exactly one box scans at a time."""

    def __init__(self, egresses: Optional[List[Egress]] = None) -> None:
        self._egresses = egresses if egresses is not None else [Egress("primary", "local")]
        self._guard = threading.Lock()

    def acquire(self, agent_name: str, prefer: str = "primary") -> Optional[Egress]:
        with self._guard:
            for e in self._egresses:
                if e.name == prefer and e.status == "idle":
                    e.status = "in_use"
                    e.in_use_by = agent_name
                    return e
            for e in self._egresses:
                if e.status == "idle":
                    e.status = "in_use"
                    e.in_use_by = agent_name
                    return e
        return None  # all egresses busy → agent must wait

    def release(self, egress: Egress) -> None:
        with self._guard:
            egress.status = "idle"
            egress.in_use_by = ""

    def active(self) -> List[Egress]:
        with self._guard:
            return [e for e in self._egresses if e.status == "in_use"]

    def single_egress_ok(self) -> bool:
        """The discipline we ship: never more than one box in use."""
        return len(self.active()) <= 1
