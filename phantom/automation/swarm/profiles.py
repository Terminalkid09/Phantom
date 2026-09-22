"""Profile picker: WHICH reasoning profile runs a task, learned over time.

Static profiles + learned selection = adaptive reasoning without an LLM
in the loop. Technique key ``swarm:<goal>:<profile>`` learns, per target
fingerprint class, which profile actually delivers the task's facts.

Selection is epsilon-greedy AND deterministic (hash of seed/goal/round,
never wall-clock or thread order — the suite requires it):

* explore (round-robin over profiles): gather evidence on the unknown;
* exploit: the profile with the lowest priors multiplier (lower = better).

Outcomes are recorded by the scheduler after every commit, so the next
operation on the same target class starts smarter.
"""
from __future__ import annotations

import hashlib

PROFILES = ("balanced", "evidence_first", "stealth_first", "force_first")
_EXPLORE_EVERY = 4  # every 4th pick explores (deterministic round-robin)


def technique(goal: str, profile: str) -> str:
    return f"swarm:{goal}:{profile or 'balanced'}"


def pick_profile(goal: str, fingerprint: str, priors, seed: int = 0,
                 round_idx: int = 0) -> str:
    """Deterministic epsilon-greedy profile pick."""
    h = int(hashlib.sha256(
        f"{seed}:{goal}:{round_idx}".encode()).hexdigest(), 16)
    if h % _EXPLORE_EVERY == 0:
        return PROFILES[(h // _EXPLORE_EVERY + round_idx) % len(PROFILES)]
    best = PROFILES[0]
    best_rank = None
    for profile in PROFILES:
        try:
            rank = float(priors.multiplier(technique(goal, profile),
                                           fingerprint))
        except Exception:
            rank = 1.0
        if best_rank is None or rank < best_rank:
            best, best_rank = profile, rank
    return best


def record_outcome(priors, goal: str, profile: str, fingerprint: str,
                   ok: bool) -> None:
    """Feed a task outcome back into the priors (never raises)."""
    try:
        priors.record(technique(goal, profile), fingerprint, bool(ok))
    except Exception:
        pass


def rotate(profile: str) -> str:
    """Next profile for a bounded requeue (deterministic rotation)."""
    if profile in PROFILES:
        return PROFILES[(PROFILES.index(profile) + 1) % len(PROFILES)]
    return PROFILES[0]
