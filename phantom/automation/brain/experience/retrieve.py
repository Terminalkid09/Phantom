"""
experience.retrieve — from episodes to a planning signal.

The output is the SAME shape the planner already understands from
`TechniquePriors`: a per-technique float where **lower means preferred**
(1.0 is neutral, the range is clamped to [0.5, 1.5]). That is deliberate —
the planner keeps one ordering rule, and the experience engine simply adds
a finer, situation-scoped term on top of the coarse global average.

Two signals are produced:

  1. DATA signal — over episodes from situations SIMILAR to the current
     one (signature similarity ≥ threshold):

        * a technique that was the working REPAIR after this cause is
          preferred (multiplier < 1)
        * a technique that failed with the SAME cause repeatedly is
          deprioritised (multiplier > 1)
        * a technique that succeeded repeatedly is mildly preferred

  2. COLD-START signal — when the current run has just hit a cause and we
     have no episodes for it yet, the classic bypasses from
     `causes.REPAIR_HINTS` get the nudge instead of nothing.

Neither signal can authorise anything: the planner still applies every
deterministic precondition, scope, opsec and stealth gate. Experience only
reorders MOVES THAT ARE ALREADY ALLOWED — exactly like the LLM advisor, and
for the same reason.
"""

from __future__ import annotations

from collections import Counter, defaultdict
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import causes as C
from .cases import Episode
from .signature import Signature

NEUTRAL = 1.0
MIN_MULT = 0.5
MAX_MULT = 1.5
DEFAULT_THRESHOLD = 0.55
DEFAULT_MIN_N = 2

# multipliers by evidence class (lower = preferred)
_M_REPAIR = 0.62          # the technique that actually unblocked this cause
_M_REPAIR_ONCE = 0.78     # same, single observation
_M_WIN = 0.86             # repeatedly successful here
_M_FAIL_ONCE = 1.10
_M_FAIL_REPEAT = 1.32     # repeatedly failed with the same cause here
_M_HINT = 0.80            # cold-start classic bypass


def _clamp(value: float) -> float:
    return max(MIN_MULT, min(MAX_MULT, round(value, 4)))


@dataclass
class Advice:
    technique: str
    multiplier: float = NEUTRAL
    reason: str = ""
    n: int = 0
    cause: str = ""
    source: str = "data"          # data | hint
    evidence: List[str] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return {
            "technique": self.technique,
            "multiplier": self.multiplier,
            "reason": self.reason,
            "n": self.n,
            "cause": self.cause,
            "source": self.source,
        }


def _sig_of(ep: Episode) -> Signature:
    return Signature.from_dict(ep.sig or {})


def similar_episodes(sig: Signature, episodes: Iterable[Episode],
                     threshold: float = DEFAULT_THRESHOLD
                     ) -> List[Tuple[Episode, float]]:
    """Episodes from situations close enough to transfer, best match first.

    Only `learnable()` episodes count: a run that failed because the local
    box lacked `nmap` must never teach the engine that the technique is
    weak.
    """
    out: List[Tuple[Episode, float]] = []
    for ep in episodes or []:
        if not ep.learnable():
            continue
        sim = sig.similarity(_sig_of(ep))
        if sim >= threshold:
            out.append((ep, sim))
    out.sort(key=lambda t: (-t[1], -t[0].ts))
    return out


def advise(sig: Signature, episodes: Iterable[Episode],
           candidates: Optional[Sequence[str]] = None,
           min_n: int = DEFAULT_MIN_N,
           threshold: float = DEFAULT_THRESHOLD) -> Dict[str, Advice]:
    """Per-technique multipliers derived from similar past episodes.

    `candidates` restricts the output to the moves the planner is actually
    considering (keeps the plan clean); None means "everything seen".
    """
    matched = similar_episodes(sig, episodes, threshold)
    if not matched:
        return {}

    fail_by_cause: Dict[str, Counter] = defaultdict(Counter)
    wins: Counter = Counter()
    runs: Counter = Counter()
    repairs: Dict[str, Counter] = defaultdict(Counter)

    for ep, sim in matched:
        tech = ep.technique
        if not tech:
            continue
        runs[tech] += 1
        if ep.ok:
            wins[tech] += 1
        else:
            fail_by_cause[ep.cause][tech] += 1
            if ep.repair:
                repairs[ep.cause][ep.repair] += 1

    # the dominant failure cause in this situation class
    total_fail = sum(sum(c.values()) for c in fail_by_cause.values())
    dominant = ""
    if total_fail:
        dominant = max(fail_by_cause.items(),
                       key=lambda kv: sum(kv[1].values()))[0]

    wanted = set(candidates) if candidates else set(runs) | set(
        t for c in repairs.values() for t in c)

    out: Dict[str, Advice] = {}

    # 1) the technique that unblocked each cause — the strongest signal
    for cause, rep in repairs.items():
        if cause == dominant or not dominant:
            for tech, count in rep.items():
                if candidates and tech not in wanted:
                    continue
                mult = _M_REPAIR if count >= min_n else _M_REPAIR_ONCE
                prev = out.get(tech)
                if prev is None or mult < prev.multiplier:
                    out[tech] = Advice(
                        technique=tech, multiplier=_clamp(mult),
                        reason=(f"unblocked '{cause}' "
                                f"({C.describe(cause)}) in {count} similar "
                                f"situation(s)"),
                        n=count, cause=cause, source="data")

    # 2) techniques that keep failing the same way here
    for cause, counter in fail_by_cause.items():
        for tech, count in counter.items():
            if candidates and tech not in wanted:
                continue
            if cause == dominant or not dominant:
                mult = _M_FAIL_REPEAT if count >= min_n else _M_FAIL_ONCE
            else:
                mult = _M_FAIL_ONCE
            existing = out.get(tech)
            if existing is not None and existing.multiplier <= mult:
                continue
            out[tech] = Advice(
                technique=tech, multiplier=_clamp(mult),
                reason=(f"failed with '{cause}' ({C.describe(cause)}) "
                        f"{count}× in similar situations"),
                n=count, cause=cause, source="data")

    # 3) reliable wins (only when they are not already flagged as failures)
    for tech, w in wins.items():
        if w < min_n:
            continue
        if candidates and tech not in wanted:
            continue
        a = out.get(tech)
        if a is not None and a.multiplier > NEUTRAL:
            continue
        out[tech] = Advice(
            technique=tech, multiplier=_clamp(_M_WIN),
            reason=f"succeeded {w}× in similar situations",
            n=w, source="data")

    return out


def cold_start_hints(causes_present: Iterable[str],
                     candidates: Sequence[str]) -> Dict[str, Advice]:
    """When the current run hits a cause we have no data for, nudge the
    classic bypasses instead of returning nothing.

    Only applies when the run is genuinely stuck on that cause, and only
    to candidates the planner is already considering.
    """
    out: Dict[str, Advice] = {}
    present = [c for c in (causes_present or []) if c in C.CAUSES]
    for cause in present:
        frags = C.repair_hints(cause)
        if not frags:
            continue
        for tech in candidates or []:
            low = str(tech).lower()
            if not any(frag in low for frag in frags):
                continue
            a = out.get(tech)
            if a is not None and a.multiplier <= _M_HINT:
                continue
            out[tech] = Advice(
                technique=tech, multiplier=_clamp(_M_HINT),
                reason=(f"classic bypass for '{cause}' "
                        f"({C.describe(cause)}) — no matching experience yet"),
                n=0, cause=cause, source="hint")
    return out


def explain(sig: Signature, technique: str, episodes: Iterable[Episode],
            threshold: float = DEFAULT_THRESHOLD) -> Dict[str, Any]:
    """Why is `technique` ranked the way it is for this situation?"""
    matched = similar_episodes(sig, episodes, threshold)
    wins = 0
    fails: Counter = Counter()
    repair_of: Counter = Counter()
    samples: List[str] = []
    for ep, sim in matched:
        if ep.technique == technique:
            if ep.ok:
                wins += 1
            else:
                fails[ep.cause] += 1
        if ep.repair == technique:
            repair_of[ep.cause] += 1
        if (ep.technique == technique or ep.repair == technique) and \
                len(samples) < 5:
            samples.append(
                f"{ep.phase}/{ep.technique} -> "
                f"{'ok' if ep.ok else ep.cause}" +
                (f" (repair: {ep.repair})" if ep.repair else ""))
    adv = advise(sig, episodes, candidates=[technique], threshold=threshold)
    return {
        "technique": technique,
        "signature": sig.human(),
        "similar_situations": len(matched),
        "wins": wins,
        "failures": dict(fails),
        "was_repair_for": dict(repair_of),
        "multiplier": adv.get(technique).multiplier if technique in adv
        else NEUTRAL,
        "reason": adv.get(technique).reason if technique in adv else
        "no matching experience",
        "samples": samples,
    }
