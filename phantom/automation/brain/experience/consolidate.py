"""
experience.consolidate — keeping the memory healthy.

Three jobs, all of them about not letting a memory rot into a liability:

  * PRUNE   — drop episodes past an age horizon and cap the store, so a
              years-old success on a long-gone product does not outrank
              something seen last week.
  * MERGE   — write the run's episodes back into the persistent store
              without duplicating them.
  * PROMOTE — when a situation-scoped pattern is strong enough (n and rate
              both high), fold it into the coarse `TechniquePriors` so the
              global average is informed by what the fine-grained engine
              learned. This is what stops the two systems from drifting
              apart: experience is the fast, contextual learner; priors is
              the slow, aggregate one that survives when the situation is
              unrecognised.
"""

from __future__ import annotations

import time
from collections import Counter, defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import causes as C
from .cases import Episode

# a pattern must be this strong before it is allowed into the global priors
PROMOTE_MIN_N = 5
PROMOTE_HIGH = 0.80
PROMOTE_LOW = 0.20


def prune_by_age(episodes: Iterable[Episode],
                 max_age_days: float = 365.0,
                 now: Optional[float] = None) -> List[Episode]:
    """Keep only episodes within the age horizon (and with a sane ts)."""
    now = time.time() if now is None else float(now)
    horizon = now - float(max_age_days) * 86400.0
    out = []
    for ep in episodes or []:
        if ep.ts <= 0.0:
            continue
        if ep.ts >= horizon:
            out.append(ep)
    return out


def merge(existing: Iterable[Episode], new: Iterable[Episode],
          max_episodes: int = 2000) -> List[Episode]:
    """Newest-wins merge with a hard cap (recency is what transfers)."""
    merged = list(existing or []) + list(new or [])
    merged.sort(key=lambda e: e.ts)
    if len(merged) > max_episodes:
        merged = merged[-int(max_episodes):]
    return merged


def dedupe(episodes: Iterable[Episode]) -> List[Episode]:
    """Collapse the SAME episode recorded twice (e.g. a merge that ran
    twice).

    Keys on the episode identity (`eid`), never on the timestamp or the
    content: two genuinely distinct attempts at the same technique can
    share every visible field, and collapsing those would silently falsify
    the statistics the whole engine depends on.
    """
    seen = set()
    out = []
    for ep in episodes or []:
        key = ep.eid or id(ep)
        if key in seen:
            continue
        seen.add(key)
        out.append(ep)
    return out


def pattern_table(episodes: Iterable[Episode],
                  min_n: int = 2) -> Dict[str, Dict[str, Any]]:
    """(technique, product-class) -> {runs, wins, rate} for learnable eps."""
    table: Dict[str, Dict[str, Any]] = {}
    buckets: Dict[Tuple[str, str], Counter] = defaultdict(Counter)
    for ep in episodes or []:
        if not ep.learnable() or not ep.technique:
            continue
        product = str((ep.sig or {}).get("product", "generic")) or "generic"
        key = f"{ep.technique}@{product}"
        buckets[key]["runs"] += 1
        if ep.ok:
            buckets[key]["wins"] += 1
    for key, c in buckets.items():
        runs = int(c["runs"])
        if runs < min_n:
            continue
        wins = int(c["wins"])
        table[key] = {"runs": runs, "wins": wins,
                      "rate": round(wins / runs, 3) if runs else 0.0}
    return table


def promote_to_priors(episodes: Iterable[Episode], priors,
                      min_n: int = PROMOTE_MIN_N) -> int:
    """Fold strong, situation-scoped patterns into the global priors.

    Only confident patterns travel: a technique that wins ≥80% (or loses
    ≤20%) over at least `min_n` learnable episodes on a product class.
    Returns the number of (technique, class) buckets promoted.
    """
    if priors is None:
        return 0
    promoted = 0
    for key, stats in pattern_table(episodes, min_n=min_n).items():
        technique, _, product = key.partition("@")
        rate = float(stats.get("rate", 0.0))
        n = int(stats.get("runs", 0))
        if rate >= PROMOTE_HIGH:
            for _ in range(n):
                priors.record(technique, product, True)
            promoted += 1
        elif rate <= PROMOTE_LOW:
            for _ in range(n):
                priors.record(technique, product, False)
            promoted += 1
    if promoted:
        try:
            priors.save()
        except Exception:
            pass
    return promoted


def cause_profile(episodes: Iterable[Episode]) -> Dict[str, Any]:
    """Where this engagement (or the whole memory) keeps getting stuck."""
    fails: Counter = Counter()
    worst: Dict[str, Counter] = defaultdict(Counter)
    for ep in episodes or []:
        if ep.ok:
            continue
        fails[ep.cause] += 1
        worst[ep.cause][ep.technique] += 1
    return {
        "total_failures": sum(fails.values()),
        "by_cause": dict(fails.most_common()),
        "worst_technique_per_cause": {
            c: counter.most_common(1)[0][0]
            for c, counter in worst.items() if counter
        },
    }
