"""
phantom.automation.brain.experience — the LEARNING engine.

Reasoning decides what to TRY next from the facts. Learning remembers what
happened last time, WHY it failed, and what unblocked it — so a wall the
agent hit in a previous engagement (or earlier in this one) is not hit
again the same way.

It is deliberately NOT the LLM and NOT the reasoning layer:

    * no model, no network in the core path — deterministic rules and a
      JSON store, so it works offline and is reproducible;
    * it can never authorise a move. It only reorders moves the planner
      has ALREADY allowed (same contract as the priors and the LLM advisor);
    * it learns from CAUSES, not from bare outcomes — a failure caused by a
      missing local tool teaches nothing and is discarded.

Two storage modes (agreed policy):

    * engagement-scoped (default) — in memory for the run only; no client
      data is ever read from or written to disk.
    * global (opt-in, `--experience` / config) — persists across
      engagements, so what was learned last month still helps today.

Typical wiring (the agent does this):

    exp = Experience(enabled=persist_learning)
    ...
    exp.sync(wm)                       # before planning
    mult = exp.multipliers(wm, candidates=ids)
    ...
    exp.finish(priors=technique_priors)  # at end of run
"""

from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence, Tuple

from . import causes as causes
from . import consolidate as consolidate
from .cases import CaseStore, Episode, experience_path
from .retrieve import NEUTRAL, Advice, advise, cold_start_hints, explain
from .signature import Signature

__all__ = [
    "Experience", "Episode", "Signature", "Advice", "CaseStore",
    "causes", "consolidate", "experience_path", "NEUTRAL",
]


@dataclass
class _RunState:
    """Bookkeeping for the episodes created by THIS engagement only, so a
    previous engagement's episodes never get a repair from this trail."""
    episodes: List[Episode]
    seen_actions: int = 0
    started: float = 0.0
    # (episode, index of its action in the audit trail). Ordering by INDEX,
    # not by timestamp: two moves routinely land in the same clock tick and
    # a `<` comparison on ts would then miss the repair entirely.
    pairs: List[Any] = field(default_factory=list)


class Experience:
    """Case-based memory over (situation, technique, outcome, repair)."""

    def __init__(self, enabled: bool = False,
                 path: Optional[str] = None,
                 max_episodes: int = 2000,
                 max_age_days: float = 365.0,
                 cause_classifier=None) -> None:
        self.store = CaseStore(path=path, enabled=enabled,
                               max_episodes=max_episodes)
        self.max_age_days = float(max_age_days)
        # OPTIONAL: a callable (technique, reason, evidence, command) -> cause
        # used only when the deterministic rules land on `other`. Wired to
        # the LLM advisor when the operator enabled it; the rules always
        # run first, so the engine works (and stays reproducible) without it.
        self._classifier = cause_classifier
        self._run = _RunState(episodes=[], seen_actions=0,
                              started=time.time(), pairs=[])
        self._sig: Optional[Signature] = None
        self._signed_for: str = ""

    # ── identity ──────────────────────────────────────────────────────
    @property
    def enabled(self) -> bool:
        """True when the memory persists ACROSS engagements."""
        return self.store.enabled

    def signature_for(self, wm) -> Signature:
        """Current situation (memoised per world-model identity)."""
        marker = f"{getattr(wm, 'target', '')}|{len(wm.all_findings())}"
        if self._sig is None or marker != self._signed_for:
            self._sig = Signature.from_worldmodel(wm)
            self._signed_for = marker
        return self._sig

    def set_classifier(self, classifier) -> None:
        """Attach (or clear) the optional cause classifier."""
        self._classifier = classifier

    def _classify(self, technique: str, reason: str = "",
                  evidence: str = "", command: str = "") -> str:
        """Rules first; the optional classifier only for the ambiguous tail.
        Its answer is accepted only if it is a member of the taxonomy."""
        cause = causes.classify(technique, reason, evidence, command)
        if cause == causes.OTHER and self._classifier is not None:
            try:
                alt = self._classifier(technique, reason, evidence, command)
                if alt in causes.CAUSES:
                    return alt
            except Exception:
                pass
        return cause

    # ── recording ─────────────────────────────────────────────────────
    def observe(self, wm, technique: str, ok: bool, reason: str = "",
                evidence: str = "", command: str = "", phase: str = "",
                repair: str = "", cause: Optional[str] = None) -> Episode:
        """Record one attempt explicitly (used by tests and by callers that
        already know the cause and the repair)."""
        sig = self.signature_for(wm)
        if not ok and not cause:
            cause = self._classify(technique, reason, evidence, command)
        ep = Episode(sig=sig.to_dict(), phase=phase or _phase_of(technique),
                     technique=technique, ok=bool(ok),
                     cause="" if ok else (cause or causes.OTHER),
                     repair=repair, detail=(reason or evidence or "")[:400])
        self.store.record(ep)
        self._run.episodes.append(ep)
        return ep

    def sync(self, wm) -> int:
        """Ingest any new actions from the world model's audit trail.

        Idempotent and incremental: only actions past the last seen index
        become episodes. Repairs are filled in a second pass, matching each
        failure with the first LATER successful move of the same run — which
        is exactly the "what unblocked me" relationship we want to learn.
        """
        try:
            actions = list(getattr(wm, "actions_taken", []) or [])
        except Exception:
            return 0
        if len(actions) < self._run.seen_actions:
            # world model was swapped/reset under us — start a fresh run
            self._run = _RunState(episodes=[], seen_actions=0,
                                  started=time.time(), pairs=[])
        base = self._run.seen_actions
        added = 0
        sig = self.signature_for(wm)
        for i, act in enumerate(actions[base:]):
            if not isinstance(act, dict):
                continue
            tech = str(act.get("capability", "") or "")
            if not tech:
                continue
            ok = bool(act.get("ok"))
            note = str(act.get("note", "") or "")
            cmd = str(act.get("command", "") or "")
            cause = "" if ok else self._classify(tech, note, "", cmd)
            ep = Episode(
                sig=sig.to_dict(), phase=_phase_of(tech), technique=tech,
                ok=ok, cause=cause, repair="",
                detail=(note or cmd or "")[:400],
                ts=float(act.get("ts", 0.0) or time.time()))
            self.store.record(ep)
            self._run.episodes.append(ep)
            self._run.pairs.append((ep, base + i))
            added += 1
        self._run.seen_actions = len(actions)
        if added:
            self._fill_repairs(actions)
        return added

    def _fill_repairs(self, actions: Sequence[Dict[str, Any]]) -> None:
        """Attach, to each failed episode of THIS run, the first later
        successful move with a different technique.

        Walks the audit trail by POSITION, not by timestamp: the clock is
        too coarse to order two moves that happened back to back.
        """
        for ep, idx in self._run.pairs:
            if ep.ok or ep.repair:
                continue
            for j in range(int(idx) + 1, len(actions)):
                act = actions[j]
                if not isinstance(act, dict) or not act.get("ok"):
                    continue
                tech = str(act.get("capability", "") or "")
                if tech and tech != ep.technique:
                    ep.repair = tech
                    break

    # ── advice ────────────────────────────────────────────────────────
    def advise(self, wm, candidates: Optional[Sequence[str]] = None,
               include_hints: bool = True) -> Dict[str, Advice]:
        """Merged advice: data signal first, cold-start hints fill the gaps."""
        sig = self.signature_for(wm)
        out = advise(sig, self.store.episodes, candidates=candidates)
        if include_hints:
            stuck = [ep.cause for ep in self._run.episodes
                     if not ep.ok and ep.cause]
            for tech, adv in cold_start_hints(stuck, list(candidates or [])
                                              ).items():
                if tech not in out:
                    out[tech] = adv
        return out

    def multipliers(self, wm,
                    candidates: Optional[Sequence[str]] = None) -> Dict[str, float]:
        """`{technique: multiplier}` — lower is preferred, 1.0 neutral.

        Drop-in compatible with `TechniquePriors.multiplier_for`, so the
        planner can combine both without a special case.
        """
        return {t: a.multiplier for t, a in
                self.advise(wm, candidates=candidates).items()}

    def explain(self, wm, technique: str) -> Dict[str, Any]:
        return explain(self.signature_for(wm), technique,
                       self.store.episodes)

    def run_context(self) -> Dict[str, Any]:
        """What happened in THIS engagement (used by the report/UI)."""
        prof = consolidate.cause_profile(self._run.episodes)
        return {
            "episodes": len(self._run.episodes),
            "failures": prof["total_failures"],
            "by_cause": prof["by_cause"],
            "worst_technique_per_cause": prof["worst_technique_per_cause"],
            "repairs_learned": sum(1 for e in self._run.episodes if e.repair),
        }

    # ── authoring trigger (evolution loop) ─────────────────────────────
    def authorable_patterns(self) -> List[Dict[str, Any]]:
        """Stable failure clusters the evolution loop could close with a
        NEW capability.

        A pattern is authorable when the SAME (technique, cause) pair
        failed on the same product class at least MIN_AUTHORABLE_N times
        in learnable episodes, and the cause is one the evolution loop
        can plausibly solve (not-found / unsupported-version /
        waf-blocked — NOT environmental causes like dep-missing, which
        no capability file can fix).
        """
        from collections import Counter, defaultdict
        authorable = []
        try:
            buckets: Dict[Tuple[str, str], Counter] = defaultdict(Counter)
            examples: Dict[Tuple[str, str], Episode] = {}
            for ep in self.store.episodes:
                if ep.ok or not ep.learnable() or not ep.technique:
                    continue
                if ep.cause not in _AUTHORABLE_CAUSES:
                    continue
                product = str((ep.sig or {}).get("product", "generic")) \
                    or "generic"
                key = (f"{ep.technique}@{product}", ep.cause)
                buckets[key]["n"] += 1
                examples.setdefault(key, ep)
            for (tech_prod, cause), c in buckets.items():
                n = int(c["n"])
                if n < MIN_AUTHORABLE_N:
                    continue
                ep = examples[(tech_prod, cause)]
                technique, _, product = tech_prod.partition("@")
                authorable.append({
                    "technique": technique,
                    "cause": cause,
                    "missing_fact": _CAUSE_TO_FACT.get(cause, ""),
                    "n": n,
                    "phase": ep.phase,
                    "signature_summary":
                        f"cls={ (ep.sig or {}).get('cls', 'generic') } "
                        f"product={product} "
                        f"services={','.join((ep.sig or {}).get('services', []))}",
                    "evidence": (ep.detail or "")[:300],
                    "remedy": ep.repair or "",
                })
        except Exception:
            return []
        return authorable

    # ── end of run ────────────────────────────────────────────────────
    def finish(self, priors=None) -> Dict[str, Any]:
        """Consolidate: prune, promote strong patterns, persist if global.

        Never raises — a failure to remember must never break an engagement.
        """
        result: Dict[str, Any] = {"pruned": 0, "promoted": 0, "saved": False}
        try:
            episodes = self.store.episodes
            kept = consolidate.prune_by_age(episodes, self.max_age_days)
            self.store._episodes = consolidate.dedupe(kept)
            result["pruned"] = max(0, len(episodes) - len(self.store._episodes))
            if priors is not None:
                result["promoted"] = consolidate.promote_to_priors(
                    self.store._episodes, priors)
            if self.enabled:
                result["saved"] = bool(self.store.save())
        except Exception:
            pass
        return result

    # ── introspection / administration ────────────────────────────────
    def stats(self) -> Dict[str, Any]:
        stats = self.store.stats()
        stats["run"] = self.run_context()
        return stats

    def reset(self) -> None:
        """Forget everything (global store included when enabled)."""
        self.store.clear()
        self._run = _RunState(episodes=[], seen_actions=0,
                              started=time.time(), pairs=[])

    def recent(self, n: int = 50) -> List[Dict[str, Any]]:
        eps = sorted(self.store.episodes, key=lambda e: e.ts)
        return [e.to_dict() for e in eps[-max(1, int(n)):]]


from phantom.automation.brain.experience.causes import (
    WAF_BLOCKED, NOT_FOUND, UNSUPPORTED,
)

# cause classes the evolution loop may close by authoring a new capability
# (environmental causes — dep-missing/scope/gated — are unfixable by code
# the loop can write, and are excluded by design)
_AUTHORABLE_CAUSES = frozenset({WAF_BLOCKED, NOT_FOUND, UNSUPPORTED})
# A SINGLE failure of an eligible cause is enough to spawn authoring: the
# planner already adapts around one-off walls in-run (that is not this
# mechanism's job), the eligible causes are concrete signals, and the real
# noise dampers are the full gate + the daily budgets — not the count.
MIN_AUTHORABLE_N = 1

# the fact kind a NEW capability should produce to close each cause gap
_CAUSE_TO_FACT: Dict[str, str] = {
    WAF_BLOCKED: "web_app",     # an access path the filter does not block
    NOT_FOUND: "web_app",       # the endpoint/service that does exist
    UNSUPPORTED: "service",     # the service that speaks a supported proto
}


def _phase_of(technique: str) -> str:
    try:
        from phantom.automation.phases import phase_of
        return phase_of(technique) or ""
    except Exception:
        return ""
