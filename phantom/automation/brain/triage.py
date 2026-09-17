"""
phantom.automation.brain.triage — the failure-case triage cell (C3).

The learning loop used to start from a pattern the experience engine already
considered "authorable", and then hand it straight to the author. That skips
the only question a senior lead asks first:

    is this failure even a CAPABILITY problem?

Most failures are not. A missing tool, a timeout, a policy block, a stealth
veto, an out-of-scope pivot, a transient 503 — none of those are fixed by
writing new offensive code, and a proposal that treats them as a capability
gap wastes the reviewer's afternoon and, worse, teaches the loop to trust its
own noise.

`Triage.package()` therefore turns a raw pattern into a `FailureCase` with a
VERDICT, and only `capability_gap` earns a proposal:

    capability_gap  a technique that failed for a reason a new capability
                    could plausibly fix (not-found / unsupported /
                    waf-blocked) and that nothing already covers
    environmental   the fix lives in setup, tooling or configuration
    operational     the failure was a POLICY outcome (veto, deferral, scope,
                    rate limit): the chain was working, it was told to stop
    unstable        too few occurrences to conclude anything yet
    covered         an existing capability already produces the missing fact

The case carries the context a human (or the authoring sub-agent) needs: the
roster that was running, the stall class, the peer's dissent, the stage, and
the remedies already observed. All of it is data, none of it is a command.
"""

from __future__ import annotations

import time
from dataclasses import asdict, dataclass, field
from typing import Any, Dict, Iterable, List, Optional, Sequence

# causes a capability COULD plausibly fix (mirrors evolution.loop)
CAPABILITY_CAUSES = ("waf_blocked", "not_found", "unsupported")

# causes whose fix lives outside the code
ENVIRONMENTAL_CAUSES = ("dep_missing", "tool_missing", "tool_unavailable",
                        "timeout", "connect_failed", "dns_failed",
                        "tls_failed", "http_5xx", "no_route")

# causes that are POLICY outcomes, not technical ones
OPERATIONAL_CAUSES = ("stealth_veto", "deferred", "egress_busy",
                      "out_of_scope", "rate_limited", "requires_aggressive",
                      "blocked")

VERDICTS = ("capability_gap", "environmental", "operational", "unstable",
            "covered")

# below this many occurrences a pattern is a coincidence, not a finding
MIN_OCCURRENCES = 3


@dataclass
class FailureCase:
    """One triaged failure: the situation, the verdict, and the evidence."""

    case_id: str = ""
    sig_hash: str = ""
    verdict: str = "unstable"
    verdict_reason: str = ""
    technique: str = ""
    cause: str = ""
    missing_fact: str = ""
    occurrences: int = 0
    phase: str = ""
    stage: str = ""
    signature: str = ""
    evidence: str = ""
    remedy: str = ""
    covered_by: str = ""
    # the roster context: WHO was running when it failed
    cells: List[str] = field(default_factory=list)
    active_stage: str = ""
    search_policy: str = "adaptive"
    profile: str = ""
    stall_class: str = ""
    dissent: str = ""
    dissent_reason: str = ""
    created: float = field(default_factory=time.time)

    def to_dict(self) -> dict:
        return asdict(self)

    @property
    def proposes_code(self) -> bool:
        return self.verdict == "capability_gap"

    def to_markdown(self) -> str:
        """The dossier a human (or the author) needs to close the gap.

        Deliberately complete about the SITUATION and deliberately silent
        about the implementation: it names what must become true, the
        contract the capability has to satisfy, and the checklist that will
        be used to accept it — but the code is the reviewer's to write.
        """
        lines = [
            f"# Failure case `{self.case_id}`",
            "",
            f"- **verdict**: `{self.verdict}` — {self.verdict_reason}",
            f"- **technique**: `{self.technique}`",
            f"- **cause**: `{self.cause}`",
            f"- **missing fact**: `{self.missing_fact or '(none derived)'}`",
            f"- **occurrences**: {self.occurrences}",
            f"- **phase / stage**: {self.phase or '?'} / {self.stage or '?'}",
            "",
            "## What was observed",
            "",
            f"- signature: `{self.signature or '(none)'}`",
            f"- evidence: {self.evidence or '(none recorded)'}",
            f"- remedy already attempted: {self.remedy or '(none recorded)'}",
            "",
            "## Why it is (not) a capability gap",
            "",
            self.verdict_reason,
            "",
        ]
        if self.covered_by:
            lines += [f"An existing capability already produces this fact: "
                      f"`{self.covered_by}` — the gap is not in the catalogue.",
                      ""]
        lines += [
            "## Roster context at failure time",
            "",
            f"- acting cells: {', '.join(self.cells) or '(none recorded)'}",
            f"- stage in flight: {self.active_stage or self.stage or '?'}",
            f"- reasoning profile: {self.profile or '?'} "
            f"(search policy: {self.search_policy})",
            f"- stall classification: {self.stall_class or '(none)'}",
        ]
        if self.dissent:
            lines += [f"- second opinion preferred `{self.dissent}`: "
                      f"{self.dissent_reason or '(no reason recorded)'}"]
        lines += [
            "",
            "## What a capability would have to do",
            "",
            f"1. **Precondition**: the world must already hold the facts that "
            f"made this technique the right move in phase "
            f"`{self.phase or '?'}`.",
            f"2. **Action**: perform the technique `{self.technique}` in a way "
            f"that survives the failure cause `{self.cause}`.",
            f"3. **Effect**: produce a `{self.missing_fact or 'new fact'}` "
            f"finding that the planner can pivot on.",
            "4. **Stealth**: declare `opsec_cost`, `detection_risk` and "
            "`stealth_level` honestly — the arbiter reads them.",
            "",
            "## Acceptance checklist",
            "",
            "- [ ] the capability is declarative (preconditions + an adapter "
            "returning typed findings, never a shell string)",
            "- [ ] a unit test reproduces the failure cause and asserts the "
            "new fact appears",
            "- [ ] a negative test asserts no side effect outside the "
            "declared scope",
            "- [ ] the lab run proves it end to end (required for the code "
            "PR path; not required for this proposal)",
            "",
            "---",
            "",
            "_Proposal only. No code is included on purpose: this file is the "
            "input for a reviewer, not a patch._",
        ]
        return "\n".join(lines)


class Triage:
    """Turns raw failure patterns into triaged cases."""

    def __init__(self, registry: Any = None) -> None:
        self.registry = registry

    # ── classification ─────────────────────────────────────────────────
    def verdict_for(self, pattern: Dict[str, Any]) -> tuple:
        """(verdict, reason). Pure function of the pattern and the registry."""
        cause = str(pattern.get("cause", "") or "")
        fact = str(pattern.get("missing_fact", "") or "")
        n = int(pattern.get("n", 0) or 0)

        if cause in OPERATIONAL_CAUSES:
            return ("operational",
                    f"the failure was a POLICY outcome (`{cause}`): the move "
                    "was refused on purpose (stealth budget, scope or "
                    "aggressiveness flag). No capability fixes that — the "
                    "operator's policy does.")
        if cause in ENVIRONMENTAL_CAUSES:
            return ("environmental",
                    f"`{cause}` is an environment/tooling failure: the fix is "
                    "in setup or tooling, not in a new capability.")
        if cause not in CAPABILITY_CAUSES:
            return ("unstable",
                    f"cause `{cause or '(empty)'}` is not a capability "
                    "problem class this loop can act on.")
        if n < MIN_OCCURRENCES:
            return ("unstable",
                    f"only {n} occurrence(s) (threshold {MIN_OCCURRENCES}): "
                    "keep observing before spending a proposal.")
        if not fact:
            return ("unstable",
                    "no missing fact could be derived from the cause, so "
                    "there is nothing for a capability to produce.")
        already = self._covered_by(fact)
        if already:
            return ("covered",
                    f"`{already}` already produces `{fact}` — the gap is in "
                    "planning or preconditions, not in the catalogue.")
        return ("capability_gap",
                f"`{cause}` on `{fact}` is exactly the class a new capability "
                "can close, nothing in the catalogue covers it, and it is "
                "stable across runs.")

    def _covered_by(self, fact: str) -> str:
        if self.registry is None:
            return ""
        try:
            for cap in self.registry.all():
                if fact in set(getattr(cap, "effects", ()) or ()):
                    return str(getattr(cap, "id", ""))
        except Exception:
            pass
        return ""

    # ── packaging ──────────────────────────────────────────────────────
    def package(self, pattern: Dict[str, Any], case_id: str = "",
                roster: Any = None, stall_class: str = "",
                dissent: Optional[Dict[str, Any]] = None,
                search_policy: str = "", profile: str = "") -> FailureCase:
        """Build the case, including WHO was running and WHAT the second
        opinion said — the context a reviewer needs to judge the gap."""
        verdict, reason = self.verdict_for(pattern)
        cells: List[str] = []
        active_stage = ""
        if roster is not None:
            try:
                cells = [c.spec.role for c in roster.team.cells]
                active_stage = getattr(roster, "_stage", "") or ""
                search_policy = search_policy or getattr(
                    roster.profile, "search_policy", "") or ""
            except Exception:
                pass
        case = FailureCase(
            case_id=case_id,
            sig_hash=str(pattern.get("sig_hash", "") or ""),
            verdict=verdict, verdict_reason=reason,
            technique=str(pattern.get("technique", "") or ""),
            cause=str(pattern.get("cause", "") or ""),
            missing_fact=str(pattern.get("missing_fact", "") or ""),
            occurrences=int(pattern.get("n", 0) or 0),
            phase=str(pattern.get("phase", "") or ""),
            stage=active_stage or str(pattern.get("phase", "") or ""),
            signature=str(pattern.get("signature_summary", "") or ""),
            evidence=str(pattern.get("evidence", "") or ""),
            remedy=str(pattern.get("remedy", "") or ""),
            covered_by=self._covered_by(str(pattern.get("missing_fact", "") or "")),
            cells=cells, active_stage=active_stage,
            search_policy=search_policy or "adaptive",
            profile=profile, stall_class=stall_class or "",
        )
        if dissent:
            case.dissent = str(dissent.get("adopted", "") or "")
            case.dissent_reason = str(dissent.get("dissent_reason", "") or "")
        return case

    def package_all(self, patterns: Sequence[Dict[str, Any]],
                    roster: Any = None, stall_class: str = "",
                    dissent: Optional[Dict[str, Any]] = None) -> List[FailureCase]:
        out: List[FailureCase] = []
        for pat in patterns:
            pid = str(pat.get("sig_hash", "") or "")
            out.append(self.package(pat, case_id=pid, roster=roster,
                                    stall_class=stall_class, dissent=dissent,
                                    profile=getattr(roster, "profile", None)
                                    and roster.profile.name or ""))
        return out

    @staticmethod
    def proposable(cases: Iterable[FailureCase]) -> List[FailureCase]:
        return [c for c in cases if c.proposes_code]
