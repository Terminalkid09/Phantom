"""coverage.py — capability coverage audit: does every declared path exist?

The planner, the strategies, the thin-surface policy and the swarm chains
are all DECLARATIVE: they name goal facts and capability ids as strings.
Nothing at import time checks that those names still refer to something.

That is how a plan silently dies. Rename a capability, drop a fact from an
``effects`` list, or add a chain step whose fact no adapter produces, and
the failure is invisible: the planner simply finds no path, reports "no
affordable path to goal", and the run degrades to scanning. There is no
traceback and no log line — the operator sees a plan that stops, not a bug.

This module turns that class of failure into a reportable one. It is
deliberately a READ-ONLY audit — it never mutates the registry — so it can
be called from the CLI, from the tests, and from a release gate.

The invariants it checks:

1. every capability id referenced by a declarative table exists in the
   registry (`unknown_id`);
2. every goal in ``GOAL_FACTS`` / ``SWARM_CHAIN`` has at least one
   capability that can produce one of its facts (`unreachable_goal`);
3. every fact any chain step needs or provides has at least one producer
   (`unproduced_fact`) — i.e. the fact-driven DAG cannot deadlock;
4. the planner's reverse index and each capability's declared ``effects``
   agree (`effect_drift`) — a plan whose last step is a capability whose
   interpreter emits more than it declares reports ``complete=False``
   even after it succeeded;
5. every engagement profile maps to an EXISTING chain template, and every
   phase that class is expected to reach is reachable (`profile_gap`).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Sequence, Tuple

# ── what each environment class must be able to reach ─────────────────────
#
# The profiles in `swarm.profile_policy` decide the STARTING posture; this
# table states the minimum kill-chain phases that posture must still be
# able to reach. A class whose plan cannot name one of these phases is not
# a plan, it is a label — which is exactly the `--profile mobile` symptom
# (a fixed web chain under a mobile label) this audit guards against.
#
# Deliberately minimal: "reachable" means the registry contains a
# capability for each phase's facts, NOT that the phase always succeeds.
PROFILE_PHASES: Dict[str, Tuple[str, ...]] = {
    "smb": ("footprint", "creds", "beacon"),
    "enterprise": ("footprint", "creds", "beacon", "post_exploit"),
    "cloud": ("identity", "cloud_creds", "cloud"),
    "financial": ("footprint", "creds", "beacon"),
    "government": ("footprint", "beacon", "ad", "lateral"),
    "mobile": ("identity", "mobile"),
}

# Goals that are META (handled by the planner itself, no facts of their
# own) and therefore exempt from the producer check.
_META_GOALS = frozenset({"deep", "complete_kill_chain"})

# Goals a MOBILE target cannot reach: the OS sandbox hides the device (no
# listening ports, no credential path to a beacon), so these stop at "no
# affordable path to goal" no matter how long the run is.
_MOBILE_STRUCTURAL_GOALS = frozenset({
    "beacon", "deliver", "complete_kill_chain", "post_exploit",
    "lateral", "crack", "ad",
})


def feasibility_warnings(profile: str, goal: str) -> List[str]:
    """Human warnings for a (profile, goal) pair that cannot succeed.

    NOT capability gaps: the code exists, but the COMBINATION — or a config
    gate — makes the goal unreachable, and the operator should learn it
    before the run instead of from a halt after it. Deterministic and
    offline, so it is safe to call on every launch.
    """
    out: List[str] = []
    p = (profile or "").strip().lower()
    g = (goal or "").strip().lower()
    if p == "mobile" and g in _MOBILE_STRUCTURAL_GOALS:
        out.append(
            f"profile 'mobile' + goal '{g}': a sandboxed phone exposes no "
            "ports and no credential path to a beacon; the honest goal for "
            "this class is 'identity' (OSINT -> phish -> victim_ip)")
    if g == "impact":
        try:
            from phantom.utils import config as cfg
            allowed = cfg.get_bool("engagement.ransom_sim_allow", False)
        except Exception:
            allowed = False
        if not allowed:
            out.append(
                "goal 'impact' is refused by design until you opt in: set "
                "engagement.ransom_sim_allow=true (PHANTOM_RANSOM_SIM_ALLOW) "
                "— the run otherwise stops at the refusal")
    if g == "evasion":
        out.append(
            "goal 'evasion' needs --aggressive AND an existing SYSTEM "
            "foothold (edr_disable is gated): with no SYSTEM yet on a "
            "hardened host this goal is unreachable until post_exploit "
            "lands — and post_exploit on such a host is what usually "
            "needs the evasion")
    if p == "smb" and g in ("ad", "crack", "lateral"):
        out.append(
            f"goal '{g}' on profile 'smb': no domain controller is expected "
            "in this class — the AD stages will have nothing to aim at")
    return out


@dataclass(frozen=True)
class CoverageGap:
    """One declaration that no longer refers to a working path."""

    kind: str      # unknown_id | unreachable_goal | unproduced_fact
                   # | effect_drift | profile_gap
    where: str     # the table/profile/goal that owns the reference
    detail: str    # what is wrong, concretely

    def __str__(self) -> str:
        return f"[{self.kind}] {self.where}: {self.detail}"


@dataclass(frozen=True)
class ProfileCoverage:
    """Reachability of one engagement profile's phases."""

    profile: str
    chain: str
    thin_surface: str = ""
    phases: Tuple[str, ...] = ()
    unreachable: Tuple[str, ...] = ()
    thin_caps_missing: Tuple[str, ...] = ()
    unknown_thin_caps: Tuple[str, ...] = ()

    @property
    def ok(self) -> bool:
        return not (self.unreachable or self.thin_caps_missing
                    or self.unknown_thin_caps)


@dataclass(frozen=True)
class CoverageAudit:
    """The whole report."""

    registry_size: int = 0
    facts: int = 0
    gaps: Tuple[CoverageGap, ...] = ()
    profiles: Tuple[ProfileCoverage, ...] = ()

    @property
    def ok(self) -> bool:
        return not self.gaps and all(p.ok for p in self.profiles)

    def by_kind(self) -> Dict[str, List[CoverageGap]]:
        out: Dict[str, List[CoverageGap]] = {}
        for gap in self.gaps:
            out.setdefault(gap.kind, []).append(gap)
        return out


# ── registry access ───────────────────────────────────────────────────────

def capability_effects() -> Dict[str, List[str]]:
    """capability id -> declared effects (from the one registry)."""
    from phantom.automation.guidance.kit import CAPABILITIES
    return {c.id: list(c.effects) for c in CAPABILITIES}


def _producers() -> Dict[str, List[str]]:
    """fact kind -> capability ids that declare it in `effects`."""
    out: Dict[str, List[str]] = {}
    for cid, effects in capability_effects().items():
        for fact in effects:
            out.setdefault(fact, []).append(cid)
    return out


def _referenced_ids() -> Dict[str, List[str]]:
    """Every capability id named by a declarative table, with its owner."""
    from phantom.automation.guidance import strategy as S
    from phantom.automation.planner import _FACT_SOURCES
    from phantom.core.chain import _OP_TO_CAP

    refs: Dict[str, List[str]] = {}

    def note(cid: str, owner: str) -> None:
        cid = (cid or "").strip()
        if cid:
            refs.setdefault(cid, [])
            if owner not in refs[cid]:
                refs[cid].append(owner)

    for fact, ids in _FACT_SOURCES.items():
        for cid in ids:
            note(cid, f"planner._FACT_SOURCES[{fact}]")
    for policy, ids in S.THIN_SURFACE_CAPS.items():
        for cid in ids:
            note(cid, f"strategy.THIN_SURFACE_CAPS[{policy}]")
    for operator, mapping in _OP_TO_CAP.items():
        if isinstance(mapping, (tuple, list)) and mapping:
            note(str(mapping[0]), f"chain._OP_TO_CAP[{operator}]")
        elif isinstance(mapping, str):
            note(mapping, f"chain._OP_TO_CAP[{operator}]")
    return refs


# ── the audit ─────────────────────────────────────────────────────────────

def audit() -> CoverageAudit:
    """Run every invariant and return the report (never raises)."""
    from phantom.automation.goals import GOAL_FACTS, SWARM_CHAIN
    from phantom.automation.swarm import profile_policy as PP
    from phantom.automation.swarm.tasks import _CHAINS

    try:
        effects = capability_effects()
    except Exception as exc:  # pragma: no cover - registry must import
        return CoverageAudit(gaps=(CoverageGap(
            "unknown_id", "registry", f"capability registry unreadable: {exc}"),
        ))

    from phantom.automation.planner import _FACT_SOURCES

    producers = _producers()
    gaps: List[CoverageGap] = []

    # 1. declarative ids must resolve
    known = set(effects)
    for cid, owners in sorted(_referenced_ids().items()):
        if cid not in known:
            gaps.append(CoverageGap(
                "unknown_id", owners[0],
                f"capability '{cid}' is not in the registry "
                f"(referenced by {', '.join(owners)})"))

    # 2. goals must be reachable
    for goal, facts in sorted(GOAL_FACTS.items()):
        if goal in _META_GOALS:
            continue
        if not facts:
            gaps.append(CoverageGap(
                "unreachable_goal", f"GOAL_FACTS[{goal}]",
                "no facts declared for this goal"))
            continue
        if not any(fact in producers for fact in facts):
            gaps.append(CoverageGap(
                "unreachable_goal", f"GOAL_FACTS[{goal}]",
                f"no capability produces any of {list(facts)}"))

    # 3. every chain fact must have a producer (the DAG cannot deadlock)
    for chain, specs in sorted(_CHAINS.items()):
        for spec in specs:
            for fact in sorted(set(spec.get("needs", ()))
                               | set(spec.get("provides", ()))):
                if fact not in producers:
                    gaps.append(CoverageGap(
                        "unproduced_fact", f"_CHAINS[{chain}].{spec.get('goal')}",
                        f"fact '{fact}' has no producing capability"))

    # 4. the planner index and the declared effects must agree
    for fact, ids in sorted(_FACT_SOURCES.items()):
        for cid in ids:
            declared = effects.get(cid)
            if declared is not None and fact not in declared:
                gaps.append(CoverageGap(
                    "effect_drift", f"planner._FACT_SOURCES[{fact}]",
                    f"'{cid}' is a source for '{fact}' but its effects are "
                    f"{declared}"))

    # 5. profiles: chain template must exist and phases must be reachable
    profiles: List[ProfileCoverage] = []
    for name, policy in sorted(PP.POLICY.items()):
        chain = policy.chain
        if chain not in _CHAINS:
            gaps.append(CoverageGap(
                "profile_gap", f"profile[{name}]",
                f"chain template '{chain}' does not exist"))
        reached = tuple(
            phase for phase in PROFILE_PHASES.get(name, ())
            if not _phase_reachable(phase, GOAL_FACTS, producers))
        thin_caps = tuple(PP_thin_caps(policy))
        missing = tuple(c for c in thin_caps if c not in known)
        profiles.append(ProfileCoverage(
            profile=name, chain=chain, thin_surface=policy.thin_surface,
            phases=tuple(PROFILE_PHASES.get(name, ())),
            unreachable=reached, thin_caps_missing=missing))

    return CoverageAudit(
        registry_size=len(effects),
        facts=len(producers),
        gaps=tuple(gaps),
        profiles=tuple(profiles),
    )


def PP_thin_caps(policy) -> Sequence[str]:
    """Capability ids the profile's thin-surface policy re-arms."""
    from phantom.automation.guidance.strategy import thin_surface_caps
    try:
        return thin_surface_caps(policy.thin_surface)
    except Exception:
        return ()


def _phase_reachable(phase: str, goal_facts: Dict[str, Sequence[str]],
                     producers: Dict[str, List[str]]) -> bool:
    """A phase is reachable when some capability produces its facts.

    A phase name that is not a goal at all is NOT reachable: a profile
    pointing at a phase nobody declared is a broken reference, and
    silently treating it as "fine" is how the label-vs-plan bug returns.
    """
    facts = goal_facts.get(phase)
    if not facts:
        return False
    return any(fact in producers for fact in facts)


def coverage_for_profile(profile: str) -> ProfileCoverage:
    """Just one profile's row (the CLI asks for one at a time)."""
    for row in audit().profiles:
        if row.profile == profile:
            return row
    return ProfileCoverage(profile=profile, chain="")


# ── rendering ─────────────────────────────────────────────────────────────

def format_report(report: CoverageAudit | None = None) -> str:
    """A compact operator-facing report (one block per profile)."""
    report = report or audit()
    lines = [
        f"capability coverage: {report.registry_size} capabilities, "
        f"{report.facts} fact kinds",
    ]
    for row in report.profiles:
        state = "ok" if row.ok else "GAP"
        lines.append(
            f"  [{state:3s}] {row.profile:12s} chain={row.chain:10s} "
            f"thin={row.thin_surface or '-'}")
        if row.unreachable:
            lines.append(f"        unreachable phases: {list(row.unreachable)}")
        if row.thin_caps_missing:
            lines.append(f"        thin-surface caps missing: "
                         f"{list(row.thin_caps_missing)}")
    if report.gaps:
        lines.append(f"  {len(report.gaps)} declaration gap(s):")
        for gap in report.gaps:
            lines.append(f"    {gap}")
    else:
        lines.append("  no declaration gaps")
    return "\n".join(lines)
