"""
planner.py — goal-directed planning over the capability graph.

The planner answers: given the WorldModel beliefs and the goal (e.g.
"reach beacon injection"), what is the cheapest, stealthed path of
capabilities that produces the missing facts?

It reasons over capability preconditions/effects (fact kinds), never over
command strings. Chains are produced as CapabilityChain (ordered list of
Capability + slot_values). The orchestrator executes them.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional

from phantom.automation.belief import WorldModel, Finding
from phantom.automation.guidance.commands import Capability, Registry
from phantom.automation.guidance.stealth import StealthEngine
from phantom.automation.guidance.tailoring import TailoringEngine

# Goal -> fact kinds that mean "goal reached". The goal vocabulary lives in
# phantom/automation/goals.py so the agent planner and the swarm engine read
# ONE source; re-exported here for the many callers that import it from the
# planner.
from phantom.automation.goals import (  # noqa: E402,F401
    CONTACT_FACTS, GOAL_FACTS, NON_CONTACT_GOALS,
)

# Fact kind -> capabilities that can produce it (reverse index, category priority)
_FACT_SOURCES = {
    "service": ["scan_tcp", "version_detect", "curl_probe"],
    "fingerprint": ["fingerprint_services"],
    "exploit_plan": ["service_exploit"],
    "hunt_anomaly": ["hunt_web"],
    "xss_exfil": ["xss_weaponize"],
    "differential_anomaly": ["differential_analysis"],
    "rce_foothold": ["web_rce", "rce_foothold"],
    "environment": ["env_probe", "env_probe_internal", "cloud_creds_harvest"],
    "cloud_creds": ["rce_foothold", "cloud_creds_harvest", "loot_triage"],
    "cloud_access": ["cloud_s3_enum", "cloud_iam_enum"],
    "cloud_lateral": ["cloud_assume_role", "cloud_cross_account", "cloud_iam_enum"],
    "mobile": ["mobile_probe", "mobile_mdm_fingerprint"],
    "mdm_vendor": ["mobile_mdm_fingerprint"],
    "os": ["os_detect", "curl_probe"],
    "banner": ["ssh_banner", "curl_probe"],
    "web_header": ["http_probe"],
    "web_app": ["http_probe"],
    "smb_share": ["smb_enum"],
    "redis": ["redis_info"],
    "creds": ["web_creds", "ssh_login", "breach_check", "harvest_campaign",
              "cred_spray", "loot_triage"],
    "identity": ["osint_identity", "persona_create", "deep_recon"],
    # I2 identity-field primitives: passive composition/verification before
    # the breach lookup, and the breach correlation for a confirmed address.
    "email_candidate": ["email_candidates"],
    "domain_candidate": ["email_candidates"],
    "email_masked": ["reset_enum"],
    "email_verified": ["email_verify"],
    "service_account": ["breach_correlate"],
    "identity_widened": ["breach_correlate"],
    "breach_exposure": ["breach_correlate", "breach_check"],
    "persona_profile": ["persona_profile"],
    "dossier": ["dossier_analyze"],
    "profile": ["profile_recon", "deep_recon"],
    "account_link": ["profile_recon", "deep_recon"],
    "phish": ["phish_identity", "campaign_launch", "dm_launch"],
    "dm_sent": ["dm_launch", "dm_stage2"],
    "dm_stage": ["dm_launch"],
    "dm_plan": ["dm_launch"],
    "follow_sent": ["dm_follow"],
    "follow_accepted": ["wait_follow"],
    "victim_ip": ["poll_hits", "harvest_campaign"],
    "beacon": ["beacon_deploy", "beacon_via_rce"],
    "persistence": ["persistence_install"],
    "system_privilege": ["privesc_system", "privesc_sudo", "privesc_service_perms"],
    "injection": ["inject_beacon"],
    "ad_domain": ["ad_enum"],
    "ad_creds": ["kerberoast", "as_rep_roast", "dc_sync"],
    "cracked": ["hash_crack"],
    "pivot": ["lateral_pivot", "smb_pivot", "winrm_pivot"],
    "internal_host": ["internal_recon"],
    "internal_service": ["internal_probe"],
    "defensive_gap": ["edr_disable"],
    "stolen_cookies": ["cookie_stealer"],
    "bt_device": ["bt_scan"],
    "cdp_cookies": ["cdp_pivot"],
    "socks_proxy": ["socks_proxy"],
    "ransom_sim": ["ransom_sim"],
    "trojan_bundle": ["trojan_deliver"],
    "cleanup": ["cleanup"],
}


def _pre_ok(pre, wm: "WorldModel") -> bool:
    """True when a precondition callable is satisfied by the current world."""
    try:
        return bool(pre(wm))
    except Exception:
        return False


def _fact_satisfied(wm: "WorldModel", fact: str) -> bool:
    """A fact is satisfied only by USEFUL findings.

    creds from a breach dump (valid=False) are knowledge, not access:
    the beacon gate requires valid credentials, so the planner must keep
    planning a creds source until a VERIFIED pair exists.
    """
    if fact == "creds":
        return bool(wm.find("creds", valid=True))
    return wm.has_any(fact)


@dataclass
class PlanStep:
    capability: Capability
    slot_values: Dict[str, str] = field(default_factory=dict)
    reason: str = ""


@dataclass
class RejectedPath:
    """A planner-transparency record: a capability that was CONSIDERED for
    a fact but not chosen, with the concrete reason. Shown to the operator
    so the plan is auditable ('why not X?' has a real answer)."""
    fact: str
    capability: str
    reason: str
    priority_hint: str = ""   # 'preferred' | 'alternative' | 'stealth-gated'

    def to_dict(self) -> dict:
        return {"fact": self.fact, "capability": self.capability,
                "reason": self.reason, "hint": self.priority_hint}


@dataclass
class Plan:
    steps: List[PlanStep] = field(default_factory=list)
    goal: str = ""
    complete: bool = False
    blocked_reason: str = ""
    exploit_hint: Optional[dict] = None  # best CVE module for fingerprinted software
    strategy: str = ""          # the strategic stage driving this plan
    strategy_chain: List[str] = field(default_factory=list)  # all applicable stages
    strategic: bool = False     # True when selected by the strategy layer
    rejected: List[RejectedPath] = field(default_factory=list)  # transparency

    def total_cost(self) -> float:
        return sum(s.capability.opsec_cost for s in self.steps)

    def first_ready(self, registry: Registry, wm: WorldModel) -> Optional[PlanStep]:
        """The first step whose preconditions are met right now."""
        for step in self.steps:
            if all(p(wm) for p in step.capability.preconditions):
                return step
        return None


class Planner:
    """Goal-directed backward planner over capabilities."""

    def __init__(self, registry: Registry, stealth: StealthEngine,
                 tailoring: Optional["TailoringEngine"] = None,
                 value_weight: float = 0.0) -> None:
        self.registry = registry
        self.stealth = stealth
        self.tailoring = tailoring
        # INFORMATION VALUE (opt-in): when > 0, ready moves are ranked by
        # how many not-yet-known facts they unlock, before priors. Default
        # 0.0 = historical behavior (registry order, then priors) — every
        # existing plan is byte-identical. The evidence_first reasoning
        # profile sets 1.0 ("buy information"); cost-greedy planning alone
        # finds the cheapest path, never the most revealing one.
        self.value_weight = float(value_weight or 0.0)
        # case-based experience memory (optional; set by the agent). Like
        # the priors it is a pure REORDERING signal over already-allowed
        # moves: it can never add, remove or authorise a move.
        self.experience: Any = None
        # cross-session technique priors (optional; set by the agent when
        # persist_learning is on). Equal-viability moves are reordered by
        # earned success rate against this target fingerprint class.
        self.priors: Any = None

    def plan(self, wm: WorldModel, goal: str = "complete_kill_chain",
             max_steps: int = 12, dead: Optional[frozenset] = None,
             preference: Optional[List[str]] = None) -> Plan:
        """Backward chain: goal facts -> capabilities -> preconditions.

        Uses the stealth engine to prefer quiet paths (cost is a signal,
        never a block); prefers low cost. `dead` is the set of capabilities
        that already failed without new facts — the planner falls back to
        the NEXT source for a fact (e.g. kerberoast dead -> as_rep_roast ->
        dc_sync), never re-picking a dead move.
        """
        dead = dead or frozenset()
        goal_facts = GOAL_FACTS.get(goal, GOAL_FACTS["complete_kill_chain"])
        # I3: a non-contact goal must never OPEN a channel. The facts that
        # only exist because a lure/DM was sent are treated as unreachable
        # for this plan, so the backward chain degrades to the non-contact
        # ladder instead of escalating to phish_identity (which would break
        # the DEEPEN worker's "widen without contact" contract).
        non_contact = goal in NON_CONTACT_GOALS
        steps: List[PlanStep] = []
        missing = [g for g in goal_facts if not _fact_satisfied(wm, g)]
        if not missing:
            return Plan(steps=steps, goal=goal, complete=True)

        # iterative backward chaining with limited backtracking: if a
        # fact's first source can't be chained (no viable sub-source),
        # the planner tries the NEXT source for the PARENT fact rather
        # than dead-ending. This lets beacon_via_rce (no creds needed)
        # surface when beacon_deploy's creds chain is exhausted.
        frontier = list(missing)
        used: set = set()
        # track which facts we've already tried sources for, so we can
        # backtrack to the parent and try alternatives
        _source_attempts: dict = {}  # fact -> set of cap_ids tried
        _parent: dict = {}  # child fact -> (parent fact, parent step idx)
        # facts that will be produced by a capability already in the plan
        # (so a precondition depending on them doesn't re-enter the frontier)
        _produced: set = set()
        # backward dependency edges, populated as steps are added:
        #   needs[fact] = the unmet precondition facts its producer requires
        # Used to refuse a source that would close a cycle (sourcing `creds`
        # via a move that itself needs `beacon`, when the beacon is what the
        # creds are for). Without this the planner accepted a mutually
        # dependent pair as a "complete", never-executable plan.
        needs: dict = {}

        def _would_cycle(cap: Capability) -> bool:
            for pre in cap.preconditions:
                try:
                    if pre(wm):
                        continue
                except Exception:
                    continue
                for pf in self._precondition_facts(pre, wm):
                    if pf == fact or self._fact_needs(pf, needs, fact):
                        return True
            return False

        # transparency ledger: every capability considered for a fact but
        # NOT chosen, with the concrete reason the operator can read
        rejected: List[RejectedPath] = []
        for _ in range(max_steps):
            if not frontier:
                break
            fact = frontier.pop(0)
            # if another step already produces this fact, skip: it will
            # be available when the plan executes in waves
            if fact in _produced:
                continue
            cap = self._pick_source(fact, used, dead, wm, preference,
                                    _tried=_source_attempts.get(fact, set()),
                                    rejected=rejected, cycle=_would_cycle)
            if cap is None:
                # no source for this fact: try backtracking to the parent
                # (e.g. creds unsourceable -> retry beacon with next source)
                par = _parent.get(fact)
                if par is not None:
                    p_fact, p_idx = par
                    if p_idx < len(steps):
                        # remove the parent step and re-plan its fact
                        # with the next source
                        old_cap = steps[p_idx].capability
                        used.discard(old_cap.id)
                        _source_attempts.setdefault(p_fact, set()).add(old_cap.id)
                        del steps[p_idx]
                        # rebuild frontier: re-add parent fact
                        if p_fact not in frontier:
                            frontier.insert(0, p_fact)
                        # clean up child facts from this branch
                        frontier = [f for f in frontier if f != fact]
                    continue
                continue
            if not self._stealth_ok(cap):
                # stealth-gated: record attempt so backtracking skips it
                _source_attempts.setdefault(fact, set()).add(cap.id)
                rejected.append(RejectedPath(
                    fact=fact, capability=cap.id,
                    reason="stealth-gated for the current profile (too loud "
                           "until de-escalation allows it)",
                    priority_hint="stealth-gated"))
                # re-add fact to try next source
                frontier.insert(0, fact)
                continue
            used.add(cap.id)
            for eff in cap.effects:
                _produced.add(eff)
            steps.append(PlanStep(capability=cap, reason=f"produces {fact}"))
            step_idx = len(steps) - 1
            # what does this capability need to run?
            for pre in cap.preconditions:
                facts = self._precondition_facts(pre, wm)
                for pf in facts:
                    if not _fact_satisfied(wm, pf):
                        needs.setdefault(fact, set()).add(pf)
                    if non_contact and pf in CONTACT_FACTS:
                        # non-contact goal: a channel-opening fact is not a
                        # valid sub-goal here (an existing lure is already
                        # satisfied, so this only fires when it would have
                        # to SEND one)
                        continue
                    if not _fact_satisfied(wm, pf) and pf not in frontier \
                            and pf not in used and pf not in _produced:
                        frontier.append(pf)
                        _parent[pf] = (fact, step_idx)

        complete = any(any(e in goal_facts for e in s.capability.effects) for s in steps)
        exploit_hint = None
        if self.tailoring is not None:
            exploit_hint = self.tailoring.suggest_exploit(wm)
        return Plan(steps=steps, goal=goal, complete=complete,
                    blocked_reason="" if complete else "no affordable path to goal",
                    exploit_hint=exploit_hint, rejected=rejected)

    @staticmethod
    def _fact_needs(start: str, needs: dict, target: str) -> bool:
        """True when `start` transitively requires `target` in the backward
        dependency graph being built for this plan (cycle detection)."""
        seen: set = set()
        stack = [start]
        while stack:
            f = stack.pop()
            if f == target:
                return True
            if f in seen:
                continue
            seen.add(f)
            stack.extend(needs.get(f, ()))
        return False

    def _pick_source(self, fact: str, used: set, dead: frozenset = frozenset(),
                     wm: Optional["WorldModel"] = None,
                     preference: Optional[List[str]] = None,
                     _tried: Optional[set] = None,
                     rejected: Optional[List[RejectedPath]] = None,
                     cycle=None
                     ) -> Optional[Capability]:
        order = _FACT_SOURCES.get(fact, [])
        if self.tailoring is not None:
            allow_banned = wm is not None and wm.has_any("beacon")
            order = self.tailoring.source_order(fact, order,
                                                allow_banned=allow_banned)
        if preference:
            # reasoning-engine hints: try preferred sources first, but never
            # drop the others — a preferred move that is dead/unviable falls
            # back to the standard order.
            pref = set(preference)
            order = [c for c in order if c in pref] + [c for c in order if c not in pref]
        _tried = _tried or set()
        candidates = []
        for cap_id in order:
            if cap_id in used or cap_id in dead or cap_id in _tried:
                if rejected is not None:
                    if cap_id in dead:
                        reason = "already failed this engagement without new facts"
                    elif cap_id in _tried:
                        reason = "already tried for this fact (backtracking)"
                    else:
                        reason = "already in the plan (single use per wave)"
                    rejected.append(RejectedPath(
                        fact=fact, capability=cap_id, reason=reason,
                        priority_hint="alternative"))
                continue
            cap = self.registry.get(cap_id)
            if cap is None:
                continue
            if wm is not None and not self._precondition_viable(cap, wm):
                # the gate can never become true (e.g. breach_check is
                # gated on email/username targets only): skip it so the
                # planner falls to the next source instead of looping
                if rejected is not None:
                    rejected.append(RejectedPath(
                        fact=fact, capability=cap_id,
                        reason="preconditions unplannable for this target type "
                               "(gate can never become true here)",
                        priority_hint="alternative"))
                continue
            if cycle is not None and cycle(cap):
                # mutually dependent source: this move needs something whose
                # producer (already in the plan) needs THIS fact — a cycle
                # that would read as complete but can never execute
                if rejected is not None:
                    rejected.append(RejectedPath(
                        fact=fact, capability=cap_id,
                        reason="would close a dependency cycle with a move "
                               "already in the plan",
                        priority_hint="alternative"))
                continue
            candidates.append(cap)
        if not candidates:
            return None
        # senior ordering: a capability whose preconditions are ALL met
        # right now (e.g. beacon_via_rce with a confirmed rce_foothold)
        # is preferred over one that still needs facts planned (e.g.
        # beacon_deploy -> web_creds). Ready moves win over chains.
        if wm is not None:
            # noise circuit breaker: when the cumulative detection risk
            # is spent, quiet moves are tried BEFORE loud ones so the
            # agent de-escalates instead of hammering a warming defender.
            # The move is still allowed (the kill chain must finish) —
            # only the ORDER changes.
            if getattr(wm, "noise_breaker_tripped", lambda: False)():
                quiet = [c for c in candidates
                         if c.stealth_level in ("passive", "quiet", "low")
                         and c.category not in ("brute", "ad")]
                if quiet:
                    ready_q = [c for c in quiet
                               if c.preconditions and all(_pre_ok(p, wm)
                                                          for p in c.preconditions)]
                    if ready_q:
                        return ready_q[0]
                    return quiet[0]
            ready = [c for c in candidates
                     if c.preconditions and all(_pre_ok(p, wm)
                                                for p in c.preconditions)]
            if ready:
                # KILL-CHAIN DISCIPLINE: when NO service has been discovered
                # yet, the footprint must come first — a target-probing
                # move (http_probe/ssh_banner) with the service fact MISSING
                # would fire blind and "fail", which reads to the operator
                # as a random order ("ssh banner -> fail -> probe -> then
                # scan"). The scan that produces services wins until the
                # WorldModel knows at least one service.
                if not wm.has_any("service"):
                    first_scan = [c for c in ready if "service" in c.effects]
                    if first_scan:
                        return first_scan[0]
                # cross-session priors: among equally-ready moves, prefer
                # the techniques that historically worked against this
                # fingerprint class (multiplier 1.0 for unknown = no-op,
                # stable sort preserves the senior priority order)
                if self.priors is not None or self.experience is not None \
                        or self.value_weight > 0:
                    # combine the coarse global average (priors) with the
                    # situation-scoped cause/repair signal (experience).
                    # Both are "lower = preferred" multipliers, so they
                    # multiply; 1.0 anywhere means "no opinion".
                    emap: Dict[str, float] = {}
                    if self.experience is not None:
                        try:
                            emap = self.experience.multipliers(
                                wm, candidates=[c.id for c in ready])
                        except Exception:
                            emap = {}

                    def _rank(cap):
                        rank = 1.0
                        if self.priors is not None:
                            try:
                                rank *= float(
                                    self.priors.multiplier_for(wm, cap.id))
                            except Exception:
                                pass
                        rank *= float(emap.get(cap.id, 1.0))
                        return rank

                    if self.value_weight > 0:
                        order_idx = {id(c): i for i, c in enumerate(ready)}
                        ready = sorted(
                            ready,
                            key=lambda c: (-self._novel_facts(c, wm),
                                           _rank(c), order_idx[id(c)]))
                    else:
                        ready = sorted(ready, key=_rank)
                return ready[0]
        return candidates[0]

    @staticmethod
    def _novel_facts(cap: Capability, wm: "WorldModel") -> int:
        """How many facts this move would newly unlock: unsatisfied
        effects plus unsatisfied precondition-chain facts. A move whose
        every effect is already known scores 0 (re-probing)."""
        novel = 0
        for effect in (cap.effects or []):
            try:
                if not _fact_satisfied(wm, effect):
                    novel += 1
            except Exception:
                novel += 1
        for pre in (cap.preconditions or []):
            try:
                chained = Planner._precondition_facts(pre, wm)
            except Exception:
                continue
            for fact in chained:
                try:
                    if not _fact_satisfied(wm, fact):
                        novel += 1
                except Exception:
                    novel += 1
        return novel

    @staticmethod
    def _service_requirement(pre) -> str:
        """The specific service a precondition gates on (e.g. 'ssh'), or ''.

        Set by ``kit._has_service_kind`` as ``_phantom_requires_service``.
        """
        return str(getattr(pre, "_phantom_requires_service", "") or "").lower()

    @staticmethod
    def _target_services(wm: "WorldModel") -> set:
        """The service labels the scan has actually observed on the target."""
        out: set = set()
        try:
            for f in wm.find("service"):
                v = f.value if isinstance(f.value, dict) else {}
                svc = str(v.get("service", "")).lower()
                if svc:
                    out.add(svc)
        except Exception:
            pass
        return out

    @staticmethod
    def _precondition_viable(cap: Capability, wm: "WorldModel") -> bool:
        """True when no precondition is provably unplannable.

        A precondition that is unmet NOW is fine when the planner can chain
        facts toward it (service, creds, beacon, victim_ip, ...). A gate
        whose fact set is empty (e.g. _has_target_type) can never be
        satisfied by planning — such a capability is not viable.
        """
        for pre in cap.preconditions:
            try:
                if pre(wm):
                    continue
            except Exception:
                continue
            if not Planner._precondition_facts(pre):
                return False
            # service-SPECIFIC gate (ssh_banner / ssh_login / brute_ssh):
            # once the scan has produced service facts and the required
            # service is not among them, no plan can conjure it. When no
            # service is known yet the gate stays plannable (a scan may
            # still reveal it), so the initial footprint is unaffected.
            req = Planner._service_requirement(pre)
            if req:
                known = Planner._target_services(wm)
                if known and req not in known:
                    return False
        return True

    def _stealth_ok(self, cap: Capability) -> bool:
        return self.stealth.allowed(cap.category, cap.stealth_level, cap.opsec_cost,
                                    forceful=cap.forceful)

    @staticmethod
    def _precondition_facts(pre, wm: Optional["WorldModel"] = None) -> List[str]:
        """Heuristic: map a precondition callable to the fact kinds it gates on.

        The built-in preconditions are thin closures; we derive the fact
        kind from the closure's name or from the WorldModel `find` usage.
        Falls back to the capability being self-sufficient ([]).
        """
        # evaluate first: a precondition already satisfied by the current
        # world state needs NOTHING to be planned (e.g. _has_network_host
        # on a plain ip target must not drag the social chain in)
        if wm is not None:
            try:
                if pre(wm):
                    return []
            except Exception:
                pass
        name = getattr(pre, "__name__", "") or ""
        if "creds" in name:
            return ["creds"]
        if "ad_service" in name:
            # dual AD surface (_has_ad_service): the domain can be reached
            # either through a beacon foothold on a domain box OR directly
            # via reachable LDAP/Kerberos. Plan BOTH so either path can
            # satisfy it — AD works with AND without a beacon.
            return ["beacon", "service"]
        if "service" in name:
            return ["service"]
        if "beacon" in name:
            return ["beacon"]
        if "system" in name:
            return ["system_privilege"]
        if "hash" in name:
            return ["ad_creds"]
        if "dm_ready" in name:
            # _dm_ready (closure _requires_dm_ready) unmet means a PRIVATE
            # account without an accepted follow: the DM is only plannable
            # once follow_accepted exists. MUST precede the generic "ad"
            # check below ("ready" contains "ad").
            return ["follow_accepted"]
        if "lure" in name:
            # _has_sent_lure (closure _requires_lure): the social chain must
            # produce a phish (email/SMS) OR a dm_sent before the grabber
            # can be polled
            return ["phish"]
        if "ad" in name:
            return ["ad_domain"]
        if "network_host" in name:
            # identity target that has not become a machine yet: the plan
            # must first harvest the victim_ip through the social chain
            return ["victim_ip"]
        if "finding" in name:
            # _has_finding("phish") etc: derive the kind from the closure
            # argument by inspecting the cell content
            cell = getattr(pre, "__closure__", None)
            if cell:
                for c in cell:
                    v = c.cell_contents
                    if isinstance(v, str) and v in (
                            "phish", "identity", "victim_ip", "persistence",
                            "system_privilege", "injection", "cleanup",
                            "stolen_cookies", "bt_device", "cdp_cookies",
                            "socks_proxy", "service", "os", "banner",
                            "web_app", "exploit_plan", "dm_sent",
                            "follow_sent", "follow_accepted", "profile",
                            "phish_open", "rce_foothold"):
                        return [v]
            return []
        if "ip" in name:
            return []
        if "target_type" in name:
            return []
        return []

    def plan_strategic(self, wm: WorldModel,
                       goal: Optional[str] = None,
                       max_steps: int = 12,
                       dead: Optional[frozenset] = None,
                       preference: Optional[List[str]] = None,
                       ledger=None) -> Plan:
        """Strategic planning: pick the best stage for THIS target.

        Profiles the target (TargetModel via ProfileDetector), filters the
        declarative strategy library, orders the applicable stages by
        weight and plans the first one whose goal facts are not satisfied
        yet. With an explicit goal, only strategies for that goal compete.
        Falls back to the generic plan (self.plan) when nothing fits — the
        strategy layer guides, never blocks.
        """
        from phantom.automation.guidance.strategy import (
            ProfileDetector, applicable_strategies)

        if self.tailoring is None:
            # the strategic layer is per-target by definition: apply the
            # tailoring preferences (breach-before-brute for identities,
            # banned bt_scan on network hosts) automatically
            self.tailoring = TailoringEngine.for_target(
                wm.target, wm.target_type)

        model = ProfileDetector.detect(wm)
        candidates = applicable_strategies(model)
        # class doctrine: the target class may FORBID stage goals outright
        # (a person never gets a port scan, an IP never gets a breach
        # lookup). The strategy layer guides; doctrine decides.
        if ledger is not None:
            from phantom.automation.brain.doctrine import allows
            # platform branch: an unmanaged iOS device is refused the
            # beacon stage (no sideload, no supervision)
            _plat = (model.mobile_platforms[0]
                     if model.mobile_platforms else None)
            candidates = [s for s in candidates
                          if allows(ledger.chain_class(), s.goal,
                                    platform=_plat,
                                    managed=model.mobile_managed)]
        goal = goal or "complete_kill_chain"
        if goal != "complete_kill_chain":
            for s in candidates:
                if s.goal != goal:
                    continue
                if any(_fact_satisfied(wm, g) for g in GOAL_FACTS.get(s.goal, [])):
                    continue  # this stage is already satisfied
                plan = self.plan(wm, goal=s.goal, max_steps=max_steps, dead=dead,
                                 preference=preference)
                if plan.complete:
                    plan.strategy = s.id
                    plan.strategy_chain = [x.id for x in candidates]
                    plan.strategic = True
                    return plan
        else:
            # the chain ends at the terminal stage (beacon): post-beacon
            # stages only run under their explicit goals
            terminal = set(GOAL_FACTS["complete_kill_chain"])
            chain = []
            for s in candidates:
                chain.append(s.id)
                if terminal.intersection(GOAL_FACTS.get(s.goal, [])):
                    break
            for s in candidates:
                if s.id not in chain:
                    continue
                facts = GOAL_FACTS.get(s.goal, [])
                if any(_fact_satisfied(wm, g) for g in facts):
                    continue  # advance to the next unsatisfied stage
                plan = self.plan(wm, goal=s.goal, max_steps=max_steps, dead=dead,
                                 preference=preference)
                if plan.complete:
                    plan.strategy = s.id
                    plan.strategy_chain = chain
                    plan.strategic = True
                    return plan
            # every stage is already satisfied: nothing left to do
            if chain:
                # But only return complete=True if the terminal goal is
                # actually satisfied — otherwise the agent dead-ends on a
                # stage whose plan didn't complete (e.g. web_creds failed,
                # creds still missing). Fall through to generic planning
                # so the agent keeps trying alternative paths.
                if all(_fact_satisfied(wm, g) for g in
                       GOAL_FACTS.get("complete_kill_chain", [])):
                    return Plan(steps=[], goal=goal, complete=True,
                                strategic=True, strategy_chain=chain)
        # fallback: generic goal-directed planning
        plan = self.plan(wm, goal=goal, max_steps=max_steps, dead=dead,
                         preference=preference)
        if not plan.steps and not plan.complete:
            # Goal not achievable for this target type right now: degrade
            # gracefully so the agent still does useful work instead of
            # halting instantly. Two directions:
            #   * network/terminal goals (beacon, deliver, complete_kill_chain)
            #     on an IDENTITY target (email/username/phone) degrade to the
            #     identity chain (osint -> phish -> poll -> victim_ip): the
            #     device surface is behind the person, so the chain converges
            #     through social engineering first and re-plans toward the
            #     beacon once a victim IP exists.
            #   * identity/social goals on a NETWORK target (ip/domain/url)
            #     degrade to footprint recon (scan + osint): the operator
            #     expects "identity" to start with a scan even on an IP.
            try:
                from phantom.automation.guidance.targets import is_identity_target
                goal_facts = GOAL_FACTS.get(goal, [])
                if is_identity_target(wm.target_type):
                    fb_goal = "identity" if goal != "identity" else None
                else:
                    identity_domain = set(GOAL_FACTS["identity"]) | {
                        "persona", "dossier", "persona_profile", "profile",
                        "account_link", "breach_exposure", "follow_accepted",
                        "follow_sent", "dm_sent", "phish"}
                    fb_goal = ("footprint"
                               if any(f in identity_domain for f in goal_facts)
                               else None)
                if fb_goal and fb_goal != goal:
                    fallback = self.plan(wm, goal=fb_goal,
                                         max_steps=max_steps, dead=dead,
                                         preference=preference)
                    if fallback.steps or fallback.complete:
                        fallback.strategy = f"fallback:{goal}->{fb_goal}"
                        fallback.strategy_chain = [s.id for s in candidates]
                        plan = fallback
            except Exception:
                pass
        plan.strategy_chain = [s.id for s in candidates]
        return plan

    def suggest_next(self, wm: WorldModel, goal: str = "complete_kill_chain") -> Optional[PlanStep]:
        """Cheap next-step suggestion: pick the cheapest usable capability
        that makes progress toward the goal facts."""
        goal_facts = GOAL_FACTS.get(goal, GOAL_FACTS["complete_kill_chain"])
        best = None
        for cap in self.registry.usable(wm):
            if any(e in goal_facts for e in cap.effects):
                if best is None or cap.opsec_cost < best.opsec_cost:
                    if self._stealth_ok(cap):
                        best = cap
        if best is None:
            return None
        slots = {}
        return PlanStep(capability=best, slot_values=slots,
                        reason="cheapest usable step toward goal")
