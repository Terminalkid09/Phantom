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
from typing import Dict, List, Optional

from phantom.automation.belief import WorldModel, Finding
from phantom.automation.guidance.commands import Capability, Registry
from phantom.automation.guidance.stealth import StealthEngine
from phantom.automation.guidance.tailoring import TailoringEngine

# Goal -> fact kinds that mean "goal reached" (any one satisfies)
GOAL_FACTS = {
    "beacon": ["beacon"],
    "creds": ["creds"],
    "footprint": ["service", "os", "web_app", "banner"],
    "identity": ["identity", "persona", "victim_ip"],
    # enrich: the DEEPEN sub-agent's goal — passive OSINT/breach/profile
    # deepening + grabber polling. Deliberately excludes the phish/dm_sent
    # facts so this worker NEVER launches new lures while the lead waits.
    "enrich": ["identity", "persona_profile", "dossier", "profile",
               "account_link", "breach_exposure", "victim_ip"],
    "complete_kill_chain": ["beacon"],  # beacon injection is the terminal goal
    "deliver": ["beacon", "persistence"],  # deliver mode: beacon + persistence, then STOP
    "post_exploit": ["beacon", "persistence", "system_privilege", "injection"],
    "harvest": ["stolen_cookies", "bt_device", "cdp_cookies", "socks_proxy"],
    "ad": ["ad_domain", "ad_creds"],
    "crack": ["ad_domain", "ad_creds", "cracked"],
    "lateral": ["pivot"],
    "cleanup": ["cleanup"],
    "impact": ["ransom_sim"],
    "trojan": ["trojan_bundle"],
    "exploit": ["exploit_plan", "hunt_anomaly", "rce_foothold"],
    "environment": ["environment"],
    "cloud_creds": ["cloud_creds"],
    "cloud": ["cloud_creds", "cloud_access", "cloud_lateral"],
    "cloud_lateral": ["cloud_lateral", "cloud_access"],
    "mobile": ["mobile", "mdm_vendor"],
}

# Fact kind -> capabilities that can produce it (reverse index, category priority)
_FACT_SOURCES = {
    "service": ["scan_tcp", "version_detect"],
    "fingerprint": ["fingerprint_services"],
    "exploit_plan": ["service_exploit"],
    "hunt_anomaly": ["hunt_web"],
    "differential_anomaly": ["differential_analysis"],
    "rce_foothold": ["web_rce", "rce_foothold"],
    "environment": ["env_probe", "env_probe_internal", "cloud_creds_harvest"],
    "cloud_creds": ["rce_foothold", "cloud_creds_harvest"],
    "cloud_access": ["cloud_s3_enum", "cloud_iam_enum"],
    "cloud_lateral": ["cloud_assume_role", "cloud_cross_account", "cloud_iam_enum"],
    "mobile": ["mobile_probe", "mobile_mdm_fingerprint"],
    "mdm_vendor": ["mobile_mdm_fingerprint"],
    "os": ["os_detect"],
    "banner": ["ssh_banner"],
    "web_header": ["http_probe"],
    "web_app": ["http_probe"],
    "smb_share": ["smb_enum"],
    "redis": ["redis_info"],
    "creds": ["web_creds", "ssh_login", "breach_check", "harvest_campaign"],
    "identity": ["osint_identity", "persona_create"],
    "breach_exposure": ["breach_check"],
    "persona_profile": ["persona_profile"],
    "dossier": ["dossier_analyze"],
    "profile": ["profile_recon"],
    "account_link": ["profile_recon"],
    "phish": ["phish_identity", "campaign_launch", "dm_launch"],
    "dm_sent": ["dm_launch"],
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
class Plan:
    steps: List[PlanStep] = field(default_factory=list)
    goal: str = ""
    complete: bool = False
    blocked_reason: str = ""
    exploit_hint: Optional[dict] = None  # best CVE module for fingerprinted software
    strategy: str = ""          # the strategic stage driving this plan
    strategy_chain: List[str] = field(default_factory=list)  # all applicable stages
    strategic: bool = False     # True when selected by the strategy layer

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
                 tailoring: Optional["TailoringEngine"] = None) -> None:
        self.registry = registry
        self.stealth = stealth
        self.tailoring = tailoring

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
        for _ in range(max_steps):
            if not frontier:
                break
            fact = frontier.pop(0)
            # if another step already produces this fact, skip: it will
            # be available when the plan executes in waves
            if fact in _produced:
                continue
            cap = self._pick_source(fact, used, dead, wm, preference,
                                    _tried=_source_attempts.get(fact, set()))
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
                    exploit_hint=exploit_hint)

    def _pick_source(self, fact: str, used: set, dead: frozenset = frozenset(),
                     wm: Optional["WorldModel"] = None,
                     preference: Optional[List[str]] = None,
                     _tried: Optional[set] = None) -> Optional[Capability]:
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
                continue
            cap = self.registry.get(cap_id)
            if cap is None:
                continue
            if wm is not None and not self._precondition_viable(cap, wm):
                # the gate can never become true (e.g. breach_check is
                # gated on email/username targets only): skip it so the
                # planner falls to the next source instead of looping
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
                return ready[0]
        return candidates[0]

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
                       preference: Optional[List[str]] = None) -> Plan:
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
