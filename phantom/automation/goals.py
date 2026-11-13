"""goals.py — the ONE goal registry, shared by both engines.

The kill-chain vocabulary used to live in two places that had to be kept in
sync by hand: ``planner.GOAL_FACTS`` (the agent planner's terminal facts)
and ``automode._GOAL_CHAIN`` (which swarm chain template covers a goal).
Every goal is now declared EXACTLY ONCE in ``GOALS`` as three facets:

* ``facts``  — fact kinds that mean "goal reached" (any one satisfies).
* ``chain``  — the fact-driven swarm chain template (``footprint``,
  ``identity``, ``creds``, ``web``, ``full``, ``deep``); "" = the goal has
  no swarm chain and runs on the single-agent path.
* ``engine`` — the engine that can drive the goal besides the agent
  planner: "swarm" when a chain exists, "agent" otherwise. This is the
  routing facet ``engine_for`` resolves against the operator's ``--engine``.

The legacy tables stay as DERIVED VIEWS at the bottom so every existing
import (planner, automode, cells, coverage, tests) keeps working against
the same objects — a policy fix is made ONCE, in ``GOALS``.

Pure data + one pure helper: no imports beyond typing, so it is cheap to
import from anywhere (including ``automode`` at module load, which must
not pull the planner in).
"""
from __future__ import annotations

from typing import Dict, List, NamedTuple, Tuple


class Goal(NamedTuple):
    """One goal's declaration: facts + chain + engine, edited in one place."""
    facts: List[str]
    chain: str = ""
    engine: str = "agent"


GOALS: Dict[str, Goal] = {
    "beacon": Goal(["beacon"], "full", "swarm"),
    "creds": Goal(["creds"], "creds", "swarm"),
    "footprint": Goal(["service", "os", "web_app", "banner"],
                      "footprint", "swarm"),
    # NOTE: "persona" was listed here but no interpreter ever emits a
    # finding of kind "persona" (the persona marker yields kind
    # "identity"). The cover itself ("persona_profile") is deliberately
    # NOT terminal: it is a MEANS to phish (see the enrich goal), and
    # listing it here pulled cover-building ahead of OSINT, breaking
    # the identity doctrine (dossier before cover). Terminal identity =
    # know who they are + where they are.
    # `geolocation` is the coarse where-they-are fact: passive phone
    # metadata (phone_osint) pins a region long before a lure ever leaks a
    # victim IP, and a report reader wants both bands. It is additive — the
    # `identity` finding from OSINT still satisfies the goal on its own.
    "identity": Goal(["identity", "victim_ip", "geolocation"],
                     "identity", "swarm"),
    # enrich: the DEEPEN sub-agent's goal — passive OSINT/breach/profile
    # deepening + grabber polling. Deliberately excludes the phish/dm_sent
    # facts so this worker NEVER launches new lures while the lead waits.
    # I3: the NON-CONTACT identity ladder lives here. `enrich` is the DEEPEN
    # worker's goal — passive OSINT/breach/profile deepening that never
    # launches a lure — so the identity-field primitives (candidate
    # composition, SMTP verification, breach correlation) are pursued by the
    # worker whose whole contract is "widen the field without contact".
    # ANY one fact satisfies the goal, so adding these widens what counts as
    # "mapped" and never makes the worker spin on an unreachable fact.
    "enrich": Goal(["identity", "persona_profile", "dossier", "profile",
                    "account_link", "breach_exposure", "victim_ip",
                    "email_candidate", "domain_candidate", "email_verified",
                    "service_account", "identity_widened",
                    "phone", "geolocation"]),
    # beacon injection is the terminal goal
    "complete_kill_chain": Goal(["beacon"], "full", "swarm"),
    # deliver mode: beacon + persistence
    "deliver": Goal(["beacon", "persistence"], "full", "swarm"),
    # web: the URL/app chain terminal is the RCE foothold, not a beacon —
    # demanding a beacon on a pure web target is unreachable by
    # construction (no creds path), which read as "spinning forever".
    "web": Goal(["web_app", "hunt_anomaly", "rce_foothold"], "web", "swarm"),
    "post_exploit": Goal(["beacon", "persistence", "system_privilege",
                          "injection"], "deep", "swarm"),
    "harvest": Goal(["stolen_cookies", "bt_device", "cdp_cookies",
                     "socks_proxy"]),
    "ad": Goal(["ad_domain", "ad_creds"], "deep", "swarm"),
    "crack": Goal(["ad_domain", "ad_creds", "cracked"], "deep", "swarm"),
    "lateral": Goal(["pivot"], "deep", "swarm"),
    # expand: post-beacon INTERNAL expansion. The beacon snapshots the
    # internal network (interfaces/routes/ARP) and bounds-probes the
    # neighbors for pivot services — without this stage the internal recon
    # capabilities would never be planned and lateral movement would have
    # no host to aim at outside a multi-target campaign.
    "expand": Goal(["internal_host", "internal_service"]),
    # evasion: neutralize the defensive stack before the loud stages. Its
    # only source (edr_disable) is aggressive-only + SYSTEM-gated.
    "evasion": Goal(["defensive_gap"]),
    "cleanup": Goal(["cleanup"]),
    "impact": Goal(["ransom_sim"]),
    "trojan": Goal(["trojan_bundle"]),
    # xss_exfil is the payoff of a confirmed XSS reflex (session theft),
    # reachable under the exploit goal alongside the RCE foothold.
    "exploit": Goal(["exploit_plan", "hunt_anomaly", "rce_foothold",
                     "xss_exfil"]),
    "environment": Goal(["environment"]),
    "cloud_creds": Goal(["cloud_creds"]),
    "cloud": Goal(["cloud_creds", "cloud_access", "cloud_lateral"]),
    "cloud_lateral": Goal(["cloud_lateral", "cloud_access"]),
    "mobile": Goal(["mobile", "mdm_vendor"]),
    # "deep" is a meta-goal handled specially by the agent planner (it
    # walks the whole ladder): no GOAL_FACTS entry of its own, but it IS a
    # swarm chain, so it lives here with empty facts.
    "deep": Goal([], "deep", "swarm"),
}

# ---------------------------------------------------------------------------
# I3 — non-contact goals and the facts that open a channel to the target.
# ---------------------------------------------------------------------------
# A NON-CONTACT goal is the contract "widen what we know WITHOUT ever
# opening a channel to the target". `enrich` is the DEEPEN worker's goal:
# it must reach the identity-field primitives but must NEVER launch a lure.
# The planner, however, would happily chain a NEW phish to satisfy
# `victim_ip` (poll_hits needs a sent lure), which violates the contract.
# CONTACT_FACTS are the facts that only exist because a channel was opened
# (a lure sent, a DM delivered). For a non-contact goal the planner treats
# them as UNREACHABLE: if a lure already exists the dependent gate is
# already satisfied (so polling still works), otherwise the branch simply
# stays unsatisfied rather than escalating to contact.
NON_CONTACT_GOALS = frozenset({"enrich"})
CONTACT_FACTS = frozenset({"phish", "dm_sent", "dm_stage", "dm_plan"})


def engine_for(goal: str, requested: str = "agent") -> Tuple[str, str]:
    """Resolve the engine that drives ``goal``: (effective engine, note).

    ``requested`` is the operator's ``--engine`` choice. It is honored
    whenever the goal's declaration supports it; otherwise the run falls
    back to the agent path with a NOTE (honest, not silent) — the note text
    is part of the operator contract, automode only prints it.
    """
    requested = (requested or "agent").strip().lower()
    if requested == "swarm":
        if GOAL_ENGINES.get(goal) == "swarm":
            return "swarm", ""
        return "agent", f"Swarm has no chain for goal '{goal}': agent path"
    return requested, ""


# ---------------------------------------------------------------------------
# derived views (kept for the existing imports; edit GOALS above instead)
# ---------------------------------------------------------------------------

# goal -> fact kinds that mean "goal reached" (any one satisfies). The
# agent planner and automode's dry-run read this view.
GOAL_FACTS: Dict[str, List[str]] = {
    goal: spec.facts for goal, spec in GOALS.items() if spec.facts}

# goal -> fact-driven chain template. Goals without a swarm chain (cleanup…)
# fall back to the single-agent path with a notice (honest, not silent).
SWARM_CHAIN: Dict[str, str] = {
    goal: spec.chain for goal, spec in GOALS.items() if spec.chain}

# goal -> the engine besides the agent planner that can drive it.
GOAL_ENGINES: Dict[str, str] = {
    goal: spec.engine for goal, spec in GOALS.items()}
