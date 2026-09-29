"""goals.py — the single goal registry, shared by both engines.

The kill-chain vocabulary used to live in two places that had to be kept
in sync by hand: ``planner.GOAL_FACTS`` (the agent planner's terminal
facts) and ``automode._GOAL_CHAIN`` (which swarm chain template covers a
goal). This module is the ONE source for both, so a new goal is declared
once and both engines see it:

* ``GOAL_FACTS``  — goal -> fact kinds that mean "goal reached". Read by
  the agent planner and by ``automode._dry_run_plan``.
* ``SWARM_CHAIN`` — goal -> fact-driven chain template name (``footprint``,
  ``identity``, ``creds``, ``web``, ``full``, ``deep``). Read by the swarm
  engine; a goal absent here runs on the single-agent path instead.

Pure data: no imports, so it is cheap to import from anywhere (including
``automode`` at module load, which must not pull the planner in).
"""
from __future__ import annotations

# Goal -> fact kinds that mean "goal reached" (any one satisfies).
GOAL_FACTS = {
    "beacon": ["beacon"],
    "creds": ["creds"],
    "footprint": ["service", "os", "web_app", "banner"],
    # NOTE: "persona" was listed here but no interpreter ever emits a
    # finding of kind "persona" (the persona marker yields kind
    # "identity"). The cover itself ("persona_profile") is deliberately
    # NOT terminal: it is a MEANS to phish (see the enrich goal), and
    # listing it here pulled cover-building ahead of OSINT, breaking
    # the identity doctrine (dossier before cover). Terminal identity =
    # know who they are + where they are.
    "identity": ["identity", "victim_ip"],
    # enrich: the DEEPEN sub-agent's goal — passive OSINT/breach/profile
    # deepening + grabber polling. Deliberately excludes the phish/dm_sent
    # facts so this worker NEVER launches new lures while the lead waits.
    "enrich": ["identity", "persona_profile", "dossier", "profile",
               "account_link", "breach_exposure", "victim_ip"],
    "complete_kill_chain": ["beacon"],  # beacon injection is the terminal goal
    "deliver": ["beacon", "persistence"],  # deliver mode: beacon + persistence,
    # web: the URL/app chain terminal is the RCE foothold, not a beacon —
    # demanding a beacon on a pure web target is unreachable by
    # construction (no creds path), which read as "spinning forever".
    "web": ["web_app", "hunt_anomaly", "rce_foothold"],
    "post_exploit": ["beacon", "persistence", "system_privilege", "injection"],
    "harvest": ["stolen_cookies", "bt_device", "cdp_cookies", "socks_proxy"],
    "ad": ["ad_domain", "ad_creds"],
    "crack": ["ad_domain", "ad_creds", "cracked"],
    "lateral": ["pivot"],
    # expand: post-beacon INTERNAL expansion. The beacon snapshots the
    # internal network (interfaces/routes/ARP) and bounds-probes the
    # neighbors for pivot services — without this stage the internal recon
    # capabilities would never be planned and lateral movement would have
    # no host to aim at outside a multi-target campaign.
    "expand": ["internal_host", "internal_service"],
    # evasion: neutralize the defensive stack before the loud stages. Its
    # only source (edr_disable) is aggressive-only + SYSTEM-gated.
    "evasion": ["defensive_gap"],
    "cleanup": ["cleanup"],
    "impact": ["ransom_sim"],
    "trojan": ["trojan_bundle"],
    # xss_exfil is the payoff of a confirmed XSS reflex (session theft),
    # reachable under the exploit goal alongside the RCE foothold.
    "exploit": ["exploit_plan", "hunt_anomaly", "rce_foothold", "xss_exfil"],
    "environment": ["environment"],
    "cloud_creds": ["cloud_creds"],
    "cloud": ["cloud_creds", "cloud_access", "cloud_lateral"],
    "cloud_lateral": ["cloud_lateral", "cloud_access"],
    "mobile": ["mobile", "mdm_vendor"],
}

# goal -> swarm chain template. Goals without a swarm chain (cleanup…)
# fall back to the single-agent path with a notice (honest, not silent).
# "deep" is a meta-goal handled specially by the agent planner, so it is
# a swarm chain here without a GOAL_FACTS entry of its own.
SWARM_CHAIN = {
    "footprint": "footprint", "identity": "identity", "creds": "creds",
    "web": "web",
    "beacon": "full", "deliver": "full", "complete_kill_chain": "full",
    "deep": "deep", "post_exploit": "deep", "ad": "deep",
    "crack": "deep", "lateral": "deep",
}
