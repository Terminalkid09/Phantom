"""benchmark.py — the AutoMode benchmark: ground truth, injected failures, and
metrics that cannot flatter the run.

The audit's gap was not "there is no test" — there are thousands — but that
nothing MEASURED a run against what was true about the target: "benchmark
AutoMode con ground truth e failure injection (goal success, partial, falsi
positivi, azioni inappropriate, time to recover, budget overrun, interventi
dell'operatore)".

Three principles make this a benchmark rather than a demo:

1. **Ground truth is declared, not observed.** A :class:`Scenario` states what
   the target actually runs, what it actually accepts and whether the goal is
   reachable AT ALL. A finding outside that truth is a FALSE POSITIVE — the
   agent inventing a service or a credential is scored, not celebrated.
2. **Failure injection is part of the scenario.** ``failures`` makes the first
   N commands matching a token fail, so RECOVERY is measured (moves between
   the last injected failure and the next move that produced evidence) instead
   of assumed.
3. **The outcome comes from the production model.** Success is whatever
   :mod:`phantom.automation.engagement_outcome` says it is — the same token the
   report and the UI show. The benchmark never has its own idea of "done".

Everything is offline: every command is answered by the scenario's scripted
runner and nothing leaves the box. ``scripts/automode_benchmark.py`` runs the
suite and exits non-zero when a scenario violates its own expectations, so CI
(or an operator before a release) fails on a regression in BEHAVIOUR, not just
on an exception.
"""

from __future__ import annotations

import os
import re
import tempfile
from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Mapping, Optional, Sequence, Tuple

from phantom.automation.engagement_outcome import (
    derive_target_outcome,
    outcome_label,
)

#: Events that hand control (or a decision) to a human. The metric counts
#: them: an auto-mode that needs the operator every two moves is not
#: autonomous, however good its findings are.
OPERATOR_EVENTS = ("handoff", "confirm", "consent", "await_operator",
                   "escalation", "manual_step")

#: Result keys that name the goal's terminal fact (evidence of success).
_GOAL_FACT_KEYS = ("beacon_established", "persistence_installed",
                   "system_privilege")


# --------------------------------------------------------------------- model


@dataclass
class Scenario:
    """One benchmark scenario: the target as it IS, and the run's expectations."""

    name: str
    summary: str = ""
    goal: str = "complete_kill_chain"
    target: str = "10.0.0.5"
    #: Engagement scope. Empty means "the /24 around the target", derived the
    #: way an operator would declare it. It is NEVER disabled: auto-mode fails
    #: closed without a scope (A-6), and a benchmark that switched that off
    #: would measure a path production does not take.
    scope: Tuple[str, ...] = ()
    profile: str = "enterprise"
    aggressive: bool = False

    # ── ground truth ─────────────────────────────────────────────────────
    services: Tuple[Tuple[str, str], ...] = ()      # (port, service) that ARE there
    creds: Tuple[Tuple[str, str], ...] = ()         # (user, password) accepted
    reachable: bool = True                          # can the goal be won here?
    forbidden: Tuple[str, ...] = ()                 # moves that are WRONG here
    max_opsec: float = 0.0                          # 0 = no budget declared
    noise_limit: float = 0.0                        # 0 = the engine's own limit

    # ── failure injection (command token -> consecutive failures) ────────
    failures: Mapping[str, int] = field(default_factory=dict)

    # ── what the run must look like ──────────────────────────────────────
    expectations: Mapping[str, Any] = field(default_factory=dict)

    def attests(self, kind: str, key: str, value: Any) -> Optional[bool]:
        """Is a finding SUPPORTED by the ground truth?

        ``None`` means "not scored" — a ``hostname`` or an ``os`` guess is not
        a claim about what runs on the box, and scoring it would produce noise
        rather than signal.
        """
        kind = str(kind or "")
        if kind == "service":
            # service keys appear as "22", "22/tcp", "10.0.0.5:22/tcp": the
            # PORT is the last number in the key, which survives all three
            numbers = re.findall(r"\d+", str(key))
            port = numbers[-1] if numbers else str(key)
            if not self.services:
                return None
            return any(str(p) == port for p, _ in self.services)
        if kind in ("creds", "ad_creds"):
            if not self.creds:
                return None
            user = ""
            if isinstance(value, dict):
                user = str(value.get("user") or value.get("username") or "")
            return any(user == u for u, _ in self.creds)
        if kind == "beacon":
            return bool(self.reachable)
        return None

    def to_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name, "goal": self.goal, "target": self.target,
            "services": [list(s) for s in self.services],
            "creds": [list(c) for c in self.creds],
            "reachable": self.reachable, "forbidden": list(self.forbidden),
            "max_opsec": self.max_opsec, "noise_limit": self.noise_limit,
            "failures": dict(self.failures),
            "expectations": dict(self.expectations),
        }


@dataclass
class Metrics:
    """A run, scored against its scenario."""

    scenario: str
    goal: str
    outcome: str = "not_started"
    goal_reached: bool = False
    partial: bool = False
    moves: int = 0
    failures: int = 0
    false_positives: List[str] = field(default_factory=list)
    inappropriate_actions: List[str] = field(default_factory=list)
    blocked_moves: List[str] = field(default_factory=list)
    time_to_recover: Optional[int] = None
    operator_interventions: int = 0
    budget: Dict[str, Any] = field(default_factory=dict)
    attempts: List[Dict[str, Any]] = field(default_factory=list)

    @property
    def outcome_label(self) -> str:
        return outcome_label(self.outcome)

    @property
    def honest(self) -> bool:
        """The two ways a benchmark run can LIE: claiming a goal it did not
        reach, or reporting an outcome that contradicts its own metrics."""
        if self.goal_reached and self.outcome != "completed_goal":
            return False
        if self.outcome == "completed_goal" and not self.goal_reached:
            return False
        return True

    def to_dict(self) -> Dict[str, Any]:
        return {
            "scenario": self.scenario, "goal": self.goal,
            "outcome": self.outcome, "outcome_label": self.outcome_label,
            "goal_reached": self.goal_reached, "partial": self.partial,
            "moves": self.moves, "failures": self.failures,
            "false_positives": list(self.false_positives),
            "inappropriate_actions": list(self.inappropriate_actions),
            "blocked_moves": list(self.blocked_moves),
            "time_to_recover": self.time_to_recover,
            "operator_interventions": self.operator_interventions,
            "budget": dict(self.budget), "honest": self.honest,
        }


# ------------------------------------------------------------------ harness


def _fake_beacon_builder(platform: str, host: str, port: int) -> Optional[str]:
    """The scenario's compiler: a real file, no toolchain (offline)."""
    handle, path = tempfile.mkstemp(prefix="bench_beacon_", suffix=".bin")
    with os.fdopen(handle, "wb") as fh:
        fh.write(b"PHANTOM-BENCH-BEACON")
    return path


def _register_beacon(target: str, index: int) -> str:
    """What a real beacon does on check-in: it appears in the C2 state."""
    from phantom.core.c2_server import c2_state
    beacon_id = f"beacon-{target}-{index}"
    c2_state.update_beacon(beacon_id, {"ip": target, "os": "Linux 5.15"})
    return beacon_id


def scope_for(scenario: Scenario) -> Tuple[str, ...]:
    """The engagement scope a scenario runs under.

    Explicit when the scenario says so, otherwise the /24 that contains the
    target. Falling back to "no scope" is not an option: the agent refuses to
    start without one, and a benchmark that turned that refusal off would
    measure code the operator never runs.
    """
    if scenario.scope:
        return tuple(str(s) for s in scenario.scope)
    try:
        import ipaddress
        network = ipaddress.ip_network(f"{scenario.target}/24", strict=False)
        return (str(network),)
    except ValueError:
        return (str(scenario.target),)


def open_target_runner(target: str, truth: Scenario,
                       log: Optional[List[str]] = None) -> Callable:
    """A plain internet-facing Linux box: SSH + a small web app.

    Every answer is derived from ``truth.services`` / ``truth.creds``, so the
    agent can only "find" what is really there — which is what makes a false
    positive detectable.
    """
    seen = {"deployed": 0}
    ports = {str(p) for p, _ in truth.services}
    passwords = {pw for _, pw in truth.creds}

    def runner(cmd, timeout=None):
        from unittest.mock import Mock
        text = str(cmd)
        if log is not None:
            log.append(text)
        res = Mock(ok=False, stdout="", stderr="")
        if "api/v1/payload" in text or ("sshpass" in text and "scp" in text):
            # the staged beacon checks in — only if the goal is reachable
            if truth.reachable:
                seen["deployed"] += 1
                _register_beacon(target, seen["deployed"])
                res.ok, res.stdout = True, "PHANTOM"
            return res
        if "nmap" in text or "masscan" in text or "nc -z" in text:
            res.ok = True
            res.stdout = "\n".join(f"{p}/tcp open {s}"
                                   for p, s in truth.services)
            return res
        if text.startswith("nc ") or "nc -w" in text:
            res.ok, res.stdout = True, "SSH-2.0-OpenSSH_8.9p1 Ubuntu"
            return res
        if "curl" in text or "wget" in text or "httpx" in text:
            res.ok = True
            res.stdout = ("HTTP/1.1 200 OK\n"
                          "Server: nginx/1.18.0\n"
                          "<html><title>Login</title></html>")
            return res
        if "sshpass" in text or "ssh_login" in text:
            if passwords:
                res.ok, res.stdout = True, "uid=0(root) gid=0(root)"
            return res
        res.ok, res.stdout = True, "PHANTOM"
        return res

    return runner


def fortress_runner(target: str, truth: Scenario,
                    log: Optional[List[str]] = None) -> Callable:
    """A hardened appliance: no 22/80, admin UI on 8443, no open creds.

    This is the shape ``scripts/hardened_target_sim.py`` argues about — here it
    is scored: the run must NOT reach the goal, must NOT invent a service and
    must NOT deploy a beacon it has no foothold for.
    """
    def runner(cmd, timeout=None):
        from unittest.mock import Mock
        text = str(cmd)
        if log is not None:
            log.append(text)
        res = Mock(ok=False, stdout="", stderr="")
        if "api/v1/payload" in text or ("sshpass" in text and "scp" in text):
            return res                       # no foothold: nothing checks in
        if "nmap" in text or "masscan" in text or "nc -z" in text:
            res.ok = True
            res.stdout = "\n".join(f"{p}/tcp open {s}"
                                   for p, s in truth.services)
            return res
        if "curl" in text or "wget" in text:
            if "8443" in text:
                res.ok = True
                res.stdout = ("HTTP/1.1 200 OK\nServer: FRTX/2.1\n"
                              "<html><title>Fortress Admin</title></html>")
            else:
                res.ok, res.stdout = False, ""   # no 80/443 at all
            return res
        return res

    return runner


def inject_failures(runner: Callable, failures: Mapping[str, int],
                    state: Optional[Dict[str, int]] = None) -> Callable:
    """Wrap a runner so the first N commands matching a token FAIL.

    Keyed by a command token (``{"nmap": 2}``) rather than by capability id,
    because that is the only thing a runner can see — and it is also what
    makes the injection independent of the planner's naming.
    """
    counters: Dict[str, int] = state if state is not None else {}

    def wrapped(cmd, timeout=None):
        from unittest.mock import Mock
        text = str(cmd)
        for token, limit in (failures or {}).items():
            if token in text:
                used = counters.get(token, 0)
                if used < int(limit):
                    counters[token] = used + 1
                    return Mock(ok=False, stdout="", stderr="injected failure")
        return runner(cmd, timeout=timeout)

    wrapped.injected = counters       # type: ignore[attr-defined]
    return wrapped


def build_agent(scenario: Scenario, runner: Callable, events: List,
                scope: Sequence[str] = ()):
    """The production agent, wired for an offline scenario.

    Deliberately the REAL class with REAL collaborators (stealth engine,
    planner, world model): a benchmark that measured a simplified loop would
    measure the simplification.
    """
    from phantom.automation.agent import AutonomousAgent
    from phantom.automation.belief import WorldModel
    from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
    from phantom.automation.runtime.stealth_runtime import (
        StealthRuntime,
        TimingGovernor,
    )
    from phantom.automation.runtime.toolchain import ToolRegistry
    from phantom.automation.sandbox.sandbox import (
        SandboxEngine,
        SandboxResult,
        SandboxVerdict,
    )

    class _Approve(SandboxEngine):
        def preflight(self, sample_path):
            return SandboxVerdict(approved=True,
                                  results=[SandboxResult(backend="bench",
                                                         ok=True)])

    wm = WorldModel(target=scenario.target)
    if scenario.noise_limit > 0:
        # NOISE_LIMIT is read through the instance, so setting it here is
        # exactly how an operator tightens the allowance for one engagement.
        wm.NOISE_LIMIT = float(scenario.noise_limit)
    engine = StealthEngine(wm, StealthConfig(aggressive=scenario.aggressive,
                                            profile=scenario.profile))
    runtime = StealthRuntime(engine, runner=runner, cost_per_action=0.5,
                             governor=TimingGovernor(base_delay=0.0,
                                                     jitter=0.0))
    return AutonomousAgent(
        target=scenario.target, target_type="ip", profile=scenario.profile,
        aggressive=scenario.aggressive,
        # ONE world model, shared with the runtime: the OPSEC ledger and the
        # noise breaker the benchmark reads are then the agent's own numbers
        # (a private copy scored 0 spend while actions really ran).
        shared_wm=wm,
        on_event=lambda kind, data: events.append((kind, dict(data or {}))),
        runtime=runtime,
        cred_discoverer=lambda service: (scenario.creds[0]
                                         if scenario.creds else None),
        sandbox=_Approve(),
        scope_list=list(scope),
        toolchain=ToolRegistry(installed={"nmap", "sshpass", "curl", "nc",
                                          "redis-cli", "smbmap", "masscan"}),
        beacon_builder=_fake_beacon_builder,
    )


# ------------------------------------------------------------------ scoring


def _attempts(events: Sequence[Tuple[str, Dict[str, Any]]]) -> List[Dict]:
    """Ordered moves: what the agent TRIED and how it ended.

    Built from the event stream the UI already renders, so the metric and the
    operator see the same run. A ``blocked`` event is a move that never ran —
    it still counts as an attempt (and as a failure to advance).
    """
    open_move: Dict[str, Dict[str, Any]] = {}
    out: List[Dict[str, Any]] = []
    for kind, data in events:
        cap = str(data.get("capability") or "")
        if kind == "run":
            move = {"capability": cap, "ok": None}
            open_move[cap] = move
            out.append(move)
        elif kind in ("found", "beacon_up"):
            move = open_move.get(cap)
            if move is not None and move["ok"] is None:
                move["ok"] = True
        elif kind == "unverified":
            move = open_move.get(cap)
            if move is not None and move["ok"] is None:
                move["ok"] = False
        elif kind == "failed":
            move = open_move.get(cap)
            if move is not None and move["ok"] is None:
                move["ok"] = False
        elif kind == "blocked":
            out.append({"capability": cap, "ok": False, "blocked": True})
    return out


def _time_to_recover(moves: Sequence[Dict],
                     injected: Mapping[str, int]) -> Optional[int]:
    """Moves between the LAST INJECTED failure and the next evidence.

    ``injected`` counts what the runner actually failed, so the recovery point
    is found precisely: the Nth failure in the move sequence is the Nth
    injection, and recovery is the first move AFTER it that produced evidence.

    ``None`` means the run did not recover (or nothing was injected) — never
    "0 moves, all good": an unrecovered failure must not look like a pass.
    """
    total = sum(int(v) for v in (injected or {}).values())
    if total <= 0:
        return None
    failures = [i for i, move in enumerate(moves)
                if move.get("ok") is False]
    if len(failures) < total:
        return None                       # the injection never even landed
    last_injected = failures[total - 1]
    for index in range(last_injected + 1, len(moves)):
        if moves[index].get("ok") is True:
            return index - last_injected
    return None


def score(scenario: Scenario, result: Dict[str, Any],
          events: Sequence[Tuple[str, Dict[str, Any]]],
          wm: Any, injected: Optional[Mapping[str, int]] = None) -> Metrics:
    """Turn one run into metrics, against the scenario's ground truth."""
    result = result or {}
    moves = _attempts(events)

    false_positives: List[str] = []
    for finding in getattr(wm, "all_findings", lambda: [])():
        verdict = scenario.attests(getattr(finding, "kind", ""),
                                   str(getattr(finding, "key", "")),
                                   getattr(finding, "value", None))
        if verdict is False:
            false_positives.append(f"{getattr(finding, 'kind', '')}:"
                                   f"{getattr(finding, 'key', '')}")

    forbidden = set(scenario.forbidden or ())
    inappropriate = sorted({move["capability"] for move in moves
                            if move["capability"] in forbidden})
    blocked = [move["capability"] for move in moves if move.get("blocked")]

    interventions = sum(1 for kind, data in events
                        if kind in OPERATOR_EVENTS
                        or (kind == "blocked"
                            and "operator" in str(data.get("reason", "")).lower()))

    goal_reached = bool(result.get("goal_reached"))
    outcome = derive_target_outcome(scenario.goal, result)
    spent = float(result.get("opsec_spent") or 0.0)
    noise = float(getattr(wm, "noise_score", 0.0) or 0.0)
    limit = float(getattr(wm, "NOISE_LIMIT", 0.0) or 0.0)
    overrun = bool(
        (scenario.max_opsec and spent > scenario.max_opsec)
        or (limit and noise > limit))
    budget = {"spent_opsec": round(spent, 2), "max_opsec": scenario.max_opsec,
              "noise": round(noise, 2), "noise_limit": limit,
              "overrun": overrun}

    metrics = Metrics(
        scenario=scenario.name, goal=scenario.goal, outcome=outcome,
        goal_reached=goal_reached, partial=(outcome == "partial"),
        moves=len(moves), failures=len([m for m in moves
                                        if m.get("ok") is False]),
        false_positives=sorted(set(false_positives)),
        inappropriate_actions=inappropriate, blocked_moves=blocked,
        time_to_recover=_time_to_recover(moves, injected or {}),
        operator_interventions=interventions, budget=budget,
        attempts=moves,
    )
    return metrics


# ------------------------------------------------------------------- runner


def run_scenario(scenario: Scenario, log: Optional[List[str]] = None,
                 max_iterations: int = 20, scope: Sequence[str] = ()) -> Metrics:
    """Run one scenario offline and score it. Never raises on a refused run."""
    from phantom.automation import engagement_outcome as eo

    events: List = []
    commands: List[str] = []
    # `reachable` chooses WHICH target this is: the scenarios that cannot be
    # won are the hardened ones, and their runner is the honest answer.
    scene_runner = (open_target_runner if scenario.reachable
                    else fortress_runner)
    base = scene_runner(scenario.target, scenario, commands)
    counters: Dict[str, int] = {}
    runner = inject_failures(base, scenario.failures, counters)

    from phantom.automation.belief import WorldModel

    original_limit = WorldModel.NOISE_LIMIT
    agent = build_agent(scenario, runner, events,
                        scope=scope or scope_for(scenario))
    error = ""
    try:
        result = agent.run(goal=scenario.goal, max_iterations=max_iterations)
    except Exception as exc:                       # a crash is a RESULT
        result = {"goal_reached": False}
        error = f"{type(exc).__name__}: {exc}"
    finally:
        WorldModel.NOISE_LIMIT = original_limit
    metrics = score(scenario, result, events, agent.wm, counters)
    if error:
        metrics.outcome = eo.derive_target_outcome(scenario.goal, result,
                                                   error=error)
    if log is not None:
        log.extend(commands)
    return metrics


def check_expectations(scenario: Scenario, metrics: Metrics) -> List[str]:
    """Every way the run broke the scenario's own contract (empty = passed)."""
    violations: List[str] = []
    expected = dict(scenario.expectations or {})

    def _flag(key: str, actual: Any) -> None:
        violations.append(f"{scenario.name}: {key} is {actual!r}, "
                          f"expected {expected[key]!r}")

    for key, want in expected.items():
        if key == "goal_reached":
            if bool(metrics.goal_reached) != bool(want):
                _flag(key, metrics.goal_reached)
        elif key == "outcome":
            if metrics.outcome != want:
                _flag(key, metrics.outcome)
        elif key == "false_positives":
            if len(metrics.false_positives) > int(want):
                _flag(key, metrics.false_positives)
        elif key == "inappropriate_actions":
            if len(metrics.inappropriate_actions) > int(want):
                _flag(key, metrics.inappropriate_actions)
        elif key == "operator_interventions_at_most":
            if metrics.operator_interventions > int(want):
                _flag(key, metrics.operator_interventions)
        elif key == "time_to_recover_at_most":
            if metrics.time_to_recover is None or \
                    metrics.time_to_recover > int(want):
                _flag(key, metrics.time_to_recover)
        elif key == "time_to_recover_at_least":
            if metrics.time_to_recover is None or \
                    metrics.time_to_recover < int(want):
                _flag(key, metrics.time_to_recover)
        elif key == "budget_overrun":
            if bool(metrics.budget.get("overrun")) != bool(want):
                _flag(key, metrics.budget.get("overrun"))
        elif key == "honest":
            if metrics.honest != bool(want):
                _flag(key, metrics.honest)
        else:
            violations.append(f"{scenario.name}: unknown expectation {key!r}")
    return violations


# ------------------------------------------------------------------ the suite

#: Moves auto-mode must NEVER take on its own, on any target: destroying or
#: hiding evidence is the operator's decision, and the chain is handed over at
#: the beacon. Attempting a PROBE (web_rce on an app that turns out not to be
#: vulnerable) is normal work and is scored as a false POSITIVE only if it is
#: reported as a success — that is what the ground truth is for.
_NEVER_AUTO = ("cleanup", "unpersist", "impact", "wiper", "ransom", "exfil")

OPEN_TARGET = Scenario(
    name="open_target",
    summary="internet-facing Linux box: SSH + a small web app, known creds",
    target="10.0.0.5",
    services=(("22", "ssh"), ("80", "http")),
    creds=(("root", "toor"),),
    reachable=True,
    forbidden=_NEVER_AUTO,
    expectations={"goal_reached": True, "outcome": "completed_goal",
                  "false_positives": 0, "inappropriate_actions": 0,
                  "honest": True},
)

FLAKY_WEB_PROBE = Scenario(
    name="flaky_web_probe",
    summary="the same box, but the web fingerprint fails TWICE: the run must "
            "route around it (the SSH path is still there) and recover",
    target="10.0.0.5",
    services=(("22", "ssh"), ("80", "http")),
    creds=(("root", "toor"),),
    reachable=True,
    forbidden=_NEVER_AUTO,
    failures={"curl": 2},
    expectations={"goal_reached": True, "time_to_recover_at_least": 1,
                  "false_positives": 0, "honest": True},
)

SCAN_FAILURE = Scenario(
    name="scan_failure",
    summary="the port scan fails TWICE. MEASURED GAP: the run does not recover "
            "the foothold path and finishes as `partial`. The benchmark "
            "asserts only that it says so (honesty), never that it succeeded.",
    target="10.0.0.5",
    services=(("22", "ssh"), ("80", "http")),
    creds=(("root", "toor"),),
    reachable=True,
    forbidden=_NEVER_AUTO,
    failures={"nmap": 2},
    expectations={"honest": True, "false_positives": 0,
                  "inappropriate_actions": 0},
)

FORTRESS = Scenario(
    name="fortress",
    summary="hardened appliance: SSH on 2222 only, admin UI on 8443, no creds",
    target="10.13.37.9",
    services=(("2222", "ssh"), ("8443", "https")),
    creds=(),
    reachable=False,          # nothing checks in: deployment must NOT happen
    forbidden=_NEVER_AUTO + ("beacon_deploy", "beacon_via_rce"),
    expectations={"goal_reached": False, "false_positives": 0,
                  "inappropriate_actions": 0, "honest": True},
)

BUDGET_CAPPED = Scenario(
    name="budget_capped",
    summary="a deliberately tiny OPSEC allowance: the overrun must be VISIBLE "
            "in the metrics instead of being discovered after the fact",
    target="10.0.0.5",
    services=(("22", "ssh"), ("80", "http")),
    creds=(("root", "toor"),),
    reachable=True,
    forbidden=_NEVER_AUTO,
    max_opsec=1.0,
    noise_limit=2.0,
    expectations={"budget_overrun": True, "honest": True},
)


def suite() -> Tuple[Scenario, ...]:
    """The standard scenarios, cheap enough to run in CI."""
    return (OPEN_TARGET, FLAKY_WEB_PROBE, SCAN_FAILURE, FORTRESS,
            BUDGET_CAPPED)


def run_suite(scenarios: Optional[Sequence[Scenario]] = None,
              max_iterations: int = 20) -> Dict[str, Any]:
    """Run every scenario, score it, and check its expectations."""
    chosen = tuple(scenarios) if scenarios else suite()
    rows: List[Dict[str, Any]] = []
    violations: List[str] = []
    for scenario in chosen:
        metrics = run_scenario(scenario, max_iterations=max_iterations)
        broken = check_expectations(scenario, metrics)
        violations.extend(broken)
        row = metrics.to_dict()
        row["summary"] = scenario.summary
        row["violations"] = broken
        rows.append(row)
    return {"scenarios": rows, "violations": violations,
            "passed": not violations}


def format_table(report: Mapping[str, Any]) -> str:
    """Operator-readable summary (no rich dependency: this runs anywhere)."""
    lines = ["=" * 96,
             "AUTOMODE BENCHMARK — ground truth + failure injection (offline)",
             "=" * 96,
             f"{'scenario':<16}{'outcome':<22}{'goal':<6}{'moves':<7}"
             f"{'recov':<7}{'fp':<4}{'bad':<5}{'op':<4}{'budget':<9}verdict"]
    for row in report.get("scenarios", []):
        budget = row.get("budget", {})
        lines.append(
            f"{row['scenario']:<16}{row['outcome']:<22}"
            f"{'yes' if row['goal_reached'] else 'no':<6}"
            f"{row['moves']:<7}"
            f"{(row['time_to_recover'] if row['time_to_recover'] is not None else '-'):<7}"
            f"{len(row['false_positives']):<4}"
            f"{len(row['inappropriate_actions']):<5}"
            f"{row['operator_interventions']:<4}"
            f"{('OVER' if budget.get('overrun') else 'ok'):<9}"
            f"{'FAIL' if row['violations'] else 'pass'}")
    lines.append("-" * 96)
    for row in report.get("scenarios", []):
        if row.get("false_positives"):
            lines.append(f"  {row['scenario']} false positives: "
                         f"{', '.join(row['false_positives'])}")
        if row.get("inappropriate_actions"):
            lines.append(f"  {row['scenario']} inappropriate: "
                         f"{', '.join(row['inappropriate_actions'])}")
    for violation in report.get("violations", []):
        lines.append(f"  VIOLATION {violation}")
    lines.append("=" * 96)
    lines.append("PASS" if report.get("passed") else
                 f"FAIL ({len(report.get('violations', []))} violation(s))")
    return "\n".join(lines)
