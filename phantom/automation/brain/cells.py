"""
phantom.automation.brain.cells — the work unit of the new auto-mode (C1).

An agent used to be "the whole campaign": one object holding the target, the
world, the stealth engine, the planner, the reasoning, the beacon session.
The orchestrator then dispatched *actions* to a thread pool. That model can
express "do this now", never "who is in charge of what, and with which
knowledge".

This module makes the WORK UNIT a first-class object:

    CellSpec  — a ROLE: its objective, the kill-chain stage it serves, the
                CONTACT it has with the target, the capability categories it
                may USE and the fact kinds it may SEE. The knowledge scope
                is the point: the recon cell that found the version can
                report a vulnerability class and still be unable to see (or
                pick) any exploit capability.
    Cell      — a ROLE OCCUPIED: id, the spec, its ReasoningProfile (so two
                cells on one task reason from different objectives), an
                advisory flag, a budget, a halt condition.
    EgressPermit — the GLOBAL contact lock. Contact with the target is the
                scarce resource, not CPU: exactly one cell holds the permit
                at a time, which is what keeps N agents from multiplying the
                engagement noise by N.
    CellTeam  — the roster for one run: which roles exist (from the chain
                shape the doctrine chose), who may ACT and who may merely
                REASON, and the escalation path when a role stalls.

Roster sizing is a property of the ACTION, not of the run (the operator's
rule): OSINT, correlation, reverse engineering and local analysis touch
nothing and parallelise freely; a scan or a probe touches the target and is
serialised; only --aggressive pays for a second acting cell.
"""

from __future__ import annotations

import threading
from dataclasses import dataclass, field
from typing import Any, Dict, FrozenSet, Iterable, List, Optional, Sequence, Tuple

from phantom.automation.brain.lenses import (
    ReasoningProfile,
    adversarial_profile,
    choose_profile,
    profile_for,
)

# ── contact classes ────────────────────────────────────────────────────────

# how a role touches the world. This single attribute decides how much of it
# can run at once, so it is the axis of the whole roster model.
CONTACT_NONE = "none"        # OSINT, correlation, local analysis, sandbox
CONTACT_RECON = "recon"      # probe/scan/banner: measurable but shallow
CONTACT_EXPLOIT = "exploit"  # exploit, credential use, delivery, post

CONTACT_CLASSES = (CONTACT_NONE, CONTACT_RECON, CONTACT_EXPLOIT)

# how many cells may ACT at once, per contact class. A cell beyond the cap is
# still allowed to REASON (advisory) — the second opinion costs no noise.
ACTING_CAP: Dict[str, int] = {
    CONTACT_NONE: 5,
    CONTACT_RECON: 1,
    CONTACT_EXPLOIT: 1,
}
# with --aggressive the operator accepts the noise of a second acting cell
ACTING_CAP_AGGRESSIVE: Dict[str, int] = {
    CONTACT_NONE: 5,
    CONTACT_RECON: 2,
    CONTACT_EXPLOIT: 2,
}
# advisory (reasoning-only) cells never add noise, so they are bounded only
# by the cost of a thread and by how much disagreement is still readable.
ADVISORY_CAP = 3

# how many extra agents the orchestrator may add on ONE role before it is
# declared a peer storm. Escalation is a second opinion, not a fan-out.
MAX_PEERS_PER_ROLE = 2

# C4 migration ledger: the STAGES whose planning the cell roster is now the
# AUTHORITY for. An entry is added only when the roster's coverage owns every
# capability category the planner can legitimately offer for that stage, on
# EVERY target class the stage can occur on (the coverage gate in
# `tests/test_stage_migration.py`, which reads the real planner). The old
# planning path keeps serving everything else. Growing this tuple IS the
# migration.
#
# Vocabulary note, and it is the bug that made the first version of this
# ledger INERT: `agent._current_stage` is set to the run's GOAL
# (`_drive_stage(goal)`), not to a doctrine chain stage. A chain stage name
# like "footprint" therefore never matches, and a ledger holding only chain
# names turns the strict loop into dead code that still looks switched on.
# Entries here are goals — the values `_current_stage` really takes.
#
# Measured, not assumed: every entry below passes the gate for ip, domain,
# cidr, email, username and phone targets; `ad` and `crack` are deliberately
# ABSENT because on an identity-class target the AD stage needs `recon`
# (ldapsearch/nmap) while the identity chain forbids `footprint`, so those
# goals keep the old path until that inconsistency is resolved.
MIGRATED_STAGES: Tuple[str, ...] = (
    "complete_kill_chain", "deliver", "beacon", "post_exploit", "expand",
    "lateral", "identity", "social", "cloud", "mobile", "harvest",
    "evasion",
)


# ── roles ──────────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class CellSpec:
    """A role: what it is FOR, what it may use, what it may see."""

    role: str
    objective: str
    stage: str
    contact: str
    # capability CATEGORIES this role may plan with (the "hands")
    uses_categories: FrozenSet[str]
    # fact KINDS this role may read (the "eyes"). Everything else is
    # invisible to the cell's reasoning, which is what makes "the scanner
    # does not consult the exploits" a property of the system rather than a
    # good intention.
    sees_kinds: FrozenSet[str]
    # fact kinds the role may PUBLISH to the shared map. Reporting a
    # vulnerability class is allowed even when exploiting it is not.
    reports_kinds: FrozenSet[str] = frozenset()

    def to_dict(self) -> dict:
        return {"role": self.role, "objective": self.objective,
                "stage": self.stage, "contact": self.contact,
                "uses": sorted(self.uses_categories),
                "sees": sorted(self.sees_kinds),
                "reports": sorted(self.reports_kinds)}


_RECON_SEES = frozenset({
    "service", "os", "banner", "web_header", "web_app", "web_title",
    "hostname", "mac", "vendor", "smb_share", "redis", "tls_cert",
    "mobile", "mdm_vendor", "environment",
})
# the vulnerability knowledge a scanning cell IS allowed to have: it may name
# the class and the path, never the exploitation artefact.
_RECON_REPORTS = frozenset({
    "vuln_class", "attack_path", "service_role", "os_inferred", "ad_hint",
    "risk", "asset_risk", "hunt_anomaly", "differential_anomaly",
})

CELL_LIBRARY: Dict[str, CellSpec] = {
    "recon": CellSpec(
        role="recon",
        objective="map the target surface: services, versions, OS, web roots",
        stage="footprint", contact=CONTACT_RECON,
        # `service` is per-service ENUMERATION (ssh banner, smb shares, redis
        # info) and belongs to recon, not to exploitation. Leaving it out
        # looks like a detail until the strict stage scope is switched on for
        # the footprint stage — then the chain silently loses three of its
        # own capabilities. Found by the stage-scope gate, not by review.
        uses_categories=frozenset({"recon", "scan", "service"}),
        sees_kinds=_RECON_SEES,
        reports_kinds=_RECON_REPORTS),
    "identity": CellSpec(
        role="identity",
        objective="resolve the engagement subject: who is this, and on what",
        stage="identity", contact=CONTACT_NONE,
        uses_categories=frozenset({"identity", "osint", "social"}),
        sees_kinds=frozenset({
            "identity", "identity_conf", "persona", "persona_profile",
            "profile", "account_link", "dossier", "breach_exposure",
            "victim_ip", "email", "phone", "handle", "device", "service",
            "environment",
        }),
        reports_kinds=frozenset({"identity_conf", "victim_ip", "dossier"})),
    "osint": CellSpec(
        role="osint",
        objective="deep open-source intelligence: profiles, links, exposure",
        stage="identity", contact=CONTACT_NONE,
        uses_categories=frozenset({"osint", "identity", "social"}),
        sees_kinds=frozenset({
            "identity", "identity_conf", "persona", "persona_profile",
            "profile", "account_link", "dossier", "breach_exposure",
            "victim_ip", "follow_accepted", "dm_sent", "service", "environment",
        }),
        reports_kinds=frozenset({"identity_conf", "victim_ip", "dossier",
                                 "breach_exposure", "follow_accepted"})),
    "web": CellSpec(
        role="web",
        objective="attack the web/API surface: parameters, uploads, authz",
        stage="exploit", contact=CONTACT_RECON,
        uses_categories=frozenset({"web", "hunt"}),
        sees_kinds=frozenset({
            "service", "web_header", "web_app", "web_title", "web_param",
            "tls_cert", "hunt_anomaly", "differential_anomaly", "vuln_class",
            "attack_path", "environment", "os",
        }),
        reports_kinds=frozenset({"hunt_anomaly", "differential_anomaly",
                                 "vuln_class", "attack_path"})),
    "exploit": CellSpec(
        role="exploit",
        objective="turn a weakness into code execution",
        stage="exploit", contact=CONTACT_EXPLOIT,
        # `creds` is credential USE (ssh_login): the exploit role is the one
        # that turns a discovery into access, so using a found credential is
        # its business. Omitted at first, and the stage-scope gate reported
        # it as a category no role owned — which is what the strict loop
        # would have refused mid-chain.
        uses_categories=frozenset({"exploit", "brute", "creds"}),
        sees_kinds=frozenset({
            "service", "os", "web_app", "web_param", "vuln_class",
            "attack_path", "exploit_plan", "hunt_anomaly",
            "differential_anomaly", "creds", "rce_foothold", "environment",
            "ad_hint", "service_role",
        }),
        reports_kinds=frozenset({"exploit_plan", "creds", "rce_foothold",
                                 "cloud_creds"})),
    "foothold": CellSpec(
        role="foothold",
        objective="convert access into a persistent beacon on the box",
        stage="deliver", contact=CONTACT_EXPLOIT,
        # `beacon` (beacon_deploy) is this role's whole objective; leaving the
        # category out made the strict loop refuse the one capability the
        # role exists for. Found by the coverage gate over the registry, not
        # by review.
        # `creds` as well: deploying the beacon onto a box whose credential
        # we already hold IS the conversion this role performs, and a chain
        # with no `creds` stage of its own (the mobile/person chain) would
        # otherwise field no cell able to run `ssh_login`.
        uses_categories=frozenset({"post", "payload", "exploit", "beacon",
                                   "creds"}),
        sees_kinds=frozenset({
            "service", "os", "creds", "rce_foothold", "cloud_creds",
            "environment", "beacon", "persistence", "system_privilege",
            "victim_ip",
        }),
        reports_kinds=frozenset({"beacon", "persistence"})),
    "post": CellSpec(
        role="post",
        objective="expand from the foothold: privesc, internal recon, pivot",
        stage="post_exploit", contact=CONTACT_EXPLOIT,
        uses_categories=frozenset({"post", "ad", "cloud", "payload"}),
        sees_kinds=frozenset({
            "beacon", "persistence", "system_privilege", "injection",
            # post operates FROM a foothold: it must be able to see the fact
            # that got it there, or it cannot reason about which path to keep.
            "rce_foothold",
            "creds", "cloud_creds", "cloud_access", "cloud_lateral",
            "ad_domain", "ad_creds", "cracked", "pivot", "internal_host",
            "internal_service", "service", "os", "environment",
            "stolen_cookies", "socks_proxy",
        }),
        reports_kinds=frozenset({"system_privilege", "injection", "ad_creds",
                                 "cracked", "pivot", "internal_host",
                                 "internal_service", "cloud_access"})),
    "cloud": CellSpec(
        role="cloud",
        objective="triage and escalate the cloud identity we landed on",
        stage="cloud", contact=CONTACT_EXPLOIT,
        uses_categories=frozenset({"cloud"}),
        sees_kinds=frozenset({
            "cloud_creds", "cloud_access", "cloud_lateral", "environment",
            "identity", "service",
        }),
        reports_kinds=frozenset({"cloud_access", "cloud_lateral"})),
    "mobile": CellSpec(
        role="mobile",
        objective="fingerprint and assess the mobile device in scope",
        stage="mobile", contact=CONTACT_RECON,
        uses_categories=frozenset({"recon", "mobile"}),
        sees_kinds=frozenset({"mobile", "mdm_vendor", "service", "os",
                              "environment", "identity"}),
        reports_kinds=frozenset({"mobile", "mdm_vendor"})),
    "report": CellSpec(
        role="report",
        objective="assemble evidence, timeline and findings",
        stage="report", contact=CONTACT_NONE,
        uses_categories=frozenset({"report"}),
        sees_kinds=frozenset({"*"}),
        reports_kinds=frozenset()),
}

# The deep run's ladder: the GOALS a `--deep` run walks back to back. Kept
# here (not in agent.py) because the ROSTER has to cover the whole ladder: a
# roster built from the doctrine chain alone never contains a `post` cell for
# a network target (its chain is footprint/exploit/creds/beacon), so the
# entire post-exploitation half of a deep run would have no owner and the
# strict loop would refuse it. The two vocabularies must therefore be joined
# when the roster is planned — and a test pins this tuple against the agent's
# ladder so the two cannot drift apart.
DEEP_LADDER: Tuple[str, ...] = ("deliver", "post_exploit", "expand", "ad",
                                "crack", "lateral")

# stage name -> role that serves it. The doctrine already decides WHICH
# stages a target class runs; this decides WHO runs them.
STAGE_ROLES: Dict[str, Tuple[str, ...]] = {
    "footprint": ("recon",),
    "identity": ("identity", "osint"),
    "environment": ("recon",),
    # doctrine-level stages that the machine roles serve
    "creds": ("exploit",),
    "social": ("osint",),
    "exploit": ("web", "exploit"),
    "deliver": ("foothold",),
    "complete_kill_chain": ("foothold",),
    "beacon": ("foothold",),
    "post_exploit": ("post",),
    "expand": ("post",),
    "ad": ("post",),
    "crack": ("post",),
    "lateral": ("post",),
    "cloud": ("cloud",),
    "cloud_creds": ("cloud",),
    "cloud_lateral": ("cloud",),
    "mobile": ("mobile",),
    "harvest": ("post",),
    "evasion": ("post",),
    "report": ("report",),
}


# ── the cell ───────────────────────────────────────────────────────────────

@dataclass
class Cell:
    """A role occupied by one reasoning agent, with its own objective.

    `advisory` cells may reason and publish propositions but hold no egress
    permit: they are the second opinion on an already-running task, and the
    reason the escalation path costs no extra noise.
    """

    cell_id: str
    spec: CellSpec
    profile: ReasoningProfile
    objective: str = ""
    advisory: bool = False
    budget: int = 0                   # 0 = unlimited
    halt: str = ""                    # fact kind that means "done"
    seed: int = 0
    used: int = 0
    notes: List[str] = field(default_factory=list)

    def __post_init__(self) -> None:
        if not self.objective:
            self.objective = self.spec.objective

    # -- knowledge scope (the "eyes") -----------------------------------
    def sees(self, kind: str) -> bool:
        """What this cell may READ. A kind the role can report is by
        definition a kind it produced or derived, so it is visible too:
        splitting "may report" and "may see" into two lists would only
        create a class of bug where a cell is asked to report something it
        cannot see."""
        return ("*" in self.spec.sees_kinds
                or kind in self.spec.sees_kinds
                or kind in self.spec.reports_kinds)

    def may_use(self, category: str) -> bool:
        return category in self.spec.uses_categories

    def capability_ids(self, registry: Any) -> List[str]:
        """The capabilities this cell is even AWARE of: everything of its
        categories, and nothing else. A recon cell therefore never sees an
        exploit capability to plan with."""
        out: List[str] = []
        try:
            for cap in registry.all():
                if self.may_use(str(getattr(cap, "category", ""))):
                    out.append(str(getattr(cap, "id", "")))
        except Exception:
            return []
        return out

    def view_of(self, findings: Iterable[Any]) -> List[Any]:
        """Project the shared map onto this cell's knowledge scope."""
        out = []
        for f in findings:
            kind = str(getattr(f, "kind", "") or "")
            if self.sees(kind):
                out.append(f)
        return out

    def can_report(self, kind: str) -> bool:
        return kind in self.spec.reports_kinds

    def spend(self) -> bool:
        """Consume one unit of budget. False means the cell must stop."""
        if self.budget and self.used >= self.budget:
            return False
        self.used += 1
        return True

    def exhausted(self) -> bool:
        return bool(self.budget) and self.used >= self.budget

    def to_dict(self) -> dict:
        return {"cell": self.cell_id, "role": self.spec.role,
                "objective": self.objective, "stage": self.spec.stage,
                "contact": self.spec.contact, "advisory": self.advisory,
                "profile": self.profile.name,
                "search_policy": self.profile.search_policy,
                "budget": self.budget, "used": self.used,
                "halt": self.halt, "seed": self.seed,
                "notes": list(self.notes)}


# ── the egress permit (the scarce resource) ────────────────────────────────

class EgressPermit:
    """Exactly one ACTING cell touches the target at a time.

    Not a thread lock: a *policy* object. It is what makes "5 agents" safe
    on OSINT and dangerous on a scan, and it is deliberately separate from
    the orchestrator's thread pool so the rule survives any scheduler
    rewrite.

    `acquire(timeout)` waits for a slot instead of failing immediately: in
    the common case a permit is held for the few seconds an action takes,
    and giving up instantly would turn serialisation into lost work. A
    timeout of 0 is a pure probe (used by the tests and by the scheduler
    when it prefers to defer).
    """

    def __init__(self, acting_cap: int = 1) -> None:
        self._acting_cap = max(1, int(acting_cap))
        self._cv = threading.Condition()
        self._holders: List[str] = []

    @property
    def acting_cap(self) -> int:
        with self._cv:
            return self._acting_cap

    @acting_cap.setter
    def acting_cap(self, value: int) -> None:
        with self._cv:
            self._acting_cap = max(1, int(value))
            self._cv.notify_all()

    @property
    def holders(self) -> List[str]:
        with self._cv:
            return list(self._holders)

    def free_slots(self) -> int:
        with self._cv:
            return max(0, self._acting_cap - len(self._holders))

    def acquire(self, cell_id: str, timeout: Optional[float] = 0.0) -> bool:
        """Take a permit slot.

        `timeout=0.0` (default) is a pure PROBE — it never blocks, which is
        what a predicate or a scheduler that prefers to defer wants.
        `timeout=<seconds>` waits up to that long (the run, before firing a
        long action). `timeout=None` waits indefinitely, and is only correct
        where a caller has already proven a holder will release.
        """
        with self._cv:
            if cell_id in self._holders:
                return True
            if timeout is None:
                while self._acting_cap - len(self._holders) <= 0:
                    self._cv.wait()
                self._holders.append(cell_id)
                return True
            import time as _t
            deadline = _t.time() + max(0.0, float(timeout))
            while self._acting_cap - len(self._holders) <= 0:
                remaining = deadline - _t.time()
                if remaining <= 0:
                    return False
                self._cv.wait(min(remaining, 0.25))
            self._holders.append(cell_id)
            return True

    def release(self, cell_id: str) -> None:
        with self._cv:
            if cell_id in self._holders:
                self._holders.remove(cell_id)
            self._cv.notify_all()

    def release_all(self) -> None:
        with self._cv:
            self._holders.clear()
            self._cv.notify_all()

    def to_dict(self) -> dict:
        return {"cap": self.acting_cap, "holders": self.holders}


# ── the roster ─────────────────────────────────────────────────────────────

class CellTeam:
    """The roster for one run: roles, permits, and the escalation path.

    Built from the chain the doctrine chose (`stages`), so an identity run
    gets two quiet cells and a full network run gets the machine roles.
    """

    def __init__(self, cells: Sequence[Cell], aggressive: bool = False) -> None:
        self.cells: List[Cell] = list(cells)
        self.aggressive = bool(aggressive)
        # the stages currently in flight. EMPTY means "the whole roster",
        # which is the conservative reading for a team that has not declared
        # a stage yet. The permit cap follows the ACTIVE stages, not the
        # roster: an identity engagement may run five quiet cells while the
        # doctrine still lists a beacon stage nobody has reached.
        self.active_stages: set = set()
        self.permit = EgressPermit(self.acting_cap())
        self.escalations: List[dict] = []

    def set_active_stage(self, stage: str) -> None:
        """Declare which stage is running now and re-cap the permit."""
        if stage:
            self.active_stages = {stage}
        self.notify_admission()

    def _active_acting(self) -> List[Cell]:
        """The acting cells that serve the ACTIVE stages.

        Matched through STAGE_ROLES (stage -> roles), not through each
        cell's own `stage` attribute: the role that serves the beacon stage
        is `foothold` whose declaration says stage `deliver`. Falling back to
        the whole roster when a stage has no role keeps a hand-built team
        working.
        """
        acting = [c for c in self.cells if not c.advisory]
        if not self.active_stages:
            return acting
        roles: set = set()
        for st in self.active_stages:
            roles.update(STAGE_ROLES.get(st, ()))
        scoped = [c for c in acting if c.spec.role in roles]
        return scoped or acting

    # -- caps ------------------------------------------------------------
    def acting_cap(self) -> int:
        """How many cells may hold a permit at once.

        The MINIMUM over the acting cells' contact classes, not the maximum:
        a team is only as parallel as its LOUDEST member allows. A quiet
        report cell sharing the roster with a recon cell must not lift the
        recon cell's serialisation — otherwise adding an unrelated role
        would silently double the engagement's noise.
        """
        table = ACTING_CAP_AGGRESSIVE if self.aggressive else ACTING_CAP
        caps = [table.get(cell.spec.contact, 1)
                for cell in self._active_acting()]
        if not caps:
            return 1
        return max(1, min(caps))

    def notify_admission(self, cell: Optional[Cell] = None) -> None:
        """Re-apply the cap to the permit when the roster changes: the
        loudest class present decides how many may act."""
        self.permit.acting_cap = max(1, self.acting_cap())

    # -- admission -------------------------------------------------------
    def admit(self, cell: Cell, timeout: float = 0.0) -> bool:
        """May this cell ACT right now? An advisory cell never acts; an
        acting cell needs a free permit slot.

        NON-BLOCKING by default (`timeout=0.0`): this is a PREDICATE, and a
        predicate that can block forever inside a scheduler is a deadlock.
        The caller that actually wants to wait (the run, before firing a
        long action) passes its own timeout.
        """
        if cell.advisory or cell.exhausted():
            return False
        return self.permit.acquire(cell.cell_id, timeout=timeout)

    def release(self, cell: Cell) -> None:
        self.permit.release(cell.cell_id)

    def get(self, cell_id: str) -> Optional[Cell]:
        for c in self.cells:
            if c.cell_id == cell_id:
                return c
        return None

    # -- roster construction ---------------------------------------------
    @classmethod
    def plan(cls, stages: Sequence[str], target_class: str = "",
             aggressive: bool = False, paranoid: bool = False,
             speed: bool = False, explicit_profile: str = "",
             sandbox_names: Sequence[str] = ()) -> "CellTeam":
        """Roster for a chain shape. Deterministic: same stages and flags,
        same team."""
        base = choose_profile("enterprise", paranoid=paranoid,
                              aggressive=aggressive, speed=speed,
                              explicit=explicit_profile)
        cells: List[Cell] = []
        seen: set = set()
        seq = 0
        for stage in stages:
            for role in STAGE_ROLES.get(stage, ()):
                if role in seen:
                    continue
                seen.add(role)
                spec = CELL_LIBRARY.get(role)
                if spec is None:
                    continue
                seq += 1
                cells.append(Cell(
                    cell_id=f"c{seq}-{role}",
                    spec=spec,
                    profile=base,
                    halt=_halt_fact_for(stage),
                ))
        # OSINT/reverse-engineering sandbox: more ANONYMOUS eyes on the same
        # subject is free (no contact), and the operator asked for it by
        # name. They use the adversarial profile, so they disagree with the
        # lead by construction rather than duplicating it.
        for name in sandbox_names:
            spec = CELL_LIBRARY.get(name)
            if spec is None or name in seen:
                continue
            seen.add(name)
            seq += 1
            cells.append(Cell(
                cell_id=f"c{seq}-{name}", spec=spec,
                profile=adversarial_profile(base),
                halt=_halt_fact_for(spec.stage),
                notes=["sandboxed parallel role (no target contact)"],
            ))
        return cls(cells, aggressive=aggressive)

    # -- escalation ------------------------------------------------------
    def escalate(self, stalled_cell: Cell,
                 reason: str = "") -> Optional[Cell]:
        """A role stalled: add a SECOND agent on the same task.

        The operator's rule: the escalation cost depends on contact. A
        sandbox role (no contact) gets a peer that acts; a target-touching
        role gets an ADVISORY peer, which reasons from a different objective
        and holds no permit — so the second opinion never adds noise.
        """
        if stalled_cell.spec.role in ("report",):
            return None
        contact_free = stalled_cell.spec.contact == CONTACT_NONE
        advisory = not contact_free
        # peer storm guard: count ADVISORY peers too. A role whose peers are
        # advisory (a target-touching role) would otherwise escalate forever
        # because the non-advisory count never grows.
        same_role = [c for c in self.cells
                     if c.spec.role == stalled_cell.spec.role]
        if len(same_role) > MAX_PEERS_PER_ROLE:
            return None
        seq = len(self.cells) + 1
        peer = Cell(
            cell_id=f"c{seq}-{stalled_cell.spec.role}-peer",
            spec=stalled_cell.spec,
            profile=adversarial_profile(stalled_cell.profile),
            objective=(f"second opinion on: {stalled_cell.objective}"
                       + (f" (stall: {reason})" if reason else "")),
            advisory=advisory,
            halt=stalled_cell.halt,
            seed=stalled_cell.seed ^ 0x5F3759DF,
            notes=[f"escalated from {stalled_cell.cell_id}"
                   + (f": {reason}" if reason else ""),
                   "advisory (no egress permit)" if advisory
                   else "acting (no target contact)"],
        )
        self.cells.append(peer)
        self.notify_admission(peer)
        self.escalations.append({
            "from": stalled_cell.cell_id, "peer": peer.cell_id,
            "advisory": advisory, "reason": reason,
            "profile": peer.profile.name,
            "search_policy": peer.profile.search_policy,
        })
        return peer

    # -- introspection ---------------------------------------------------
    def acting(self) -> List[Cell]:
        return [c for c in self.cells if not c.advisory]

    def advisory_cells(self) -> List[Cell]:
        return [c for c in self.cells if c.advisory]

    def stats(self) -> dict:
        return {"cells": len(self.cells),
                "acting": len(self.acting()),
                "advisory": len(self.advisory_cells()),
                "acting_cap": self.permit.acting_cap,
                "active_stages": sorted(self.active_stages),
                "holders": self.permit.holders,
                "escalations": list(self.escalations),
                "roles": [c.spec.role for c in self.cells]}


def _halt_fact_for(stage: str) -> str:
    """The fact kind that means "this role's job is done"."""
    return {
        "footprint": "service",
        "identity": "identity",
        "environment": "environment",
        "exploit": "rce_foothold",
        "deliver": "beacon",
        "beacon": "beacon",
        "post_exploit": "system_privilege",
        "expand": "internal_host",
        "ad": "ad_creds",
        "crack": "cracked",
        "lateral": "pivot",
        "cloud": "cloud_access",
        "mobile": "mobile",
        "harvest": "stolen_cookies",
        "evasion": "defensive_gap",
    }.get(stage, "")


def team_for_goal(goal: str, target_type: str = "",
                  aggressive: bool = False, paranoid: bool = False,
                  speed: bool = False, explicit_profile: str = "",
                  stages: Optional[Sequence[str]] = None) -> CellTeam:
    """Roster for a goal, using the doctrine's chain when `stages` is not
    given explicitly (the caller that already computed the chain passes it
    so the roster is always coherent with the chosen doctrine)."""
    if stages is None:
        stages = _goal_stages(goal, target_type)
    sandbox: Tuple[str, ...] = ()
    if target_type in ("identity", "email", "phone", "username", "person"):
        sandbox = ("osint",)
    return CellTeam.plan(stages, target_class=target_type,
                         aggressive=aggressive, paranoid=paranoid,
                         speed=speed, explicit_profile=explicit_profile,
                         sandbox_names=sandbox)


def _goal_stages(goal: str, target_type: str = "") -> Tuple[str, ...]:
    """Fallback chain shape when the doctrine was not consulted."""
    if target_type in ("identity", "email", "phone", "username", "person") \
            or goal == "identity":
        return ("identity",)
    if goal == "deliver":
        return ("footprint", "exploit", "deliver")
    if goal == "post_exploit":
        return ("deliver", "post_exploit", "expand")
    if goal in ("ad",):
        return ("deliver", "ad")
    if goal in ("cloud",):
        return ("cloud",)
    if goal in ("mobile",):
        return ("mobile",)
    if goal in ("deep", "complete_kill_chain"):
        return ("footprint", "exploit", "deliver", "post_exploit", "expand")
    return ("footprint", "exploit", "deliver")
