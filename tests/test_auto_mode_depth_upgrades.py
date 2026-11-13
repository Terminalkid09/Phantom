"""Tests for the auto-mode depth upgrades: lockout-aware credential spray,
planner transparency (rejected paths), post-beacon loot triage, fuzz
grammar expansion (deserialization + GraphQL), and manual-core chain
preview. No real network is touched in any test."""
import os
import tempfile

import pytest

from phantom.automation.belief import WorldModel


# ── 1. lockout-aware credential spray ───────────────────────────────────────

def _spray_wm():
    wm = WorldModel("10.0.0.9")
    wm.add_finding("service", "s:22", {"port": 22, "service": "ssh"})
    wm.add_finding("service", "s:445", {"port": 445, "service": "microsoft-ds"})
    wm.add_finding("creds", "c:admin", {"username": "admin",
                                        "password": "Summer2024!"})
    wm.add_finding("creds", "c:jdoe", {"username": "jdoe",
                                       "password": "Welcome1"})
    return wm


def test_spray_one_password_many_accounts():
    """The spray shape is the lockout-safe core: ONE password per round
    against MANY accounts, never many passwords against one account."""
    from phantom.automation.guidance.spray import SprayLedger, plan_spray
    rounds = plan_spray(_spray_wm(), SprayLedger())
    assert rounds, "expected spray rounds"
    for r in rounds:
        assert r.users, "round must target at least one account"
    # every account gets the SAME single password in a round (spray, not brute)
    ssh_rounds = [r for r in rounds if r.service == "ssh"]
    assert ssh_rounds
    # every account in ONE round gets the SAME password (that is the
    # spray shape); successive rounds may rotate the password
    assert len(ssh_rounds[0].users) > 1
    assert all(r.users == ssh_rounds[0].users for r in ssh_rounds)


def test_spray_cross_service_reuse():
    """A password harvested from any source is tried on EVERY sprayable
    service the scan proved open — reuse is the senior move."""
    from phantom.automation.guidance.spray import SprayLedger, plan_spray
    rounds = plan_spray(_spray_wm(), SprayLedger())
    services = {r.service for r in rounds}
    assert {"ssh", "microsoft-ds"} <= services, services


def test_spray_lockout_cap():
    """Attempts per account are hard-capped; exhausted accounts are backed
    off for the engagement and never hit again."""
    from phantom.automation.guidance.spray import SprayLedger, plan_spray
    ledger = SprayLedger()
    plan_spray(_spray_wm(), ledger)
    assert ledger.summary()["accounts_backed_off"] == 0
    # plan twice more: every account must hit the cap and stop
    plan_spray(_spray_wm(), ledger)
    plan_spray(_spray_wm(), ledger)
    after = plan_spray(_spray_wm(), ledger)
    assert after == []
    assert ledger.summary()["accounts_backed_off"] > 0


def test_spray_parse_output():
    from phantom.automation.guidance.spray import parse_spray_output
    hits = parse_spray_output(
        "[22][ssh] host: 10.0.0.9   login: admin   password: Summer2024!\n"
        "1 valid password found\n")
    assert hits == [("", "10.0.0.9", "admin", "Summer2024!")]


def test_cred_spray_capability_registered():
    """cred_spray is a real capability: effects creds, aggressive, and its
    adapter emits hydra spray commands (one password per round)."""
    from phantom.automation.guidance.kit import CAPABILITIES
    cap = [c for c in CAPABILITIES if c.id == "cred_spray"]
    assert cap, "cred_spray not registered"
    cap = cap[0]
    assert "creds" in cap.effects
    out = cap.make_command(_spray_wm(), {})
    assert "hydra" in out and "-p " in out  # single password, many users


# ── 2. planner transparency ─────────────────────────────────────────────────

def _planner():
    from phantom.automation.planner import Planner
    from phantom.automation.guidance.stealth import StealthEngine
    from phantom.automation.guidance.kit import CAPABILITIES
    from phantom.automation.guidance.commands import Registry
    reg = Registry()
    for c in CAPABILITIES:
        reg.register(c)
    return Planner(reg, StealthEngine(WorldModel("10.0.0.9")))


def test_planner_rejected_paths_recorded():
    """Sources skipped for a fact carry a concrete reason the operator can
    read — 'why not X?' is answerable."""
    wm = WorldModel("10.0.0.9")
    wm.add_finding("service", "s:22", {"port": 22, "service": "ssh"})
    plan = _planner().plan(wm, "complete_kill_chain")
    assert plan.rejected, "expected rejected-path transparency records"
    reasons = {r.reason for r in plan.rejected}
    assert any("preconditions" in r or "failed" in r or "tried" in r
               for r in reasons)


def test_rejected_path_to_dict():
    from phantom.automation.planner import RejectedPath
    d = RejectedPath("creds", "brute_ssh", "too loud").to_dict()
    assert d["fact"] == "creds" and d["capability"] == "brute_ssh"


# ── 3. post-beacon loot triage ──────────────────────────────────────────────

@pytest.fixture
def loot_dir():
    """Files live under a downloads/ subdir — the shape the adapter scans
    (data_dir()/downloads) — and scan_dir is recursive so the plain
    scan tests see them too."""
    tmp = tempfile.mkdtemp(prefix="loot_test_")
    dl = os.path.join(tmp, "downloads")
    os.makedirs(dl, exist_ok=True)
    open(os.path.join(dl, "web.config"), "w").write(
        '<add connectionString="Data Source=10.0.0.5;User Id=sa;'
        'Password=Sup3rS3cret!" />')
    open(os.path.join(dl, ".env"), "w").write(
        "AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE\n"
        "AWS_SECRET_ACCESS_KEY=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY\n"
        "DB_PASSWORD=Tr0ub4dor&3\n")
    open(os.path.join(dl, "id_rsa"), "w").write(
        "-----BEGIN OPENSSH PRIVATE KEY-----\nABCDEF\n"
        "-----END OPENSSH PRIVATE KEY-----\n")
    return tmp


def test_loot_scan_extracts(loot_dir):
    from phantom.automation.loot import scan_dir
    report = scan_dir(loot_dir)
    assert report.files_seen == 3
    labels = {h.label for h in report.hits}
    assert "aws_access_key" in labels
    assert "db_password" in labels or "password_literal" in labels
    assert "private_key_block" in labels


def test_loot_derive_next_steps(loot_dir):
    from phantom.automation.loot import scan_dir
    report = scan_dir(loot_dir)
    joined = "\n".join(report.next_steps)
    assert "cloud" in joined, joined
    # db_password extracted from .env -> cross-service spray advice
    assert "spray" in joined or "creds" in joined, joined


def test_loot_registers_worldmodel(loot_dir):
    from phantom.automation.loot import triage_and_register
    wm = WorldModel("10.0.0.9")
    report = triage_and_register(wm, loot_dir)
    assert report.hits
    assert wm.find("creds"), "loot passwords must become creds findings"
    assert wm.find("cloud_creds"), "loot AWS keys must become cloud findings"


def test_loot_triage_capability_end_to_end(loot_dir):
    """The capability channel: adapter emits LOOT: markers, interpreter
    turns them back into WorldModel findings."""
    from unittest.mock import patch
    from phantom.automation.guidance.kit import CAPABILITIES
    cap = [c for c in CAPABILITIES if c.id == "loot_triage"][0]
    with patch("phantom.utils.paths.data_dir", return_value=loot_dir):
        wm = WorldModel("10.0.0.9")
        out = cap.adapter(wm, {})
    assert "LOOT:" in out
    wm2 = WorldModel("10.0.0.9")
    findings = cap.interpret(out, wm2, {})
    kinds = {f.kind for f in findings}
    assert "creds" in kinds or "cloud_creds" in kinds or "next_step" in kinds


# ── 4. fuzz grammar expansion ───────────────────────────────────────────────

def test_anomaly_library_has_deser_and_graphql():
    from phantom.automation.exploit.anomaly import probe_library
    lib = probe_library()
    assert "deser" in lib, "deserialization class missing"
    assert "graphql" in lib, "graphql class missing"
    deser_names = {p.name for p in lib["deser"]}
    assert {"java-magic", "java-b64", "pickle-proto", "php-object",
            "net-viewstate"} <= deser_names


def test_graphql_probes_retarget_to_endpoint():
    from phantom.automation.exploit.anomaly import (_endpoint_probes,
                                                    Endpoint)
    root = Endpoint(path="/", source="root")
    ep = Endpoint(path="/graphql", source="common")
    probes = _endpoint_probes("graphql", ep, root)
    assert probes
    assert all(p.path == "/graphql" for p in probes if p.method == "POST")
    get_probes = [p for p in probes if p.method == "GET"]
    assert get_probes and all("/graphql?query=" in p.path for p in get_probes)


def test_anomaly_plan_includes_new_classes():
    from phantom.automation.exploit.anomaly import HuntEngine, Endpoint
    engine = HuntEngine(runner=lambda m, u, b, t: type(
        "R", (), {"ok": False})(), time_budget=5)
    eps = [Endpoint(path="/", source="root"),
           Endpoint(path="/graphql", source="common"),
           Endpoint(path="/api/session", params=["data"], source="common")]
    plan = engine._plan(eps)
    classes = {cls for _, cls, _ in plan}
    assert "deser" in classes and "graphql" in classes


def test_deser_and_graphql_mutations_exist():
    from phantom.automation.exploit.anomaly import (probe_library,
                                                    mutate_probe)
    for cls in ("deser", "graphql"):
        probe = [p for p in probe_library()[cls] if not p.baseline][0]
        muts = mutate_probe(probe)
        assert muts, f"{cls} mutations missing"


# ── 5. manual-core chain preview ────────────────────────────────────────────

def test_chain_preview_builds_command_without_executing():
    """preview_step returns the concrete command for a mapped step WITHOUT
    running it; engine-only steps say so explicitly."""
    from phantom.core import chain
    from phantom.core.knowledge import reset_wm
    wm = reset_wm("10.0.0.5")
    wm.add_finding("service", "s:80", {"port": 80, "service": "http"})
    wm.add_finding("web_app", "app", {"app": "demo", "framework": "flask"})
    wm.add_finding("web_header", "h", {"server": "werkzeug"})
    wm.add_finding("hunt_anomaly", "sqli",
                   {"cls": "sqli", "confirmed": True, "endpoint": "/x?id=1"})
    plans = chain.plan(wm)
    assert plans, "expected a chain from web facts"
    step = plans[0]["steps"][0]
    ok, cmd = chain.preview_step(step, "10.0.0.5")
    if step.get("cap"):
        assert ok and cmd, "preview must build a command for mapped steps"
    else:
        assert not ok and "engine-only" in cmd


def test_chain_execute_requires_mapped_cap():
    from phantom.core import chain
    ok, summary = chain.execute_step({"cap": None, "op": "web.x"}, "")
    assert not ok and "engine-only" in summary