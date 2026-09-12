"""Fase 4 — the auto-mode <-> manual-core session bridge.

Before the bridge, the two halves kept separate memories: the agent could
not see the operator's manual recon, and the manual core (map / suggest /
exploit / report) could not see anything the agent learned. These tests
pin the bidirectional, idempotent contract.
"""
import pytest

from phantom.automation.belief import WorldModel
from phantom.core import session as session_mod
from phantom.core.session_bridge import (
    merge_agent_into_session,
    seed_findings_from_session,
    seed_agent_wm,
)


@pytest.fixture(autouse=True)
def _clean_session():
    """Every test starts from a blank session (singleton)."""
    s = session_mod.session
    s.target = ""
    s.results.clear()
    s.knowledge_base = {
        "target": "", "target_type": None, "stealth": True, "aggressive": False,
        "started_at": None, "status": {}, "services": [], "os_info": {},
        "creds_found": [], "rce_vectors": [], "cves": [], "web_endpoints": [],
        "social_profiles": [], "emails_found": [], "subdomains_found": [],
        "breaches_found": [], "beacon_deployed": False,
        "persistence_set": False, "current_step": None, "errors": [],
        "next_targets": [], "last_output": {},
    }
    from phantom.core.knowledge import reset_wm
    reset_wm("", "ip")
    yield


class _FakeAgent:
    def __init__(self, target="10.0.0.5"):
        self.target = target
        self.wm = WorldModel(target=target, target_type="ip")


def _agent_with_findings():
    a = _FakeAgent()
    a.wm.add_finding("service", "tcp/445",
                     {"port": 445, "proto": "tcp", "service": "microsoft-ds",
                      "version": "Samba 4.9"}, source="scan_tcp")
    a.wm.add_finding("os", "os", {"name": "Linux 4.x", "accuracy": 92},
                     source="os_detect")
    a.wm.add_finding("creds", "ssh:root",
                     {"username": "root", "password": "toor", "valid": True,
                      "service": "ssh"}, source="offline_brute_ssh")
    a.wm.add_finding("beacon", "B-1", {"beacon_id": "B-1"}, source="beacon_deploy")
    a.wm.add_finding("persistence", "runkey", {"method": "runkey"},
                     source="persistence_install")
    a.wm.add_finding("internal_service", "10.0.0.9",
                     {"host": "10.0.0.9", "service": "smb"}, source="internal_probe")
    a.wm.add_finding("defensive_gap", "wd", {"control": "defender"},
                     source="edr_disable")
    a.wm.add_finding("cloud_creds", "iam_aws", {"provider": "aws"},
                     source="cloud_creds_harvest")
    a.wm.add_finding("mdm_vendor", "fingerprint", {"vendors": ["intune"]},
                     source="mobile_mdm_fingerprint")
    return a


# ── auto-mode -> core ───────────────────────────────────────────────────────

def test_merge_populates_knowledge_base():
    counts = merge_agent_into_session(_agent_with_findings(), "10.0.0.5")
    kb = session_mod.session.knowledge_base
    assert counts["services"] == 1
    ports = [s["port"] for s in kb["services"]]
    assert 445 in ports
    assert kb["os_info"]["name"] == "Linux 4.x"
    assert kb["creds_found"][0]["username"] == "root"
    assert kb["beacon_deployed"] is True
    assert kb["persistence_set"] is True


def test_merge_reaches_manual_world_model():
    """The manual core's WM must carry the agent's facts, so suggest/exploit
    can plan against them."""
    from phantom.core.knowledge import session_wm
    merge_agent_into_session(_agent_with_findings(), "10.0.0.5")
    mwm = session_wm()
    assert mwm.find("service"), "service facts missing in manual WM"
    assert mwm.find("creds", valid=True), "creds missing in manual WM"
    assert mwm.find("internal_service"), "pivot candidate missing in manual WM"
    assert mwm.find("cloud_creds"), "cloud finding missing in manual WM"


def test_merge_records_internal_pivots_for_the_operator():
    merge_agent_into_session(_agent_with_findings(), "10.0.0.5")
    nexts = session_mod.session.knowledge_base["next_targets"]
    assert any(n["ip"] == "10.0.0.9" and n["service"] == "smb" for n in nexts)


def test_merge_is_idempotent():
    a = _agent_with_findings()
    merge_agent_into_session(a, "10.0.0.5")
    first = dict(session_mod.session.knowledge_base)
    merge_agent_into_session(a, "10.0.0.5")
    second = session_mod.session.knowledge_base
    assert len(second["services"]) == len(first["services"])
    assert len(second["creds_found"]) == len(first["creds_found"])
    assert len(second["next_targets"]) == len(first["next_targets"])


def test_merge_tolerates_none_agent():
    assert merge_agent_into_session(None, "10.0.0.5") == {}


# ── core -> auto-mode ───────────────────────────────────────────────────────

def test_seed_reads_manual_knowledge_base():
    kb = session_mod.session.knowledge_base
    session_mod.session.target = "10.0.0.5"
    kb["services"] = [{"port": 22, "protocol": "tcp", "service": "ssh",
                       "version": "OpenSSH 8.2", "host": "10.0.0.5"}]
    kb["os_info"] = {"name": "Ubuntu", "accuracy": 88}
    kb["creds_found"] = [{"username": "admin", "password": "admin",
                          "service": "ssh"}]
    seeds = seed_findings_from_session("10.0.0.5")
    kinds = {s["kind"] for s in seeds}
    assert {"service", "os", "creds"} <= kinds


def test_seed_is_applied_to_a_fresh_agent_wm():
    kb = session_mod.session.knowledge_base
    kb["services"] = [{"port": 22, "protocol": "tcp", "service": "ssh",
                       "version": "OpenSSH 8.2", "host": "10.0.0.5"}]
    agent = _FakeAgent()
    assert seed_agent_wm(agent, "10.0.0.5") >= 1
    keys = {f.key for f in agent.wm.find("service")}
    assert "tcp/22" in keys


def test_seed_never_overwrites_stronger_agent_facts():
    kb = session_mod.session.knowledge_base
    kb["services"] = [{"port": 445, "protocol": "tcp", "service": "old",
                       "version": "", "host": "10.0.0.5"}]
    agent = _FakeAgent()
    agent.wm.add_finding("service", "tcp/445",
                         {"port": 445, "service": "fresh"}, source="agent")
    seed_agent_wm(agent, "10.0.0.5")
    v = agent.wm.get("service", "tcp/445").value
    assert v["service"] == "fresh"


# ── the two directions compose ──────────────────────────────────────────────

# ── regression: the auto-mode entry points accept the wired kwargs ─────────

def test_run_autonomous_accepts_stop_event_and_seed():
    """`_run_agent_single` always passed stop_event, but run_autonomous did
    not declare it — the single-target auto-mode raised TypeError on the
    first call. Pin the signature so it can never regress."""
    import inspect
    from phantom.automation.agent import run_autonomous
    params = inspect.signature(run_autonomous).parameters
    assert "stop_event" in params
    assert "seed_findings" in params


def test_run_campaign_accepts_stop_event():
    import inspect
    from phantom.automation.agent import run_campaign
    assert "stop_event" in inspect.signature(run_campaign).parameters


def test_seed_agent_helper_is_safe():
    from phantom.automation.agent import _seed_agent
    assert _seed_agent(None, None) == 0
    agent = _FakeAgent()
    assert _seed_agent(agent, None) == 0
    assert _seed_agent(agent, [{"kind": "os", "key": "os",
                                "value": {"name": "x"}}]) == 1
    # second application is a no-op (idempotent)
    assert _seed_agent(agent, [{"kind": "os", "key": "os",
                                "value": {"name": "x"}}]) == 0


def test_round_trip_agent_then_new_agent():
    merged = merge_agent_into_session(_agent_with_findings(), "10.0.0.5")
    assert merged["services"] == 1
    fresh = _FakeAgent()
    applied = seed_agent_wm(fresh, "10.0.0.5")
    assert applied >= 1
    assert fresh.wm.find("service")
