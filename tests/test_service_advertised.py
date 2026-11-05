"""A scanner's word is not a handshake.

Measured 2026-11-02 on the ``decoy_scan`` benchmark: the scripted target
advertises MySQL on 3306 without anything listening, the run stored it as a
``service`` belief and the report scored ``service:tcp/3306`` as a false
positive. The defect was not the wrong port — it was that TEXT output and a
successful TCP connect were the same kind of evidence.

These tests pin the three states of one fact:

* advertised  -> visible, never actionable (a cheap probe may confirm it);
* confirmed   -> actionable as before, and only one code path clears the flag;
* operator-supplied services keep today's behaviour (they are not promises
  parsed out of a report).
"""
from __future__ import annotations

from phantom.automation.belief import WorldModel
from phantom.automation.exploit.access import _candidate_from_service, collect_candidates
from phantom.automation.perception import parse_nmap_ports

TARGET = "10.0.0.5"


def _candidate(wm, cid: str):
    for cand in collect_candidates(wm=wm, include_nvd=False):
        if cand.id == cid:
            return cand
    return None


def _advertised(wm: WorldModel, port: str = "6379", service: str = "redis"):
    wm.add_finding("service", f"tcp/{port}",
                   {"port": port, "protocol": "tcp", "service": service,
                    "version": "", "product": "", "advertised": True},
                   confidence=0.9, source="nmap")
    return wm


def test_a_scan_report_marks_the_port_advertised():
    findings = parse_nmap_ports("3306/tcp open  mysql")
    assert len(findings) == 1
    assert findings[0]["value"]["advertised"] is True


def test_masscan_counts_as_a_report_too():
    findings = parse_nmap_ports("Discovered open port 3306/tcp on 10.0.0.5")
    assert findings[0]["value"]["advertised"] is True


def test_an_nc_succeeded_line_is_a_handshake_not_an_advertisement():
    """`nc -zv` logs the line AFTER the connect succeeded: it is evidence."""
    findings = parse_nmap_ports(
        "Connection to 10.0.0.5 22 port [tcp/ssh] succeeded!")
    assert findings[0]["value"]["advertised"] is False


def test_an_advertised_service_is_not_actionable():
    wm = _advertised(WorldModel(target=TARGET))
    cand = _candidate(wm, "noncve:service:redis:6379")
    assert cand is not None, "the candidate must stay visible to be verified"
    assert cand.actionable is False
    assert cand.auto_execute is False
    assert cand.metadata.get("needs_confirmation") is True


def test_confirm_service_makes_it_actionable():
    wm = _advertised(WorldModel(target=TARGET))
    assert wm.confirm_service("tcp/6379", source="redis-cli") is True
    stored = wm.get("service", "tcp/6379")
    assert stored.value["advertised"] is False
    assert stored.confidence >= 0.95
    assert "redis-cli" in stored.sources
    cand = _candidate(wm, "noncve:service:redis:6379")
    assert cand.actionable is True
    assert cand.auto_execute is True


def test_a_probe_banner_confirms_the_port_it_came_from():
    """The confirmation wire that needs no extra call: a banner IS a reply."""
    wm = _advertised(WorldModel(target=TARGET))
    wm.add_finding("banner", "tcp/6379",
                   {"port": "6379", "banner": "# Server"},
                   confidence=0.6, source="curl_probe")
    cand = _candidate(wm, "noncve:service:redis:6379")
    assert cand.actionable is True
    assert wm.get("service", "tcp/6379").value["advertised"] is False


def test_a_protocol_fact_confirms_its_own_service():
    wm = _advertised(WorldModel(target=TARGET))
    wm.add_finding("redis", "version", {"version": "7.2.4"},
                   confidence=0.9, source="redis")
    cand = _candidate(wm, "noncve:service:redis:6379")
    assert cand.actionable is True


def test_confirm_service_never_raises_and_refuses_nothing_to_confirm():
    wm = WorldModel(target=TARGET)
    assert wm.confirm_service("tcp/1") is False          # no such finding
    wm.add_finding("service", "tcp/2", "not-a-dict")
    assert wm.confirm_service("tcp/2") is False           # not a value dict
    confirmed = _advertised(WorldModel(target=TARGET))
    confirmed.confirm_service("tcp/6379")
    assert confirmed.confirm_service("tcp/6379") is False  # already confirmed


def test_operator_supplied_services_keep_their_behaviour():
    """A service the operator names is not a promise parsed out of a report."""
    cands = collect_candidates(services=[{"port": "6379", "service": "redis"}],
                               target=TARGET, include_nvd=False)
    redis = [c for c in cands if c.id == "noncve:service:redis:6379"][0]
    assert redis.actionable is True


def test_the_candidate_builder_can_be_called_directly():
    """The advertised flag travels through the builder, not just the collector."""
    cand = _candidate_from_service("redis", "", TARGET, "6379",
                                   advertised=True)
    assert cand.actionable is False
    assert cand.metadata.get("advertised") is True
