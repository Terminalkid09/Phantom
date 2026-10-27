"""Training data must speak the same JSON as the runtime.

A label the runtime validator refuses is a model trained to be rejected. These
tests pin every builder and the synthetic seed generator to
``phantom.automation.ai.schemas``, and pin the eval conversion so a score is
measured on the shape the runtime would actually return.
"""
from __future__ import annotations

import json

from phantom.automation.ai import schemas
from training import build_dataset, predict, synth


def _session() -> dict:
    return {
        "target": "10.0.0.5", "goal": "deliver", "profile": "enterprise",
        "wm": {
            "findings": [
                {"kind": "service", "key": "tcp/22",
                 "value": {"port": "22", "service": "ssh",
                           "product": "OpenSSH", "version": "8.2"},
                 "confidence": 0.9, "source": "nmap"},
                {"kind": "os_inferred", "key": "os:linux",
                 "value": {"os": "linux"}, "confidence": 0.7},
                {"kind": "web_anomaly", "key": "sqli:login",
                 "value": {"param": "user"}, "confidence": 0.6},
            ],
            "actions": [
                {"capability": "scan_tcp", "slots": {},
                 "command": "nmap -Pn -sT -p- 10.0.0.5",
                 "output": "22/tcp open ssh\n443/tcp open https", "ok": True},
                {"capability": "ssh_login", "slots": {},
                 "command": "ssh admin@10.0.0.5", "output": "",
                 "ok": True},
            ],
            "failures": [
                {"capability": "service_exploit",
                 "reason": "no new facts learned", "unblock": "new creds"},
            ],
            "identity": {
                "nodes": [
                    {"key": "github:mrossi", "platform": "github",
                     "bio": "backend"},
                    {"key": "x:mrossi", "platform": "x", "bio": "backend"},
                ],
                "edges": [{"src": "github:mrossi", "dst": "x:mrossi",
                           "kind": "same_handle", "confidence": 0.6}],
            },
        },
    }


def _labels(records):
    for record in records:
        yield record["phase"], json.loads(record["messages"][2]["content"])


def test_every_builder_label_passes_the_runtime_validator():
    session = _session()
    seen = set()
    for phase in ("exploit", "finding", "osint", "scan_parse", "evolution"):
        records, _ = build_dataset.build(phase, [("s", session)], [], [])
        assert records, phase
        for label_phase, label in _labels(records):
            assert schemas.validate(label_phase, label) == [], (phase, label)
            seen.add(phase)
    assert seen == {"exploit", "finding", "osint", "scan_parse", "evolution"}


def test_finding_kinds_are_mapped_into_the_closed_set():
    records, _ = build_dataset.build("finding", [("s", _session())], [], [])
    kinds = {label["findings"][0]["kind"] for _, label in _labels(records)}
    assert kinds <= schemas.FINDING_KINDS
    assert "os" in kinds and "hunt_anomaly" in kinds


def test_synthetic_seeds_are_valid_and_non_empty():
    for phase in ("osint", "social", "scan_parse"):
        rows = synth.build(phase)
        assert rows, phase
        for record in rows:
            label = json.loads(record["messages"][2]["content"])
            assert schemas.validate(phase, label) == [], (phase, label)
        first = json.loads(rows[0]["messages"][2]["content"])
        if phase == "social":
            assert "http" not in first["text"].lower()
            assert "?" in first["text"]
        if phase == "scan_parse":
            assert first == {"findings": [], "notes": ""} or first["findings"]


def test_prediction_conversion_matches_the_eval_shapes():
    assert predict.to_eval("exploit",
                           {"ranked": [{"id": "ssh_login"},
                                       {"id": "CVE-1"}]}, {}) == {
        "ranking": ["ssh_login", "CVE-1"]}
    assert predict.to_eval("finding",
                           {"findings": [{"kind": "note", "key": "k"}]},
                           {}) == {"value": {"kind": "note", "key": "k"}}
    assert predict.to_eval("scan_parse",
                           {"findings": [{"port": 22}, {"port": "80"}]},
                           {}) == {"open_ports": ["22", "80"]}
    assert predict.to_eval("osint",
                           {"links": [{"handle": "m", "platform": "x",
                                       "confidence": 0.7}]},
                           {"candidate": {"handle": "m",
                                          "platform": "x"}}) == {
        "probability": 0.7}
    assert predict.to_eval("evolution",
                           {"summary": "timeout", "proposal": "retry"},
                           {}) == {"value": {"cause": "timeout",
                                             "repair": "retry",
                                             "new_capability": True}}


def test_baseline_predictions_are_deterministic_and_shaped():
    scan = predict._baseline("scan_parse", {
        "output": "22/tcp open ssh\n443/tcp open https"})
    assert scan == {"open_ports": ["22", "443"]}
    empty = predict._baseline("scan_parse", {
        "output": "All 1000 scanned ports on 10.0.0.5 are in ignored states."})
    assert empty == {"open_ports": []}
    finding = predict._baseline("finding", {
        "observation": {"kind": "service", "key": "tcp/22",
                        "value": {"port": "22"}, "confidence": 0.9}})
    assert finding["value"]["kind"] == "service"
