"""P2-1 closure tests: honest exec-class on every capability.

The classification drives the enterprise validation matrix — an
in-process engine mislabeled as a shell command would demand lab proof
it can never provide, and a shell capability labeled as a stub would
skip validation entirely.
"""
from collections import Counter

from phantom.automation.guidance.commands import make_registry


def test_registry_loads_and_every_capability_is_classified():
    reg = make_registry()
    caps = reg.all()
    assert len(caps) >= 70
    for c in caps:
        assert c.exec_class in ("shell_command", "in_process_engine",
                                "marker_only", "beacon_task", "lab_only",
                                "not_validated"), c.id


def test_in_process_engines_are_labeled_as_such():
    reg = make_registry()
    for cid in ("hunt_web", "idor_scan", "web_creds",
                "differential_analysis"):
        cap = reg.get(cid)
        assert cap is not None, cid
        assert cap.exec_class == "in_process_engine", (cid, cap.exec_class)


def test_real_shell_capabilities_stay_shell_command():
    reg = make_registry()
    for cid in ("scan_tcp", "ssh_login", "beacon_deploy",
                "persistence_install", "http_probe"):
        cap = reg.get(cid)
        assert cap is not None, cid
        assert cap.exec_class == "shell_command", (cid, cap.exec_class)


def test_classification_distribution_is_sane():
    reg = make_registry()
    dist = Counter(c.exec_class for c in reg.all())
    # the overwhelming majority produces real commands; the in-process
    # engines are the honest minority (roadmap note on the marker stubs)
    assert dist["shell_command"] > dist["in_process_engine"]
    assert dist["in_process_engine"] >= 4
