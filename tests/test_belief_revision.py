"""Belief revision (7.4): a belief is revised PER FACT, and never silently.

The bug this closes: `WorldModel.add_finding` overwrote whatever was stored
under `(kind, key)`. A re-probe that produced a WEAKER reading (a fuzzy OS
guess, a banner from the wrong service) replaced a strong belief with no
record, and the plan then acted on a world nobody had measured. There was
also no signal that the world contradicted the model.

The rule now: a contradicting belief either SUPERSEDES (evidence at least
as strong) or is REJECTED (strictly weaker — the stronger belief stands),
and either way the change lands in `revisions`. The arbiter/reasoning
layers that used to fail mute are covered too.
"""
import pytest


def _wm(**kw):
    from phantom.automation.belief import WorldModel
    return WorldModel(target=kw.pop("target", "10.0.0.5"), **kw)


class TestAddFindingRevision:
    def test_first_belief_is_stored_without_a_revision(self):
        wm = _wm()
        f = wm.add_finding("service", "tcp/22", {"service": "ssh"},
                           confidence=0.9)
        assert wm.get("service", "tcp/22") is f
        assert wm.revisions == [] and wm.last_revision is None

    def test_stronger_evidence_supersedes_and_is_recorded(self):
        wm = _wm()
        wm.add_finding("os", "detected", {"name": "Linux 5.x"}, confidence=0.5)
        wm.add_finding("os", "detected", {"name": "Windows 10"},
                       confidence=0.8, source="smb_probe")
        assert wm.get("os", "detected").value["name"] == "Windows 10"
        rev = wm.last_revision
        assert rev.action == "superseded" and rev.superseded
        assert rev.kind == "os" and rev.key == "detected"
        assert rev.old_value["name"] == "Linux 5.x"
        assert rev.new_value["name"] == "Windows 10"
        assert rev.source == "smb_probe" and "0.80" in rev.reason

    def test_weaker_evidence_cannot_overwrite_a_belief(self):
        wm = _wm()
        strong = wm.add_finding("os", "detected", {"name": "Windows 10"},
                                confidence=0.8)
        stored = wm.add_finding("os", "detected", {"name": "Linux 5.x"},
                                confidence=0.4)
        # the RETURNED belief is the one now stored: the old one
        assert stored is strong
        assert wm.get("os", "detected").value["name"] == "Windows 10"
        rev = wm.last_revision
        assert rev.action == "rejected" and not rev.superseded
        assert rev.old_value["name"] == "Windows 10"
        assert rev.new_value["name"] == "Linux 5.x"

    def test_equal_confidence_supersedes(self):
        # a tie means the fresher measurement wins (the pre-7.4 behaviour),
        # so nothing regresses for the common re-probe case
        wm = _wm()
        wm.add_finding("banner", "ssh", {"product": "OpenSSH_8.9"},
                       confidence=0.7)
        wm.add_finding("banner", "ssh", {"product": "OpenSSH_9.3"},
                       confidence=0.7)
        assert wm.get("banner", "ssh").value["product"] == "OpenSSH_9.3"
        assert wm.last_revision.action == "superseded"

    def test_corroboration_never_weakens_the_belief(self):
        wm = _wm()
        wm.add_finding("creds", "ssh:root", {"username": "root"},
                       confidence=0.9, evidence="hydra hit")
        wm.add_finding("creds", "ssh:root", {"username": "root"},
                       confidence=0.4)
        f = wm.get("creds", "ssh:root")
        assert f.confidence == 0.9                 # max ever seen
        assert f.evidence == "hydra hit"           # proof is not dropped
        assert wm.revisions == []                  # agreement is not a revision

    def test_revision_is_per_fact(self):
        wm = _wm()
        wm.add_finding("service", "tcp/445", {"service": "smb"}, confidence=0.9)
        wm.add_finding("service", "tcp/22", {"service": "ssh"}, confidence=0.9)
        # a contradiction on one key leaves the other alone
        wm.add_finding("service", "tcp/22", {"service": "telnet"},
                       confidence=0.2)
        assert wm.get("service", "tcp/445").value["service"] == "smb"
        assert wm.get("service", "tcp/22").value["service"] == "ssh"
        assert len(wm.revisions) == 1

    def test_contradictions_only_lists_refused_challengers(self):
        wm = _wm()
        wm.add_finding("os", "detected", {"name": "Windows"}, confidence=0.8)
        wm.add_finding("os", "detected", {"name": "Linux"}, confidence=0.3)
        wm.add_finding("service", "tcp/80", {"service": "http"},
                       confidence=0.5)
        wm.add_finding("service", "tcp/80", {"service": "https"},
                       confidence=0.9)          # superseded, not a refusal
        assert [r.kind for r in wm.contradictions()] == ["os"]
        assert len(wm.revisions_of("service")) == 1

    def test_a_stronger_os_flip_is_the_wrong_model_signal(self):
        wm = _wm()
        wm.add_finding("os", "detected", {"name": "Linux"}, confidence=0.5)
        assert wm.fingerprint_mismatch is False
        wm.add_finding("os", "detected", {"name": "Windows"}, confidence=0.7)
        assert wm.fingerprint_mismatch is True

    def test_a_tie_on_the_os_alone_is_not_a_wrong_model_signal(self):
        # equal confidence is a normal re-probe, not proof the model is wrong
        wm = _wm()
        wm.add_finding("os", "detected", {"name": "Linux"}, confidence=0.6)
        wm.add_finding("os", "detected", {"name": "Windows"}, confidence=0.6)
        assert wm.fingerprint_mismatch is False

    def test_a_weaker_non_os_belief_is_not_a_wrong_model_signal(self):
        wm = _wm()
        wm.add_finding("service", "tcp/80", {"v": 1}, confidence=0.9)
        wm.add_finding("service", "tcp/80", {"v": 2}, confidence=0.2)
        assert wm.fingerprint_mismatch is False

    def test_history_is_bounded(self):
        wm = _wm()
        for i in range(260):
            wm.add_finding("service", "tcp/80", {"v": i}, confidence=0.5)
        assert len(wm.revisions) <= 200

    def test_revisions_survive_a_checkpoint_round_trip(self):
        from phantom.automation.belief import WorldModel
        wm = _wm()
        wm.add_finding("os", "detected", {"name": "Linux"}, confidence=0.4)
        wm.add_finding("os", "detected", {"name": "Windows"}, confidence=0.9)
        wm.add_finding("os", "detected", {"name": "FreeBSD"}, confidence=0.2)
        clone = WorldModel.from_dict(wm.to_dict())
        assert len(clone.revisions) == 2
        assert clone.revisions[-1].action == "rejected"
        assert clone.revisions[-1].new_value["name"] == "FreeBSD"
        assert clone.fingerprint_mismatch is True
        assert clone.get("os", "detected").value["name"] == "Windows"


class _Agent:
    """Just enough agent to exercise the finding sink and the reasoning call."""

    def __init__(self):
        self.wm = _wm()
        self.events = []
        self._degraded_layers = set()
        self._failed_caps = {}
        self.reasoning = None

    def _emit(self, kind, **data):
        self.events.append((kind, data))

    def _degrade(self, layer, exc):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent._degrade(self, layer, exc)

    def _resolve(self):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent._resolve_hypotheses(self)


class TestAgentWiring:
    def _register(self, agent, cap_id, findings):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent._register_findings(agent, cap_id, findings)

    def _finding(self, kind, key, value, confidence=0.5, evidence=""):
        from phantom.automation.belief import Finding
        return Finding(kind=kind, key=key, value=value,
                       confidence=confidence, evidence=evidence)

    def test_a_refused_challenger_is_not_new_and_is_announced(self):
        agent = _Agent()
        self._register(agent, "nmap", [self._finding(
            "os", "detected", {"name": "Windows"}, confidence=0.8)])
        agent.events.clear()
        new = self._register(agent, "nmap", [self._finding(
            "os", "detected", {"name": "Linux"}, confidence=0.3)])
        assert new is False
        kinds = [k for k, _ in agent.events]
        assert "contradiction" in kinds
        data = dict(agent.events)["contradiction"]
        assert data["finding"] == "os:detected"
        # both sides of the differential reach the operator
        assert "Windows" in data["stored"] and "Linux" in data["value"]

    def test_an_accepted_value_is_new_and_needs_no_contradiction(self):
        agent = _Agent()
        self._register(agent, "nmap", [self._finding(
            "os", "detected", {"name": "Linux"}, confidence=0.4)])
        agent.events.clear()
        new = self._register(agent, "nmap", [self._finding(
            "os", "detected", {"name": "Windows"}, confidence=0.9)])
        assert new is True
        assert "contradiction" not in [k for k, _ in agent.events]

    def test_a_repeated_fact_is_not_new(self):
        agent = _Agent()
        f = self._finding("service", "tcp/22", {"service": "ssh"}, 0.9)
        assert self._register(agent, "nmap", [f]) is True
        assert self._register(agent, "nmap", [f]) is False

    def test_hypothesis_resolution_failure_is_not_silent(self):
        class _Boom:
            def resolve(self, wm, failed_cap_ids=None):
                raise RuntimeError("resolver exploded")

        agent = _Agent()
        agent.reasoning = _Boom()
        assert agent._resolve() == []
        assert ("degraded", {"layer": "hypotheses",
                             "detail": "RuntimeError: resolver exploded"}) \
            in agent.events

    def test_hypothesis_resolution_failure_is_announced_once(self):
        class _Boom:
            def resolve(self, wm, failed_cap_ids=None):
                raise RuntimeError("resolver exploded")

        agent = _Agent()
        agent.reasoning = _Boom()
        agent._resolve()
        agent._resolve()
        assert len([e for e in agent.events if e[0] == "degraded"]) == 1


class TestContradictionRendering:
    def test_the_contrast_is_visible_not_verbose_only(self):
        from phantom.core import stream_contract as sc
        rendered = sc.render_event("contradiction", {
            "target": "10.0.0.5", "capability": "nmap",
            "finding": "os:detected", "value": "Linux 5.x",
            "stored": "Windows 10", "confidence": 0.8}, verbose=False)
        assert rendered is not None
        assert rendered.level == "warn"
        text = rendered.head
        assert "Windows 10" in text and "Linux 5.x" in text

    def test_a_contradiction_with_no_values_does_not_crash(self):
        from phantom.core import stream_contract as sc
        assert sc.render_event("contradiction", {}) is not None
