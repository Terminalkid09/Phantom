"""Decision traces (7.5): why the run moved, in order, auditable.

`agent._decisions` is keyed by capability id, so a re-decision erases the
earlier verdict, the order is lost, and nothing survives a checkpoint: the
operator could see which lens drove the move that ran, never the sequence
that led there. `DecisionTrace` keeps the ordered ledger and the report
prints it, so "why did it do that?" has a step number.
"""
import pytest

from phantom.automation.brain.lenses import Decision
from phantom.automation.brain.trace import (
    TRACE_LIMIT,
    DecisionTrace,
    TraceEntry,
)


def _decision(capability="scan_tcp", value=2.0, base=2.0, driver="progress",
              veto="", profile="balanced", policy="adaptive"):
    return Decision(capability=capability, base=base, value=value,
                    driver=driver, runner_up="stealth", profile=profile,
                    search_policy=policy,
                    contributions={"progress": 0.6, "stealth": 0.3},
                    signals={"stage": "footprint"}, veto=veto)


class TestRecording:
    def test_the_ledger_keeps_the_order(self):
        trace = DecisionTrace()
        trace.note(_decision("scan_tcp"), stage="footprint")
        trace.note(_decision("version_detect"), stage="footprint")
        trace.note(_decision("ssh_login"), stage="deliver")
        assert [e.capability for e in trace] == ["scan_tcp", "version_detect",
                                                 "ssh_login"]
        assert [e.seq for e in trace] == [1, 2, 3]
        assert [e.stage for e in trace] == ["footprint", "footprint",
                                            "deliver"]

    def test_a_repeated_decision_is_not_recorded_again(self):
        # the planner rates every candidate on every pass: without dedupe
        # the ledger would be the same decision 200 times and the history
        # of CHANGES would be buried
        trace = DecisionTrace()
        assert trace.note(_decision(), stage="footprint") is not None
        assert trace.note(_decision(), stage="footprint") is None
        assert len(trace) == 1

    def test_a_changed_verdict_is_recorded(self):
        trace = DecisionTrace()
        trace.note(_decision(driver="progress"), stage="footprint")
        assert trace.note(_decision(driver="evidence", value=2.4),
                          stage="footprint") is not None
        assert [e.driver for e in trace] == ["progress", "evidence"]

    def test_the_same_verdict_in_another_stage_is_a_new_decision(self):
        trace = DecisionTrace()
        trace.note(_decision(), stage="footprint")
        assert trace.note(_decision(), stage="deliver") is not None
        assert len(trace) == 2

    def test_a_vetoed_move_is_recorded(self):
        trace = DecisionTrace()
        trace.note(_decision(veto="aggressive only"), stage="footprint")
        assert trace.last().vetoed is True
        assert "VETOED" in trace.last().explain()

    def test_history_is_bounded(self):
        trace = DecisionTrace(limit=10)
        for i in range(60):
            trace.note(_decision(value=1.0 + i * 0.01))
        assert len(trace) <= 10

    def test_default_limit_is_the_documented_one(self):
        assert TRACE_LIMIT > 0
        assert DecisionTrace().limit == TRACE_LIMIT


class TestQueries:
    def _trace(self):
        trace = DecisionTrace()
        trace.note(_decision("scan_tcp", driver="progress"), stage="footprint")
        trace.note(_decision("scan_tcp", driver="evidence", value=3.0),
                   stage="footprint")
        trace.note(_decision("phish_send", driver="collateral"), stage="identity")
        return trace

    def test_of_one_capability_is_oldest_first(self):
        assert [e.driver for e in self._trace().of("scan_tcp")] == \
            ["progress", "evidence"]

    def test_of_stage_scopes_the_entries(self):
        trace = self._trace()
        assert len(trace.of_stage("footprint")) == 2
        assert len(trace.of_stage("identity")) == 1

    def test_drivers_counts_what_actually_decided(self):
        stats = self._trace().drivers()
        assert stats["progress"] == 1 and stats["evidence"] == 1
        assert stats["collateral"] == 1

    def test_vetoes_are_counted_apart_from_the_lenses(self):
        trace = DecisionTrace()
        trace.note(_decision(veto="requires --aggressive"))
        assert trace.drivers() == {"veto": 1}

    def test_explain_all_reads_like_a_history(self):
        lines = self._trace().explain_all()
        assert len(lines) == 3
        assert lines[0].startswith("#1 scan_tcp")
        assert "driven by progress" in lines[0]

    def test_empty_trace_is_falsey(self):
        trace = DecisionTrace()
        assert not trace and len(trace) == 0


class TestSerialization:
    def test_round_trip_keeps_every_field(self):
        trace = DecisionTrace()
        trace.note(_decision(driver="evidence", value=3.25), stage="exploit")
        clone = DecisionTrace.from_dict(trace.to_dict())
        assert len(clone) == 1
        got = clone.last()
        assert got.capability == "scan_tcp" and got.stage == "exploit"
        assert got.driver == "evidence" and got.value == 3.25
        assert got.signals == {"stage": "footprint"}
        assert got.contributions["progress"] == 0.6
        assert clone.explain_all() == trace.explain_all()

    def test_from_dict_tolerates_junk(self):
        assert len(DecisionTrace.from_dict(None)) == 0
        assert len(DecisionTrace.from_dict({})) == 0
        assert len(DecisionTrace.from_dict({"entries": [{"seq": "x"}]})) == 1


class TestExplain:
    def test_the_line_names_the_lens_and_the_band(self):
        entry = TraceEntry(seq=2, capability="beacon_deploy", base=2.0,
                           value=3.0, driver="progress", runner_up="success",
                           profile="balanced", search_policy="depth")
        text = entry.explain()
        assert text.startswith("#2 beacon_deploy")
        assert "driven by progress" in text
        assert "runner-up success" in text
        assert "x1.50" in text and "balanced/depth" in text

    def test_a_veto_needs_no_band(self):
        entry = TraceEntry(seq=1, capability="payload_bind",
                           veto="bind shell requires --aggressive")
        text = entry.explain()
        assert "VETOED" in text and "x0" not in text


class TestAgentWiring:
    def _agent(self):
        from phantom.automation.agent import AutonomousAgent
        return AutonomousAgent(target="10.0.0.5")

    def test_a_decision_lands_in_the_trace(self):
        from types import SimpleNamespace
        agent = self._agent()
        cap = agent.registry.get("scan_tcp")
        if cap is None:
            pytest.skip("scan_tcp not in the registry")
        agent._decision_for(SimpleNamespace(capability=cap, reason="probe"),
                            base=1.0)
        assert len(agent.trace) == 1
        assert agent.trace.last().capability == "scan_tcp"
        # and the last verdict is still where the `run` event reads it
        assert "scan_tcp" in agent._decisions

    def test_the_decision_event_reaches_the_operator_stream(self):
        from types import SimpleNamespace
        seen = []
        from phantom.automation.agent import AutonomousAgent
        agent = AutonomousAgent(target="10.0.0.5",
                                on_event=lambda k, d: seen.append((k, d)))
        cap = agent.registry.get("scan_tcp")
        if cap is None:
            pytest.skip("scan_tcp not in the registry")
        agent._decision_for(SimpleNamespace(capability=cap, reason="probe"),
                            base=1.0)
        kinds = [k for k, _ in seen]
        assert "decision" in kinds
        payload = dict(seen)["decision"]
        assert payload["capability"] == "scan_tcp"
        assert "driven by" in payload["detail"]

    def test_the_trace_survives_a_checkpoint(self, tmp_path):
        from types import SimpleNamespace
        agent = self._agent()
        cap = agent.registry.get("scan_tcp")
        if cap is None:
            pytest.skip("scan_tcp not in the registry")
        agent._decision_for(SimpleNamespace(capability=cap, reason="probe"),
                            base=1.0)
        path = agent.save_state(str(tmp_path / "checkpoint.json"))
        from phantom.automation.agent import AutonomousAgent
        clone = AutonomousAgent.from_state(path)
        assert len(clone.trace) == 1
        assert clone.trace.last().capability == "scan_tcp"

    def test_a_report_carries_the_trace(self):
        from phantom.automation.reporting import RawReport
        agent = self._agent()
        from types import SimpleNamespace
        cap = agent.registry.get("scan_tcp")
        if cap is None:
            pytest.skip("scan_tcp not in the registry")
        agent._decision_for(SimpleNamespace(capability=cap, reason="probe"),
                            base=1.0)
        report = RawReport.from_agent(agent)
        assert report.decision_trace
        assert report.decision_trace[0]["capability"] == "scan_tcp"
        body = report.to_markdown()
        assert "## Decision Trace" in body
        assert "driven by" in body


class TestRenderContract:
    def test_the_decision_event_is_verbose_only(self):
        from phantom.core import stream_contract as sc
        assert sc.render_event("decision", {"capability": "x"},
                               verbose=False) is None
        rendered = sc.render_event("decision", {
            "capability": "scan_tcp",
            "detail": "#1 scan_tcp: 1.00 -> 1.20 (x1.20) driven by progress "
                      "[balanced/adaptive]"}, verbose=True)
        assert rendered is not None
        assert "driven by progress" in rendered.head

    def test_an_empty_decision_event_does_not_crash(self):
        from phantom.core import stream_contract as sc
        assert sc.render_event("decision", {}, verbose=True) is not None
