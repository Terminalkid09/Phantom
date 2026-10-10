"""Tests for the hygiene pass: swallowed failures must be COUNTABLE, and a
corrupt state file must not be treated as state."""
import json
import os
import tempfile

from phantom.utils import quiet


class TestQuietRegistry:
    def _fresh(self):
        quiet.registry.reset()
        return quiet.registry

    def test_a_swallowed_failure_is_counted_with_its_site(self):
        reg = self._fresh()
        try:
            reg.swallow("audit.append", ValueError("disk full"))
        finally:
            pass
        sites = reg.sites()
        assert len(sites) == 1
        assert sites[0].where == "audit.append" and sites[0].count == 1
        assert sites[0].exc_type == "ValueError"
        assert "disk full" in sites[0].last
        assert reg.total() == 1

    def test_repeats_accumulate_and_keep_the_last_message(self):
        reg = self._fresh()
        reg.swallow("x", ValueError("first"))
        reg.swallow("x", ValueError("second"))
        site = reg.sites()[0]
        assert site.count == 2 and "first" in site.first \
            and "second" in site.last

    def test_the_registry_never_raises_and_caps_itself(self):
        reg = quiet.QuietRegistry(max_sites=2)
        reg.swallow("a", None, "msg")
        reg.swallow("b", None, "msg")
        reg.swallow("c", None, "msg")      # over the cap: counted out, no raise
        assert len(reg.sites()) == 2
        reg.swallow(None, object())        # junk input must not raise

    def test_report_names_the_sites_and_counts(self):
        reg = self._fresh()
        try:
            assert reg.report() == "quiet failures: none recorded"
            reg.swallow("journal.write", OSError("no space"))
            text = reg.report()
        finally:
            reg.reset()
        assert "journal.write" in text and "1x" in text or "1 swallowed" in text
        assert "no space" in text

    def test_the_module_shorthand_uses_the_global_registry(self):
        quiet.registry.reset()
        quiet.swallow("module.level", RuntimeError("boom"))
        try:
            assert quiet.registry.total() == 1
        finally:
            quiet.registry.reset()


class TestCalibrationTreatsABrokenFileAsAbsent:
    def _engine(self, content):
        from phantom.core.calibration import CalibrationEngine, INITIAL_WEIGHTS
        path = os.path.join(tempfile.mkdtemp(prefix="phantom-cal-"),
                           "weights.json")
        with open(path, "w", encoding="utf-8") as handle:
            handle.write(content)
        quiet.registry.reset()
        return CalibrationEngine(weights_file=path), path, INITIAL_WEIGHTS

    def test_an_unparsable_file_is_ignored_and_recorded(self):
        engine, _path, initial = self._engine("dummy")
        assert engine.weights == initial
        assert any("calibration" in s.where for s in quiet.registry.sites())
        quiet.registry.reset()

    def test_a_file_without_a_weights_mapping_is_not_state(self):
        engine, _path, initial = self._engine(json.dumps({"junk": 1}))
        assert engine.weights == initial
        quiet.registry.reset()

    def test_a_missing_file_stays_silent(self):
        from phantom.core.calibration import CalibrationEngine, INITIAL_WEIGHTS
        quiet.registry.reset()
        engine = CalibrationEngine(weights_file=os.path.join(
            tempfile.mkdtemp(prefix="phantom-cal-"), "absent.json"))
        assert engine.weights == INITIAL_WEIGHTS
        assert quiet.registry.total() == 0

    def test_a_valid_file_still_loads_its_weights(self):
        engine, _path, _initial = self._engine(json.dumps({
            "weights": {"smtp_probe": 4.5, "bogus": "not-a-number"},
            "observations": {"smtp_probe": {"ok": 3}}}))
        assert engine.weights["smtp_probe"] == 4.5
        # a non-numeric value never loads: calibration runs on numbers only
        assert "bogus" not in engine.weights
        assert engine.observations == {"smtp_probe": {"ok": 3}}
        quiet.registry.reset()


class TestDoctorSurfacesBoth:
    """The registry and the settings nucleus are useless unless a human sees
    them: `doctor` is that read path."""

    def test_the_swallowed_failures_appear_in_doctor(self):
        from phantom.core.doctor import run_doctor
        quiet.registry.reset()
        try:
            clean = {c.name: c for c in run_doctor().checks}
            assert clean["quiet-failures"].status == "pass"
            quiet.registry.swallow("journal.write", OSError("no space"))
            after = {c.name: c for c in run_doctor().checks}
            check = after["quiet-failures"]
            assert check.status == "warn"
            assert "journal.write" in check.hint
        finally:
            quiet.registry.reset()

    def test_the_settings_nucleus_is_reported_without_values(self):
        from phantom.core.doctor import run_doctor
        check = {c.name: c for c in run_doctor().checks}["settings"]
        assert check.status == "pass"
        assert "declared" in check.detail
        assert "never reported" in check.detail


class TestTheAuditAppendNoLongerVanishes:
    def test_a_failing_audit_append_is_recorded_and_the_route_still_answers(self):
        """The real regression: the result was stored, the chain-of-custody
        entry was not, and nothing said so."""
        from phantom.core import c2_server
        from phantom.utils import audit_log as audit_mod
        quiet.registry.reset()
        calls = []

        def boom(*_a, **_k):
            calls.append(1)
            raise OSError("disk full")

        original = audit_mod.audit_log.append
        audit_mod.audit_log.append = boom
        try:
            result = c2_server._record_task_result_with_audit(
                "beacon-1", "task-1", "output")
        finally:
            audit_mod.audit_log.append = original
        assert calls, "the audit append must have been attempted"
        # the helper must not propagate: the result is already stored
        assert result is None
        assert any("audit" in s.where for s in quiet.registry.sites()), (
            "a silent swallow is what this test exists to prevent")
        quiet.registry.reset()
