"""Tests for the engagement timeline: merge, ordering, phase tagging,
severity, client sanitisation and report integration."""
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.timeline import (
    TimelineEntry,
    build_timeline,
    render_markdown,
    store,
    timeline_stats,
    to_dicts,
)


def _wm() -> WorldModel:
    wm = WorldModel(target="10.0.0.5", target_type="ip")
    wm.add_finding("service", "tcp/80", {"port": 80, "service": "http"},
                   source="scan_tcp")
    wm.add_finding("os", "linux", {"name": "Linux 5.x"}, source="os_detect")
    wm.add_finding("creds", "ssh", {"service": "ssh", "valid": True},
                   source="ssh_login")
    wm.add_finding("beacon", "b1", {"callback": "http://x/y"},
                   source="deliver")
    wm.add_finding("internal_host", "10.0.0.9", {"ip": "10.0.0.9"},
                   source="internal_recon")
    wm.add_finding("defensive_gap", "edr", {"vendor": "none"},
                   source="edr_disable")
    wm.record_action("scan_tcp", {}, "nmap -sV 10.0.0.5", True, opsec=1.0)
    wm.record_action("web_upload_rce", {}, "curl -F file=@x", False)
    wm.record_failure("ssh_banner", "no output")
    wm.record_noise("loud_scan", 1.5)
    return wm


class TestBuild(unittest.TestCase):
    def test_merges_every_source(self):
        entries = build_timeline(_wm())
        kinds = {e.kind for e in entries}
        self.assertEqual(kinds, {"finding", "action", "failure", "noise"})
        self.assertEqual(len(entries), 6 + 2 + 1 + 1)

    def test_ordered_by_timestamp(self):
        entries = build_timeline(_wm())
        ts = [e.ts for e in entries]
        self.assertEqual(ts, sorted(ts))

    def test_drops_timestampless_entries(self):
        wm = WorldModel(target="t")
        wm.actions_taken.append({"capability": "x", "ts": 0.0})
        self.assertEqual(build_timeline(wm), [])

    def test_phase_resolved_from_capability_index(self):
        from phantom.automation.phases import phase_of
        entries = build_timeline(_wm())
        by_actor = {e.actor: e.phase for e in entries}
        self.assertEqual(by_actor["scan_tcp"], "recon")
        self.assertEqual(by_actor["internal_recon"], "post")
        self.assertEqual(by_actor["edr_disable"], "post")
        # any capability the canonical index knows must match it exactly
        for actor in ("scan_tcp", "ssh_login", "internal_recon"):
            canon = phase_of(actor)
            if canon:
                self.assertEqual(by_actor[actor], canon)
        self.assertNotIn("other", by_actor.values())

    def test_severity_by_kind(self):
        entries = build_timeline(_wm())
        sev = {(e.kind, e.actor): e.severity for e in entries}
        self.assertEqual(sev[("finding", "deliver")], "critical")
        self.assertEqual(sev[("finding", "ssh_login")], "high")
        self.assertEqual(sev[("finding", "internal_recon")], "medium")
        self.assertEqual(sev[("finding", "scan_tcp")], "info")

    def test_beacon_evidence_placed_after_last_event(self):
        wm = _wm()
        entries = build_timeline(wm, c2_evidence=[
            {"beacon_id": "b1", "ip": "10.0.0.9", "os": "linux"},
            {"beacon_id": "b1", "task_id": "t1", "output_tail": "root"},
        ])
        last_non_beacon = max(e.ts for e in entries if e.kind != "beacon")
        first_beacon = min(e.ts for e in entries if e.kind == "beacon")
        self.assertGreater(first_beacon, last_non_beacon)
        self.assertEqual(entries[-1].kind, "beacon")

    def test_stats_roll_up(self):
        stats = timeline_stats(build_timeline(_wm()))
        self.assertEqual(stats["total"], 10)
        self.assertEqual(stats["by_severity"]["critical"], 1)
        self.assertEqual(stats["by_kind"]["action"], 2)


class TestRender(unittest.TestCase):
    def test_operator_view_has_commands_and_detail(self):
        out = "\n".join(render_markdown(build_timeline(_wm()), client=False))
        self.assertIn("Engagement Timeline", out)
        self.assertIn("nmap -sV 10.0.0.5", out)
        self.assertIn("Timeline", out)

    def test_client_view_hides_actions_and_commands(self):
        out = "\n".join(render_markdown(build_timeline(_wm()), client=True))
        self.assertNotIn("nmap -sV", out)          # no command lines
        self.assertNotIn("curl -F", out)
        self.assertIn("[beacon]", out)             # phase tag is shown
        self.assertIn("[post]", out)

    def test_client_view_never_names_credentials(self):
        out = "\n".join(render_markdown(build_timeline(_wm()), client=True))
        self.assertNotIn("Valid credentials", out)
        self.assertNotIn("creds", out)
        # ...but the operator view still carries them
        raw = "\n".join(render_markdown(build_timeline(_wm()), client=False))
        self.assertIn("Valid credentials", raw)

    def test_client_view_neutralises_failures(self):
        out = "\n".join(render_markdown(build_timeline(_wm()), client=True))
        self.assertNotIn("ssh_banner", out)
        self.assertIn("automated check did not apply", out)

    def test_empty_timeline(self):
        out = "\n".join(render_markdown([]))
        self.assertIn("No recorded activity", out)

    def test_truncation_notice(self):
        wm = WorldModel(target="t")
        for i in range(20):
            wm.add_finding("service", f"p{i}", {"port": i}, source="scan_tcp")
        out = "\n".join(render_markdown(build_timeline(wm), max_entries=5))
        self.assertIn("more events", out)


class TestStore(unittest.TestCase):
    def test_store_update_and_recent(self):
        st = store()
        st.update(build_timeline(_wm()))
        self.assertEqual(st.stats()["total"], 10)
        self.assertTrue(st.built_at)
        self.assertEqual(len(st.recent(3)), 3)

    def test_to_dicts_round_trip(self):
        dicts = to_dicts(build_timeline(_wm()))
        self.assertTrue(all(isinstance(d, dict) for d in dicts))
        # every dict must be reconstructible into a TimelineEntry
        entries = [TimelineEntry(**{k: v for k, v in d.items() if k != "iso"})
                   for d in dicts]
        self.assertEqual(entries[0].phase, build_timeline(_wm())[0].phase)


class _Sink:
    def __init__(self):
        self.events = []


class _Agent:
    """Minimal agent-shaped object for report integration tests."""

    def __init__(self, wm):
        self.wm = wm
        self.target = wm.target
        self.goal = "identity"
        self.sink = _Sink()
        self._session = None


class TestReportIntegration(unittest.TestCase):
    def test_raw_report_carries_timeline(self):
        from phantom.automation.reporting import RawReport
        raw = RawReport.from_agent(_Agent(_wm()))
        self.assertTrue(raw.timeline)
        self.assertIn("timeline", raw.to_dict())
        md = raw.to_markdown()
        self.assertIn("## Engagement Timeline", md)
        self.assertIn("Timeline roll-up", md)

    def test_client_report_carries_sanitised_timeline(self):
        from phantom.automation.reporting import ClientReport
        c = ClientReport.from_agent(_Agent(_wm()))
        self.assertTrue(c.timeline)
        self.assertIn("timeline", c.to_dict())
        md = c.to_markdown()
        self.assertIn("## Engagement Timeline", md)
        self.assertNotIn("nmap -sV", md)

    def test_report_survives_empty_timeline(self):
        from phantom.automation.reporting import RawReport
        raw = RawReport(target="t", goal="g", started="now")
        self.assertEqual(raw.timeline, [])
        self.assertIn("# Phantom Raw Report", raw.to_markdown())


if __name__ == "__main__":
    unittest.main()
