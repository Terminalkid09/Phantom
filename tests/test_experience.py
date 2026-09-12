"""Tests for the experience learning engine.

Covers the four things that decide whether it is trustworthy:
  1. the signature is deterministic and transfers only between like targets
  2. the cause taxonomy is correct AND never learns from environmental noise
  3. retrieval prefers the technique that actually unblocked a cause
  4. persistence is opt-in, bounded and never leaks between engagements
"""
import json
import os
import tempfile
import time
import unittest

from phantom.automation.belief import WorldModel
from phantom.automation.brain.experience import (
    Episode,
    Experience,
    Signature,
    causes,
    consolidate,
)
from phantom.automation.brain.experience.retrieve import (
    NEUTRAL,
    advise,
    cold_start_hints,
    explain,
    similar_episodes,
)


def _wm(target="10.0.0.5", ttype="ip", product="nginx", waf=False):
    wm = WorldModel(target=target, target_type=ttype)
    wm.add_finding("service", "tcp/80", {"port": 80, "service": "http"},
                   source="scan_tcp")
    wm.add_finding("service", "tcp/443", {"port": 443, "service": "https"},
                   source="scan_tcp")
    wm.add_finding("web_header", "server", {"server": product},
                   source="http_probe")
    if waf:
        wm.add_finding("defensive_gap", "waf",
                       {"vendor": "cloudflare"}, source="hunt_web")
    return wm


def _ep(wm, technique, ok, cause="", repair="", ts=None, phase="exploit"):
    sig = Signature.from_worldmodel(wm)
    return Episode(sig=sig.to_dict(), phase=phase, technique=technique,
                   ok=ok, cause="" if ok else cause, repair=repair,
                   ts=time.time() if ts is None else ts)


class TestSignature(unittest.TestCase):
    def test_deterministic(self):
        a = Signature.from_worldmodel(_wm())
        b = Signature.from_worldmodel(_wm())
        self.assertEqual(a.key, b.key)
        self.assertEqual(a.features, b.features)

    def test_identical_situations_are_a_full_match(self):
        a = Signature.from_worldmodel(_wm())
        b = Signature.from_worldmodel(_wm())
        self.assertEqual(a.similarity(b), 1.0)

    def test_different_service_sets_score_lower(self):
        a = Signature.from_worldmodel(_wm())
        b = Signature.from_worldmodel(_wm(product="apache"))
        self.assertLess(b.similarity(a), 1.0)

    def test_class_separation(self):
        net = Signature.from_worldmodel(_wm())
        ident = Signature.from_worldmodel(
            _wm(target="@handle", ttype="username"))
        self.assertEqual(net.cls, "network")
        self.assertEqual(ident.cls, "identity")
        self.assertLess(ident.similarity(net), 0.9)

    def test_waf_changes_the_signature(self):
        plain = Signature.from_worldmodel(_wm(waf=False))
        waf = Signature.from_worldmodel(_wm(waf=True))
        self.assertNotEqual(plain.key, waf.key)
        self.assertIn("def:cloudflare", waf.features)
        self.assertIn("cloudflare", waf.human())

    def test_round_trip_dict(self):
        a = Signature.from_worldmodel(_wm(waf=True))
        b = Signature.from_dict(a.to_dict())
        self.assertEqual(a.key, b.key)
        self.assertEqual(a.similarity(b), 1.0)


class TestCauses(unittest.TestCase):
    def test_rules(self):
        cases = [
            ("out of scope: 10.0.0.9", causes.SCOPE_DENIED),
            ("bind shell requires --aggressive", causes.GATED),
            ("tool unavailable: nmap, masscan", causes.DEPENDENCY_MISSING),
            ("blocked by cloudflare waf", causes.WAF_BLOCKED),
            ("HTTP 403 forbidden", causes.WAF_BLOCKED),
            ("429 too many requests", causes.RATE_LIMITED),
            ("command timed out after 300s", causes.TIMEOUT),
            ("Connection refused", causes.UNREACHABLE),
            ("401 unauthorized", causes.AUTH_REQUIRED),
            ("permission denied", causes.PRIVILEGE),
            ("404 not found", causes.NOT_FOUND),
            ("unsupported cipher suite", causes.UNSUPPORTED),
            ("no output", causes.NO_SIGNAL),
            ("failed to parse json response", causes.PARSE_ERROR),
        ]
        for text, expected in cases:
            self.assertEqual(causes.classify("cap", text), expected, text)

    def test_explicit_cause_wins(self):
        self.assertEqual(
            causes.classify("cap", "whatever", cause=causes.WAF_BLOCKED),
            causes.WAF_BLOCKED)
        # an unknown explicit cause falls back to rules, not to the string
        self.assertEqual(
            causes.classify("cap", "404 not found", cause="bogus"),
            causes.NOT_FOUND)

    def test_environmental_causes_are_not_learnable(self):
        for c in (causes.DEPENDENCY_MISSING, causes.SCOPE_DENIED,
                  causes.GATED):
            self.assertFalse(causes.is_learnable(c))
        for c in (causes.WAF_BLOCKED, causes.TIMEOUT, causes.AUTH_REQUIRED):
            self.assertTrue(causes.is_learnable(c))

    def test_environmental_episodes_are_ignored_by_retrieval(self):
        wm = _wm()
        eps = [
            _ep(wm, "port_scan", False, causes.DEPENDENCY_MISSING),
            _ep(wm, "port_scan", False, causes.DEPENDENCY_MISSING),
            _ep(wm, "port_scan", False, causes.DEPENDENCY_MISSING),
        ]
        self.assertEqual(similar_episodes(Signature.from_worldmodel(wm), eps),
                         [])

    def test_repair_hints_exist_for_common_causes(self):
        self.assertTrue(causes.repair_hints(causes.WAF_BLOCKED))
        self.assertEqual(causes.repair_hints(causes.SCOPE_DENIED), ())
        self.assertIn("authentication", causes.describe(causes.AUTH_REQUIRED))


class TestRetrieval(unittest.TestCase):
    def test_repair_is_preferred(self):
        wm = _wm()
        eps = [
            _ep(wm, "web_upload_rce", False, causes.WAF_BLOCKED,
                repair="sql_injection"),
            _ep(wm, "web_upload_rce", False, causes.WAF_BLOCKED,
                repair="sql_injection"),
        ]
        adv = advise(Signature.from_worldmodel(wm), eps)
        self.assertLess(adv["sql_injection"].multiplier, NEUTRAL)
        self.assertGreater(adv["web_upload_rce"].multiplier, NEUTRAL)
        self.assertEqual(adv["sql_injection"].source, "data")

    def test_repeated_failure_is_deprioritised_more_than_once(self):
        wm = _wm()
        once = advise(Signature.from_worldmodel(wm),
                      [_ep(wm, "hunt_web", False, causes.WAF_BLOCKED)])
        twice = advise(Signature.from_worldmodel(wm), [
            _ep(wm, "hunt_web", False, causes.WAF_BLOCKED),
            _ep(wm, "hunt_web", False, causes.WAF_BLOCKED),
        ])
        self.assertGreater(twice["hunt_web"].multiplier,
                           once["hunt_web"].multiplier)

    def test_reliable_win_is_preferred(self):
        wm = _wm()
        eps = [_ep(wm, "ssh_login", True), _ep(wm, "ssh_login", True),
               _ep(wm, "ssh_login", True)]
        adv = advise(Signature.from_worldmodel(wm), eps)
        self.assertLess(adv["ssh_login"].multiplier, NEUTRAL)

    def test_multiplier_is_clamped(self):
        wm = _wm()
        eps = [_ep(wm, "hunt_web", False, causes.WAF_BLOCKED)
               for _ in range(20)]
        adv = advise(Signature.from_worldmodel(wm), eps)
        self.assertLessEqual(adv["hunt_web"].multiplier, 1.5)
        self.assertGreaterEqual(adv["hunt_web"].multiplier, 0.5)

    def test_unrelated_target_gives_no_advice(self):
        net = _wm()
        ident = _wm(target="@handle", ttype="username", product="instagram")
        eps = [_ep(net, "hunt_web", False, causes.WAF_BLOCKED)]
        adv = advise(Signature.from_worldmodel(ident), eps)
        self.assertEqual(adv, {})

    def test_candidates_filter(self):
        wm = _wm()
        eps = [
            _ep(wm, "web_upload_rce", False, causes.WAF_BLOCKED,
                repair="sql_injection"),
            _ep(wm, "web_upload_rce", False, causes.WAF_BLOCKED,
                repair="sql_injection"),
        ]
        adv = advise(Signature.from_worldmodel(wm), eps,
                     candidates=["sql_injection"])
        self.assertEqual(set(adv), {"sql_injection"})

    def test_cold_start_hints(self):
        hints = cold_start_hints([causes.WAF_BLOCKED],
                                 ["http_get_page", "unrelated_thing"])
        self.assertIn("http_get_page", hints)
        self.assertNotIn("unrelated_thing", hints)
        self.assertEqual(hints["http_get_page"].source, "hint")

    def test_explain(self):
        wm = _wm()
        eps = [_ep(wm, "web_upload_rce", False, causes.WAF_BLOCKED,
                   repair="sql_injection")]
        info = explain(Signature.from_worldmodel(wm), "sql_injection", eps)
        self.assertEqual(info["similar_situations"], 1)
        self.assertEqual(info["was_repair_for"][causes.WAF_BLOCKED], 1)
        self.assertLess(info["multiplier"], NEUTRAL)


class TestStoreAndFacade(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()
        self.path = os.path.join(self.tmp, "exp.json")

    def test_engagement_scoped_never_touches_disk(self):
        exp = Experience(enabled=False, path=self.path)
        exp.observe(_wm(), "hunt_web", False, reason="blocked by waf",
                    phase="exploit")
        exp.finish()
        self.assertFalse(os.path.exists(self.path))
        self.assertEqual(exp.stats()["episodes"], 1)

    def test_global_mode_persists_and_reloads(self):
        exp = Experience(enabled=True, path=self.path)
        exp.observe(_wm(), "hunt_web", False, reason="blocked by waf",
                    phase="exploit")
        self.assertEqual(exp.finish()["saved"], True)
        self.assertTrue(os.path.exists(self.path))
        with open(self.path, encoding="utf-8") as fh:
            payload = json.load(fh)
        self.assertEqual(len(payload["episodes"]), 1)
        again = Experience(enabled=True, path=self.path)
        self.assertEqual(again.stats()["episodes"], 1)

    def test_reset_clears_memory(self):
        exp = Experience(enabled=True, path=self.path)
        exp.observe(_wm(), "hunt_web", False, reason="timeout")
        exp.reset()
        self.assertEqual(exp.stats()["episodes"], 0)

    def test_sync_is_incremental_and_fills_repairs(self):
        wm = _wm()
        exp = Experience(enabled=False, path=self.path)
        wm.record_action("web_upload_rce", {}, "curl -F f=@x", False,
                         note="blocked by cloudflare waf")
        wm.record_action("sql_injection", {}, "sqlmap -u .../export", True)
        self.assertEqual(exp.sync(wm), 2)
        self.assertEqual(exp.sync(wm), 0)          # idempotent
        eps = exp.store.episodes
        failed = [e for e in eps if not e.ok][0]
        self.assertEqual(failed.cause, causes.WAF_BLOCKED)
        self.assertEqual(failed.repair, "sql_injection")

    def test_sync_survives_world_model_swap(self):
        exp = Experience(enabled=False, path=self.path)
        wm = _wm()
        wm.record_action("scan_tcp", {}, "nmap", True)
        exp.sync(wm)
        exp.sync(_wm())                             # brand new wm
        self.assertEqual(exp.stats()["run"]["episodes"], 0)

    def test_sync_does_not_borrow_repairs_from_old_episodes(self):
        exp = Experience(enabled=True, path=self.path)
        # an episode from a PREVIOUS engagement
        exp.store.record(Episode(
            sig=Signature.from_worldmodel(_wm()).to_dict(),
            phase="exploit", technique="old_move", ok=False,
            cause=causes.WAF_BLOCKED, ts=time.time() - 10_000))
        wm = _wm()
        wm.record_action("fresh_move", {}, "x", True)
        exp.sync(wm)
        self.assertFalse(exp.store.episodes[0].repair)

    def test_multipliers_and_advise(self):
        exp = Experience(enabled=False, path=self.path)
        wm = _wm()
        for _ in range(2):
            exp.observe(wm, "web_upload_rce", False, reason="403 forbidden",
                        repair="sql_injection", phase="exploit")
        mult = exp.multipliers(wm, candidates=["sql_injection",
                                               "web_upload_rce"])
        self.assertLess(mult["sql_injection"], NEUTRAL)
        self.assertGreater(mult["web_upload_rce"], NEUTRAL)
        self.assertIn("sql_injection", exp.advise(wm))

    def test_run_context_reports_repairs(self):
        wm = _wm()
        exp = Experience(enabled=False, path=self.path)
        wm.record_action("web_upload_rce", {}, "curl", False,
                         note="blocked by waf")
        wm.record_action("sql_injection", {}, "sqlmap", True)
        exp.sync(wm)
        ctx = exp.run_context()
        self.assertEqual(ctx["episodes"], 2)
        self.assertEqual(ctx["repairs_learned"], 1)
        self.assertIn(causes.WAF_BLOCKED, ctx["by_cause"])

    def test_finish_prunes_and_promotes(self):
        wm = _wm()

        class _Priors:
            def __init__(self):
                self.calls = []

            def record(self, technique, cls, ok):
                self.calls.append((technique, cls, ok))

            def save(self):
                pass

        exp = Experience(enabled=False, path=self.path)
        for _ in range(6):
            exp.observe(wm, "sql_injection", True, phase="exploit")
        for _ in range(6):
            exp.observe(wm, "hopeless_move", False, reason="403 forbidden",
                        phase="exploit")
        p = _Priors()
        res = exp.finish(priors=p)
        self.assertGreater(res["promoted"], 0)
        self.assertTrue(any(ok for _, _, ok in p.calls))
        self.assertTrue(any(not ok for _, _, ok in p.calls))


class TestConsolidate(unittest.TestCase):
    def test_prune_by_age(self):
        now = time.time()
        old = Episode(technique="a", ts=now - 400 * 86400)
        fresh = Episode(technique="b", ts=now)
        kept = consolidate.prune_by_age([old, fresh], 365.0, now=now)
        self.assertEqual([e.technique for e in kept], ["b"])

    def test_prune_drops_zero_ts(self):
        self.assertEqual(
            consolidate.prune_by_age([Episode(technique="a", ts=0.0)]), [])

    def test_merge_caps_and_keeps_newest(self):
        now = time.time()
        old = [Episode(technique=f"o{i}", ts=now - i) for i in range(10)]
        new = [Episode(technique="n", ts=now + 1)]
        merged = consolidate.merge(old, new, max_episodes=3)
        self.assertEqual(len(merged), 3)
        self.assertIn("n", [e.technique for e in merged])

    def test_dedupe(self):
        ep = Episode(technique="a", ts=1.0)
        self.assertEqual(len(consolidate.dedupe([ep, ep])), 1)

    def test_pattern_table_skips_environmental(self):
        wm = _wm()
        eps = [_ep(wm, "x", False, causes.GATED) for _ in range(5)]
        self.assertEqual(consolidate.pattern_table(eps), {})

    def test_cause_profile(self):
        wm = _wm()
        eps = [_ep(wm, "a", False, causes.WAF_BLOCKED),
               _ep(wm, "b", False, causes.WAF_BLOCKED),
               _ep(wm, "c", True)]
        prof = consolidate.cause_profile(eps)
        self.assertEqual(prof["total_failures"], 2)
        self.assertEqual(prof["by_cause"][causes.WAF_BLOCKED], 2)


if __name__ == "__main__":
    unittest.main()
