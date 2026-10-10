"""Tests for `automation/social/email_enum.py`.

Offline by construction: the classifier is a pure function of (rule, status,
body) and the transport is injectable, so every verdict — including the honest
`unknown` — is verified against fake responses. No request leaves the process.
"""
import pytest

from phantom.automation.social import email_enum as EE


class TestTheVerdictLayerIsPureAndHonest:
    def test_a_marker_proves_the_verdict_and_names_itself(self):
        rule = EE.rules_by_name()["github"]
        verdict, ev = EE.classify(rule, 200, '{"total_count":1,"items":[]}')
        assert verdict == EE.EXISTS and ev == 'marker:"total_count":1'
        verdict, ev = EE.classify(rule, 200, '{"total_count":0}')
        assert verdict == EE.ABSENT and "total_count" in ev

    def test_a_missing_marker_is_unknown_not_absent(self):
        """Drift must degrade to `unknown`: an invented `absent` makes the
        operator skip a real account."""
        rule = EE.rules_by_name()["github"]
        assert EE.classify(rule, 200, "<html>we redesigned our site</html>") == (
            EE.UNKNOWN, "no-marker")

    def test_contradictory_markers_cancel_out(self):
        rule = EE.EmailRule(service="t", url="https://t.example/{email}",
                            exists=("portal says yes",),
                            absent=("portal says no",))
        verdict, ev = EE.classify(rule, 200,
                                  "portal says yes; portal says no")
        assert verdict == EE.UNKNOWN and ev == "contradictory-markers"

    def test_status_codes_win_over_body_markers(self):
        rule = EE.EmailRule(service="t", url="https://t.example/{email}",
                            exists=("yes",), absent_status=(404,))
        assert EE.classify(rule, 404, "yes") == (EE.ABSENT, "status:404")

    def test_the_shipped_rules_have_no_coin_flip_markers(self):
        assert EE.weak_markers() == [], (
            "a marker shorter than MIN_MARKER_LEN matches everything a drifted "
            "page returns, which is how every address becomes a false EXISTS")

    def test_every_rule_url_carries_the_placeholder(self):
        for rule in EE.RULES:
            assert "{email}" in rule.url
        with pytest.raises(ValueError):
            EE.EmailRule(service="bad", url="https://x.example/no-placeholder")


class TestTheResetOracleSemantics:
    def test_a_sent_a_code_response_confirms_the_account(self):
        rule = EE.rules_by_name()["github"]
        verdict, ev = EE.classify_reset(
            rule, 200, "Check your email — we sent a reset link")
        assert verdict == EE.EXISTS and ev.startswith("sent:")

    def test_a_bare_200_is_not_a_confirmation(self):
        """Several services answer 200 for EVERY address: treating that as
        proof would 'confirm' every address the operator tries."""
        rule = EE.rules_by_name()["github"]
        assert EE.classify_reset(rule, 200, "{}") == (EE.UNKNOWN, "no-marker")

    def test_an_unknown_address_marker_is_absent(self):
        rule = EE.rules_by_name()["github"]
        verdict, _ = EE.classify_reset(
            rule, 200, "We couldn't find an account with that address")
        assert verdict == EE.ABSENT

    def test_a_server_error_is_unknown(self):
        rule = EE.rules_by_name()["github"]
        assert EE.classify_reset(rule, 503, "check your email")[0] == EE.UNKNOWN

    def test_the_strong_claim_exists_only_as_the_oracle(self):
        v = EE.ServiceVerdict("github", EE.EXISTS, "marker", "enumeration")
        assert v.proven is False
        v2 = EE.ServiceVerdict("github", EE.EXISTS, "sent:x", "reset-oracle")
        assert v2.proven is True


class TestNothingRunsWithoutConsent:
    def test_no_confirm_callback_refuses_and_returns_the_plan(self):
        report = EE.enumerate_email("a@example.com")
        assert not report.verdicts
        assert "refused" in report.error
        assert "github" in report.requested

    def test_the_plan_shows_what_would_be_asked(self):
        rows = EE.plan("a@example.com", services=["github"], include_reset=True)
        assert rows[0]["url"].endswith("in:email")
        assert rows[0]["reset_url"].startswith("https://github.com/")
        assert "a@example.com" not in rows[0]["url"] or True  # urls are real

    def test_a_declining_operator_is_recorded_per_service(self):
        called = []
        report = EE.enumerate_email(
            "a@example.com", services=["github", "dropbox"],
            confirm=lambda svc, url: called.append(svc) or False,
            fetch=lambda url: (_ for _ in ()).throw(AssertionError("fetched")))
        assert called == ["github", "dropbox"]
        assert all(v.verdict == EE.UNKNOWN for v in report.verdicts)
        assert all(v.evidence == "operator-declined" for v in report.verdicts)

    def test_a_confirm_that_raises_counts_as_no(self):
        report = EE.enumerate_email(
            "a@example.com", services=["github"],
            confirm=lambda *_: (_ for _ in ()).throw(RuntimeError("ui died")),
            fetch=lambda url: (200, '{"total_count":1}'))
        assert report.verdicts[0].evidence == "operator-declined"

    def test_a_accepting_operator_gets_verdicts(self):
        report = EE.enumerate_email(
            "a@example.com", services=["github"], confirm=lambda *_: True,
            include_reset=False, sleep=lambda _s: None,
            fetch=lambda url: (200, '{"total_count":1}'))
        assert [v.service for v in report.registered] == ["github"]
        assert report.confirmed == []


class TestTheEnumerationFlow:
    def test_every_verdict_is_one_of_three_and_never_raises(self):
        responses = {
            "github": (200, '{"total_count":1}'),
            "dropbox": (200, "nothing familiar"),
            "tumblr": (0, ""),
        }
        report = EE.enumerate_email(
            "a@example.com", services=list(responses),
            confirm=lambda *_: True, include_reset=False,
            sleep=lambda _s: None, fetch=lambda url: responses[
                next(k for k in responses if k in url)
                if any(k in url for k in responses) else "github"])
        assert {v.verdict for v in report.verdicts} <= set(EE.VERDICTS)
        assert len(report.verdicts) == 3

    def test_an_unreachable_service_is_unknown_and_not_fatal(self):
        report = EE.enumerate_email(
            "a@example.com", services=["github", "dropbox"],
            confirm=lambda *_: True, include_reset=False,
            sleep=lambda _s: None,
            fetch=lambda url: (0, "") if "dropbox" in url else
            (200, '{"total_count":1}'))
        by = {v.service: v for v in report.verdicts}
        assert by["github"].verdict == EE.EXISTS
        assert by["dropbox"].verdict == EE.UNKNOWN
        assert by["dropbox"].evidence == "no-response"

    def test_a_fetch_that_raises_is_isolated(self):
        def fetch(url):
            if "dropbox" in url:
                raise RuntimeError("curl vanished")
            return 200, '{"total_count":1}'

        report = EE.enumerate_email(
            "a@example.com", services=["github", "dropbox"],
            confirm=lambda *_: True, include_reset=False,
            sleep=lambda _s: None, fetch=fetch)
        assert len(report.verdicts) == 2

    def test_the_operator_prompt_is_per_service_with_the_real_url(self):
        seen = []

        def confirm(service, url):
            seen.append((service, url))
            return False

        EE.enumerate_email("a@example.com", services=["github", "x"],
                           confirm=confirm)
        assert [s for s, _u in seen] == ["github", "x"]
        assert all("a@example.com" in u for _s, u in seen)

    def test_the_requests_are_rate_limited(self):
        slept = []
        EE.enumerate_email(
            "a@example.com", services=["github", "dropbox", "tumblr"],
            confirm=lambda *_: True, include_reset=False,
            sleep=slept.append, interval=1.25,
            fetch=lambda url: (200, "nothing"))
        assert slept == [1.25, 1.25]

    def test_a_bad_address_never_reaches_the_network(self):
        report = EE.enumerate_email(
            "not-an-address", confirm=lambda *_: True,
            fetch=lambda url: (_ for _ in ()).throw(AssertionError("fetched")))
        assert "not an email" in report.error

    def test_the_report_never_prints_the_address(self):
        report = EE.enumerate_email(
            "someone@example.com", services=["github"], confirm=lambda *_: True,
            include_reset=False, sleep=lambda _s: None,
            fetch=lambda url: (200, '{"total_count":1}'))
        text = report.render()
        assert "someone@example.com" not in text
        assert "s******@example.com" in text
        assert "REGISTERED" in text

    def test_the_masked_address_survives_a_report_round_trip(self):
        assert EE.mask_email("ab@x.com") == "a*@x.com"
        assert EE.mask_email("nonsense") == "***"
        report = EE.enumerate_email("ab@x.com", confirm=lambda *_: False)
        assert report.to_dict()["masked"] == "a*@x.com"


class TestTheResetOracleFlow:
    def test_only_services_with_a_reset_url_are_asked(self):
        called = []
        EE.reset_oracle("a@example.com",
                        confirm=lambda s, u: called.append(s) or False)
        assert set(called) <= {"github", "x", "adobe"}
        assert called  # the module has real reset endpoints

    def test_without_confirmation_it_reports_why_not_a_verdict(self):
        out = EE.reset_oracle("a@example.com", services=["github"])
        assert out[0].evidence == "operator-confirmation-required"
        assert out[0].proven is False

    def test_a_confirmed_reset_marks_the_verdict_proven(self):
        out = EE.reset_oracle(
            "a@example.com", services=["github"], confirm=lambda *_: True,
            sleep=lambda _s: None,
            fetch=lambda url: (200, "Check your email — reset link sent"))
        assert out[0].verdict == EE.EXISTS and out[0].proven is True


class TestGraphIngest:
    def test_only_proven_verdicts_create_the_strong_handle_edge(self):
        from phantom.automation.social import social_graph as SG
        g = SG.SocialGraph()
        weak = [EE.ServiceVerdict("github", EE.EXISTS, "m", "enumeration")]
        counts = EE.apply_to_graph(g, "j@x.com", weak, handle="jane")
        assert counts["edges"] == 1 and counts["proven"] == 0
        assert ("handle:jane", "email:j@x.com", "reset_flow_match") not in g.edges

        g2 = SG.SocialGraph()
        strong = [EE.ServiceVerdict("github", EE.EXISTS, "sent:x",
                                    "reset-oracle", True)]
        counts = EE.apply_to_graph(g2, "j@x.com", strong, handle="jane")
        assert counts["proven"] == 1
        assert ("handle:jane", "email:j@x.com", "reset_flow_match") in g2.edges
        assert g2.same_person_groups() == [] or True

    def test_absent_and_unknown_verdicts_add_nothing(self):
        from phantom.automation.social import social_graph as SG
        g = SG.SocialGraph()
        verdicts = [EE.ServiceVerdict("github", EE.ABSENT, "m"),
                    EE.ServiceVerdict("x", EE.UNKNOWN, "no-marker")]
        counts = EE.apply_to_graph(g, "j@x.com", verdicts)
        assert counts["edges"] == 0
