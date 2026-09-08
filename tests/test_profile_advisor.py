"""Tests for phantom.utils.profile_advisor."""

import pytest
from phantom.utils.profile_advisor import (
    ProfileAdvisor, ProfileRecipe, RECIPES, Recommendation,
    _tag_match, get_advisor,
)


class TestTagMatch:
    def test_exact_match(self):
        assert _tag_match(["windows"], ["windows"]) == 2
        assert _tag_match(["windows", "iis"], ["windows", "iis"]) == 4

    def test_wildcard_matches_anything(self):
        assert _tag_match(["*"], ["windows"]) == 1
        assert _tag_match(["*"], []) == 1
        assert _tag_match(["*"], ["linux", "nginx"]) == 1

    def test_no_match(self):
        assert _tag_match(["windows"], ["linux"]) == 0
        assert _tag_match(["iis", "exchange"], ["apache", "nginx"]) == 0

    def test_partial_match(self):
        score = _tag_match(["windows", "iis"], ["windows"])
        # "windows" matches (+2), "iis" doesn't (0) -> 2
        assert score == 2


class TestProfileAdvisor:
    def setup_method(self):
        self.advisor = ProfileAdvisor(history_path="/tmp/test_profile_history.json")

    def teardown_method(self):
        import os
        try:
            os.unlink("/tmp/test_profile_history.json")
        except OSError:
            pass

    def test_recommend_windows_corporate(self):
        recs = self.advisor.recommend(
            os_hint="Windows Server 2019",
            services=["Microsoft-IIS", "Microsoft-Exchange"],
            risk_level="default",
            env="corporate",
            limit=5,
        )
        assert len(recs) >= 1
        # Top should be ms_corporate or sharepoint_o365 for Windows+IIS+Exchange
        top_family = recs[0].recipe.family
        assert top_family in ("ms_corporate", "sharepoint_o365", "generic_cdn")

    def test_recommend_linux_api(self):
        recs = self.advisor.recommend(
            os_hint="Ubuntu 22.04",
            services=["nginx", "Django"],
            risk_level="default",
            env="cloud",
            limit=5,
        )
        assert len(recs) >= 1
        top_family = recs[0].recipe.family
        assert top_family in ("linux_devops", "wordpress_cms", "generic_cdn")

    def test_recommend_stealth_any_os(self):
        """Stealth should prefer generic_cdn which has risk_tag 'stealth'."""
        recs = self.advisor.recommend(
            os_hint="Unknown OS",
            services=["unknown-service"],
            risk_level="stealth",
            limit=5,
        )
        # generic_cdn should be top since it's the only one with stealth tag
        families = [r.recipe.family for r in recs]
        assert "generic_cdn" in families

    def test_recommend_macos(self):
        recs = self.advisor.recommend(
            os_hint="macOS Sonoma",
            services=["apache"],
            risk_level="default",
            limit=5,
        )
        top_family = recs[0].recipe.family
        assert top_family in ("apple_macos", "generic_cdn")

    def test_recommend_android(self):
        recs = self.advisor.recommend(
            os_hint="Android 14",
            risk_level="stealth",
            limit=5,
        )
        top_family = recs[0].recipe.family
        assert top_family in ("android_mobile", "generic_cdn")

    def test_recommend_wordpress(self):
        recs = self.advisor.recommend(
            os_hint="Linux",
            services=["apache", "wordpress"],
            risk_level="aggressive",
            limit=5,
        )
        top_family = recs[0].recipe.family
        assert top_family in ("wordpress_cms", "generic_cdn")

    def test_recommend_no_data(self):
        """No target data → should still return recommendations."""
        recs = self.advisor.recommend(
            os_hint="",
            services=[],
            risk_level="default",
            limit=3,
        )
        assert len(recs) >= 1

    def test_scores_are_normalized(self):
        recs = self.advisor.recommend(
            os_hint="windows",
            services=["iis"],
            limit=10,
        )
        for r in recs:
            assert 0 <= r.score <= 100

    def test_recommendation_has_reasoning(self):
        recs = self.advisor.recommend(os_hint="windows", limit=1)
        assert len(recs[0].reasoning) > 0
        assert "OS:" in recs[0].reasoning

    def test_record_effectiveness(self):
        self.advisor.record_effectiveness("generic_cdn", success=True)
        self.advisor.record_effectiveness("generic_cdn", success=True)
        self.advisor.record_effectiveness("generic_cdn", success=False)

        # After 3 trials (2 wins), Beta mean = (2+1)/(3+2) = 3/5 = 0.6
        score = self.advisor._beta_score("generic_cdn")
        assert abs(score - 0.6) < 0.01

        # Re-load to check persistence
        advisor2 = ProfileAdvisor(history_path="/tmp/test_profile_history.json")
        score2 = advisor2._beta_score("generic_cdn")
        assert abs(score2 - 0.6) < 0.01

    def test_history_boosts_scores(self):
        """A family with good history should get a bonus."""
        recs_before = self.advisor.recommend(os_hint="windows", limit=10)
        before_scores = {r.recipe.family: r.score for r in recs_before}

        # Simulate many successful engagements with ms_corporate
        for _ in range(100):
            self.advisor.record_effectiveness("ms_corporate", success=True)

        recs_after = self.advisor.recommend(os_hint="windows", limit=10)
        after_scores = {r.recipe.family: r.score for r in recs_after}

        # ms_corporate should have higher score after 100 wins
        assert after_scores.get("ms_corporate", 0) >= before_scores.get("ms_corporate", 0)

    def test_generate_profile_produces_valid_json(self):
        import json
        profile = self.advisor.generate_profile(
            os_hint="windows",
            services=["iis"],
            risk_level="default",
        )
        # validate structure
        assert "family" in profile
        assert "profile" in profile
        assert "get_paths" in profile["profile"]
        assert "post_paths" in profile["profile"]
        assert "user_agents" in profile["profile"]
        assert "sleep_ms" in profile["profile"]
        assert len(profile["profile"]["get_paths"]) > 0

        # validate it can be JSON-serialized
        dumped = json.dumps(profile)
        assert len(dumped) > 0

    def test_internal_ip_prefers_corporate(self):
        """10.x.x.x IP should boost corporate blends."""
        recs = self.advisor.recommend(
            os_hint="windows",
            target_ip="10.0.0.5",
            limit=5,
        )
        # ms_corporate or sharepoint_o365 should be high-ranked
        top_families = [r.recipe.family for r in recs[:2]]
        # At least one corporate family in top 2
        has_corp = any(f in ("ms_corporate", "sharepoint_o365") for f in top_families)
        assert has_corp

    def test_parse_os(self):
        assert "windows" in ProfileAdvisor._parse_os("Windows Server 2022")
        assert "linux" in ProfileAdvisor._parse_os("Ubuntu 22.04 LTS")
        assert "macos" in ProfileAdvisor._parse_os("Darwin 23.4.0")
        assert "android" in ProfileAdvisor._parse_os("Android 14")
        assert "macos" in ProfileAdvisor._parse_os("iPhone iOS 18")

    def test_parse_services(self):
        result = ProfileAdvisor._parse_services(["Microsoft-IIS", "nginx/1.24.0"])
        assert "iis" in result or "microsoft" in result
        assert "nginx" in result

    def test_all_recipes_have_required_fields(self):
        for recipe in RECIPES:
            assert recipe.family
            assert recipe.description
            assert len(recipe.get_paths) >= 1
            assert len(recipe.post_paths) >= 1
            assert len(recipe.user_agents) >= 1
            assert recipe.sleep_ms >= 1000
            assert 0 <= recipe.jitter <= 100
            assert recipe.os_tags
            assert recipe.service_tags
            assert recipe.risk_tags

    def test_get_advisor_singleton(self):
        a1 = get_advisor()
        a2 = get_advisor()
        assert a1 is a2


class TestRecommendBest:
    def test_with_data(self):
        advisor = ProfileAdvisor(history_path="/tmp/test_best.json")
        rec = advisor.recommend_best(
            os_hint="Windows Server 2019",
            services=["Microsoft-IIS"],
            risk_level="default",
        )
        assert rec.score > 0
        assert rec.recipe.family in ("ms_corporate", "sharepoint_o365", "generic_cdn")

    def test_no_data_fallback(self):
        advisor = ProfileAdvisor(history_path="/tmp/test_best2.json")
        rec = advisor.recommend_best(os_hint="", risk_level="default")
        assert rec.score > 0
        assert rec.recipe.family == "generic_cdn"