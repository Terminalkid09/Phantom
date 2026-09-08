"""Tests for the real-video picker used by the IP-grabber share links."""
import unittest

from phantom.automation.social.video_picker import (
    pick_video,
    sanitize_query,
    topic_for,
)


class TestTopicFor(unittest.TestCase):

    def test_football_from_bio(self):
        self.assertEqual(topic_for("big serie a fan, calcio every sunday"),
                         "football")

    def test_gaming_keywords(self):
        self.assertEqual(topic_for("minecraft and fortnite nights"),
                         "gaming")

    def test_tech_bio(self):
        self.assertEqual(topic_for("python developer, linux user"), "tech")

    def test_default_music(self):
        self.assertEqual(topic_for(""), "music")
        self.assertEqual(topic_for("random words here"), "music")


class TestPickVideo(unittest.TestCase):

    def test_ytdlp_result_wins_when_search_works(self):
        def fake_fetch(query):
            self.assertIn("football", query)
            return [{"id": "abc123", "title": "Best goals",
                     "channel": "Some Channel"}]
        video = pick_video(interests="football fan", fetcher=fake_fetch)
        self.assertEqual(video["id"], "abc123")

    def test_explicit_query_beats_interests(self):
        seen = []

        def fake_fetch(query):
            seen.append(query)
            return [{"id": "xyz", "title": "T", "channel": "C"}]
        pick_video(interests="cooking", query="funny cats", fetcher=fake_fetch)
        self.assertIn("funny cats", seen[0])

    def test_curated_fallback_when_search_empty(self):
        video = pick_video(interests="football", fetcher=lambda q: [], seed=1)
        self.assertEqual(video["id"], "pRpeEdMmmQ0")  # real Waka Waka upload

    def test_curated_fallback_music_default(self):
        video = pick_video(interests="", fetcher=lambda q: [], seed=0)
        self.assertTrue(video["id"])
        self.assertTrue(video["title"])
        self.assertTrue(video["channel"])

    def test_deterministic_with_seed(self):
        a = pick_video(interests="music", fetcher=lambda q: [], seed=42)
        b = pick_video(interests="music", fetcher=lambda q: [], seed=42)
        self.assertEqual(a, b)

    def test_fetcher_exception_degrades_to_catalog(self):
        def boom(q):
            raise RuntimeError("no yt-dlp")
        video = pick_video(interests="music", fetcher=boom)
        self.assertTrue(video["id"])


class TestSanitizeQuery(unittest.TestCase):

    def test_plain_text_passes(self):
        self.assertEqual(sanitize_query("funny cat compilation"),
                         "funny cat compilation")

    def test_urls_and_braces_stripped(self):
        # URLs, braces and other metacharacters are dropped: the query
        # cannot carry placeholder-injection or shell metacharacters
        out = sanitize_query("http://evil.com {x} drop table")
        self.assertNotIn(":", out)
        self.assertNotIn("/", out)
        self.assertNotIn("{", out)
        self.assertNotIn("}", out)
        self.assertIn("evil.com x drop table", out)

    def test_bounded_length(self):
        self.assertLessEqual(len(sanitize_query("x" * 500)), 80)


if __name__ == "__main__":
    unittest.main()
