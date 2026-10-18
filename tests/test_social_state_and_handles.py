"""The platform-state classifier and the handle filter, locked to LIVE evidence.

Every expectation here was first observed on the wire (2026-10-16) by fetching
a KNOWN-REAL handle and a handle that cannot exist on each platform:

    telegram   real 10 944 B  "tgme_page_title" present   -> public
               fake  9 938 B  "you can contact" present   -> missing
    github     real 213 073 B "itemprop=\"name\"" present -> public
               fake      9 B  "not found"                 -> missing
    x          real 167 955 B (no marker)                 -> public
               fake 36 957 B  "user profile not found"    -> missing
    reddit     real == fake (blocked page, no marker)     -> unknown
    tiktok     real == fake (app shell, i18n string)      -> unknown
    instagram  real == fake (byte-identical shell)        -> unknown

Before the fix the classifier said `private` for a real Telegram account and
for a real GitHub account (their "private" markers are PRESENCE markers and a
URL fragment), `missing` for a real TikTok account, and `public conf=1.00` for
handles that DO NOT EXIST on X, Reddit and Instagram — which is how the
identity graph came back with seven Instagram "variant accounts" that were
nothing but the platform's universal page shell.
"""
import unittest
from unittest import mock

from phantom.automation.social import recon as R

SHELL_BIG = "<html><body>" + ("x" * 5000) + "</body></html>"


def _vote_with(page_body, platform="instagram", username="somebody"):
    """Run `_state_vote` against a canned page, no network."""
    with mock.patch.object(R, "_fetch", return_value=page_body):
        return R._state_vote(username, platform)


class TestStateClassifier(unittest.TestCase):

    def test_telegram_present_page_is_public_not_private(self):
        page = '<html><head><meta property="og:title" content="Durov">' \
               "</head><body><div class=tgme_page_title>Durov</div>" \
               "<a>View in Telegram</a></body></html>"
        state, conf, _ = _vote_with(page, "telegram", "durov")
        self.assertEqual(state, "public")
        self.assertGreaterEqual(conf, 0.5)

    def test_telegram_absent_page_is_missing(self):
        page = ('<html><head><title>Telegram: Contact @nobody</title></head>'
                '<body><div class="tgme_page_additional">If you have '
                'Telegram, you can contact @nobody right away.</div>'
                "</body></html>")
        state, _, _ = _vote_with(page, "telegram", "nobody")
        self.assertEqual(state, "missing")

    def test_github_present_page_is_public_despite_404_assets(self):
        """A real GitHub page embeds a bare '404' (asset URLs) — the private
        marker table carried it and voted a real account `private`."""
        page = ('<html><head><link href="https://x/404.css"></head>'
                '<body><span itemprop="name">Linus</span>'
                '<div id="user-profile-frame"></div></body></html>')
        state, _, _ = _vote_with(page, "github", "torvalds")
        self.assertEqual(state, "public")

    def test_github_absent_page_is_missing(self):
        state, _, _ = _vote_with("Not Found", "github", "nobody")
        self.assertEqual(state, "missing")

    def test_x_absent_page_is_missing(self):
        page = ('<html><head><title>User profile not found - X</title></head>'
                '<body>Hmm...this page doesn\u2019t exist. Try searching for '
                "something else. The account may be private, deleted, or only "
                "available on the app.</body></html>")
        state, _, _ = _vote_with(page, "x", "nobody")
        self.assertEqual(state, "missing")

    def test_x_present_page_is_public(self):
        state, _, _ = _vote_with(SHELL_BIG, "x", "jack")
        self.assertEqual(state, "public")

    def test_instagram_shell_is_unknown_never_public(self):
        """The same shell comes back for a handle that cannot exist, so a
        `public` verdict there is a claim nothing supports."""
        for handle in ("polo_1300__", "zzqx_nonexistent_probe"):
            state, _, _ = _vote_with(SHELL_BIG, "instagram", handle)
            self.assertEqual(state, "unknown")

    def test_tiktok_shell_with_the_i18n_string_is_unknown(self):
        page = SHELL_BIG + '"account_deleted_toast_message":"couldn\'t find ' \
                           'this account."'
        state, _, _ = _vote_with(page, "tiktok", "somebody")
        self.assertEqual(state, "unknown")

    def test_reddit_blocked_page_is_unknown(self):
        state, _, _ = _vote_with(SHELL_BIG + "blocked", "reddit", "spez")
        self.assertEqual(state, "unknown")

    def test_reddit_json_profile_is_public(self):
        page = '{"data": {"name": "spez", "total_karma": 12345}}'
        state, _, _ = _vote_with(page, "reddit", "spez")
        self.assertEqual(state, "public")

    def test_a_failed_fetch_is_unknown_not_missing(self):
        """`missing` is a claim about the world; an empty fetch means we did
        not read the world (timeout, TLS, block)."""
        state, _, _ = _vote_with("", "github", "torvalds")
        self.assertEqual(state, "unknown")


class TestHandleFilter(unittest.TestCase):

    def test_css_and_js_directives_are_not_handles(self):
        for junk in ("media", "media.css", "__PURE__", "import", "font-face",
                     "keyframes", "supports", "tailwind", "gmail.com"):
            self.assertFalse(R._is_real_handle(junk), junk)

    def test_real_handles_pass(self):
        for good in ("polo_1300__", "polo.1300..", "torvalds", "durov",
                     "a_b.c"):
            self.assertTrue(R._is_real_handle(good), good)

    def test_github_style_filename_is_not_a_handle(self):
        self.assertFalse(R._is_real_handle("main.js"))
        self.assertFalse(R._is_real_handle("style.css"))

    def test_leading_underscores_do_not_hide_a_directive(self):
        self.assertFalse(R._is_real_handle("_media"))
        self.assertFalse(R._is_real_handle("__pure__"))


if __name__ == "__main__":
    unittest.main()
