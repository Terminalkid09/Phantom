"""Social profile URLs are identity targets, not websites to scan."""

import pytest

from phantom.automation.guidance.targets import social_profile_target


@pytest.mark.parametrize("value,expected", [
    ("https://www.instagram.com/mario.rossi/", ("mario.rossi", "instagram")),
    ("https://instagram.com/mario.rossi?hl=it", ("mario.rossi", "instagram")),
    ("https://www.tiktok.com/@mario.rossi", ("mario.rossi", "tiktok")),
    ("https://x.com/mario_rossi", ("mario_rossi", "x")),
    ("https://twitter.com/mario_rossi/status/123", None),
    ("https://github.com/mario-rossi", ("mario-rossi", "github")),
    ("https://t.me/mario_rossi", ("mario_rossi", "telegram")),
    ("https://www.reddit.com/user/mario_rossi", ("mario_rossi", "reddit")),
    ("instagram.com/mario.rossi", ("mario.rossi", "instagram")),
    ("@mario.rossi", ("mario.rossi", "")),
    ("https://instagram.com/p/ABC123", None),
    ("https://example.com/mario", None),
    ("mario.rossi", None),
])
def test_social_profile_target(value, expected):
    assert social_profile_target(value) == expected
