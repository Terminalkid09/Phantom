"""The Dockerfile uses `COPY . .`; local-only artefacts must be ignored.

`.env` was already excluded, but the audit found `.c2_token`, an OSINT dump and
a 14 MB chat transcript were not. Building an image from a working tree with
those files baked them into the build context, even though Git ignored them.
"""
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def test_local_secret_and_engagement_artefacts_are_dockerignored():
    text = (ROOT / ".dockerignore").read_text(encoding="utf-8")
    patterns = {line.strip() for line in text.splitlines()
                if line.strip() and not line.lstrip().startswith("#")}
    required = {
        ".c2_token",
        ".c2_token.*",
        "someuser.txt",
        "comando.txt",
        ".body.ps1",
        "freebuff-chat-*.md",
        ".env",
        ".env.*",
    }
    assert required <= patterns, sorted(required - patterns)


def test_dockerignore_runs_before_the_sensitive_artefacts():
    """A broad later rule must not re-include what these lines exclude."""
    lines = (ROOT / ".dockerignore").read_text(encoding="utf-8").splitlines()
    assert any(line.strip() == ".c2_token" for line in lines)
    assert not any(line.strip() == "!.c2_token" for line in lines)
