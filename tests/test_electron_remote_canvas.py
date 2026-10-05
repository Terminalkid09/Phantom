"""F-03: source-contract guards for the remote input canvas.

There is no JS unit-test runner in this repo, so — like the allowlist-sync
and viewer-bind tests — these assert on the component SOURCE. They pin the
two behaviours Manus flagged: the cumulative per-keystroke `type` (which the
module writes verbatim, duplicating text on the target) and the optimistic
`streaming` flip that ignored the HTTP status.
"""
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
CANVAS = os.path.join(ROOT, "electron", "src", "components", "RemoteCanvas.tsx")


def _src() -> str:
    with open(CANVAS, "r", encoding="utf-8") as handle:
        return handle.read()


def test_type_is_not_sent_cumulatively_per_keypress():
    src = _src()
    # the old bug: `sendInput(`type ${typeText + e.key}`)` every keypress
    assert "type ${typeText + e.key}" not in src
    assert "$" + "{typeText + e.key}" not in src


def test_streaming_is_gated_on_http_status():
    src = _src()
    # startStream must check the real response status, not truthiness of a
    # value that is always defined
    assert "res.status === 200" in src
    assert "if (res !== undefined)" not in src


def test_text_is_sent_once_on_enter():
    src = _src()
    # Enter flushes the local buffer exactly once, then clears it
    assert "sendInput(`type ${typeText}`)" in src
    assert "setTypeText('')" in src
