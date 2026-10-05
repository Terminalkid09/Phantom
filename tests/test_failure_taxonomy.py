"""Typed failure classification (brief §12.5)."""
from phantom.automation import failure_taxonomy as ft


class _Res:
    def __init__(self, error="", timed_out=False, returncode=0):
        self.error = error
        self.timed_out = timed_out
        self.returncode = returncode


def test_timeout_wins():
    assert ft.classify_failure(_Res(timed_out=True)) == ft.TIMEOUT


def test_scope_denied():
    assert ft.classify_failure(_Res(error="out of scope: 10.0.0.5")) \
        == ft.SCOPE_DENIED
    assert ft.classify_failure(_Res(error="no engagement scope defined")) \
        == ft.SCOPE_DENIED


def test_tool_missing():
    assert ft.classify_failure(
        _Res(error="tool 'nmap' not installed")) == ft.TOOL_MISSING


def test_policy_denied():
    assert ft.classify_failure(_Res(error="refused: unsafe command")) \
        == ft.POLICY_DENIED


def test_auth_failed():
    assert ft.classify_failure(_Res(error="403 Forbidden")) == ft.AUTH_FAILED


def test_network_unreachable():
    assert ft.classify_failure(_Res(error="connection refused")) \
        == ft.NETWORK_UNREACHABLE


def test_nonzero_exit_without_specific_text_is_a_crash():
    assert ft.classify_failure(_Res(returncode=1)) == ft.TOOL_CRASHED


def test_silent_result_is_unknown():
    assert ft.classify_failure(_Res()) == ft.UNKNOWN
    assert ft.classify_failure(None) == ft.UNKNOWN


def test_partial_and_parse():
    assert ft.classify_failure(_Res(error="partial output after timeout "
                                     "salvage")) in (ft.PARTIAL_RESULT, ft.TIMEOUT)
    assert ft.classify_failure(_Res(error="parse failed: bad json")) \
        == ft.PARSE_FAILED


def test_never_raises_on_garbage():
    assert ft.classify_failure(object()) == ft.UNKNOWN
    assert ft.classify_failure(_Res(), error=None) == ft.UNKNOWN


def test_every_kind_is_declared():
    # a classified value must always be a declared kind
    for probe in ("out of scope", "not installed", "refused", "401",
                  "timeout", "refused", "parse", "partial", "stale",
                  "contradict", "cancel", "whatever"):
        assert ft.classify_failure(_Res(error=probe)) in ft.ALL_KINDS
