"""The Defender note answers a question about the TARGET, not about this box.

Measured 2026-11-03: the deploy caveat was gated on the OPERATOR machine's
``Windefend`` registry key, so deploying to a Windows target from Linux or
macOS printed no warning at all — it vanished exactly in the case where no
local engine could scan the payload. These tests pin the split, and they pin
"unscanned" so it can never be recorded or reported as "approved".
"""

import pytest


def test_windows_target_is_warned_even_without_a_local_scanner():
    from phantom.utils.defender_check import target_defender_note

    note = target_defender_note("windows", local_present=False)

    assert "quarantin" in note.lower()
    assert "unknown" in note.lower(), (
        "an unscanned build must not read as clean")
    assert "Get-MpThreatDetection" in note, (
        "the operator needs the one command that answers 'was it eaten'")


def test_local_scanner_changes_the_sentence_not_the_verdict():
    from phantom.utils.defender_check import target_defender_note

    absent = target_defender_note("windows", local_present=False)
    present = target_defender_note("windows", local_present=True)

    assert absent != present, "the two cases must be distinguishable"
    assert "quarantin" in present.lower()
    assert "unknown" not in present.lower(), (
        "with a scanner the verdict is the preflight's, not 'unknown'")


@pytest.mark.parametrize("platform", ["linux", "macos", "", "android",
                                      "unknown"])
def test_non_windows_targets_get_no_caveat(platform):
    from phantom.utils.defender_check import target_defender_note

    assert target_defender_note(platform, local_present=True) == ""


def test_legacy_note_stays_local_gated(monkeypatch):
    """``defender_note`` keeps answering the OLD question on purpose.

    It is the "is there a Defender HERE that may eat the drop" variant, and
    callers that relied on its silence must keep getting it; the deploy path
    uses ``target_defender_note`` instead.
    """
    from phantom.utils import defender_check

    monkeypatch.setattr(defender_check, "is_defender_present", lambda: False)
    assert defender_check.defender_note("windows") == ""
    monkeypatch.setattr(defender_check, "is_defender_present", lambda: True)
    assert "quarantin" in defender_check.defender_note("Windows").lower()


class _Verdict:
    """Stand-in for ``SandboxVerdict`` (no backend, no scanner, no docker)."""

    def __init__(self, approved, results=(), coverage="", skipped=False,
                 reason=""):
        self.approved = approved
        self.results = list(results)
        self.coverage = coverage
        self._skipped = skipped
        self.reason = reason

    @property
    def skipped(self):
        return self._skipped

    def summary(self):
        if self.skipped:
            return "no sandbox backend available — sample not pre-flighted"
        if self.approved:
            return "approved by all applicable sandbox backends"
        return "denied: " + self.reason


def test_a_skipped_preflight_is_never_an_approval():
    """No backend ran, so nothing was approved — whatever the flag says."""
    from phantom.utils.defender_check import preflight_record

    record = preflight_record(_Verdict(True, skipped=True))

    assert record["scanned"] is False
    assert record["approved"] is False, "nothing ran, so nothing was approved"
    assert "not pre-flighted" in record["summary"]


def test_a_real_approval_is_recorded_as_scanned():
    from phantom.utils.defender_check import preflight_record

    record = preflight_record(_Verdict(True))

    assert (record["scanned"], record["approved"]) == (True, True)


def test_denied_sample_is_scanned_but_not_approved():
    from phantom.utils.defender_check import preflight_record

    record = preflight_record(_Verdict(False,
                                       reason="Defender: threat detected"))

    assert (record["scanned"], record["approved"]) == (True, False)
    assert "threat" in record["summary"].lower(), (
        "the reason must survive into the record, not just the boolean")


def test_a_verdict_that_cannot_report_coverage_is_not_assumed_scanned():
    """Duck-typed stand-in: only an explicit approval counts as scanned."""
    from phantom.utils.defender_check import preflight_record

    class _Bare:
        approved = False

        def summary(self):
            return ""

    record = preflight_record(_Bare())

    assert record["scanned"] is False
    assert record["approved"] is False
