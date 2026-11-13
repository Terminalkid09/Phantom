"""Losing the crash-loop guard must be SAID, not swallowed.

`auto_resume._write_counter` persists the restart budget — the thing that makes
an unattended relaunch stop with a reason instead of looping. Its failure path
was a silent `try/except: pass`: on a read-only or full disk the next process
read the OLD count and could relaunch a crash loop past its budget, and nothing
anywhere said so (audit §6.5.3).

The write stays best-effort (it must never kill a running engagement), but the
failure is now announced through the notifier, with the number of relaunches
that are unaccounted for.
"""
import io
import os
import sys

from phantom.utils import auto_resume as AR


def _capture(fn) -> str:
    buffer = io.StringIO()
    original = sys.stdout
    sys.stdout = buffer
    try:
        fn()
    finally:
        sys.stdout = original
    return " ".join(buffer.getvalue().split())


def _squash(text: str) -> str:
    """``text`` with EVERY whitespace character removed.

    The renderer (rich) folds a line at the console width, and the fold lands
    wherever the column happens to fall: on the CI runner the path
    ``/tmp/pytest-of-runner/pytest-0/test_a_broken_write_warns_with0/readonly/
    auto_restarts.json`` is long enough that it broke INSIDE the file name
    (``auto_re`` / ``starts.json``), so an assertion on the contiguous name
    failed there and passed on a Windows disk, where the break fell elsewhere.
    Where a line wraps is the renderer's business; that the warning NAMES the
    file and the count is the assertion, so the comparison happens on
    whitespace-free text.
    """
    return "".join(str(text).split())


def test_a_broken_write_warns_with_the_path_and_the_count(tmp_path,
                                                          monkeypatch):
    target = tmp_path / "readonly" / "auto_restarts.json"

    def refuse(*args, **kwargs):
        raise OSError("read-only file system")

    monkeypatch.setattr("builtins.open", refuse)
    text = _squash(_capture(lambda: AR._write_counter(str(target), 3)))
    assert _squash("restart counter NOT persisted") in text
    assert "auto_restarts.json" in text
    assert _squash("read-only file system") in text
    assert _squash("is 3") in text, "the in-memory count must be reported"


def test_a_broken_write_never_raises_into_the_runner(tmp_path, monkeypatch):
    """A read-only disk must not take down a live engagement."""
    monkeypatch.setattr("builtins.open",
                        lambda *a, **kw: (_ for _ in ()).throw(
                            OSError("disk full")))
    AR._write_counter(str(tmp_path / "auto_restarts.json"), 1)   # no raise


def test_a_working_write_stays_quiet(tmp_path):
    path = tmp_path / "auto_restarts.json"
    text = _capture(lambda: AR._write_counter(str(path), 2))
    assert text == "", "a successful write is not a warning"
    import json
    assert json.loads(path.read_text(encoding="utf-8"))["restarts"] == 2


def test_the_counter_still_gates_a_crash_loop(tmp_path):
    """The behaviour the guard exists for: read back → budget respected."""
    path = os.path.join(str(tmp_path), "auto_restarts.json")
    AR._write_counter(path, 3)
    assert AR._read_counter(path) == 3
    AR._write_counter(path, 0)                 # note_success clears it
    assert AR._read_counter(path) == 0
