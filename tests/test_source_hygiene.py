"""The tree must compile without invalid escape sequences.

Python 3.12 turned ``"\\S"`` and ``"\\["`` into ``SyntaxWarning``; 3.10 and
3.11 only emit a ``DeprecationWarning`` that pytest's default filters hide.
That difference is how 19 invalid escapes survived a green 3.10 run while a
3.12 review saw them as warnings (measured 2026-11-08). The check compiles
every shipped Python file and fails on the warning itself, so the answer does
not depend on which interpreter runs the suite.
"""

from __future__ import annotations

import pathlib
import warnings

ROOT = pathlib.Path(__file__).resolve().parents[1]

#: Directories that ship Python. ``electron/node_modules`` and build output are
#: never ours to compile, and scanning them would only add noise.
SOURCES = ("phantom", "tests", "scripts", "training")
SKIP_PARTS = {"__pycache__", ".venv", "venv", "node_modules", "dist",
              "dist-release", "build", ".git"}


def _python_files():
    for name in SOURCES:
        base = ROOT / name
        if not base.is_dir():
            continue
        for path in sorted(base.rglob("*.py")):
            if SKIP_PARTS & set(path.parts):
                continue
            yield path


def test_no_invalid_escape_sequences():
    problems: list[str] = []
    for path in _python_files():
        source = path.read_text(encoding="utf-8", errors="replace")
        with warnings.catch_warnings(record=True) as caught:
            warnings.simplefilter("always")
            try:
                compile(source, str(path), "exec")
            except SyntaxError as exc:
                problems.append(
                    f"{path.relative_to(ROOT)}:{exc.lineno}: "
                    f"SyntaxError: {exc.msg}")
                continue
        for item in caught:
            message = str(item.message)
            if "invalid escape" in message.lower():
                problems.append(
                    f"{path.relative_to(ROOT)}:{item.lineno}: {message}")

    assert not problems, (
        "invalid escape sequences (use a raw string or double the backslash):\n"
        + "\n".join(problems))
