"""One application version, read from one place.

The defect this pins: the Electron About card printed a HARDCODED ``3.7.3``
while ``package.json``, ``setup.py`` and the README badge all said ``3.0.0``,
and the same screen showed two different numbers at once (title bar from
``package.json``, footer from a literal). ``3.7.3`` is a version nothing in the
tree ever declared, so whichever number an operator quoted in a report was
wrong half the time.

The rule is the one ``electron/src/hooks/useAppVersion.ts`` states: the number
lives in ONE place and every surface reads it. This test fails if a literal
comes back.
"""

import json
import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

_SETUP_RE = re.compile(r'__version__\s*=\s*"([^"]+)"')
_BADGE_RE = re.compile(r"badge/version-([0-9][^-)]*)-")
#: A semver-looking literal printed as text by a component: the shape the About
#: card used (``<span ...>3.7.3</span>``). The version must come from the hook.
_LITERAL_IN_UI_RE = re.compile(r">\s*\d+\.\d+\.\d+\s*<")


def _setup_version() -> str:
    """The ONE declaration (``phantom/version.py``), not setup.py's copy."""
    match = _SETUP_RE.search(
        (ROOT / "phantom" / "version.py").read_text(encoding="utf-8"))
    return match.group(1) if match else ""


def _package_version() -> str:
    data = json.loads((ROOT / "electron" / "package.json").read_text(encoding="utf-8"))
    return str(data.get("version") or "")


def test_the_declared_version_is_the_same_everywhere():
    setup_version = _setup_version()
    package_version = _package_version()
    assert setup_version, "phantom/version.py declares no version"
    setup_py = (ROOT / "setup.py").read_text(encoding="utf-8")
    assert "version=_version()" in setup_py, (
        "setup.py must READ the version, not hardcode a second number")
    assert package_version, "electron/package.json declares no version"
    assert setup_version == package_version, (
        f"setup.py says {setup_version!r} and package.json says "
        f"{package_version!r}: an operator quoting either is wrong half the time")


def test_the_readme_badge_matches_the_declared_version():
    badge = _BADGE_RE.search((ROOT / "README.md").read_text(encoding="utf-8"))
    assert badge, "README carries no version badge"
    assert badge.group(1) == _setup_version(), (
        f"README badge says {badge.group(1)!r}, the tree says {_setup_version()!r}")


def test_no_component_prints_a_hardcoded_version():
    """A rendered semver literal is the regression. An occurrence inside a
    COMMENT or a docstring is the opposite — it is the note that explains why
    the literal is forbidden — so comments are stripped before scanning."""
    offenders = []
    for path in (ROOT / "electron" / "src").rglob("*.tsx"):
        try:
            lines = path.read_text(encoding="utf-8").splitlines()
        except (OSError, UnicodeDecodeError):
            continue
        code = []
        in_block = False
        for line in lines:
            stripped = line.strip()
            if in_block:
                if "*/" in stripped:
                    in_block = False
                continue
            if stripped.startswith("/*"):
                in_block = "*/" not in stripped
                continue
            if stripped.startswith("//") or stripped.startswith("*"):
                continue
            code.append(line)
        if _LITERAL_IN_UI_RE.search("\n".join(code)):
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, (
        "these components render a hardcoded version instead of reading it: "
        f"{offenders}")


def test_the_about_card_reads_the_version_instead_of_printing_one():
    source = (ROOT / "electron" / "src" / "components" / "SettingsPanel.tsx") \
        .read_text(encoding="utf-8")
    assert "useAppVersion" in source, (
        "SettingsPanel must read the version from the hook, not from a literal")

def test_python_surfaces_read_the_same_version():
    """The AUTO banner and the report footer are version surfaces too.

    The banner said v3.5.0 while package metadata said 3.0.0; the Electron
    About card is covered above, but the first screen an operator sees and
    the report they hand a client must not disagree with the build.
    """
    from phantom.version import __version__
    from phantom.core.auto_shell import build_auto_banner
    from phantom.modules.report import VERSION

    assert __version__ == _setup_version() == _package_version()
    assert VERSION == __version__
    banner = build_auto_banner()
    assert f"v{__version__}" in banner
    assert "v3.5.0" not in banner
