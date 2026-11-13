"""A clone must be able to BUILD THE PAYLOAD — the headers are the proof.

The bug this file exists for: `main.cpp` includes `build_id.h` and
`config_encrypted.h`, the remote's `crypto.h` includes `crypto_config.h`, and
none of them is tracked (they are per-build). Nothing CREATED
`config_encrypted.h` from its template, so the payload only compiled on a
machine where a build had already run: a clean checkout — CI, or a new
contributor — died at `#include`. The beacon-syntax job and every
beacon-smoke job compile the real translation unit, so those jobs could never
have passed on a clean tree.

No compiler here: the invariant is "every generated header the sources include
has a writer, and that writer produces it on an empty tree", which is exactly
what the compile step depends on.
"""
import importlib.util
import os
import re
import shutil
import subprocess
import sys

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_SCRIPT = os.path.join(_ROOT, "scripts", "ci_beacon_prepare.py")
BEACON = os.path.join(_ROOT, "phantom", "payloads", "beacon")
REMOTE = os.path.join(_ROOT, "phantom", "payloads", "remote")

# written by the crypto/enrollment writers that ran before this file was fixed
_CRYPTO_HEADERS = ("crypto_config.h", "c2_config.h", "beacon_auth.h")
_GENERATED = (*_CRYPTO_HEADERS, "build_id.h", "config_encrypted.h",
              "malleable_config.h")


def _load_prepare():
    """Import scripts/ci_beacon_prepare.py without making scripts a package."""
    spec = importlib.util.spec_from_file_location("ci_beacon_prepare", _SCRIPT)
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _git(*args):
    """Run git in the repo; None when there is no git or no repo."""
    try:
        out = subprocess.run(["git"] + list(args), cwd=_ROOT,
                             capture_output=True, text=True)
    except OSError:
        return None
    return out


class TestEveryGeneratedIncludeHasAGenerator:
    def test_the_beacon_sources_are_covered(self):
        mod = _load_prepare()
        needed = mod.local_includes(BEACON)
        # the two that were missing: included by main.cpp, written by nobody
        assert "build_id.h" in needed and "config_encrypted.h" in needed
        for header in sorted(needed):
            path = os.path.join(BEACON, "src", header)
            assert (os.path.isfile(path) or header in mod.NON_SECRET_HEADERS
                    or header in _CRYPTO_HEADERS), (
                f"{header} is included by the payload's own sources but no "
                f"generator writes it: a clean checkout cannot compile")

    def test_the_remote_sources_are_covered(self):
        mod = _load_prepare()
        for header in sorted(mod.local_includes(REMOTE)):
            path = os.path.join(REMOTE, "src", header)
            assert (os.path.isfile(path) or header in mod.NON_SECRET_HEADERS
                    or header in _CRYPTO_HEADERS), header


class TestThePrepareStepWritesThem:
    def _prepare(self, payload_dir, tree, monkeypatch, mod):
        """Run the real prepare step against a COPY of the payload tree.

        The generated headers are DELETED after copying: the point is a tree
        that has never built, which is what a clone is. Leaving them in (what a
        plain copy does) would hide the exact bug this asserts.
        """
        shutil.copytree(payload_dir, tree, dirs_exist_ok=True)
        src = os.path.join(tree, "src")
        for name in _GENERATED:
            try:
                os.remove(os.path.join(src, name))
            except OSError:
                pass
        monkeypatch.setattr(sys, "argv", ["ci_beacon_prepare.py", "--dir", tree,
                                          "--ci-identity"])
        assert mod.main() == 0
        return src

    def test_a_clean_beacon_tree_gets_every_header_it_includes(self, tmp_path,
                                                               monkeypatch):
        mod = _load_prepare()
        src = self._prepare(BEACON, str(tmp_path / "beacon"), monkeypatch, mod)
        for header in _GENERATED:
            assert os.path.isfile(os.path.join(src, header)), header

    def test_the_generated_header_is_well_formed(self, tmp_path, monkeypatch):
        mod = _load_prepare()
        src = self._prepare(BEACON, str(tmp_path / "beacon"), monkeypatch, mod)
        text = open(os.path.join(src, "config_encrypted.h"),
                    encoding="utf-8").read()
        assert text.startswith("#pragma once")
        assert len(re.findall(
            r"constexpr uint64_t CONFIG_SEED = 0x[0-9A-F]{16}ULL;", text)) == 1
        assert "@CONFIG_SEED@" not in text
        # what main.cpp compiles against must survive the template
        assert "namespace config_enc" in text
        assert "decrypt_config" in text

    def test_the_remote_tree_needs_no_beacon_header(self, tmp_path, monkeypatch):
        mod = _load_prepare()
        src = self._prepare(REMOTE, str(tmp_path / "remote"), monkeypatch, mod)
        assert not os.path.exists(os.path.join(src, "config_encrypted.h")), (
            "the remote module never includes it: writing it would only add an "
            "untracked stray to its tree")


class TestTheTemplateIsTrackedSource:
    def test_the_template_ships(self):
        template = os.path.join(BEACON, "src", "config_encrypted.h.in")
        assert os.path.isfile(template)
        assert "@CONFIG_SEED@" in open(template, encoding="utf-8").read()

    def test_the_generated_header_is_not_tracked(self):
        out = _git("ls-files", "--",
                   "phantom/payloads/beacon/src/config_encrypted.h")
        if out is None or out.returncode != 0:
            pytest.skip("not a git checkout")
        assert not out.stdout.strip(), (
            "the per-build header must stay untracked: ci_beacon_lint fails "
            "if it is committed")

    def test_the_template_is_not_swallowed_by_gitignore(self):
        out = _git("check-ignore", os.path.join(
            "phantom", "payloads", "beacon", "src", "config_encrypted.h.in"))
        if out is None or out.returncode not in (0, 1):
            pytest.skip("not a git checkout")
        assert out.returncode == 1, f"the template is ignored: {out.stdout}"

    def test_the_generator_refuses_a_broken_template(self, tmp_path,
                                                     monkeypatch):
        from phantom.utils import builder as B
        template = str(tmp_path / "broken.h.in")
        with open(template, "w", encoding="utf-8") as handle:
            handle.write("#pragma once\nconstexpr uint64_t CONFIG_SEED = "
                         "0x@CONFIG_SEED@ULL;\n// @SOMETHING_ELSE@\n")
        monkeypatch.setattr(B, "_CONFIG_TEMPLATE", template)
        (tmp_path / "src").mkdir()
        with pytest.raises(ValueError):
            B.write_config_encrypted(str(tmp_path))
