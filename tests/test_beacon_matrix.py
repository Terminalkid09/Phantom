"""The feature × OS × arch × transport grid must not be a marketing page.

`docs/beacon_platform_matrix.md` was a reviewed CLAIM, and the CI jobs only
proved that some binary was produced per platform. This module pins the grid
in `phantom/utils/beacon_matrix.py` against the payload itself:

* every verb the C2 may send belongs to exactly one feature row;
* every file under `payloads/beacon/src` is classified (feature header, helper,
  or documented non-beacon file) — a new header cannot be added silently;
* a feature the grid calls usable on POSIX must have a non-Windows branch in
  the header(s) it names (the same scan `test_beacon_arsenal_parity` uses);
* a feature the grid calls `windows_only` must live in a header with NO
  non-Windows branch — where a Windows-only mechanism shares a header with a
  cross-platform one, the row names no header and says so in its note;
* the docs page quotes a GENERATED block, so the table a reader sees is the
  table the code enforces.

What these tests cannot prove is that a POSIX branch is USEFUL — the grid's own
vocabulary keeps that distinction (`posix` vs `degrade` vs `absent`), and the
smoke jobs are what compile the branches for real.
"""
import importlib.util
import os
import pathlib
import tempfile
import unittest

from phantom.core.task_policy import BEACON_VERBS
from phantom.utils import beacon_matrix as bm

_SCRIPT = _ROOT_SCRIPT = pathlib.Path(__file__).resolve().parent.parent / \
    "scripts" / "beacon_matrix_verify.py"


def _load_script():
    spec = importlib.util.spec_from_file_location("beacon_matrix_verify",
                                                  str(_SCRIPT))
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "phantom" / "payloads" / "beacon" / "src"
_DOC = _ROOT / "docs" / "beacon_platform_matrix.md"

# build artefacts that live next to the sources (gitignored) — not inputs
_BUILD_ARTEFACTS = (".o", ".bin", ".obj", ".a")


def _files() -> list:
    return sorted(p.name for p in _SRC.iterdir() if p.is_file()
                  and not p.name.endswith(_BUILD_ARTEFACTS))


class TestTheGridIsWellFormed(unittest.TestCase):
    def test_the_grid_matches_the_python_verb_contract(self):
        # both directions: a verb with no row, and a row claiming a verb the
        # beacon does not dispatch, are errors
        self.assertEqual(bm.matrix_errors(BEACON_VERBS), [])

    def test_every_os_has_arch_transport_and_pin(self):
        self.assertEqual(bm.matrix_errors(), [])

    def test_every_cell_is_a_real_builder_target(self):
        cells = bm.matrix_cells()
        self.assertEqual(len(cells),
                         sum(len(bm.ARCHES[o]) for o in bm.OSES))
        for os_name, arch, transport in cells:
            self.assertIn(arch, bm.ARCHES[os_name])
            self.assertEqual(transport, bm.TRANSPORTS[os_name])
            name, value = bm.machine_for(os_name, arch)
            self.assertTrue(name and value, f"{os_name}/{arch}")

    def test_the_vocabulary_is_closed(self):
        for feature in bm.FEATURES:
            for level in feature.support.values():
                self.assertIn(level, bm.SUPPORT_LEVELS, feature.name)


def _elf(machine: int) -> bytes:
    ident = b"\x7fELF" + bytes([2, 1, 1, 0]) + b"\x00" * 8
    header = ident + b"\x02\x00" + machine.to_bytes(2, "little")
    assert len(header) == 20
    return header + b"\x00" * 5000


def _pe(machine: int) -> bytes:
    header = b"MZ" + b"\x00" * (0x3C - 2) + (0x40).to_bytes(4, "little")
    return header + b"PE\x00\x00" + machine.to_bytes(2, "little") + \
        b"\x00" * 5000


def _macho(cputype: int) -> bytes:
    return b"\xcf\xfa\xed\xfe" + cputype.to_bytes(4, "little") + \
        b"\x00" * 5000


class TestTheArtefactVerifier(unittest.TestCase):
    """The verifier's own contract: a cell passes only if it IS that cell."""

    def setUp(self):
        self.mod = _load_script()
        self.dir = tempfile.mkdtemp(prefix="beacon-cell-")

    def _place(self, name, blob):
        path = os.path.join(self.dir, name)
        with open(path, "wb") as handle:
            handle.write(blob)
        return path

    def test_a_correct_cell_passes(self):
        self._place("beacon_android", _elf(0xB7))
        self.assertEqual(
            self.mod.verify_cell("android", "aarch64", self.dir), 0)

    def test_the_wrong_architecture_fails(self):
        # an x86-64 ELF is still \x7fELF: the machine field is the check
        self._place("beacon_android", _elf(0x3E))
        self.assertEqual(self.mod.verify_cell("android", "aarch64", self.dir), 1)

    def test_the_wrong_container_fails(self):
        self._place("beacon_linux", b"NOT-A-BINARY" + b"x" * 5000)
        self.assertEqual(self.mod.verify_cell("linux", "x86_64", self.dir), 1)

    def test_a_windows_pe_with_the_right_machine_passes(self):
        self._place("beacon.pe", _pe(0x8664))
        self.assertEqual(self.mod.verify_cell("windows", "x86_64", self.dir), 0)

    def test_a_macos_arm64_mach_o_passes(self):
        self._place("beacon_macos", _macho(0x0100000C))
        self.assertEqual(self.mod.verify_cell("macos", "arm64", self.dir), 0)

    def test_a_macos_x86_64_binary_is_not_arm64(self):
        self._place("beacon_macos", _macho(0x01000007))
        self.assertEqual(self.mod.verify_cell("macos", "arm64", self.dir), 1)

    def test_a_missing_artefact_is_a_SKIP_not_a_pass(self):
        self.assertEqual(self.mod.verify_cell("linux", "x86_64", self.dir), 2)
        code = self.mod.main(["--platform", "linux", "--arch", "x86_64",
                              "--beacon-dir", self.dir, "--require"])
        self.assertEqual(code, 1)

    def test_an_unknown_arch_for_the_platform_is_refused(self):
        code = self.mod.main(["--platform", "android", "--arch", "x86_64",
                              "--beacon-dir", self.dir])
        self.assertEqual(code, 1)

    def test_lint_validates_the_grid(self):
        self.assertEqual(self.mod.main(["--lint"]), 0)


class TestTheDocsBlockIsGenerated(unittest.TestCase):
    def test_write_docs_inserts_the_block_and_is_idempotent(self):
        mod = _load_script()
        with tempfile.TemporaryDirectory() as tmp:
            page = pathlib.Path(tmp) / "matrix.md"
            page.write_text("# Matrix\n\nIntro line.\n\n## Section\n\nbody\n",
                            encoding="utf-8")
            self.assertEqual(mod.write_docs(str(page)), 0)
            first = page.read_text(encoding="utf-8")
            self.assertIn(bm.to_markdown(), first)
            self.assertIn(bm._BEGIN, first)
            self.assertEqual(mod.write_docs(str(page)), 0)
            self.assertEqual(first, page.read_text(encoding="utf-8"))


class TestTheGridMatchesTheSource(unittest.TestCase):
    def test_every_source_file_is_classified(self):
        declared = {h for f in bm.FEATURES for h in f.headers}
        helpers = set(bm.HELPER_HEADERS)
        extra = set(bm.NON_HEADER_FILES)
        unclassified = [n for n in _files()
                        if n not in declared | helpers | extra]
        self.assertEqual(unclassified, [],
                         "classify these in beacon_matrix (feature, helper or "
                         "non-beacon file)")

    def test_a_feature_named_on_posix_has_a_posix_branch(self):
        """`native`/`posix` on a POSIX OS means the branch is compiled in."""
        offenders = []
        for feature in bm.FEATURES:
            for os_name in ("linux", "macos", "android"):
                if feature.support.get(os_name) not in ("native", "posix"):
                    continue
                for header in feature.headers:
                    text = (_SRC / header).read_text(encoding="utf-8",
                                                     errors="replace")
                    if "#ifdef _WIN32" not in text:
                        continue                      # compiles everywhere
                    if "#else" not in text and "#elif" not in text:
                        offenders.append(
                            f"{feature.name}/{os_name}: {header} has no "
                            f"non-Windows branch")
        self.assertEqual(offenders, [])

    def test_a_windows_only_feature_really_is_windows_only(self):
        offenders = []
        for feature in bm.FEATURES:
            if feature.support.get("windows") != "windows_only":
                continue
            for header in feature.headers:
                text = (_SRC / header).read_text(encoding="utf-8",
                                                 errors="replace")
                if "#ifdef _WIN32" not in text:
                    offenders.append(f"{feature.name}: {header} is unguarded")
                    continue
                if "#else" in text or "#elif" in text:
                    offenders.append(
                        f"{feature.name}: {header} has a non-Windows branch, "
                        f"so it is not windows_only")
        self.assertEqual(offenders, [])

    def test_the_accepted_windows_only_headers_are_the_ones_the_parity_test_pins(self):
        """One list, not two: the arsenal parity test and the grid must agree."""
        from tests.test_beacon_arsenal_parity import _WINDOWS_ONLY as accepted
        grid = {h for f in bm.FEATURES
                if f.support.get("windows") == "windows_only"
                for h in f.headers}
        # jpeg_enc/wasapi/sleep_ekko/winhttp were classified per header, so the
        # grid must at least COVER every header the parity test accepts
        self.assertEqual(set(accepted) - grid, set())
        for header in accepted:
            text = (_SRC / header).read_text(encoding="utf-8", errors="replace")
            self.assertNotIn("#else", text.split("#endif")[0],
                             f"{header} gained a POSIX branch")


class TestTheParityGapIsExplicit(unittest.TestCase):
    def test_windows_can_dispatch_every_verb(self):
        self.assertEqual(bm.missing_verbs("windows", BEACON_VERBS), set())

    def test_the_posix_gaps_are_only_documented_absences(self):
        """A verb missing on a POSIX OS must be a DECLARED absence.

        Two legitimate reasons: the feature is an NT-only mechanism
        (`windows_only`), or the OS has no path for it at all (`absent`, e.g.
        cookie harvesting on macOS/Android). Anything else is an undocumented
        regression of the kind the grid exists to catch.
        """
        for os_name in ("linux", "macos", "android"):
            gap = bm.missing_verbs(os_name, BEACON_VERBS)
            for verb in gap:
                feature = bm.feature_for_verb(verb)
                self.assertIsNotNone(feature, verb)
                level = feature.support.get(os_name)
                self.assertIn(level, ("windows_only", "absent"),
                              f"{os_name}: {verb} ({level})")
            # a POSIX beacon must keep the vast majority of the verb surface
            self.assertLess(len(gap), 10, f"{os_name} lost too much: {gap}")

    def test_the_documented_degradations_are_the_ones_declared(self):
        self.assertIn("netstat", bm.DEGRADED["macos"])
        self.assertIn("screenshot", bm.DEGRADED["macos"])
        self.assertEqual(bm.DEGRADED["windows"], ())
        self.assertEqual(bm.DEGRADED["linux"], ())

    def test_the_transport_pin_differs_only_where_libcurl_forces_it(self):
        self.assertEqual(bm.pin_primitive("macos"), "pubkey-spki-sha256")
        for os_name in ("windows", "linux", "android"):
            self.assertEqual(bm.pin_primitive(os_name), "cert-sha256-der")


class TestTheDocsQuoteTheGrid(unittest.TestCase):
    def test_the_documented_block_is_the_generated_one(self):
        doc = _DOC.read_text(encoding="utf-8", errors="replace")
        block = bm.markdown_block(doc)
        self.assertTrue(block, "the docs page must carry the generated block")
        self.assertEqual(
            block, bm.to_markdown(),
            "docs/beacon_platform_matrix.md is stale: regenerate the block "
            "between the beacon-matrix markers")

    def test_every_feature_appears_in_the_docs_block(self):
        doc = _DOC.read_text(encoding="utf-8", errors="replace")
        for feature in bm.FEATURES:
            self.assertIn(f"| {feature.name} |", doc, feature.name)


if __name__ == "__main__":
    unittest.main()
