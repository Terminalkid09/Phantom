"""A payload helper no platform calls, and the CI flag that hid it.

The bug this file exists for: the remote module carried three static helpers —
`_unb64`, `_now_str` and `_sha256_hex` — that no translation unit could reach.
`beacon-syntax (macos-latest)` failed on all three (`clang: error: unused
function ... [-Werror,-Wunused-function]`) while the SAME commit passed
`beacon-syntax (ubuntu-latest)` and `beacon-syntax (windows-latest)`.

Root cause, and it is not a platfom quirk of the code: g++ only runs its
unused-function pass when it really compiles, and the CI step compiled with
`-fsyntax-only` — which stops before that pass. clang diagnoses an unused
static during semantic analysis, so the macOS leg saw what the other two legs
were structurally unable to see. A green Linux check therefore said nothing
about macOS.

Two halves are locked in here:

* no column-0 `static` free function in a payload module may be unreferenced
  (dead code that clang rejects and g++ -fsyntax-only will not report), and
* the CI compile step must COMPILE (`-c ... -o /dev/null`), not merely parse,
  so all three legs can catch the rest of the warning classes.
"""
import os
import re

import pytest

_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
_CI = os.path.join(_ROOT, ".github", "workflows", "ci.yml")
MODULES = ("beacon", "remote")

# A definition of a free function at column 0: `static <type> name(...)`.
# Statics that carry an initialiser (`static int g_counter = 0;`) and anything
# indented (members, statics inside a namespace) are not free functions and are
# skipped — this module only ever defines its helpers the way below.
_DEF = re.compile(r"^static\s+(?P<sig>[^=()]*?)\((?P<rest>.*)$")


def _module_sources(module, root=None):
    """Every tracked-text source of a payload module, as {path: text}."""
    src = os.path.join(root or _ROOT, "phantom", "payloads", module, "src")
    files = sorted(f for f in os.listdir(src)
                   if f.endswith((".h", ".cpp")))
    out = {}
    for name in files:
        with open(os.path.join(src, name), encoding="utf-8",
                  errors="ignore") as handle:
            out[name] = handle.read()
    return out


def _static_free_functions(module, root=None):
    """[(name, uses, filename, lineno)] for each `static <t> name(...)` def.

    `uses` counts the identifier across the whole module, definition included,
    so 1 means "nothing but its own signature mentions it" — dead on every
    platform. Counting textually (not by parsing `#if` branches) is
    deliberate: a helper used only by a Windows block must NOT be reported,
    because the compiler decides per platform and this scan must never
    contradict a build that works.
    """
    sources = _module_sources(module, root)
    whole = "\n".join(sources.values())
    found = []
    for name, text in sources.items():
        for lineno, line in enumerate(text.splitlines(), 1):
            match = _DEF.match(line)
            if not match or "=" in match.group("sig"):
                continue
            identifier = re.search(r"(\w+)\s*$", match.group("sig").rstrip())
            if not identifier:
                continue
            fn = identifier.group(1)
            uses = len(re.findall(r"\b" + re.escape(fn) + r"\b", whole))
            found.append((fn, uses, name, lineno))
    return found


def _ci_text():
    with open(_CI, encoding="utf-8") as handle:
        return handle.read()


class TestNoPayloadHelperIsDeadOnEveryPlatform:
    @pytest.mark.parametrize("module", MODULES)
    def test_every_static_helper_has_a_caller(self, module):
        dead = [f"{name} at {path}:{line}"
                for name, uses, path, line in _static_free_functions(module)
                if uses <= 1]
        assert not dead, (
            f"{module} defines static helper(s) nothing calls: {dead}. "
            "clang fails the build for an unused static function "
            "(-Werror,-Wunused-function) while g++ under -fsyntax-only does "
            "not, so this is exactly how the Linux leg stayed green while the "
            "macOS leg failed. Delete it, or scope its definition to the "
            "platform that calls it.")

    def test_the_scan_is_not_vacuous(self, tmp_path):
        """A tree with one dead and one used helper: only the dead one is bad."""
        src = tmp_path / "phantom" / "payloads" / "remote" / "src"
        src.mkdir(parents=True)
        (src / "dead.h").write_text(
            "static std::string _dead_helper(const char* s) {\n"
            "    return std::string(s);\n"
            "}\n", encoding="utf-8")
        # the caller is NOT static on purpose: a static caller would itself be
        # dead, and the point of this fixture is the used helper only
        (src / "used.h").write_text(
            "static std::string _live_helper(const char* s) {\n"
            "    return std::string(s);\n"
            "}\nvoid caller() { _live_helper(\"x\"); }\n",
            encoding="utf-8")
        dead = {n for n, uses, _, _ in _static_free_functions("remote",
                                                             str(tmp_path))
                if uses <= 1}
        assert dead == {"_dead_helper"}, dead

    @pytest.mark.parametrize("module", MODULES)
    def test_the_real_modules_are_actually_scanned(self, module):
        """Guard against a rename that silently scans nothing."""
        assert len(_static_free_functions(module)) >= 5, (
            f"the {module} scan found almost no static helpers — the detection "
            "pattern no longer matches the sources, so it proves nothing")


class TestTheCompileStepCompiles:
    """`-fsyntax-only` cannot catch what clang catches. Do not go back."""

    def _compile_step(self):
        """The step's CODE: the comments explain the -fsyntax-only story, so
        a substring check over the raw block would read its own prose."""
        text = _ci_text()
        start = text.index("Compile beacon AND remote translation units")
        step = text[start:text.index("- name:", start)]
        return "\n".join(line for line in step.splitlines()
                         if not line.strip().startswith("#"))

    def test_the_payloads_are_really_compiled_not_just_parsed(self):
        step = self._compile_step()
        assert "-fsyntax-only" not in step, (
            "g++ skips its unused-function pass under -fsyntax-only, so the "
            "Linux and Windows legs cannot see a dead static helper that the "
            "macOS leg rejects")
        assert step.count(" -c ") == 2, step
        assert step.count("-o /dev/null") == 2, step

    def test_the_step_still_fails_on_warnings(self):
        step = self._compile_step()
        assert "-Werror" in step
        assert "-Wall" in step and "-Wextra" in step


class TestTheWindowsToolchainStepDoesNotDependOnChoco:
    """`choco install mingw` failing must not skip the compile silently.

    Observed on windows-latest: the install step went red on a network hiccup,
    every compile step was skipped, and the job said nothing about the code.
    The image already ships MinGW, so the step probes for a compiler first.
    """

    def test_a_preinstalled_compiler_is_tried_before_chocolatey(self):
        text = _ci_text()
        step = text[text.index("Install MinGW"):]
        step = step[:step.index("- name:", 10)]
        probe = step.index("command -v g++")
        assert probe < step.index("choco install mingw"), (
            "the step installs over the network before checking the compiler "
            "the image already ships")
        # the fallback stays: a future image without MinGW must still build
        assert "choco install mingw" in step
