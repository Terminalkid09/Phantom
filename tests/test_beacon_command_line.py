"""The OS-shell verb must not truncate its argument at the first newline.

The measured failure (2026-11-11 lab chain): auto-mode ran `persistence_install`,
the beacon answered `sh: 1: Syntax error: Unterminated quoted string`, and the
interpreter recorded no `persistence` fact. The command itself was valid — the
Linux builder ships a systemd unit with real newlines inside single quotes — but
the dispatcher read the argument with `std::getline`, which stops at the first
newline. The target's `sh -c` then saw an unterminated quote.

The C++ test is compiled and RUN where a compiler exists; the source assertions
pin that `main.cpp` actually routes shell/exec/run through the helper.
"""
import os
import pathlib
import shutil
import subprocess
import tempfile
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SRC = _ROOT / "phantom" / "payloads" / "beacon" / "src"
_MAIN = _SRC / "main.cpp"
_HELPER = _SRC / "command_line.h"
_CPP_TEST = _ROOT / "tests" / "test_beacon_command_line.cpp"


def _compiler():
    for name in ("g++", "clang++", "cl"):
        found = shutil.which(name)
        if found:
            return found
    return None


def _code_only(text):
    """Drop full-line `//` comments: the fix may NAME the old call in prose."""
    return "\n".join(
        line for line in text.splitlines()
        if not line.lstrip().startswith("//"))


class TestTheHelperExists(unittest.TestCase):
    def test_argument_rest_is_header_only(self):
        header = _HELPER.read_text(encoding="utf-8")
        self.assertIn("inline std::string argument_rest", header)
        # It must not stop at a newline: that was the bug. Comments may NAME
        # the old call, so only the code lines are checked.
        self.assertNotIn("getline(", _code_only(header))


class TestTheDispatcherUsesIt(unittest.TestCase):
    def setUp(self):
        self.src = _MAIN.read_text(encoding="utf-8")

    def test_shell_branch_uses_argument_rest(self):
        start = self.src.index('XOR_STR("shell")')
        # The branch ends at the next `else if`.
        end = self.src.index("else if", start)
        branch = self.src[start:end]
        self.assertIn("command_line::argument_rest", branch)
        self.assertNotIn("std::getline", _code_only(branch),
                         "getline truncates a multi-line shell command")

    def test_the_header_is_included(self):
        self.assertIn('#include "command_line.h"', self.src)


class TestCppExecutable(unittest.TestCase):
    def test_the_cpp_command_line_test_passes(self):
        compiler = _compiler()
        if compiler is None:
            self.skipTest("no C++ compiler on this runner")
        with tempfile.TemporaryDirectory() as tmp:
            exe = os.path.join(tmp, "command_line_test")
            includes = ["-I" + str(_SRC)]
            argv = [compiler, "-std=c++20", "-O1", *includes, "-o", exe,
                    str(_CPP_TEST)]
            build = subprocess.run(argv, capture_output=True, text=True,
                                   timeout=600)
            self.assertEqual(build.returncode, 0,
                             f"command-line test failed to build:\n"
                             f"{build.stdout}\n{build.stderr}")
            run = subprocess.run([exe], capture_output=True, text=True,
                                 timeout=300)
            self.assertEqual(run.returncode, 0,
                             "command-line invariants violated:\n"
                             f"{run.stdout}\n{run.stderr}")
            self.assertIn("all command-line checks passed", run.stdout)


if __name__ == "__main__":
    unittest.main()
