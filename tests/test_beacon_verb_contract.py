"""The Python task policy and the C++ beacon must agree on the verb list.

`BEACON_VERBS` (phantom/core/task_policy.py) is the allow-list the C2 checks
a task against before sending it; `dispatch_command` (payloads/beacon/src/
main.cpp) is the ONE place the beacon decides whether it can act on it. A
verb in one and not the other is a task that is either rejected locally
while the beacon would run it, or sent and silently ignored — both are the
kind of drift no Python test used to catch (the suite never exercised the
C++ verbs).

This parses the dispatch body, not a hand-copied list, so the test is a
CONTRACT: add a handler without updating BEACON_VERBS and it fails.
"""
import os
import re
import unittest

from phantom.core.task_policy import BEACON_VERBS

_MAIN_CPP = os.path.join(
    os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
    "phantom", "payloads", "beacon", "src", "main.cpp")

_ANCHOR = ("std::string dispatch_command(const std::string& cmd, "
           "net::C2Config& cfg) {")

# both dispatch forms: the XOR-obfuscated `action == XOR_DEC(XOR_STR("v"))`
# and the plain `action == "v"` the media verbs use
_VERB_RE = re.compile(
    r'action\s*==\s*(?:XOR_DEC\(XOR_STR\("([^"]+)"\)|"([^"]+)")')


def _dispatch_body(src: str) -> str:
    start = src.index(_ANCHOR)
    depth = 0
    for j in range(start, len(src)):
        if src[j] == "{":
            depth += 1
        elif src[j] == "}":
            depth -= 1
            if depth == 0:
                return src[start:j]
    raise AssertionError("unterminated dispatch_command body")


def dispatch_verbs(src: str) -> set:
    return {a or b for a, b in _VERB_RE.findall(_dispatch_body(src))}


class TestBeaconVerbContract(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        with open(_MAIN_CPP, encoding="utf-8") as fh:
            cls.cpp_verbs = dispatch_verbs(fh.read())

    def test_the_dispatch_parses(self):
        # a broken regex would make the contract vacuously true
        self.assertGreater(len(self.cpp_verbs), 30, self.cpp_verbs)

    def test_every_python_verb_has_a_cpp_handler(self):
        missing = sorted(BEACON_VERBS - self.cpp_verbs)
        self.assertFalse(missing,
                         f"BEACON_VERBS sends verbs the beacon cannot "
                         f"dispatch: {missing}")

    def test_every_cpp_handler_is_in_the_python_allow_list(self):
        extra = sorted(self.cpp_verbs - BEACON_VERBS)
        self.assertFalse(extra,
                         f"the beacon dispatches verbs the C2 policy would "
                         f"reject: {extra}")


if __name__ == "__main__":
    unittest.main()
