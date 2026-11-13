"""The Go data plane must not be a second, looser C2.

The audit's finding: `c2d` served the same wire protocol but enforced NO task
policy (only mTLS + the operator token), no retention and a plain, unchained
audit trail — so switching backends silently downgraded the operator's
protections. The README said "do not expose that endpoint"; a README is not an
enforcement mechanism.

Three things are now pinned here:

* `c2d/policy_vectors.json` is a SHARED contract — the Python policy evaluates
  every case and must agree with the expectations in the file, which the Go
  test (`c2d/task_policy_test.go`) asserts from the other side;
* `c2d/audit_vectors.json` pins the canonical record and its digest, so both
  chain implementations hash identically;
* the constants that decide behaviour (lease, result retention) are checked to
  be equal in Go and Python, because a different value on one backend is a
  behavioural difference nobody would notice in a review.
"""
import json
import os
import pathlib
import re
import unittest

from phantom.core.c2_server import MAX_RESULTS_PER_BEACON, TASK_LEASE_SECONDS
from phantom.core.task_policy import BEACON_VERBS, TaskPolicy, TypedTask

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_C2D = _ROOT / "c2d"


def _read(path: pathlib.Path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


class TestPolicyVectors(unittest.TestCase):
    """One contract, two implementations: Python decides, Go must agree."""

    @classmethod
    def setUpClass(cls):
        cls.doc = json.loads(_read(_C2D / "policy_vectors.json"))

    def test_the_vector_file_covers_both_task_forms(self):
        cases = self.doc["cases"]
        self.assertGreaterEqual(len(cases), 10)
        self.assertTrue(any(c["typed"] for c in cases))
        self.assertTrue(any(not c["typed"] for c in cases))

    def test_python_agrees_with_every_pinned_expectation(self):
        for case in self.doc["cases"]:
            policy = TaskPolicy()
            if case["grants"] is not None:
                policy.set_grants(case["beacon"], case["grants"])
            typed = case["typed"]
            if typed:
                decision = policy.check_typed(case["beacon"], TypedTask(
                    capability_id=typed.get("capability_id", ""),
                    args=typed.get("args", []),
                    expires_at=typed.get("expires_at", 0.0)))
            else:
                decision = policy.check_legacy(case["beacon"],
                                               case["command"] or "")
            self.assertEqual(decision.allowed, case["allowed"], case["name"])
            self.assertEqual(decision.mode, case["mode"], case["name"])
            self.assertEqual(decision.reason, case["reason"], case["name"])

    def test_the_go_side_reads_the_same_file(self):
        text = _read(_C2D / "task_policy_test.go")
        self.assertIn("policy_vectors.json", text)
        self.assertIn("TestPolicyMatchesThePythonVectors", text)


class TestTheVerbListIsTheSameList(unittest.TestCase):
    def test_go_and_python_allow_the_same_verbs(self):
        text = _read(_C2D / "task_policy.go")
        block = text.split("var BeaconVerbs = []string{", 1)[1].split("}", 1)[0]
        verbs = {v for v in re.findall(r'"([^"]+)"', block)}
        self.assertEqual(verbs, set(BEACON_VERBS),
                         "c2d/task_policy.go drifted from "
                         "phantom/core/task_policy.py")

    def test_go_and_python_agree_on_the_high_impact_set(self):
        from phantom.core.task_policy import HIGH_IMPACT_VERBS
        text = _read(_C2D / "task_policy.go")
        block = text.split("var HighImpactVerbs = []string{", 1)[1].split("}",
                                                                         1)[0]
        verbs = {v for v in re.findall(r'"([^"]+)"', block)}
        self.assertEqual(verbs, set(HIGH_IMPACT_VERBS))


class TestTheConstantsAgree(unittest.TestCase):
    def _go_const(self, name: str) -> int:
        text = _read(_C2D / "store.go")
        match = re.search(rf"{name}\s*=\s*(\d+)", text)
        self.assertIsNotNone(match, f"{name} not found in c2d/store.go")
        return int(match.group(1))

    def test_the_task_lease_is_the_same_on_both_backends(self):
        self.assertEqual(self._go_const("TaskLeaseSeconds"), TASK_LEASE_SECONDS)

    def test_result_retention_is_the_same_on_both_backends(self):
        self.assertEqual(self._go_const("MaxResultsPerBeacon"),
                         MAX_RESULTS_PER_BEACON)


class TestTheAuditChainVector(unittest.TestCase):
    def test_the_python_chain_produces_the_pinned_digest(self):
        import hashlib
        from phantom.utils.audit_log import _canonical
        doc = json.loads(_read(_C2D / "audit_vectors.json"))
        canonical = _canonical(doc["record"])
        self.assertEqual(canonical, doc["canonical"])
        digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()
        self.assertEqual(digest, doc["sha256"])

    def test_the_go_side_reads_the_same_vector(self):
        text = _read(_C2D / "audit_test.go")
        self.assertIn("audit_vectors.json", text)

    def test_the_go_audit_is_a_chain_not_a_plain_log(self):
        text = _read(_C2D / "audit.go")
        for token in ("prev", "recordHash", "sha256", "Verify"):
            self.assertIn(token, text)


class TestTheQueueEndpointIsGuarded(unittest.TestCase):
    def test_the_handler_consults_the_policy_before_queueing(self):
        text = _read(_C2D / "server.go")
        handler = text.split("func (s *Server) handleQueue", 1)[1]
        handler = handler.split("\nfunc ", 1)[0]
        self.assertIn("s.policy.Check", handler)
        # the policy must run BEFORE the task reaches the store
        self.assertLess(handler.index("s.policy.Check"),
                        handler.index("QueueTaskWithTTL"))
        self.assertIn("StatusForbidden", handler)
        self.assertIn("task_denied", handler)

    def test_the_capabilities_endpoint_no_longer_claims_no_policy(self):
        text = _read(_C2D / "server.go")
        self.assertNotIn("task_policy\":    false", text)
        self.assertIn('"task_policy":    true', text)


if __name__ == "__main__":
    unittest.main()
