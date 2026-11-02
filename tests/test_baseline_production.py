"""The production scorer against OUR corpus: what it can and cannot measure.

The empty intersection these tests pin is the whole point. A test that only
proved "the function returns a dict" would let the coverage silently fall back
to zero and call it a measurement.
"""

import pytest

from training.baseline_production import production_ranking, scoreable

#: The golden row shape: capability ids, and services that production does not
#: turn into access candidates (measured 2026-10-31 — zero intersection).
GOLDEN = {
    "target": "127.0.0.1",
    "candidates": [{"id": "scan_tcp"}, {"id": "http_probe"},
                   {"id": "web_creds"}, {"id": "web_rce"},
                   {"id": "beacon_deploy"}, {"id": "privesc_sudo"}],
    "services": [{"port": "53", "service": "domain"},
                 {"port": "80", "service": "http"},
                 {"port": "139", "service": "netbios-ssn"},
                 {"port": "443", "service": "https"},
                 {"port": "445", "service": "microsoft-ds"},
                 {"port": "8080", "service": "http-proxy"}],
}

#: Two services `access.SERVICE_PROBES` knows, so `collect_candidates` builds
#: two non-CVE candidates with include_nvd=False — no network in a test.
REDIS_PORT, MEMCACHED_PORT = "6379", "11211"


def _service_payload(candidate_ids):
    return {
        "target": "10.0.0.5",
        "candidates": [{"id": cid} for cid in candidate_ids],
        "services": [{"port": REDIS_PORT, "service": "redis"},
                     {"port": MEMCACHED_PORT, "service": "memcached"}],
    }


class TestTheEmptyIntersection:
    def test_the_corpus_vocabulary_is_not_the_production_one(self):
        block = production_ranking(GOLDEN)
        assert block["coverage"] == 0.0
        assert block["shared"] == []
        assert block["corpus_ids"][0] == "scan_tcp"

    def test_the_reason_names_the_two_vocabularies(self):
        """A zero must read as "these are different things", not "the model
        scored badly" — otherwise someone will try to fix it by training harder.
        """
        reason = production_ranking(GOLDEN)["reason"].lower()
        assert "vocabular" in reason
        assert "capability" in reason and "access" in reason

    def test_it_is_not_scoreable(self):
        assert scoreable(GOLDEN) is False


class TestTheProductionVocabulary:
    def test_two_service_candidates_give_a_full_measurement(self):
        # Read the ids production itself produces rather than hard-coding the
        # naming scheme here: if that scheme changes, this test must follow.
        probe = production_ranking({"target": "10.0.0.5",
                                    "services": [{"port": REDIS_PORT,
                                                  "service": "redis"},
                                                 {"port": MEMCACHED_PORT,
                                                  "service": "memcached"}]})
        assert len(probe["ids"]) >= 2, probe["reason"]

        payload = _service_payload(probe["ids"])
        block = production_ranking(payload)
        assert block["coverage"] == 1.0
        assert block["reason"] == ""
        assert scoreable(payload) is True

    def test_the_order_is_by_production_score(self):
        probe = production_ranking({"target": "10.0.0.5",
                                    "services": [{"port": REDIS_PORT,
                                                  "service": "redis"},
                                                 {"port": MEMCACHED_PORT,
                                                  "service": "memcached"}]})
        block = production_ranking(_service_payload(probe["ids"]))
        scores = [block["scores"][cid] for cid in block["ids"]]
        assert scores == sorted(scores, reverse=True)

    def test_the_shared_order_follows_production_not_the_payload(self):
        """`shared` is what a label is scored against, so it has to be
        production's opinion even when the payload listed the ids backwards."""
        probe = production_ranking({"target": "10.0.0.5",
                                    "services": [{"port": REDIS_PORT,
                                                  "service": "redis"},
                                                 {"port": MEMCACHED_PORT,
                                                  "service": "memcached"}]})
        payload = _service_payload(list(reversed(probe["ids"])))
        assert production_ranking(payload)["shared"] == probe["ids"]


class TestPartialCoverage:
    def test_one_known_and_one_unknown_id_is_half(self):
        probe = production_ranking({"target": "10.0.0.5",
                                    "services": [{"port": REDIS_PORT,
                                                  "service": "redis"},
                                                 {"port": MEMCACHED_PORT,
                                                  "service": "memcached"}]})
        payload = _service_payload([probe["ids"][0], "scan_tcp"])
        block = production_ranking(payload)
        assert block["coverage"] == 0.5
        assert block["shared"] == [probe["ids"][0]]
        # Half an ordering cannot be scored as if it were the whole field.
        assert scoreable(payload) is False
        assert block["reason"]


class TestItNeverRaises:
    @pytest.mark.parametrize("payload", [
        None, {}, {"candidates": "not a list"},
        {"candidates": [None, 7, {"no_id": True}]},
        {"candidates": [{"id": "x"}], "services": "not a list"},
    ])
    def test_a_hostile_payload_is_zero_coverage(self, payload):
        block = production_ranking(payload)
        assert block["coverage"] == 0.0
        assert block["reason"]
        assert scoreable(payload) is False


class TestDeterminism:
    def test_two_calls_return_the_same_order(self):
        probe = production_ranking({"target": "10.0.0.5",
                                    "services": [{"port": REDIS_PORT,
                                                  "service": "redis"},
                                                 {"port": MEMCACHED_PORT,
                                                  "service": "memcached"}]})
        payload = _service_payload(probe["ids"])
        assert production_ranking(payload)["ids"] == production_ranking(payload)["ids"]
