"""Tests: full swarm chains (creds/ad/crack/lateral) release by facts."""
from phantom.automation.swarm.board import Board
from phantom.automation.swarm.tasks import build_tasks

TARGET = "10.0.0.5"


def _svc():
    return [{"kind": "service", "key": "tcp/80",
             "value": {"port": "80", "service": "http"},
             "confidence": 0.9, "source": "t"}]


class TestChainTemplates:
    def test_creds_chain(self):
        tasks = build_tasks("creds", [TARGET])
        assert [t.goal for t in tasks] == ["footprint", "creds"]
        creds = tasks[1]
        assert creds.needs == frozenset({"service"})
        assert creds.provides == frozenset({"creds"})
        from phantom.automation.brain.cells import CONTACT_EXPLOIT
        assert creds.contact == CONTACT_EXPLOIT

    def test_full_chain_has_creds_and_post(self):
        goals = [t.goal for t in build_tasks("full", [TARGET])]
        assert goals == ["footprint", "complete_kill_chain", "creds",
                         "post_exploit"]

    def test_deep_chain_order(self):
        goals = [t.goal for t in build_tasks("deep", [TARGET])]
        assert goals == ["footprint", "complete_kill_chain", "creds",
                         "post_exploit", "ad", "crack", "lateral"]

    def test_crack_is_offline(self):
        from phantom.automation.brain.cells import CONTACT_NONE
        tasks = build_tasks("deep", [TARGET])
        crack = next(t for t in tasks if t.goal == "crack")
        assert crack.contact == CONTACT_NONE  # hash cracking: no contact
        assert crack.max_agents > 1  # fans out like osint


class TestChainGating:
    def _board_with(self, staged):
        board = Board([TARGET])
        for kind, entries in staged.items():
            board.commit("t", TARGET, entries)
        return board

    def test_crack_waits_for_ad_creds(self):
        tasks = build_tasks("deep", [TARGET])
        crack = next(t for t in tasks if t.goal == "crack")
        board = self._board_with({"service": _svc()})
        assert crack.ready(board) is False
        board.commit("ad", TARGET, [{"kind": "ad_creds", "key": "u",
                                     "value": {}, "confidence": 0.8,
                                     "source": "ad"}])
        assert crack.ready(board) is True

    def test_lateral_waits_for_beacon_and_creds(self):
        tasks = build_tasks("deep", [TARGET])
        lateral = next(t for t in tasks if t.goal == "lateral")
        board = Board([TARGET])
        board.commit("x", TARGET, [{"kind": "beacon", "key": "b",
                                    "value": {}, "confidence": 0.9,
                                    "source": "x"}])
        assert lateral.ready(board) is False  # creds still missing
        board.commit("x", TARGET, [{"kind": "creds", "key": "c",
                                    "value": {}, "confidence": 0.7,
                                    "source": "x"}])
        assert lateral.ready(board) is True

    def test_ad_releases_on_beacon(self):
        tasks = build_tasks("deep", [TARGET])
        ad = next(t for t in tasks if t.goal == "ad")
        board = Board([TARGET])
        assert ad.ready(board) is False
        board.commit("e", TARGET, [{"kind": "beacon", "key": "b",
                                    "value": {}, "confidence": 0.9,
                                    "source": "e"}])
        assert ad.ready(board) is True
