"""Tests: the agent's channel dispatch registry (agent._CHANNEL_ROUTES).

_execute_capability used to be a monolithic dispatcher: shared gates, an
if-chain over category/id, and the whole shell-command path. The routing is
now an ordered registry grouped per kill-chain phase; these tests pin the
routing SEMANTICS (which channel runs which capability) and the row-order
contract that the old if-chain encoded.
"""
import unittest
from types import SimpleNamespace

from phantom.automation.agent import AutonomousAgent


def _cap(id, category, **kw):
    c = SimpleNamespace(id=id, category=category)
    for k, v in kw.items():
        setattr(c, k, v)
    return c


def _route(cap):
    for _phase, match, handler in AutonomousAgent._CHANNEL_ROUTES:
        if match(cap):
            return handler
    raise AssertionError("no route matched")


class TestRegistryShape(unittest.TestCase):
    def test_every_handler_exists_on_the_agent(self):
        for _phase, _match, handler in AutonomousAgent._CHANNEL_ROUTES:
            self.assertTrue(callable(getattr(AutonomousAgent, handler, None)),
                            handler)

    def test_last_row_is_the_default_command_channel(self):
        _phase, match, handler = AutonomousAgent._CHANNEL_ROUTES[-1]
        self.assertEqual(handler, "_execute_command_capability")
        self.assertTrue(match(_cap("anything", "anything")))

    def test_id_routes_are_tagged_with_their_phase(self):
        from phantom.automation.phases import phase_of
        for cid in ("idor_scan", "origin_discovery", "web_creds"):
            cap = _cap(cid, "unmatched-category")
            for _phase, match, handler in AutonomousAgent._CHANNEL_ROUTES:
                if match(cap):  # first match wins, like the dispatch does
                    self.assertEqual(_phase, phase_of(cid), (cid, handler))
                    break


class TestRouting(unittest.TestCase):
    def test_category_channels(self):
        self.assertEqual(_route(_cap("cleanup", "post")),
                         "_execute_post_capability")
        self.assertEqual(_route(_cap("kerberoast", "ad")),
                         "_execute_ad_capability")
        self.assertEqual(_route(_cap("osint_identity", "osint")),
                         "_execute_social_capability")
        self.assertEqual(_route(_cap("phish_identity", "social")),
                         "_execute_social_capability")
        self.assertEqual(_route(_cap("hunt_web", "hunt")),
                         "_execute_hunt_capability")

    def test_identity_lane_engine_is_not_social(self):
        # phone_osint is an offline lookup: engine channel, not social
        cap = _cap("phone_osint", "osint",
                   exec_class="in_process_engine", engine=object())
        self.assertEqual(_route(cap), "_execute_engine_capability")

    def test_id_channels(self):
        self.assertEqual(_route(_cap("idor_scan", "exploit")),
                         "_execute_idor_capability")
        self.assertEqual(_route(_cap("origin_discovery", "recon")),
                         "_execute_origin_capability")
        self.assertEqual(_route(_cap("web_creds", "exploit")),
                         "_execute_web_creds_capability")

    def test_generic_engine_channel(self):
        cap = _cap("fingerprint_services", "recon",
                   exec_class="in_process_engine", engine=object())
        self.assertEqual(_route(cap), "_execute_engine_capability")

    def test_learned_lane(self):
        cap = _cap("learned.x", "custom", source_module="m.py")
        self.assertEqual(_route(cap), "_execute_learned_capability")

    def test_shell_command_is_the_default(self):
        self.assertEqual(_route(_cap("scan_tcp", "recon")),
                         "_execute_command_capability")
        self.assertEqual(_route(_cap("beacon_deploy", "beacon")),
                         "_execute_command_capability")

    def test_row_order_is_the_legacy_if_chain_contract(self):
        # first match wins, exactly like the old if-chain: these
        # combinations never occur in the live registry, but the ORDER is
        # the contract and must not silently change.
        self.assertEqual(_route(_cap("web_creds", "post")),
                         "_execute_post_capability")
        self.assertEqual(_route(_cap("idor_scan", "hunt")),
                         "_execute_hunt_capability")
        self.assertEqual(_route(_cap("origin_discovery", "osint")),
                         "_execute_social_capability")
        self.assertEqual(_route(_cap("learned.x", "post",
                                     source_module="m.py")),
                         "_execute_post_capability")
        # the id-specific engines outrank the generic engine lane
        cap = _cap("web_creds", "exploit",
                   exec_class="in_process_engine", engine=object())
        self.assertEqual(_route(cap), "_execute_web_creds_capability")


if __name__ == "__main__":
    unittest.main()
