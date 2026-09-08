"""Tests for the social sleep state (waiting for the human) and the
private-account follow -> wait -> DM orchestration."""
import os
import unittest

from phantom.automation.agent import AutonomousAgent
from phantom.automation.belief import WorldModel
from phantom.automation.guidance.commands import make_registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.planner import Planner
from phantom.automation.social.engine import SocialEngine


class _FakeHarvestEngine:
    """Engine stub: harvest()/wait_follow() return canned markers."""

    def __init__(self, hits_after: int = 0):
        self.calls = 0
        self.hits_after = hits_after

    def harvest(self, timeout: float = 15.0):
        self.calls += 1
        if self.calls > self.hits_after:
            return True, ["VICTIM_IP: ip=9.9.9.9 ua=ua when=now"]
        return True, []

    def wait_follow(self, timeout: float = 300.0):
        return True, []


class TestSocialWaitHorizon(unittest.TestCase):

    def _horizon(self, speed=False, env=None):
        old = os.environ.get("PHANTOM_SOCIAL_WAIT")
        if env:
            os.environ["PHANTOM_SOCIAL_WAIT"] = env
        else:
            os.environ.pop("PHANTOM_SOCIAL_WAIT", None)
        try:
            agent = AutonomousAgent(target="mario.rossi@gmail.com",
                                    target_type="email", speed=speed)
            return agent._social_wait_horizon()
        finally:
            if old is not None:
                os.environ["PHANTOM_SOCIAL_WAIT"] = old
            else:
                os.environ.pop("PHANTOM_SOCIAL_WAIT", None)

    def test_speed_mode_never_waits_long(self):
        self.assertEqual(self._horizon(speed=True), 30.0)

    def test_stealth_default_waits(self):
        self.assertEqual(self._horizon(), 600.0)

    def test_env_override(self):
        self.assertEqual(self._horizon(env="120"), 120.0)


class TestWaitCapabilityExecution(unittest.TestCase):

    def _run_wait(self, engine, env="1"):
        old = os.environ.get("PHANTOM_SOCIAL_WAIT")
        os.environ["PHANTOM_SOCIAL_WAIT"] = env
        try:
            events = []
            agent = AutonomousAgent(
                target="mario.rossi@gmail.com", target_type="email",
                speed=False, on_event=lambda k, d: events.append(k))
            agent.social_engine = engine
            cap = agent.registry.get("harvest_campaign")
            out = agent._run_social_wait_capability(cap, {})
            return out, events
        finally:
            if old is not None:
                os.environ["PHANTOM_SOCIAL_WAIT"] = old
            else:
                os.environ.pop("PHANTOM_SOCIAL_WAIT", None)

    def test_wait_breaks_when_victim_click_arrives(self):
        # env="3" gives two chunks: the first waits (event emitted), the
        # second receives the click and breaks the sleep
        out, events = self._run_wait(_FakeHarvestEngine(hits_after=1), env="3")
        self.assertIn("VICTIM_IP: ip=9.9.9.9", out)
        self.assertIn("waiting", events)  # sleep state was surfaced

    def test_wait_returns_empty_on_timeout(self):
        out, events = self._run_wait(_FakeHarvestEngine(hits_after=999))
        self.assertEqual(out, "")
        self.assertIn("waiting", events)


class TestFollowFlow(unittest.TestCase):

    def _engine(self):
        eng = SocialEngine()
        eng._discovered.update({"platform": "instagram"})
        return eng

    def test_follow_request_then_accept_then_wait(self):
        eng = self._engine()
        ok, lines = eng.dm_follow(["mario.rossi"], platform="instagram")
        self.assertTrue(ok)
        self.assertTrue(any(l.startswith("FOLLOW_SENT: handle=mario.rossi")
                            for l in lines), lines)
        # not accepted yet -> wait_follow finds nothing
        ok, lines = eng.wait_follow(timeout=0.1)
        self.assertFalse(ok)
        # the target accepts -> wait_follow reports it
        self.assertTrue(eng.accept_follow("mario.rossi"))
        ok, lines = eng.wait_follow(timeout=0.1)
        self.assertTrue(ok)
        self.assertTrue(any(l.startswith("FOLLOW_ACCEPTED: handle=mario.rossi")
                            for l in lines), lines)


class _FakeCadenceEngine(_FakeHarvestEngine):
    """harvest() reports nothing until hits_after polls; follow_up() records
    the cadence re-engagement call."""

    def __init__(self, hits_after: int = 0):
        super().__init__(hits_after=hits_after)
        self.follow_calls = 0

    def follow_up(self, targets, use_video=True, use_login_page=False):
        self.follow_calls += 1
        return True, [f"CAMPAIGN: id=fu pretext=fu to={targets[0]} "
                      f"status=sent link=fu"]


class TestCadenceReengagement(unittest.TestCase):
    """Cadence: while the lead waits for a click and the target stays
    silent past the grace delay, ONE follow-up lure (fresh pretext) is sent
    and the deadline is extended. Never fires when the click already
    arrived, cadence is disabled (0), or the wait is speed-short."""

    def _run(self, engine, wait="2", cadence="0.4", speed=False):
        old = {k: os.environ.get(k) for k in
               ("PHANTOM_SOCIAL_WAIT", "PHANTOM_SOCIAL_CADENCE",
                "PHANTOM_SOCIAL_CADENCE_MAX")}
        os.environ["PHANTOM_SOCIAL_WAIT"] = wait
        os.environ["PHANTOM_SOCIAL_CADENCE"] = cadence
        try:
            events = []
            agent = AutonomousAgent(target="mario.rossi@gmail.com",
                                    target_type="email", speed=speed,
                                    on_event=lambda k, d: events.append(k))
            agent.social_engine = engine
            cap = agent.registry.get("harvest_campaign")
            out = agent._run_social_wait_capability(cap, {})
            return out, events, engine
        finally:
            for k, v in old.items():
                if v is not None:
                    os.environ[k] = v
                else:
                    os.environ.pop(k, None)

    def test_silent_target_triggers_one_followup(self):
        out, events, engine = self._run(_FakeCadenceEngine(hits_after=999))
        self.assertEqual(engine.follow_calls, 1)      # bounded: one second touch
        self.assertIn("cadence", events)
        self.assertIn("waiting", events)
        self.assertIn("CAMPAIGN: id=fu", out)         # follow-up lure markers

    def test_click_arrives_no_followup(self):
        out, events, engine = self._run(_FakeCadenceEngine(hits_after=0))
        self.assertEqual(engine.follow_calls, 0)
        self.assertIn("VICTIM_IP: ip=9.9.9.9", out)
        self.assertNotIn("cadence", events)

    def test_cadence_disabled_with_zero(self):
        out, events, engine = self._run(_FakeCadenceEngine(hits_after=999),
                                         wait="1", cadence="0")
        self.assertEqual(engine.follow_calls, 0)

    def test_speed_mode_never_cadences(self):
        out, events, engine = self._run(_FakeCadenceEngine(hits_after=999),
                                         wait="1", cadence="0.2", speed=True)
        self.assertEqual(engine.follow_calls, 0)


class TestPrivateProfilePlanning(unittest.TestCase):

    def test_planner_orders_follow_before_dm_for_private(self):
        wm = WorldModel(target="mario.rossi", target_type="username")
        wm.add_finding("identity", "identity:mario.rossi",
                       {"username": "mario.rossi", "platform": "instagram"})
        wm.add_finding("profile", "profile:mario.rossi",
                       {"username": "mario.rossi", "platform": "instagram",
                        "private": True})
        planner = Planner(make_registry(),
                          StealthEngine(wm, StealthConfig(aggressive=False)))
        # the generic beacon plan chains the full social path for a private
        # account: follow -> wait -> DM -> harvest (no email phish)
        plan = planner.plan(wm, goal="beacon")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("dm_follow", ids)
        self.assertIn("wait_follow", ids)
        self.assertIn("dm_launch", ids)
        self.assertIn("harvest_campaign", ids)
        # the email-phish lures are gated off for private accounts
        self.assertNotIn("phish_identity", ids)
        self.assertNotIn("campaign_launch", ids)

    def test_public_profile_keeps_dm_path(self):
        wm = WorldModel(target="mario.rossi", target_type="username")
        wm.add_finding("identity", "identity:mario.rossi",
                       {"username": "mario.rossi", "platform": "instagram"})
        wm.add_finding("profile", "profile:mario.rossi",
                       {"username": "mario.rossi", "platform": "instagram",
                        "private": False})
        planner = Planner(make_registry(),
                          StealthEngine(wm, StealthConfig(aggressive=False)))
        plan = planner.plan(wm, goal="beacon")
        ids = [s.capability.id for s in plan.steps]
        self.assertIn("phish_identity", ids)  # email chain available
        self.assertIn("harvest_campaign", ids)
        self.assertNotIn("dm_follow", ids)    # no follow needed


if __name__ == "__main__":
    unittest.main()
