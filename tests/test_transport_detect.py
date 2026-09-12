"""Tests for the zero-config transport layer: data/config.json auto-creation,
env-var override bridge, and the social degrade-with-reason behavior."""
import os
import tempfile
import unittest
from unittest.mock import Mock

from phantom.automation.guidance import kit
from phantom.automation.guidance.commands import Registry
from phantom.automation.guidance.stealth import StealthConfig, StealthEngine
from phantom.automation.guidance.threatmodel import BlueTeamModel
from phantom.automation.runtime.stealth_runtime import (
    StealthRuntime,
    TimingGovernor,
)
from phantom.automation.runtime.toolchain import ToolRegistry
from phantom.automation.belief import WorldModel
from phantom.automation.social.engine import SocialEngine
from phantom.utils import config as cfg

TARGET = "10.0.0.77"


def _set_config_path(tmp_dir: str):
    cfg._CONFIG_PATH = os.path.join(tmp_dir, "config.json")
    cfg._loaded = None


class TestConfigModule(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="phantom_cfg_")
        _set_config_path(self.tmp)

    def test_first_read_creates_defaults(self):
        cfg.reload_config()
        self.assertTrue(os.path.exists(cfg.config_path()))
        self.assertEqual(cfg.get("c2.port", 8080), 8080)
        self.assertEqual(cfg.get("tracker.skin", "youtube"), "youtube")
        # nothing external is pre-configured
        self.assertEqual(cfg.get("transports.smtp.username", ""), "")

    def test_file_value_used_when_no_env(self):
        cfg.set("transports.smtp.username", "file@phantom.local")
        cfg.reload_config()
        self.assertEqual(cfg.get("transports.smtp.username", ""),
                         "file@phantom.local")

    def test_env_wins_over_file(self):
        cfg.set("transports.smtp.username", "file@phantom.local")
        os.environ["PHANTOM_SMTP_USER"] = "env@phantom.local"
        try:
            self.assertEqual(cfg.get("transports.smtp.username", "",
                                     env="PHANTOM_SMTP_USER"),
                             "env@phantom.local")
        finally:
            os.environ.pop("PHANTOM_SMTP_USER", None)

    def test_atomic_save_roundtrip(self):
        cfg.set("c2.port", 9090)
        cfg.reload_config()
        self.assertEqual(cfg.get("c2.port", 8080), 9090)

    def test_mailer_reads_config_file(self):
        from phantom.automation.social.mailers import env_mail_config
        os.environ.pop("PHANTOM_SMTP_USER", None)
        os.environ.pop("PHANTOM_SMTP_PASSWORD", None)
        cfg.set("transports.smtp.username", "file@phantom.local")
        cfg.set("transports.smtp.password", "sekrit")
        cfg.reload_config()
        mc = env_mail_config()
        self.assertEqual(mc.username, "file@phantom.local")
        self.assertEqual(mc.password, "sekrit")


class TestTransportDetection(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp(prefix="phantom_tr_")
        _set_config_path(self.tmp)
        cfg.reload_config()
        os.environ.pop("PHANTOM_SMTP_USER", None)
        os.environ.pop("PHANTOM_SMTP_PASSWORD", None)
        os.environ.pop("PHANTOM_TELEGRAM_BOT_TOKEN", None)
        os.environ.pop("PHANTOM_SMS_CARRIER", None)
        os.environ.pop("PHANTOM_DISCORD_WEBHOOK", None)
        os.environ.pop("PHANTOM_DM_TRANSPORT", None)

    def test_fresh_checkout_local_only(self):
        from phantom.automation.social.transports import (
            missing_transports,
            transport_status,
        )
        st = transport_status()
        self.assertTrue(st["tracker"]["ready"])     # local: always usable
        self.assertFalse(st["email"]["ready"])      # external: needs creds
        self.assertFalse(st["sms"]["ready"])
        self.assertFalse(st["dm"]["ready"])
        # delivery phases report the missing transport
        self.assertEqual(missing_transports("phish_identity"), ["email"])
        self.assertEqual(missing_transports("campaign_launch"), ["email"])
        self.assertEqual(missing_transports("dm_launch"), ["dm"])
        # local-only phases never block
        self.assertEqual(missing_transports("harvest_campaign"), [])
        self.assertEqual(missing_transports("osint_identity"), [])
        self.assertEqual(missing_transports("wait_follow"), [])

    def test_smtp_creds_enable_email_chain(self):
        from phantom.automation.social.transports import (
            missing_transports,
            transport_status,
        )
        os.environ["PHANTOM_SMTP_USER"] = "op@phantom.local"
        os.environ["PHANTOM_SMTP_PASSWORD"] = "x"
        st = transport_status()
        self.assertTrue(st["email"]["ready"])
        self.assertEqual(missing_transports("phish_identity"), [])
        self.assertEqual(missing_transports("campaign_launch"), [])
        # SMS channel alone also unblocks phish_identity (email-to-SMS)
        os.environ.pop("PHANTOM_SMTP_USER", None)
        os.environ.pop("PHANTOM_SMTP_PASSWORD", None)
        self.assertEqual(missing_transports("phish_identity"), ["email"])

    def test_telegram_enables_dm(self):
        from phantom.automation.social.transports import missing_transports
        os.environ["PHANTOM_TELEGRAM_BOT_TOKEN"] = "123:abc"
        self.assertEqual(missing_transports("dm_launch"), [])

    def test_setup_hint_names_the_channel(self):
        from phantom.automation.social.transports import (
            missing_transports,
            setup_hint,
        )
        hint = setup_hint(missing_transports("phish_identity"))
        self.assertIn("SMTP", hint)

    def test_config_file_enables_email_without_env(self):
        from phantom.automation.social.transports import missing_transports
        cfg.set("transports.smtp.username", "file@phantom.local")
        cfg.set("transports.smtp.password", "p")
        cfg.reload_config()
        self.assertEqual(missing_transports("phish_identity"), [])


class TestAgentDegrade(unittest.TestCase):
    """The auto-mode must SKIP a social phase with a clear reason when its
    transport is missing — not fail blindly or spin."""

    def _make_agent(self, runner, social=None, target_type="email"):
        from phantom.automation.agent import AutonomousAgent
        reg = Registry()
        for c in kit.CAPABILITIES:
            reg.register(c)
        agent = AutonomousAgent(
            target="t@example.com", target_type=target_type, profile="enterprise",
            on_event=lambda k, d: None,
            runtime=StealthRuntime(
                StealthEngine(WorldModel(target="t@example.com"),
                              StealthConfig()),
                runner=runner, cost_per_action=0.5,
                governor=TimingGovernor(base_delay=0.0, jitter=0.0)),
            toolchain=ToolRegistry(installed={"nmap", "curl", "nc"}),
            registry=reg,
            social_engine=social or Mock())
        # satisfy phish_identity preconditions (identity known, no private
        # profile blocking the lure)
        agent.wm.add_finding("identity", "email:t@example.com",
                             {"email": "t@example.com", "platform": "email"},
                             source="osint_identity")
        return agent

    def test_phish_blocked_when_smtp_missing(self):
        from phantom.automation.social.transports import missing_transports
        os.environ.pop("PHANTOM_SMTP_USER", None)
        os.environ.pop("PHANTOM_SMTP_PASSWORD", None)
        self.tmp = tempfile.mkdtemp(prefix="phantom_ag_")
        _set_config_path(self.tmp)
        cfg.reload_config()

        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = True
            res.stdout = "PHISH_SENT:1\n"
            res.stderr = ""
            return res

        agent = self._make_agent(runner, social=SocialEngine())
        cap = agent.registry.get("phish_identity")
        self.assertIsNotNone(cap)
        self.assertTrue(missing_transports("phish_identity"))
        events = []
        agent._on_event = lambda k, d: events.append((k, d))
        # execute directly: should be blocked, not sent
        from phantom.automation.planner import PlanStep
        step = PlanStep(capability=cap, slot_values={"email": "t@t.com"})
        ok = agent._execute_capability(step)
        self.assertFalse(ok)
        kinds = [k for k, _ in events]
        self.assertIn("blocked", kinds)
        self.assertNotIn("run", kinds)
        blocked = next(d for k, d in events if k == "blocked")
        self.assertIn("transport not configured", blocked["reason"])

    def test_harvest_never_blocked(self):
        from phantom.automation.social.transports import missing_transports
        self.tmp = tempfile.mkdtemp(prefix="phantom_ag2_")
        _set_config_path(self.tmp)
        cfg.reload_config()

        def runner(cmd, timeout=None):
            res = Mock()
            res.ok = True
            res.stdout = "VICTIM_IP:1.2.3.4\n"
            res.stderr = ""
            return res

        agent = self._make_agent(runner)
        self.assertEqual(missing_transports("harvest_campaign"), [])


if __name__ == "__main__":
    unittest.main()