"""Tests: auto-mode event rendering (extracted to automode_render).

Pins the CLI stream contract: level -> notifier channel, the verbose gate
on reasoning events, and the guarantee that a broken frontend consumer
never interrupts the engagement engine.
"""
import unittest
from unittest.mock import Mock, patch

from phantom.core import automode_render as rnd
from phantom.core.stream_contract import Rendered


class TestEmitRendered(unittest.TestCase):
    def _emit(self, level):
        rendered = Rendered(kind="x", level=level, lines=["a", "b"])
        with patch.object(rnd.notifier, "success") as m_suc, \
                patch.object(rnd.notifier, "warn") as m_warn, \
                patch.object(rnd.notifier, "error") as m_err, \
                patch.object(rnd.notifier, "info") as m_info:
            rnd.emit_rendered(rendered)
        return m_suc, m_warn, m_err, m_info

    def test_level_maps_to_notifier_channel(self):
        m_suc, m_warn, m_err, m_info = self._emit("success")
        self.assertEqual(m_suc.call_count, 2)   # every line, no merge
        m_warn.assert_not_called()
        m_err.assert_not_called()
        m_info.assert_not_called()
        for level, channel_name in (("warn", "warn"), ("error", "error"),
                                    ("info", "info")):
            with self.subTest(level=level):
                mocks = dict(zip(("success", "warn", "error", "info"),
                                 self._emit(level)))
                self.assertEqual(mocks[channel_name].call_count, 2)
                for other, m in mocks.items():
                    if other != channel_name:
                        m.assert_not_called()


class TestStreamAgentEvent(unittest.TestCase):
    def test_verbose_only_reasoning_is_silent_without_verbose(self):
        with patch.object(rnd.notifier, "info") as m_info:
            rnd.stream_agent_event(
                "reason", {"hypotheses": [{"capability": "ssh_login",
                                           "reason": "test reuse",
                                           "priority": 0.85}]},
                verbose=False)
        m_info.assert_not_called()

    def test_verbose_renders_reasoning(self):
        with patch.object(rnd.notifier, "info") as m_info:
            rnd.stream_agent_event(
                "reason", {"hypotheses": [{"capability": "ssh_login",
                                           "reason": "test reuse",
                                           "priority": 0.85}]},
                verbose=True)
        self.assertTrue(m_info.called)

    def test_unknown_kind_is_never_dropped_silently(self):
        with patch.object(rnd.notifier, "info") as m_info:
            rnd.stream_agent_event("no_such_kind", {"x": 1}, verbose=False)
        self.assertTrue(m_info.called)


class TestMakeAgentStream(unittest.TestCase):
    def test_frontend_receives_the_same_events(self):
        seen = []
        stream = rnd.make_agent_stream(verbose=False,
                                       on_event=lambda k, d: seen.append(k))
        with patch.object(rnd.notifier, "info"):
            stream("note", {"capability": "c", "detail": "d"})
        self.assertEqual(seen, ["note"])

    def test_broken_frontend_never_interrupts_the_engine(self):
        def boom(kind, data):
            raise RuntimeError("frontend bug")

        stream = rnd.make_agent_stream(verbose=False, on_event=boom)
        with patch.object(rnd.notifier, "info") as m_info:
            stream("note", {"capability": "c", "detail": "d"})
        self.assertTrue(m_info.called)  # the CLI still saw the event

    def test_stream_swarm_event_calls_on_event_even_when_not_rendered(self):
        on_event = Mock()
        with patch.object(rnd.notifier, "info"):
            rnd.stream_swarm_event("reason", {"hypotheses": []},
                                   verbose=False, on_event=on_event)
        on_event.assert_called_once()


if __name__ == "__main__":
    unittest.main()
