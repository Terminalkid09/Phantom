"""Tests for the manual shell UX upgrade (banner, status bar, aliases,
tab-completion, step-aware next, preflight, quiet mode)."""

import io
from unittest.mock import patch

from phantom.core.session import session
from phantom.core import shell as SH


class TestBanner:
    def test_banner_has_art_and_wordmark(self):
        banner = SH.build_banner()
        assert "██████╗" in banner             # wordmark start
        assert "v3.0.0" in banner
        assert "Offensive Security Framework" in banner

    def test_banner_clean_wordmark_no_mascot(self):
        banner = SH.build_banner()
        # the wordmark is intact (all 6 rows)
        assert "██████╗ ██╗  ██╗ █████╗" in banner
        assert "██╔══██╗██║  ██║██╔══██╗" in banner
        assert "██████╔╝███████║███████║" in banner
        assert "██╔═══╝ ██╔══██║██╔══██║" in banner
        assert "██║     ██║  ██║██║  ██║" in banner
        assert "╚═╝     ╚═╝  ╚═╝╚═╝  ╚═╝" in banner

    def test_banner_wordmark_single_color(self):
        banner = SH.build_banner()
        # one accent color for the wordmark (no rainbow gradient)
        assert "bold red" in banner

    def test_banner_compact(self):
        banner = SH.build_banner_compact()
        assert "v3.0.0" in banner
        assert len(banner) < len(SH.build_banner())


class TestContextHint:
    def test_hint_without_target(self, monkeypatch):
        monkeypatch.setattr(session, "target", None)
        hint = SH._context_hint()
        assert "set target" in hint

    def test_hint_with_target_no_findings(self, monkeypatch):
        from phantom.core import knowledge as K
        K.reset_wm("10.0.0.5")
        monkeypatch.setattr(session, "target", "10.0.0.5")
        hint = SH._context_hint()
        assert "use scan" in hint

    def test_hint_after_services(self, monkeypatch):
        from phantom.core import knowledge as K
        K.reset_wm("10.0.0.5")
        K.add_service("22", "ssh", source="scan")
        monkeypatch.setattr(session, "target", "10.0.0.5")
        hint = SH._context_hint()
        assert "use exploit" in hint


class TestStatusBar:
    def test_status_bar_renders(self):
        s = SH.build_status_bar()
        assert "PHANTOM" in s
        assert "svc" in s and "creds" in s and "vuln" in s

    def test_elapsed_formats(self, monkeypatch):
        session.engagement_started = None
        assert SH._engagement_elapsed() == "0s"

    def test_status_bar_counts_from_knowledge(self, monkeypatch):
        from phantom.core import knowledge as K
        K.reset_wm("10.0.0.5")
        K.add_service("22", "ssh", source="scan")
        s = SH.build_status_bar()
        assert "svc 1" in s


class TestAliasesAndCompletion:
    def setup_method(self):
        self.sh = SH.PhantomShell()

    def test_module_aliases(self):
        for alias, expect in [("s", "scan"), ("e", "exploit"),
                              ("wl", "wordlist"), ("pi", "pivot"),
                              ("r", "report"), ("b", "brute")]:
            assert self.sh.MODULE_ALIASES.get(alias, alias) == expect

    def test_complete_use(self):
        names = self.sh.complete_use("s", "use s", 0, 0)
        assert "scan" in names

    def test_complete_set_keys_and_values(self):
        session.target = "10.0.0.9"
        assert "10.0.0.9" in self.sh.complete_set("10", "set target 10", 4, 5)
        assert "scope" in self.sh.complete_set("s", "set s", 4, 5)

    def test_new_commands_exist(self):
        for name in ("run", "preflight"):
            assert hasattr(self.sh, "do_" + name), name


class TestRunAndPreflight:
    def setup_method(self):
        self.sh = SH.PhantomShell()
        from phantom.core import knowledge as K
        K.reset_wm("10.0.0.5")

    def test_run_requires_target(self, caplog):
        session.target = None
        with caplog.at_level("ERROR", logger="phantom"):
            self.sh.do_run("")
        assert "No target set" in caplog.text

    def test_preflight_reports_missing_tools(self, monkeypatch):
        session.target = "10.0.0.5"
        import shutil
        monkeypatch.setattr(shutil, "which", lambda t: None)
        buf = io.StringIO()
        with patch("phantom.core.shell.console",
                   SH.Console(file=buf, width=140, force_terminal=False)):
            self.sh.do_preflight("scan")
        out = buf.getvalue()
        assert "Missing tools" in out
        assert "nmap" in out


class TestQuietMode:
    def test_quiet_toggle_and_run(self):
        from phantom.modules.scan import ScanModule
        session.target = "10.0.0.5"
        mod = ScanModule()
        mod.do_quiet("")
        assert getattr(mod, "quiet", False) is True
        mod.do_quiet("")
        assert getattr(mod, "quiet", False) is False

    def test_run_quiet_executes_top_suggestion(self):
        from phantom.modules.scan import ScanModule
        session.target = "10.0.0.5"
        mod = ScanModule()
        mod.quiet = True
        fake = type("R", (), {"stdout": "22 open ssh\n", "stderr": "",
                              "returncode": 0, "ok": True})()
        with patch("phantom.core.executor.execute_quiet", return_value=fake) as eq:
            buf = io.StringIO()
            with patch("sys.stdout", buf):
                mod.do_run("--quiet")
        assert eq.called
        assert "22 open ssh" in buf.getvalue()

    def test_report_run_quiet_exports_full_set(self):
        from phantom.modules.report import ReportModule
        mod = ReportModule()
        mod.quiet = True
        with patch.object(mod, "_export_full_set") as exp:
            mod.do_run("--quiet")
        exp.assert_called_once()


class TestModulePrompt:
    def test_base_module_prompt_has_module_and_target(self):
        from phantom.modules.base_module import BaseModule
        session.target = "10.0.0.5"
        b = BaseModule()
        assert "base" in b.prompt and "10.0.0.5" in b.prompt
