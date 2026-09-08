import importlib
import sys
from unittest.mock import patch, MagicMock

import pytest


class TestShellStability:
    """Verify shell loads without errors."""

    def test_shell_import(self):
        """PhantomShell should import cleanly."""
        from phantom.core.shell import PhantomShell
        assert PhantomShell is not None

    def test_shell_instantiation(self):
        """PhantomShell should instantiate without side effects."""
        from phantom.core.shell import PhantomShell
        shell = PhantomShell()
        assert shell.prompt == "\x1b[1;36m[phantom]\x1b[0m > "

    def test_adaptive_run_instantiates_suggested_module(self):
        """The adaptive next step must resolve to an instantiable module."""
        from phantom.core.shell import PhantomShell
        from phantom.core.session import session
        from phantom.core import knowledge as K
        shell = PhantomShell()
        session.target = "10.0.0.5"
        K.reset_wm("10.0.0.5")
        suggestion = shell._next_step()
        assert suggestion is not None
        module, _reason = suggestion
        assert shell._instantiate_module(module) is not None

    def test_precmd_hyphen_translation(self):
        """Hyphens in commands should be translated to underscores."""
        from phantom.core.shell import PhantomShell
        shell = PhantomShell()
        assert shell.precmd("load-profile test") == "load_profile test"
        assert shell.precmd("save-session my_session") == "save_session my_session"
        assert shell.precmd("") == ""


class TestModuleLoading:
    """Verify all modules can be imported and instantiated."""

    MODULE_PATHS = [
        ("phantom.modules.scan", "ScanModule"),
        ("phantom.modules.osint", "OsintModule"),
        ("phantom.modules.wifi", "WifiModule"),
        ("phantom.modules.web", "WebModule"),
        ("phantom.modules.brute", "BruteModule"),
        ("phantom.modules.exploit", "ExploitModule"),
        ("phantom.modules.payload", "PayloadModule"),
        ("phantom.modules.handler", "HandlerModule"),
        ("phantom.modules.pivot", "PivotModule"),
        ("phantom.modules.analyzer", "AnalyzerModule"),
        ("phantom.modules.report", "ReportModule"),
    ]

    @pytest.mark.parametrize("module_path,class_name", MODULE_PATHS)
    def test_module_import_and_init(self, module_path, class_name):
        """Each module should import and instantiate without error."""
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        instance = cls()
        assert instance.module_name is not None
        assert hasattr(instance, "do_back")
        assert hasattr(instance, "do_exit")

    @pytest.mark.parametrize("module_path,class_name", MODULE_PATHS)
    def test_module_has_required_methods(self, module_path, class_name):
        """Each module must have do_run and build_commands."""
        mod = importlib.import_module(module_path)
        cls = getattr(mod, class_name)
        instance = cls()
        assert hasattr(instance, "do_run")
        assert hasattr(instance, "build_commands") or hasattr(instance, "do_preview")


class TestPluginLoading:
    """Verify plugin loader security and correctness."""

    def test_plugin_loader_no_crash_empty_dir(self, tmp_path, monkeypatch):
        """Plugin loader should handle empty plugin directories gracefully."""
        from phantom.core.shell import PhantomShell
        monkeypatch.setattr(
            "os.path.expanduser",
            lambda p: str(tmp_path / "plugins") if "phantom" in p else p
        )
        shell = PhantomShell()
        plugins = shell._load_plugins()
        assert isinstance(plugins, dict)


class TestSessionIntegrity:
    """Verify session operations don't corrupt state."""

    def test_session_add_and_retrieve(self):
        from phantom.core.session import Session
        s = Session()
        s.add_result("test_mod", {"key": "value"})
        assert s.get_result("test_mod") == {"key": "value"}
        assert s.get_result("nonexistent") is None

    def test_session_note_structure(self):
        from phantom.core.session import Session
        s = Session()
        s.add_note("Test note")
        assert len(s.notes) == 1
        assert "timestamp" in s.notes[0]
        assert s.notes[0]["text"] == "Test note"

    def test_ai_connector_removed(self):
        """ai_connector was removed in v3.0 — getattr returns None (not crash)."""
        from phantom.core.session import Session
        s = Session()
        ai = getattr(s, "ai_connector", None)
        assert ai is None


class TestExecutorSafety:
    """Verify executor safety checks."""

    def test_safe_target_validation(self):
        from phantom.core.executor import _is_safe_target
        assert _is_safe_target("10.0.0.1") is True
        assert _is_safe_target("example.com") is True
        assert _is_safe_target("10.0.0.1:8080") is True
        assert _is_safe_target("; rm -rf /") is False
        assert _is_safe_target("$(whoami)") is False
        assert _is_safe_target("target && cat /etc/passwd") is False

    def test_out_of_scope_blocked(self):
        from phantom.core.executor import run_command
        from phantom.core.session import session
        session.scope = ["10.0.0.0/24"]
        output = run_command("echo test", target_ip="192.168.1.1")
        assert output == ""
        session.scope = []
