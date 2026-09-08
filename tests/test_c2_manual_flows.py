"""Focused regression tests for interactive C2/manual boundaries."""

from unittest.mock import patch

from phantom.core.c2_shell import C2Shell, run_c2


def test_c2_entry_does_not_start_telegram():
    with patch("phantom.core.c2_shell.C2Shell.cmdloop"), patch("phantom.core.c2_shell.server_instance.stop"):
        with patch("phantom.modules.telegram.run") as telegram_run:
            run_c2()
    telegram_run.assert_not_called()


def test_c2_unknown_command_is_safe_without_active_beacon():
    shell = C2Shell()
    with patch("phantom.core.c2_shell.notifier.error") as error:
        shell.default("whoami")
    error.assert_called_once()
    assert "No active beacon" in error.call_args.args[0]


def test_c2_exit_stops_listener():
    shell = C2Shell()
    with patch("phantom.core.c2_shell.server_instance.stop") as stop:
        assert shell.do_exit("") is True
    stop.assert_called_once()
