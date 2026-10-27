import pytest

from phantom.core.preview import PreviewSession


groups = {
    "NMAP": ["sudo nmap -sS 10.0.0.1", "sudo nmap -sV 10.0.0.1"],
    "NETWORK": ["ping -c 4 10.0.0.1"],
}


class TestPreviewSession:
    def test_initializes_with_flat_groups(self):
        """PreviewSession should flatten grouped commands on initialization."""
        preview = PreviewSession(groups.copy())
        assert preview.run_all() == ["sudo nmap -sS 10.0.0.1", "sudo nmap -sV 10.0.0.1", "ping -c 4 10.0.0.1"]

    def test_edit_replaces_command_at_index(self):
        """edit() should replace the command at the specified flat index."""
        preview = PreviewSession({"NMAP": ["a", "b"], "NETWORK": ["c"]})
        preview.edit(2, "new-b")
        assert preview.run_all()[1] == "new-b"

    def test_remove_rebuilds_flat_list_and_renumbers(self):
        """remove() should remove the command and update the flat command order."""
        preview = PreviewSession({"NMAP": ["a", "b"], "NETWORK": ["c"]})
        preview.remove(1)
        assert preview.run_all() == ["b", "c"]

    def test_add_appends_to_existing_group_and_creates_new_group(self):
        """add() should add commands to existing groups and create groups when needed."""
        preview = PreviewSession({"NMAP": ["a"], "NETWORK": []})
        preview.add("NMAP", "b")
        preview.add("CUSTOM", "x")
        assert preview.run_group("NMAP") == ["a", "b"]
        assert preview.run_group("CUSTOM") == ["x"]

    def test_run_group_returns_correct_commands(self):
        """run_group() should return the commands for the named group."""
        preview = PreviewSession(groups.copy())
        assert preview.run_group("NETWORK") == ["ping -c 4 10.0.0.1"]

    def test_run_group_returns_empty_for_nonexistent_group(self):
        """run_group() should return an empty list for unknown groups."""
        preview = PreviewSession(groups.copy())
        assert preview.run_group("UNKNOWN") == []

    def test_run_all_preserves_flat_order(self):
        """run_all() should return all commands in flat order."""
        preview = PreviewSession(groups.copy())
        expected = ["sudo nmap -sS 10.0.0.1", "sudo nmap -sV 10.0.0.1", "ping -c 4 10.0.0.1"]
        assert preview.run_all() == expected

    def test_indices_after_remove_are_renumbered(self):
        """Indices should renumber automatically after removing a command."""
        preview = PreviewSession({"NMAP": ["a", "b", "c"]})
        preview.remove(2)
        assert preview.run_all() == ["a", "c"]
        assert preview.run_single(2) == ["c"]


class TestNonInteractiveFallback:
    """A piped stdin must not reach `input()`.

    `use scan` + `run` inside a pipe died with "EOF when reading a line",
    which made the manual module shell unscriptable: no CI and no end-to-end
    run could touch it (measured 2026-10-26)."""

    def test_non_interactive_runs_the_first_group_and_says_so(self, capsys):
        preview = PreviewSession(groups.copy())
        chosen = preview.non_interactive()
        assert chosen == groups["NMAP"]
        assert "stdin is not a terminal" in capsys.readouterr().out

    def test_non_interactive_honours_a_named_group(self):
        preview = PreviewSession(groups.copy())
        assert preview.non_interactive("NETWORK") == groups["NETWORK"]

    def test_non_interactive_with_an_unknown_group_runs_nothing(self):
        preview = PreviewSession(groups.copy())
        assert preview.non_interactive("NOPE") is None

    def test_non_interactive_with_no_commands_runs_nothing(self):
        preview = PreviewSession({"NMAP": [], "NETWORK": []})
        assert preview.non_interactive() is None

    def test_first_group_skips_empty_ones(self):
        preview = PreviewSession({"SUGGESTED": [], "NMAP": ["a"]})
        assert preview.group_names() == ["NMAP"]
        assert preview.non_interactive() == ["a"]

    def test_choose_never_calls_input_without_a_terminal(self, monkeypatch):
        import phantom.core.preview as preview_mod

        monkeypatch.setattr(preview_mod, "_stdin_is_tty", lambda: False)
        monkeypatch.setattr(
            preview_mod.PreviewSession, "interactive",
            lambda self: pytest.fail("interactive() reached without a TTY"))
        preview = PreviewSession(groups.copy())
        assert preview.choose() == groups["NMAP"]

    def test_interactive_degrades_on_eof_instead_of_raising(self, monkeypatch,
                                                          capsys):
        def _eof(_prompt=""):
            raise EOFError

        monkeypatch.setattr("builtins.input", _eof)
        preview = PreviewSession(groups.copy())
        assert preview.interactive() == groups["NMAP"]
        assert "stdin closed" in capsys.readouterr().out
