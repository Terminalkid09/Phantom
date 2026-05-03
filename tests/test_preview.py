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
