import os
from unittest.mock import MagicMock

import pytest

from phantom.core.session import session
from phantom.utils.wordlists import WordlistManager


class TestWordlistManager:
    def setup_method(self):
        self.manager = WordlistManager()

    def test_categorize_known_filenames(self):
        """Known filename patterns should map to the correct category."""
        assert self.manager._categorize("rockyou.txt") == "passwords"
        assert self.manager._categorize("directory-list-2.3-medium.txt") == "directories"
        assert self.manager._categorize("subdomains-top1million.txt") == "subdomains"
        assert self.manager._categorize("usernames.lst") == "usernames"
        assert self.manager._categorize("xss-fuzz.txt") == "web"

    def test_categorize_unknown_filenames_returns_other(self):
        """Unknown filenames should be categorized as other."""
        assert self.manager._categorize("mystery_wordlist.bin") == "other"

    def test_format_size_formats_bytes_kb_mb(self):
        """_format_size should format bytes into B, K, and M units."""
        assert self.manager._format_size(512) == "512B"
        assert self.manager._format_size(2048) == "2K"
        assert self.manager._format_size(2_500_000) == "2M"

    def test_handle_dispatches_to_correct_method(self, monkeypatch):
        """handle() should route commands to the correct internal methods."""
        self.manager._build_index = lambda: None
        called = []

        monkeypatch.setattr(self.manager, "_list", lambda arg="": called.append(("list", arg)))
        monkeypatch.setattr(self.manager, "_use", lambda arg: called.append(("use", arg)))
        monkeypatch.setattr(self.manager, "_search", lambda arg: called.append(("search", arg)))
        monkeypatch.setattr(self.manager, "_info", lambda arg: called.append(("info", arg)))

        self.manager.handle("list passwords")
        self.manager.handle("use /tmp/wordlist.txt")
        self.manager.handle("search ssh")
        self.manager.handle("info rockyou")

        assert called == [
            ("list", "passwords"),
            ("use", "/tmp/wordlist.txt"),
            ("search", "ssh"),
            ("info", "rockyou"),
        ]

    def test_list_with_empty_index_shows_message(self, capsys):
        """_list() should print a help message when the index is empty."""
        self.manager._index = []
        self.manager._list()
        captured = capsys.readouterr()
        assert "No wordlists found" in captured.out

    def test_use_with_absolute_path_sets_active_wordlist(self, monkeypatch):
        """_use() should set the session active_wordlist when given a valid absolute file path."""
        test_path = "/tmp/test_wordlist.txt"
        monkeypatch.setattr(os.path, "isabs", lambda arg: True)
        monkeypatch.setattr(os.path, "isfile", lambda arg: True)

        session.active_wordlist = ""
        self.manager._use(test_path)

        assert session.active_wordlist == test_path
