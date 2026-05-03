import builtins
import json
import os
from unittest.mock import MagicMock, mock_open

import pytest

from phantom.core.session import Session


class TestSession:
    def setup_method(self):
        self.session = Session()

    def test_add_result_and_get_result(self):
        """Session should store and retrieve module results."""
        self.session.add_result("scan", {"foo": "bar"})
        assert self.session.get_result("scan") == {"foo": "bar"}

    def test_add_note_adds_timestamp(self):
        """Adding a note should append a timestamp and text to session notes."""
        self.session.add_note("Test note")
        assert len(self.session.notes) == 1
        assert self.session.notes[0]["text"] == "Test note"
        assert "timestamp" in self.session.notes[0]

    def test_add_history_records_command(self):
        """History entries should be recorded with a timestamp."""
        self.session.add_history("set target 10.0.0.1")
        assert len(self.session.history) == 1
        assert "set target 10.0.0.1" in self.session.history[0]

    def test_save_writes_json_file(self, monkeypatch):
        """Session.save should write JSON data to the expected file path."""
        mocked_open = mock_open()
        monkeypatch.setattr(os, "makedirs", lambda *args, **kwargs: None)
        monkeypatch.setattr("builtins.open", mocked_open)
        json_dump_mock = MagicMock()
        monkeypatch.setattr("phantom.core.session.json.dump", json_dump_mock)

        self.session.target = "127.0.0.1"
        self.session.mode = "full"
        self.session.save("testsession")

        mocked_open.assert_called_once_with("data/sessions/testsession.json", "w", encoding="utf-8")
        assert json_dump_mock.called

    def test_load_reads_json_file(self, monkeypatch):
        """Session.load should populate session data from a JSON file."""
        sample_data = {"target": "1.2.3.4", "mode": "recon", "scope": ["10.0.0.0/24"], "results": {}, "notes": [], "history": []}
        mocked_open = mock_open(read_data=json.dumps(sample_data))
        monkeypatch.setattr("builtins.open", mocked_open)
        monkeypatch.setattr("phantom.core.session.json.load", lambda f: sample_data)

        self.session.load("testsession")

        assert self.session.target == "1.2.3.4"
        assert self.session.mode == "recon"
        assert self.session.scope == ["10.0.0.0/24"]

    def test_list_saved_returns_only_json_names(self, monkeypatch):
        """List_saved should return saved session names without file extensions."""
        monkeypatch.setattr(os, "makedirs", lambda *args, **kwargs: None)
        monkeypatch.setattr(os, "listdir", lambda path: ["one.json", "two.txt", "three.json"])

        result = Session.list_saved()
        assert result == ["one", "three"]
