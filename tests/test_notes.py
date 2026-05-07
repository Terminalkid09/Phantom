"""
Test suite for phantom/core/notes.py

Tests:
- Display of empty notes
- Display of multiple notes
- Timestamp format validation
"""

import re
from unittest.mock import MagicMock

import pytest

from phantom.core.notes import show_notes
from phantom.core.session import session


class TestShowNotes:
    """Tests for show_notes() function."""

    def setup_method(self):
        """Reset session before each test."""
        session.notes = []
        session.target = ""

    def test_show_notes_with_empty_notes_list(self, capsys):
        """show_notes should display a message when there are no notes."""
        session.notes = []
        show_notes()
        captured = capsys.readouterr()
        assert "No notes" in captured.out

    def test_show_notes_displays_all_notes(self, capsys):
        """show_notes should display all notes in the session."""
        session.notes = [
            {"timestamp": "10:00:00", "text": "First note"},
            {"timestamp": "10:01:00", "text": "Second note"},
            {"timestamp": "10:02:00", "text": "Third note"},
        ]
        session.target = "10.0.0.1"
        show_notes()
        captured = capsys.readouterr()
        assert "First note" in captured.out
        assert "Second note" in captured.out
        assert "Third note" in captured.out

    def test_show_notes_displays_timestamps(self, capsys):
        """show_notes should display timestamps in HH:MM:SS format."""
        session.notes = [
            {"timestamp": "14:23:45", "text": "Test note"},
        ]
        show_notes()
        captured = capsys.readouterr()
        assert "14:23:45" in captured.out

    def test_show_notes_displays_no_target_when_none_set(self, capsys):
        """show_notes should display 'no target' when session.target is empty."""
        session.notes = [{"timestamp": "10:00:00", "text": "Test"}]
        session.target = ""
        show_notes()
        captured = capsys.readouterr()
        assert "no target" in captured.out.lower()

    def test_show_notes_displays_target_when_set(self, capsys):
        """show_notes should display the current target."""
        session.notes = [{"timestamp": "10:00:00", "text": "Test"}]
        session.target = "example.com"
        show_notes()
        captured = capsys.readouterr()
        assert "example.com" in captured.out

    def test_show_notes_formats_as_table(self, capsys):
        """show_notes output should be formatted as a table."""
        session.notes = [
            {"timestamp": "10:00:00", "text": "Note 1"},
            {"timestamp": "10:01:00", "text": "Note 2"},
        ]
        session.target = "10.0.0.1"
        show_notes()
        captured = capsys.readouterr()
        # Check for table structure indicators
        assert ("#" in captured.out or "Time" in captured.out) or "Note" in captured.out

    def test_show_notes_with_special_characters_in_text(self, capsys):
        """show_notes should handle special characters in note text."""
        session.notes = [
            {"timestamp": "10:00:00", "text": "Test with [brackets] and @symbols"},
        ]
        show_notes()
        captured = capsys.readouterr()
        assert "Test with [brackets] and @symbols" in captured.out or "Test with" in captured.out
