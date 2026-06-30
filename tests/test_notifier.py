import pytest
import logging
from phantom.utils.notifier import notifier
from phantom.core.session import session

def test_notifier_logging(caplog):
    """Verify that notifier logs messages correctly."""
    caplog.set_level(logging.INFO)
    notifier.success("Test Success")
    assert "SUCCESS: Test Success" in caplog.text
    
    notifier.error("Test Error")
    assert "ERROR: Test Error" in caplog.text

def test_session_notes_integration():
    """Verify that notes can be added via session (used by sniffer/web)."""
    initial_count = len(session.notes)
    session.add_note("Automation Test Note")
    assert len(session.notes) == initial_count + 1
    assert session.notes[-1]["text"] == "Automation Test Note"
