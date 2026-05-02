import json
import os
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List

@dataclass
class Session:
    """
    Holds all session data. Access via 'from phantom.core.session import session'.
    """
    target: str = ""
    mode: str = "recon"          # recon, osint, full, exploit
    scope: List[str] = field(default_factory=list) # list CIDR or ip
    results: Dict[str, Any] = field(default_factory=dict)
    notes: List[Dict[str, str]] = field(default_factory=list) # list of notes with timestamps
    history: List[str] = field(default_factory=list) # list of commands
    active_wordlist: str = "" # path to the active wordlist file
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    # methods
    def add_result(self, module: str, data: Any) -> None:
        """Store output from a module (e.g., scan results)."""
        self.results[module] = data

    def get_result(self, module: str) -> Any:
        """Retrieve stored results for a given module."""
        return self.results.get(module)

    def add_note(self, text: str) -> None:
        """Add an inline note with a timestamp."""
        self.notes.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "text": text
        })

    def add_history(self, cmd: str) -> None:
        """Add a command to the session history."""
        self.history.append(f"[{datetime.now().strftime('%H:%M:%S')}] {cmd}")

    def save(self, name: str) -> None:
        """Save the current session to data/sessions/{name}.json."""
        os.makedirs("data/sessions", exist_ok=True)
        path = f"data/sessions/{name}.json"
        with open(path, "w", encoding="utf-8") as f:
            json.dump(self.__dict__, f, indent=2, default=str)
        print(f"[+] Session saved: {path}")

    def load(self, name: str) -> None:
        """Load a session from data/sessions/{name}.json."""
        path = f"data/sessions/{name}.json"
        with open(path, "r", encoding="utf-8") as f:
            data = json.load(f)
        for key, value in data.items():
            setattr(self, key, value)

    @staticmethod
    def list_saved() -> List[str]:
        """Return list of saved session names (without .json extension)."""
        os.makedirs("data/sessions", exist_ok=True)
        return [f.replace(".json", "") for f in os.listdir("data/sessions") if f.endswith(".json")]


session = Session()