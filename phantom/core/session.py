import json
import os
import tempfile
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List
from rich.console import Console

console = Console()

@dataclass
class Session:
    target: str = ""
    mode: str = "recon"
    scope: List[str] = field(default_factory=list)
    results: Dict[str, Any] = field(default_factory=dict)
    notes: List[Dict[str, str]] = field(default_factory=list)
    history: List[str] = field(default_factory=list)
    active_wordlist: str = ""
    created_at: str = field(default_factory=lambda: datetime.now().isoformat())

    def add_result(self, module: str, data: Any) -> None:
        self.results[module] = data

    def get_result(self, module: str) -> Any:
        return self.results.get(module)

    def add_note(self, text: str) -> None:
        self.notes.append({
            "timestamp": datetime.now().strftime("%H:%M:%S"),
            "text": text
        })

    def add_history(self, cmd: str) -> None:
        self.history.append(f"[{datetime.now().strftime('%H:%M:%S')}] {cmd}")

    def save(self, name: str) -> None:
        """Save the current session to data/sessions/{name}.json atomically."""
        os.makedirs("data/sessions", exist_ok=True)
        path = f"data/sessions/{name}.json"
        with tempfile.NamedTemporaryFile(mode='w', dir='data/sessions', delete=False, suffix='.json', encoding='utf-8') as tmp:
            json.dump(self.__dict__, tmp, indent=2, default=str)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
        console.print(f"[green][+] Session saved: {path}[/]")

    def load(self, name: str) -> None:
        path = f"data/sessions/{name}.json"
        try:
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for k, v in data.items():
                setattr(self, k, v)
            console.print(f"[green][+] Session loaded: {name}[/]")
        except FileNotFoundError:
            console.print(f"[red]Session '{name}' not found.[/]")

    @staticmethod
    def list_saved() -> List[str]:
        os.makedirs("data/sessions", exist_ok=True)
        return [f.replace(".json", "") for f in os.listdir("data/sessions") if f.endswith(".json")]

session = Session()