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
    ai_connector: Any = None

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

    def export_markdown(self, filename: str) -> None:
        """Export session to a structured Markdown report."""
        os.makedirs("data/sessions", exist_ok=True)
        path = f"data/sessions/{filename}"
        with open(path, "w", encoding="utf-8") as f:
            f.write(f"# Phantom Engagement Report\n")
            f.write(f"**Target:** {self.target}\n")
            f.write(f"**Date:** {self.created_at}\n\n")
            f.write(f"## Command History\n")
            for h in self.history: f.write(f"- {h}\n")
            f.write(f"\n## Notes\n")
            for n in self.notes: f.write(f"- [{n['timestamp']}] {n['text']}\n")
            f.write(f"\n## Results Summary\n")
            for mod, res in self.results.items():
                f.write(f"### {mod.upper()}\n")
                f.write(f"Data captured: {len(str(res))} bytes\n")
        console.print(f"[green][+] Report exported: {path}[/]")

    def load(self, name: str) -> None:
        # Check data/sessions (was formerly workspace/ as well)
        path = f"data/sessions/{name}.json"
        if os.path.exists(path):
            with open(path, 'r', encoding='utf-8') as f:
                data = json.load(f)
            for k, v in data.items():
                setattr(self, k, v)
            console.print(f"[green][+] Session loaded: {path}[/]")
            return
        console.print(f"[red]Session '{name}' not found.[/]")

    @staticmethod
    def list_saved() -> List[str]:
        os.makedirs("data/sessions", exist_ok=True)
        d = [f.replace(".json", "") for f in os.listdir("data/sessions") if f.endswith(".json")]
        return sorted(list(set(d)))

    @staticmethod
    def load_raw(name: str) -> dict:
        """Load a session file as a raw dictionary without affecting the current session."""
        path = f"data/sessions/{name}.json"
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

session = Session()
