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
    lhost: str = ""
    lport: int = 0
    mode: str = ""
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
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        path = os.path.join(sdir, f"{name}.json")
        with tempfile.NamedTemporaryFile(mode='w', dir=sdir, delete=False, suffix='.json', encoding='utf-8') as tmp:
            json.dump(self.__dict__, tmp, indent=2, default=str)
            tmp_path = tmp.name
        os.replace(tmp_path, path)
        console.print(f"[green][+] Session saved: {path}[/]")

    def export_markdown(self, filename: str) -> None:
        """Export session to a structured Markdown report."""
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        path = os.path.join(sdir, filename)
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
        from phantom.utils.paths import sessions_dir
        path = os.path.join(sessions_dir(), f"{name}.json")
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
        from phantom.utils.paths import sessions_dir
        sdir = sessions_dir()
        os.makedirs(sdir, exist_ok=True)
        d = [f.replace(".json", "") for f in os.listdir(sdir) if f.endswith(".json")]
        return sorted(list(set(d)))

    @staticmethod
    def load_raw(name: str) -> dict:
        """Load a session file as a raw dictionary without affecting the current session."""
        from phantom.utils.paths import sessions_dir
        path = os.path.join(sessions_dir(), f"{name}.json")
        if os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as f:
                    return json.load(f)
            except Exception:
                return {}
        return {}

session = Session()
