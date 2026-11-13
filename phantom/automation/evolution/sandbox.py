"""evolution/sandbox.py — the only door between the author LLM and this repo.

Policy (as agreed):
  * the author may READ the whole repository — full context, professional
    output — through a bounded, redacted `read()` tool;
  * the author may WRITE only inside three whitelisted directories:
        phantom/automation/guidance/learned/   the new capability
        tests/learned/                         its test
        docs/evolution/<id>/                   the proposal / postmortem
    everything else raises SandboxViolation;
  * redaction happens HERE, on every read result, before the text can
    reach the LLM transport — not in the transport, so a future caller
    cannot forget it.

The sandbox exists so the guardrails cannot be rewritten by the thing
they guard: planner.py, agent.py, gate.py itself are OUTSIDE the write
allowlist by construction, not by the LLM's good behaviour.
"""

from __future__ import annotations

import os
import re
from pathlib import Path
from typing import Dict, List, Optional

from phantom.automation.llm_advisor import redact

PROJECT_ROOT = Path(__file__).resolve().parents[3]

WRITE_ROOTS = (
    "phantom/automation/guidance/learned/",
    "tests/learned/",
    "docs/evolution/",
)

MAX_READS_PER_ATTEMPT = 20
MAX_FILE_BYTES = 200_000          # refuse to read huge artefacts whole
MAX_OUTPUT_CHARS = 16_000         # per-read window given to the LLM

# Files that are NEVER readable by the author, even inside the allowlist:
# secrets and anything that could smuggle instructions into the prompt.
FORBIDDEN_PARTS = (
    ".git", ".env", "__pycache__", "node_modules", ".venv", "venv",
    "data/sessions", "data/remote", "data/beacons",
)

SECRET_PATTERNS = (
    re.compile(r"(?i)(api[_-]?key|token|secret|password|passwd|credential)"
               r"\s*[=:]\s*['\"][^'\"]{6,}['\"]"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----"),
    re.compile(r"ghp_[A-Za-z0-9]{20,}"),          # GitHub PAT
    re.compile(r"(?i)authorization:\s*bearer\s+\S+"),
)


class SandboxViolation(Exception):
    """A write outside the allowlist, or a read of a forbidden file."""


class Sandbox:
    """Read-broad / write-narrow filesystem view for the author agent."""

    def __init__(self, proposal_id: str, root: Optional[Path] = None) -> None:
        self.root = Path(root) if root else PROJECT_ROOT
        self.proposal_id = re.sub(r"[^a-zA-Z0-9_.-]", "_", proposal_id)
        self.reads_used = 0
        self.written: Dict[str, str] = {}   # relpath -> content (staged)

    # ── reads ────────────────────────────────────────────────────────────

    def read(self, relpath: str, offset: int = 0,
             max_lines: int = 400) -> str:
        """Read a repo file (redacted). Counts against the read budget."""
        if self.reads_used >= MAX_READS_PER_ATTEMPT:
            raise SandboxViolation(
                f"read budget exhausted ({MAX_READS_PER_ATTEMPT} per attempt)")
        p = self._resolve_read(relpath)
        self.reads_used += 1
        try:
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError as exc:
            raise SandboxViolation(f"unreadable {relpath}: {exc}") from exc
        lines = text.splitlines()
        window = lines[offset:offset + max_lines]
        out = "\n".join(window)[:MAX_OUTPUT_CHARS]
        return redact(out)

    def tree(self, subdir: str = "", depth: int = 3) -> str:
        """A shallow tree, so the author can orient without burning reads."""
        base = self._resolve_read(subdir or ".")
        lines: List[str] = []
        for cur, dirs, files in os.walk(base):
            rel = os.path.relpath(cur, base)
            if rel == ".":
                rel = subdir or "."
            depth_now = rel.count(os.sep)
            if depth_now >= depth:
                dirs[:] = []
            dirs[:] = [d for d in dirs
                       if not any(part in d for part in FORBIDDEN_PARTS)
                       and d != "__pycache__"]
            lines.append(f"{rel}/")
            for f in sorted(files)[:40]:
                lines.append(f"  {f}")
        return "\n".join(lines[:400])

    # ── writes ───────────────────────────────────────────────────────────

    def stage(self, relpath: str, content: str) -> str:
        """Stage a write; content is validated at gate time, flushed on
        approval. Returns the canonical relpath."""
        rp = self._resolve_write(relpath)
        if len(content) > MAX_FILE_BYTES:
            raise SandboxViolation(
                f"staged file too large ({len(content)} bytes, cap "
                f"{MAX_FILE_BYTES})")
        self.written[rp] = content
        return rp

    def flush(self) -> List[str]:
        """Write every staged file to disk (atomically). Returns paths."""
        out: List[str] = []
        for rp, content in self.written.items():
            p = self.root / rp
            p.parent.mkdir(parents=True, exist_ok=True)
            tmp = p.with_suffix(p.suffix + ".tmp")
            tmp.write_text(content, encoding="utf-8")
            tmp.replace(p)
            out.append(rp)
        return out

    def reset(self) -> None:
        """Drop staged writes (failed attempt → next attempt starts clean)."""
        self.written.clear()

    def cleanup_files(self, relpaths: List[str]) -> None:
        """Remove files this sandbox previously flushed (rollback)."""
        for rp in relpaths:
            p = self.root / rp
            try:
                p.unlink(missing_ok=True)
            except OSError:
                pass

    # ── path policy ──────────────────────────────────────────────────────

    def _resolve_read(self, relpath: str) -> Path:
        p = (self.root / relpath.lstrip("/\\")).resolve()
        if self.root not in p.parents and p != self.root:
            raise SandboxViolation(f"read escapes the repo: {relpath}")
        for part in FORBIDDEN_PARTS:
            if part in p.relative_to(self.root).parts:
                raise SandboxViolation(f"read of forbidden path: {relpath}")
        if p.stat().st_size > MAX_FILE_BYTES if p.exists() else False:
            raise SandboxViolation(f"file too large to read: {relpath}")
        return p

    def _resolve_write(self, relpath: str) -> str:
        rp = relpath.replace("\\", "/").lstrip("/")
        if rp not in ("", ".") and (".." in Path(rp).parts):
            raise SandboxViolation(f"write path traversal: {relpath}")
        allowed = False
        for root in WRITE_ROOTS:
            if rp.startswith(root):
                allowed = True
                break
        if not allowed:
            raise SandboxViolation(
                f"write outside the sandbox: {rp} (allowed roots: "
                + ", ".join(WRITE_ROOTS) + ")")
        # only python/md files in learned/tests; anything textual under docs
        if rp.startswith(("phantom/", "tests/")) and not rp.endswith(".py"):
            raise SandboxViolation(f"only .py files under phantom/tests: {rp}")
        return rp
