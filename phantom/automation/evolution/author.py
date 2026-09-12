"""evolution/author.py — the author sub-agent.

An LLM-driven worker (remote-first transport per config; every payload
crossing the transport boundary is already redacted at the sandbox read
layer) that turns a stable failure pattern into a validated capability:

    context  -> prompt built from the experience case: signature, cause,
                the repair that worked, a similar built-in as a worked
                example, the capability schema, the repo tree
    write    -> sandboxed files (capability + test + PROPOSAL)
    validate -> the full gate
    repair   -> gate failure reports fed back as context, up to a
                dynamic attempt budget

The author never decides when it is "done" — the gate does. On final
failure nothing it wrote survives (rollback + postmortem instead of PR).
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Dict, List, Optional, Tuple

from phantom.automation.evolution.sandbox import Sandbox, SandboxViolation
from phantom.automation.evolution import gate as gate_mod

PROJECT_ROOT = Path(__file__).resolve().parents[3]

# A minimal WORKED EXAMPLE ships with the prompt (not read from the repo,
# so the prompt is stable regardless of what the author burns reads on).
_SCHEMA_DOC = '''
You are authoring ONE capability for the Phantom auto-mode planner.

A capability is a module in phantom/automation/guidance/learned/ exposing
exactly one module-level object:

    CAPABILITY = _mk(id, category, desc, inputs, effects, adapter,
                     interpreter=None, opsec_cost=..., detection_risk=...,
                     stealth_level=..., timeout=..., preconditions=[...])

  id             : MUST start with "learned." (e.g. "learned.ssti_waf_bypass")
  category       : one of "recon" | "brute" | "web" | "post" | "cloud" | "mobile"
  inputs         : list of _mk_slot(name, type, required, desc); type is one of
                   "ip" | "port" | "host" | "url" | "username" | "password" |
                   "path" | "wordlist" | "target" | "command" | "choice"
  effects        : fact kinds it produces (e.g. ["web_app", "web_header"])
  adapter        : def _adapter(slots) -> str  — runs ONE command/HTTP request,
                   returns its output. Stdlib only (urllib.request, socket, re,
                   json...). NO third-party imports. NEVER edit files outside
                   your own module. Bounded timeouts on every network call.
  interpreter    : def _interp(output, wm, slots) -> list[Finding]  — parse the
                   output into findings: Finding(kind=..., key=..., value=...,
                   target=wm.target, evidence=output[:400])
  preconditions  : callables over the WorldModel, e.g.
                   lambda wm: bool(wm.find("web_header"))

HARD RULES
  * self-contained: stdlib + phantom imports ONLY; no imports from other
    learned modules; no ctypes/winreg; no writes to the filesystem.
  * opsec: recon/enum probes should be GET-only, low rate, honest
    stealth_level ("passive" | "active" | "aggressive") and honest
    detection_risk. The stealth engine gates on these — do not lie.
  * the interpreter must NEVER crash on unexpected output: wrap parsing
    in try/except and return [].
'''

_WORKED_EXAMPLE = '''# FILE: phantom/automation/guidance/learned/_example_template.py
"""Learned capability template — delete this comment block."""
from phantom.automation.belief import Finding
from phantom.automation.guidance.kit import _mk, _mk_slot


def _adapter(slots):
    import urllib.request
    base = slots.get("base_url") or "http://127.0.0.1:8081"
    url = base.rstrip("/") + "/exports"
    try:
        with urllib.request.urlopen(url, timeout=10) as r:
            return r.read(20000).decode("utf-8", "replace")
    except Exception as exc:
        return f"ERR {exc}"


def _interp(output, wm, slots):
    try:
        if output.startswith("ERR") or "export" not in output.lower():
            return []
        return [Finding(kind="web_app", key="export_endpoint",
                        value={"endpoint": "/exports", "open": True},
                        target=wm.target, evidence=output[:400])]
    except Exception:
        return []


CAPABILITY = _mk(
    "learned.example_export_enum", "web",
    "Enumerate the /exports endpoint exposed by the lab-style app",
    [_mk_slot("base_url", "url", False, "base URL (default target web)")],
    ["web_app"], _adapter, _interp,
    opsec_cost=0.6, detection_risk=0.15, stealth_level="active",
    timeout=30, preconditions=[lambda wm: bool(wm.find("web_header"))],
    banner="learned: /exports enumeration")
'''

_FILE_MARKER = re.compile(
    r"#\s*FILE:\s*(?P<path>[^\n`]+?)\s*```(?:python)?\s*\n(?P<body>.*?)```",
    re.DOTALL)

# the author asks for ONE file at a time ("legge ciò che serve, se serve"):
# it emits `READ <repo-relative-path>` and gets the (redacted) content as
# tool feedback — NO bulk repo dump, no read unless the model asks for it
_READ_REQUEST = re.compile(r"^\s*READ\s+(\S+\.py|\S+\.md)\s*$",
                           re.MULTILINE)
_MAX_TOOL_ROUNDS = 4   # read turns per attempt (within the 20-read budget)


def _generate_with_reads(advisor, prompt: str, sb: Sandbox,
                         temperature: float = 0.2,
                         max_tokens: int = 2400) -> str:
    """Chat loop where the model pulls repo context on demand.

    Round shape: the model replies EITHER with `READ <path>` lines (it
    receives the redacted file content and thinks again) OR with the final
    `# FILE:` blocks. The default prompt already carries the schema, a
    worked example and the tree, so most attempts need zero reads; the
    loop exists for the cases where the author wants to imitate a specific
    built-in's adapter or check a real interpreter's shape.
    """
    messages = [{"role": "user", "content": prompt +
                 "\n\nCONTEXT PROTOCOL: if you need a specific repo file "
                 "(e.g. a similar built-in capability), reply with only "
                 "`READ <repo-relative-path>` (max "
                 f"{_MAX_TOOL_ROUNDS} reads). Otherwise emit the final "
                 "# FILE: blocks directly."}]
    for _ in range(_MAX_TOOL_ROUNDS):
        raw = advisor._chat(messages, temperature=temperature,
                            max_tokens=max_tokens)
        reqs = _READ_REQUEST.findall(raw or "")
        if not reqs:
            return raw or ""
        feedback = []
        for path in reqs[:2]:
            try:
                content = sb.read(path)
                feedback.append(f"--- {path} ---\n{content}")
            except SandboxViolation as exc:
                feedback.append(f"READ {path} refused: {exc}")
        messages.append({"role": "assistant", "content": raw})
        messages.append({"role": "user",
                         "content": "\n".join(feedback) +
                         "\n(continue: more READs or the final # FILE: blocks)"})
    # rounds exhausted: one final forced answer
    return advisor._chat(
        messages + [{"role": "user",
                     "content": "No more reads. Emit the final # FILE: "
                                "blocks now."}],
        temperature=temperature, max_tokens=max_tokens) or ""


@dataclass
class AuthorResult:
    ok: bool
    cap_relpath: str = ""
    test_relpath: str = ""
    proposal_relpath: str = ""
    attempts: int = 0
    gate_history: List[Dict] = field(default_factory=list)
    error: str = ""


class AuthorUnavailable(Exception):
    """No usable LLM transport — the loop must skip, not crash."""


def _extract_files(raw: str) -> Dict[str, str]:
    files: Dict[str, str] = {}
    for m in _FILE_MARKER.finditer(raw or ""):
        path = m.group("path").strip()
        body = m.group("body")
        if path and body.strip():
            files[path] = body
    return files


def dynamic_attempts(case_stats: Dict, floor: int = 3, ceil: int = 5) -> int:
    """The agreed dynamic budget: patterns with a track record of
    successful authoring earn more attempts than cold ones."""
    rate = float(case_stats.get("author_success_rate", 0.0))
    if rate >= 0.5:
        return ceil
    if rate > 0.0:
        return min(ceil, floor + 1)
    return floor


def author(proposal_id: str, case: Dict, advisor,
           sandbox: Optional[Sandbox] = None,
           max_attempts: Optional[int] = None,
           case_stats: Optional[Dict] = None) -> AuthorResult:
    """Run the write->gate->repair loop. Returns a structured result; on
    total failure everything flushed is rolled back and a POSTMORTEM is
    staged for loop.py to persist."""
    if advisor is None or not getattr(advisor, "available", lambda: False)():
        raise AuthorUnavailable("no LLM transport available for authoring")

    sb = sandbox or Sandbox(proposal_id)
    attempts = max_attempts or dynamic_attempts(case_stats or {})
    gate_history: List[Dict] = []
    flushed: List[str] = []
    feedback = ""
    cap_rel = test_rel = proposal_rel = ""

    for attempt in range(1, attempts + 1):
        prompt = _build_prompt(proposal_id, case, sb, feedback, attempt)
        try:
            raw = _generate_with_reads(advisor, prompt, sb)
        except Exception as exc:
            return AuthorResult(ok=False, attempts=attempt,
                                gate_history=gate_history,
                                error=f"transport failure: {exc}")
        files = _extract_files(raw)
        if not files:
            feedback = ("Your previous reply contained no parsable "
                        "# FILE: blocks. Emit every file as:\n"
                        "  # FILE: <repo-relative-path>\\n```python\\n...```")
            continue

        sb.reset()
        cap_rel = test_rel = proposal_rel = ""
        try:
            for path, body in files.items():
                staged = sb.stage(path, body)
                if staged.startswith("phantom/automation/guidance/learned/"):
                    cap_rel = staged
                elif staged.startswith("tests/learned/"):
                    test_rel = staged
                elif staged.endswith("PROPOSAL.md"):
                    proposal_rel = staged
            if not cap_rel:
                feedback = ("No file was staged under "
                            "phantom/automation/guidance/learned/ — the "
                            "capability file is mandatory.")
                continue
            if not test_rel:
                feedback = ("The capability test under tests/learned/ is "
                            "mandatory (stage 3 of the gate runs it).")
                continue
            flushed = sb.flush()
        except SandboxViolation as exc:
            feedback = f"Sandbox refused a write: {exc}. Respect the " \
                       "three allowed roots and the .py-only rule."
            continue

        ok, results = gate_mod.run_gate(cap_rel, test_rel, skip_lab=False)
        gate_history.extend(r.as_dict() for r in results)
        if ok:
            return AuthorResult(ok=True, cap_relpath=cap_rel,
                                test_relpath=test_rel,
                                proposal_relpath=proposal_rel,
                                attempts=attempt, gate_history=gate_history)
        first_fail = next(r for r in results if not r.ok)
        feedback = ("GATE FAILURE. " + first_fail.failure_report()
                    + "\nFix ONLY this problem and re-emit ALL files.")

    # budget exhausted: rollback everything, stage the postmortem
    sb.cleanup_files(flushed)
    _stage_postmortem(sb, proposal_id, case, gate_history)
    return AuthorResult(ok=False, cap_relpath=cap_rel,
                        test_relpath=test_rel, attempts=attempts,
                        gate_history=gate_history,
                        error="attempt budget exhausted; postmortem staged")


def _build_prompt(proposal_id: str, case: Dict, sb: Sandbox,
                  feedback: str, attempt: int) -> str:
    parts = [
        _SCHEMA_DOC,
        "WORKED EXAMPLE (shape and style to imitate):\n```python\n"
        + _WORKED_EXAMPLE + "\n```",
        "THE PATTERN TO SOLVE (from the experience engine; all values "
        "already redacted):",
        f"  proposal_id : {proposal_id}",
        f"  signature   : {case.get('signature_summary', '')}",
        f"  phase       : {case.get('phase', '')}",
        f"  failing technique: {case.get('technique', '')}",
        f"  cause class : {case.get('cause', '')} (n={case.get('n', '?')})",
        f"  remedy observed  : {case.get('remedy', 'none — this is the gap')}",
        f"  evidence     : {case.get('evidence', '')}",
        "You do NOT get the repo dumped on you: the prompt carries the "
        "schema, a worked example and the tree below. If (and only if) you "
        f"need a specific file, request it with `READ <path>` (budget: "
        f"{20 - sb.reads_used} reads left) — e.g. a similar built-in "
        "capability to imitate. The tree (orientation only):\n"
        + sb.tree("phantom/automation", depth=2),
    ]
    if feedback:
        parts.append(f"PREVIOUS ATTEMPT {attempt - 1} FAILED:\n{feedback}")
    parts.append(
        "NOW emit exactly three files, each introduced by a `# FILE:` "
        "marker followed by a fenced code block:\n"
        f"  1. # FILE: phantom/automation/guidance/learned/learned_"
        f"{_slug(proposal_id)}.py\n"
        f"  2. # FILE: tests/learned/test_learned_{_slug(proposal_id)}.py\n"
        f"  3. # FILE: docs/evolution/{proposal_id}/PROPOSAL.md "
        "(what happened, why this capability, expected effect)")
    return "\n\n".join(parts)


def _slug(proposal_id: str) -> str:
    return re.sub(r"[^a-zA-Z0-9_]", "_", proposal_id).strip("_").lower()


def _stage_postmortem(sb: Sandbox, proposal_id: str, case: Dict,
                      gate_history: List[Dict]) -> None:
    lines = [
        f"# Postmortem — {proposal_id}",
        "",
        "The author sub-agent could not produce a gate-clean capability "
        f"within the attempt budget. Nothing was published.",
        "",
        f"- signature: {case.get('signature_summary', '')}",
        f"- technique: {case.get('technique', '')}",
        f"- cause: {case.get('cause', '')} (n={case.get('n', '?')})",
        f"- evidence: {case.get('evidence', '')}",
        "",
        "## Gate history (last attempt)",
    ]
    for g in gate_history[-6:]:
        lines.append(f"- [{g.get('stage')}] ok={g.get('ok')} "
                     f"— {g.get('detail', '')[:200]}")
    try:
        sb.stage(f"docs/evolution/{proposal_id}/POSTMORTEM.md",
                 "\n".join(lines) + "\n")
        sb.flush()
    except SandboxViolation:
        pass
