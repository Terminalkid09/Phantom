"""
evolution/proposal.py — the markdown-only learning mode (`--oM`).

Two ways to close a learning gap were conflated: "write the capability" and
"write down what happened so a human can write it". The second is often the
right one — an unclear gap, a cause no rule covers, an engagement where the
operator simply wants a reviewed note rather than machine-authored code.

`--oM` (only markdown) makes that a first-class mode:

    * the artifact is a DOSSIER (`docs/evolution/<pid>.md`) built
      deterministically from the triaged case — no LLM, no lab, no code;
    * it runs on its OWN daily budget (`proposals`), so a proposal never
      consumes the gate/PR budget reserved for authored capabilities;
    * publishing reuses the existing PR machinery: an `AuthorResult` with
      only `proposal_relpath` set is exactly what `publish()` already knows
      how to open a branch and a PR for.

Why this matters operationally: proposals still work with no LLM transport
and no lab, which are precisely the two conditions under which the code path
refuses to run. A team with neither can still accumulate reviewed learning.
"""

from __future__ import annotations

import os
import tempfile
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable, Dict, Optional

PROJECT_ROOT = Path(__file__).resolve().parents[3]
EVOLUTION_DOCS = PROJECT_ROOT / "docs" / "evolution"


@dataclass
class ProposalResult:
    ok: bool
    relpath: str = ""
    markdown: str = ""
    case: Dict[str, Any] = field(default_factory=dict)
    error: str = ""


def build_dossier(case: Any) -> str:
    """The markdown for a case. Accepts a FailureCase or its dict form."""
    if hasattr(case, "to_markdown"):
        return case.to_markdown()
    from phantom.automation.brain.triage import FailureCase
    fields = {k: v for k, v in (case or {}).items()
              if k in FailureCase.__dataclass_fields__}
    return FailureCase(**fields).to_markdown()


def _write_atomic(path: Path, text: str) -> None:
    """Temp file + os.replace: a crash mid-write never leaves a torn
    dossier in the tree (same discipline as the evolution state file)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(dir=str(path.parent), prefix=".proposal-",
                               suffix=".tmp")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            fh.write(text)
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, path)
    except BaseException:
        try:
            os.unlink(tmp)
        except OSError:
            pass
        raise


def write_proposal(pid: str, case: Any,
                   emit: Optional[Callable] = None,
                   root: Optional[Path] = None) -> ProposalResult:
    """Materialise the dossier and return it in the publish-compatible shape.

    The result carries `relpath` (relative to the project root, which is
    what `publish()` expects) and the markdown, so a caller that cannot
    publish (no git remote, no budget) still has the artifact on disk.
    """
    try:
        markdown = build_dossier(case)
    except Exception as exc:                     # noqa: BLE001
        return ProposalResult(False, error=f"dossier build failed: {exc}")
    base = Path(root) if root is not None else EVOLUTION_DOCS
    path = base / f"{pid}.md"
    try:
        _write_atomic(path, markdown)
    except OSError as exc:
        return ProposalResult(False, error=f"write failed: {exc}")
    try:
        relpath = str(path.relative_to(PROJECT_ROOT)).replace("\\", "/")
    except ValueError:                            # a custom root outside the repo
        relpath = str(path).replace("\\", "/")
    if emit is not None:
        try:
            emit("note", {"capability": "evolution",
                          "detail": f"proposal written: {relpath}"})
        except Exception:
            pass
    case_dict = case.to_dict() if hasattr(case, "to_dict") else dict(case or {})
    return ProposalResult(True, relpath=relpath, markdown=markdown,
                         case=case_dict)


def as_author_result(proposal: ProposalResult):
    """Wrap a proposal in the AuthorResult shape `publish()` consumes.

    `cap_relpath`/`test_relpath` stay EMPTY on purpose: in proposal mode
    there is no authored code, and `publish()` already skips empty paths
    when it collects the files to commit.
    """
    from phantom.automation.evolution.author import AuthorResult
    return AuthorResult(ok=True, proposal_relpath=proposal.relpath,
                        attempts=0)
