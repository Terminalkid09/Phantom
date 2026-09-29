"""Tool provisioning, consent-gated.

The agent plans against the tools it can see (``ToolRegistry``). When a
needed tool is missing, the honest options are: fail loudly, or install
it — but installing is an OPERATOR action, never something the engine
does on its own. This module is the single place where "install a
missing tool" happens, and it refuses without explicit consent.

Isolation note: there is no container and no venv here on purpose. A venv
isolates *Python packages*, not system binaries (nmap, hydra, sqlmap are
OS packages), so the only honest isolation is the operator's own scope:
the existing installer already runs apt/brew/choco/pip in USER scope and
routes WSL installs as root of the toolbox distro.

Nothing here runs by default: ``provision(..., consent=False)`` returns
the plan only. The CLI passes ``consent=True`` only for an explicit
``--allow-install``.
"""
from __future__ import annotations

from typing import Callable, Dict, Iterable, List, Optional

# Baseline recon the planner assumes on a fresh box. Kept small and
# explicit; a profile may widen it later.
CORE_TOOLS = ("nmap", "curl", "nc")


def missing(toolchain, tools: Iterable[str] = CORE_TOOLS) -> List[str]:
    """The tools in ``tools`` the toolchain cannot see (never raises)."""
    out: List[str] = []
    for tool in tools:
        try:
            if not toolchain.has(tool):
                out.append(tool)
        except Exception:
            out.append(tool)
    return out


def provision(tools: Iterable[str], consent: bool,
              installer: Optional[Callable[[str], dict]] = None,
              toolchain=None) -> Dict[str, object]:
    """Install the missing tools — only with consent.

    Returns ``{"plan": [...], "results": {tool: {ok, command, output}},
    "installed": [...], "reason": str}``. Without consent NO installer is
    called; ``reason`` is ``"consent required"``.
    """
    wanted = list(dict.fromkeys(t for t in tools if t))
    if toolchain is not None:
        wanted = missing(toolchain, wanted)
    if not consent:
        return {"plan": wanted, "results": {}, "installed": [],
                "reason": "consent required"}
    if installer is None:
        from phantom.core.executor import install_tool as installer  # type: ignore

    results: Dict[str, dict] = {}
    installed: List[str] = []
    for tool in wanted:
        try:
            res = installer(tool) or {}
        except Exception as exc:  # noqa: BLE001 - never let an install crash a run
            res = {"ok": False, "command": f"install {tool}",
                   "output": str(exc)}
        results[tool] = res
        if res.get("ok"):
            installed.append(tool)
    return {"plan": wanted, "results": results, "installed": installed,
            "reason": "provisioned"}


def provision_missing(toolchain, consent: bool,
                      tools: Iterable[str] = CORE_TOOLS,
                      installer: Optional[Callable[[str], dict]] = None
                      ) -> Dict[str, object]:
    """Convenience: provision the missing subset of ``tools``."""
    return provision(list(tools), consent=consent, installer=installer,
                     toolchain=toolchain)
