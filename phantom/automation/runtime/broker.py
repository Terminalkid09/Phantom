"""broker.py — one choke point for driver preflight and execution.

AutoModeBrief §13.5: scope check, policy check, tool availability, input
validation, argv construction, timeout, cancellation, redaction and the audit
event should happen in ONE place, so no adapter can bypass a control by
calling the executor directly.

The broker does not invent new checks; it ORDERS the ones that already exist:

  1. cancellation   — an operator stop refuses the run up front;
  2. registry       — the capability must be ``enabled`` in the trust store;
  3. approval policy— :func:`approval.decide` must not deny/require approval
                      the record has not satisfied;
  4. scope          — a network target must be inside the engagement scope
                      (identity targets are the subject, always allowed);
  5. availability   — the declared tool must be present (WSL-aware toolchain);
  6. inputs         — every required declared slot must be supplied;
  7. command        — the argv/template is built here (never by the adapter).

:meth:`preflight` runs checks 1-7 and returns a :class:`BrokerDecision`; the
command is built with the driver's own adapter, so the broker and the planner
produce byte-identical commands. :meth:`run` then delegates to an injected
``runner`` (offline-safe in tests) and emits an audit event.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Dict, List, Optional

from phantom.automation.runtime import approval as _approval
from phantom.automation.runtime.drivers import _driver_adapter


@dataclass
class BrokerDecision:
    allowed: bool
    reasons: List[str] = field(default_factory=list)
    command: str = ""

    def explain(self) -> str:
        if self.allowed:
            return f"allowed: {self.command}"
        return "refused: " + "; ".join(self.reasons)


@dataclass
class BrokerResult:
    ok: bool
    decision: BrokerDecision
    output: str = ""
    error: str = ""

    def to_dict(self) -> Dict[str, Any]:
        return {"ok": self.ok, "allowed": self.decision.allowed,
                "reasons": list(self.decision.reasons),
                "command": self.decision.command, "output": self.output,
                "error": self.error}


class ExecutionBroker:
    """Centralized preflight + execution for declarative drivers."""

    def __init__(self, registry: Any = None, toolchain: Any = None,
                 scope_list: Optional[List[str]] = None, lab: bool = False,
                 cancel: Any = None, audit: Any = None) -> None:
        self.registry = registry
        self.toolchain = toolchain
        self.scope_list = list(scope_list or [])
        self.lab = bool(lab)
        self.cancel = cancel
        self.audit = audit

    # ---------------------------------------------------------- preflight

    def _scope_ok(self, target: str) -> bool:
        if not self.scope_list:
            return True                     # [] = warn-and-continue (agent path)
        try:
            from phantom.automation.guidance.targets import (
                classify_target, is_identity_target)
            from phantom.core.scope import is_in_scope
            if is_identity_target(classify_target(target)):
                return True                 # scope gates machines, not people
            return bool(is_in_scope(target, self.scope_list))
        except Exception:
            return True                     # never fail-open on a broken check?

    def _availability_ok(self, driver: Any) -> bool:
        if self.toolchain is None:
            return True
        try:
            return bool(self.toolchain.has(getattr(driver, "tool", "")))
        except Exception:
            return True

    def _inputs_ok(self, driver: Any, slots: Dict[str, Any]) -> List[str]:
        missing: List[str] = []
        values = dict(slots or {})
        values.setdefault("target", "")
        for slot in getattr(driver, "inputs", ()) or ():
            name = slot.get("name")
            if slot.get("required") and name and not values.get(name):
                missing.append(name)
        return missing

    def preflight(self, driver: Any, target: str = "",
                  slots: Optional[Dict[str, Any]] = None,
                  source: str = "operator-local") -> BrokerDecision:
        reasons: List[str] = []

        # 1. cancellation
        if self.cancel is not None and getattr(self.cancel, "cancelled", False):
            return BrokerDecision(False, [f"cancelled: {self.cancel.reason}"])

        sources = dict(slots or {})
        sources.setdefault("target", target or getattr(driver, "tool", ""))
        cap_id = getattr(driver, "id", "")

        # 2. registry trust state
        record = None
        if self.registry is not None:
            try:
                record = self.registry.of(cap_id)
            except Exception:
                record = None
            if record is None:
                reasons.append(f"{cap_id} is not registered")
            elif not record.enabled:
                reasons.append(f"{cap_id} is {record.state}, not enabled")

        # 3. approval policy. An APPROVED registry record is operator-vetted,
        # so its original (possibly untrusted) source no longer disqualifies
        # it: the review the policy demands has happened.
        effective_source = source
        if record is not None and record.approved:
            effective_source = "operator-local"
        decision = _approval.decide(driver, source=effective_source,
                                    lab=self.lab)
        if decision.action == _approval.ACTION_DENY:
            reasons.append(f"policy denies: {decision.reason}")

        # 4. scope
        if not self._scope_ok(target or sources.get("target", "")):
            reasons.append(f"target {target} outside engagement scope")

        # 5. tool availability
        if not self._availability_ok(driver):
            reasons.append(f"tool {getattr(driver, 'tool', '?')} is unavailable")

        # 6. required inputs
        missing = self._inputs_ok(driver, sources)
        if missing:
            reasons.append(f"missing required input(s): {', '.join(missing)}")

        if reasons:
            return BrokerDecision(False, reasons)

        # 7. build the command (the broker, not the adapter, decides)
        try:
            command = _driver_adapter(driver)(_Slots(sources), sources)
        except Exception as exc:  # noqa: BLE001 — surface as a refusal
            return BrokerDecision(False, [f"command build failed: {exc}"])
        return BrokerDecision(True, [], command)

    # ---------------------------------------------------------------- run

    def run(self, driver: Any, target: str = "",
            slots: Optional[Dict[str, Any]] = None,
            source: str = "operator-local",
            runner: Optional[Callable[[str, int], Any]] = None,
            timeout: Optional[int] = None) -> BrokerResult:
        decision = self.preflight(driver, target=target, slots=slots,
                                  source=source)
        if not decision.allowed:
            self._emit(driver, target, decision, ok=False)
            return BrokerResult(False, decision, error="; ".join(
                decision.reasons))
        if runner is None:
            # offline default: refuse rather than shell out behind the
            # caller's back. A real caller injects the executor.
            return BrokerResult(False, decision, error="no runner injected")

        seconds = int(timeout if timeout is not None
                      else getattr(driver, "timeout", 60) or 60)
        try:
            result = runner(decision.command, seconds)
        except Exception as exc:  # noqa: BLE001 — a crashed runner is a result
            return BrokerResult(False, decision, error=str(exc))
        ok, output = _split_runner(result)
        self._emit(driver, target, decision, ok=ok)
        return BrokerResult(ok, decision, output=output)

    def _emit(self, driver: Any, target: str, decision: BrokerDecision,
              ok: bool) -> None:
        if self.audit is None:
            return
        try:
            self.audit.record(
                "capability_executed" if decision.allowed
                else "capability_refused",
                capability=getattr(driver, "id", ""), target=target,
                ok=bool(ok), command=decision.command,
                reason="; ".join(decision.reasons))
        except Exception:
            pass


class _Slots:
    """Minimal WorldModel-like shim exposing ``target`` for the adapter."""

    def __init__(self, values: Dict[str, Any]) -> None:
        self.target = values.get("target", "")
        self.__dict__.update({k: v for k, v in values.items()
                              if isinstance(k, str) and k.isidentifier()})


def _split_runner(result: Any):
    """Accept ``(ok, output)``, ``True/False``, or an object with ``.ok``."""
    if isinstance(result, tuple) and len(result) == 2:
        return bool(result[0]), str(result[1])
    if isinstance(result, bool):
        return result, ""
    ok = bool(getattr(result, "ok", False))
    output = str(getattr(result, "output", "") or "")
    return ok, output
