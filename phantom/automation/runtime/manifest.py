"""manifest.py — strong validation of a declarative tool manifest.

``drivers.parse_driver`` is deliberately lenient: it returns ``None`` for any
unusable manifest so a bad file never takes the planner down. That is the
right runtime posture, but it is a poor REVIEW posture — "why was my driver
rejected?" had no answer, and a manifest could declare an unknown
placeholder, an unbounded timeout or an out-of-range detection risk and be
dropped without a word.

This module validates a manifest against a strict schema and returns TYPED
errors (field + reason) alongside the parsed :class:`ToolDriver`. It reuses
the driver module's constants and helpers so the two never diverge, then
defers to ``parse_driver`` for the final construction.
"""

from __future__ import annotations

import string
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

from phantom.automation.runtime.drivers import (
    ToolDriver,
    _KNOWN_CATEGORIES,
    _as_str_tuple,
    _binary_matches,
    parse_driver,
)

# manifests must terminate within an hour and stay inside sane risk ranges
MAX_TIMEOUT = 3600
MAX_OPSEC_COST = 10.0
MAX_DETECTION_RISK = 10.0
_STEALTH_LEVELS = ("passive", "quiet", "active", "noisy", "loud")
# implicit placeholders every driver may reference without declaring them
_IMPLICIT_SLOTS = ("target", "host")


@dataclass
class ManifestError:
    """One validation failure: the field and why it was rejected."""

    field: str
    reason: str

    def __str__(self) -> str:
        return f"{self.field}: {self.reason}"


@dataclass
class ValidationResult:
    """The outcome of validating one manifest."""

    ok: bool
    driver: Optional[ToolDriver] = None
    errors: List[ManifestError] = field(default_factory=list)

    def explain(self) -> str:
        if self.ok:
            return f"manifest valid: {self.driver.id if self.driver else '?'}"
        return "; ".join(str(e) for e in self.errors) or "invalid manifest"


def _placeholders(template: str) -> List[str]:
    """Every ``{name}`` field referenced by a template (ignores ``{{``)."""
    out: List[str] = []
    try:
        for _, name, _, _ in string.Formatter().parse(template):
            if name:
                # strip attribute/index access: {a.b} / {a[0]} -> a
                base = name.split(".")[0].split("[")[0].strip()
                if base:
                    out.append(base)
    except ValueError:
        pass
    return out


def validate_manifest(data: Any) -> ValidationResult:
    """Validate one manifest dict -> (driver, typed errors)."""
    errors: List[ManifestError] = []
    if not isinstance(data, dict):
        return ValidationResult(False, None, [ManifestError(
            "<root>", "manifest must be a JSON object")])

    def _need(field_name: str, value: Any) -> None:
        if not value:
            errors.append(ManifestError(field_name, "required and non-empty"))

    cap_id = str(data.get("id") or "").strip()
    tool = str(data.get("tool") or "").strip()
    category = str(data.get("category") or "").strip().lower()
    command = str(data.get("command") or "").strip()
    raw_argv = data.get("argv")
    argv: Tuple[str, ...] = ()
    if isinstance(raw_argv, (list, tuple)):
        argv = tuple(str(a).strip() for a in raw_argv if str(a).strip())
    effects = _as_str_tuple(data.get("effects"))

    _need("id", cap_id)
    _need("tool", tool)
    _need("category", category)
    if category and category not in _KNOWN_CATEGORIES:
        errors.append(ManifestError(
            "category", f"unknown category {category!r}"))
    if not effects:
        errors.append(ManifestError("effects", "declare at least one effect"))
    if not command and not argv:
        errors.append(ManifestError(
            "command", "a command template OR an argv vector is required"))

    # executable allowlist: the declared binary must be the declared tool
    if tool and (command or argv) and not _binary_matches(tool, command, argv):
        errors.append(ManifestError(
            "tool", f"the executable does not match the declared tool "
                    f"{tool!r} (command/argv[0] must invoke it)"))

    # declared input slots
    declared: List[str] = []
    for slot in (data.get("inputs") or []):
        if isinstance(slot, dict) and str(slot.get("name") or "").strip():
            declared.append(str(slot["name"]).strip())
    allowed = set(_IMPLICIT_SLOTS) | set(declared)

    # placeholders: the template must consume something and only declared slots
    used: List[str] = []
    for tmpl in ([command] if command else []) + list(argv):
        used.extend(_placeholders(tmpl))
    if (command or argv) and not used:
        errors.append(ManifestError(
            "command", "the template references no placeholder (a constant "
                       "string is not a driver)"))
    for name in sorted(set(used) - allowed):
        errors.append(ManifestError(
            "inputs", f"unknown placeholder {{{name}}} "
                      f"(declare it under 'inputs' or use one of "
                      f"{sorted(allowed)})"))

    # bounded numeric ranges
    timeout = data.get("timeout", 60)
    try:
        timeout_i = int(timeout)
        if not (0 < timeout_i <= MAX_TIMEOUT):
            errors.append(ManifestError(
                "timeout", f"must be in (0, {MAX_TIMEOUT}]"))
    except (TypeError, ValueError):
        errors.append(ManifestError("timeout", "must be an integer"))

    for name, cap in (("opsec_cost", MAX_OPSEC_COST),
                      ("detection_risk", MAX_DETECTION_RISK)):
        if name in data:
            try:
                value = float(data[name])
                if not (0.0 <= value <= cap):
                    errors.append(ManifestError(
                        name, f"must be within [0, {cap}]"))
            except (TypeError, ValueError):
                errors.append(ManifestError(name, "must be a number"))

    stealth = data.get("stealth_level")
    if stealth is not None and str(stealth).strip().lower() not in _STEALTH_LEVELS:
        errors.append(ManifestError(
            "stealth_level", f"unknown level {stealth!r}"))

    if errors:
        return ValidationResult(False, None, errors)

    driver = parse_driver(data)
    if driver is None:
        errors.append(ManifestError("<root>", "rejected by the driver parser"))
        return ValidationResult(False, None, errors)
    return ValidationResult(True, driver, [])


def validate_manifests(items: List[Any]) -> List[ValidationResult]:
    return [validate_manifest(item) for item in (items or [])]
