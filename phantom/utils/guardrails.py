"""guardrails.py - what was ON, what the operator turned OFF, and proof.

Phantom's safety controls (scope gate, beacon HMAC, mTLS, API auth, driver
approval) are all on by default and all overridable, because lab work and
production engagements need both. That is the right design and it has one
fatal gap: **an override is invisible once made.**

`PHANTOM_ALLOW_UNSCOPED=1`, `--force-network` and an empty
`PHANTOM_API_TOKEN` all change what the engagement is allowed to do, and
afterwards the report looks exactly like a run where nothing was touched. In
a real engagement that is not a cosmetic problem:

* the operator who set a flag last Tuesday cannot tell, on Monday, that it is
  still set — so a run silently executes outside the agreed scope;
* if the client disputes the engagement, the report cannot demonstrate that
  the declared limits were respected, because it never recorded them.

So every run computes a MANIFEST: the state of each control, where that state
came from (default / config / env / run flag), and a stable digest. The
manifest goes three places — the operator's screen, the report, and the
hash-chained audit log. The operator can still turn anything off; they just
cannot turn it off invisibly.

Design rules, in priority order:
1. Never change what a control DOES. This module only observes and reports.
2. Report the SOURCE, because "off" and "off because you set it last week"
   are different risks.
3. Fail loud on the silent ones. An empty `PHANTOM_API_TOKEN` does not
   disable auth in a visible way today; here it is at least visible.
"""

from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple

# ── where a value came from ─────────────────────────────────────────────────
DEFAULT = "default"      # the safe value, nobody chose it
CONFIG = "config"        # data/config.json, via `phantom setup`
ENV = "env"              # a PHANTOM_* environment variable
STATE = "state"          # the persisted secrets/flags file
RUN = "run"              # a flag on this run only (--force-network)

SOURCE_ORDER = (RUN, ENV, STATE, CONFIG, DEFAULT)


@dataclass(frozen=True)
class Guardrail:
    """One safety control, as it stands right now."""

    key: str
    label: str
    #: True means the control is ACTIVE (scope enforced, auth required...).
    #: The name is the safe direction: `enabled` is what you want.
    enabled: bool
    #: True when disabling is a legitimate, expected operator choice.
    #: Overridable guards still get reported; they are just not alarming.
    overridable: bool = True
    #: One line explaining the CURRENT state, not the general rule.
    detail: str = ""
    source: str = DEFAULT
    #: Where to change it, shown in `guardrails why`.
    remedy: str = ""

    @property
    def overridden(self) -> bool:
        """Off AND chosen by a human, rather than never set."""
        return not self.enabled and self.source != DEFAULT

    def to_dict(self) -> Dict[str, Any]:
        return {
            "key": self.key,
            "label": self.label,
            "enabled": self.enabled,
            "overridable": self.overridable,
            "overridden": self.overridden,
            "detail": self.detail,
            "source": self.source,
            "remedy": self.remedy,
        }


@dataclass
class Manifest:
    """The full picture for one moment in an engagement."""

    guards: List[Guardrail] = field(default_factory=list)
    #: Free-form context (scope, targets, engagement id) shown alongside.
    context: Dict[str, Any] = field(default_factory=dict)

    # ── queries ──
    @property
    def active(self) -> List[Guardrail]:
        return [g for g in self.guards if g.enabled]

    @property
    def off(self) -> List[Guardrail]:
        return [g for g in self.guards if not g.enabled]

    @property
    def overrides(self) -> List[Guardrail]:
        """Controls a human turned off. This is the list that matters."""
        return [g for g in self.guards if g.overridden]

    def get(self, key: str) -> Optional[Guardrail]:
        for g in self.guards:
            if g.key == key:
                return g
        return None

    def summary(self) -> str:
        """One line: how many on, how many a human disabled."""
        off = len(self.overrides)
        if off:
            return (f"{len(self.active)}/{len(self.guards)} guardrails on, "
                    f"{off} disabled by the operator")
        return f"{len(self.active)}/{len(self.guards)} guardrails on"

    def digest(self) -> str:
        """Stable hash of the DECISIONS (not the context).

        Two runs with the same guardrail states share a digest, so the audit
        log can show "nothing changed since the last engagement" without
        storing the whole manifest each time. The context (which target, which
        scope) is deliberately excluded: the digest answers "was this run
        protected the same way", not "was it the same run" — that second
        question is `engagement_digest`.
        """
        payload = json.dumps(
            {g.key: [g.enabled, g.source] for g in sorted(
                self.guards, key=lambda x: x.key)},
            sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def engagement_digest(self) -> str:
        """Hash of decisions PLUS scope and targets.

        Two runs with the same digest() protected the same way; two runs with
        the same engagement_digest() were aimed at the same thing with the
        same protection. Kept separate rather than merged so "protection
        changed" and "target changed" stay distinguishable in the audit log.
        """
        ctx = self.context or {}
        payload = json.dumps({
            "guards": {g.key: [g.enabled, g.source] for g in sorted(
                self.guards, key=lambda x: x.key)},
            "scope": sorted(str(s) for s in (ctx.get("scope") or [])),
            "targets": sorted(str(t) for t in (ctx.get("targets") or [])),
        }, sort_keys=True, separators=(",", ":"))
        return hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16]

    def blocking_overrides(self) -> List[Guardrail]:
        """Overrides that must stop a run while strict mode is on.

        Only real protections, never `network_range`: that one is a per-run
        flag whose whole purpose is to widen a single engagement on purpose,
        and locking it out would make strict mode refuse the legitimate case
        it is meant to leave room for.
        """
        strict = self.get("strict_guardrails")
        if strict is None or not strict.enabled:
            return []
        return [g for g in self.overrides
                if g.key != "network_range" and g.key != "strict_guardrails"]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "guards": [g.to_dict() for g in self.guards],
            "summary": self.summary(),
            "digest": self.digest(),
            "engagement_digest": self.engagement_digest(),
            "overrides": [g.key for g in self.overrides],
            "blocking": [g.key for g in self.blocking_overrides()],
            "context": dict(self.context),
        }


# ── source resolution ───────────────────────────────────────────────────────
def _env(name: str) -> Optional[str]:
    value = os.getenv(name)
    if value is None:
        return None
    return value.strip()


def _config(key: str) -> Optional[Any]:
    try:
        from phantom.utils import config as cfg
        value = cfg.get(key, None)
    except Exception:
        return None
    return value


def _flag(name: str, default: bool) -> Tuple[bool, str]:
    """A boolean state flag + where the answer came from."""
    try:
        from phantom.utils import state as st
    except Exception:
        return default, DEFAULT
    raw = _env(name)
    if raw is not None and raw != "":
        return st.get_flag(name, default), ENV
    with st._STATE_LOCK:
        data = st._read()
    if name in data:
        return st.get_flag(name, default), STATE
    return default, DEFAULT


def _secret(name: str) -> Tuple[bool, str]:
    """A generated secret: present (any source) or absent, plus the source."""
    raw = _env(name)
    if raw:
        return True, ENV
    try:
        from phantom.utils import state as st
    except Exception:
        return False, DEFAULT
    with st._STATE_LOCK:
        data = st._read()
    if data.get(name):
        return True, STATE
    return False, DEFAULT


def _cfg_bool(key: str, env: str) -> Tuple[bool, str]:
    raw = _env(env)
    if raw is not None and raw != "":
        try:
            from phantom.utils import config as cfg
            return cfg.get_bool(key, False, env=env), ENV
        except Exception:
            return raw.lower() in ("1", "true", "yes", "on"), ENV
    try:
        from phantom.utils import config as cfg
        value = cfg.get(key, None)
    except Exception:
        return False, DEFAULT
    if value is None:
        return False, DEFAULT
    try:
        from phantom.utils import config as cfg
        return cfg.get_bool(key, False), CONFIG
    except Exception:
        return bool(value), CONFIG


# ── the guards ──────────────────────────────────────────────────────────────
def _g_scope_gate(scope: Any) -> Guardrail:
    """The API scope gate. OFF means an unscoped target is allowed."""
    allowed, source = _cfg_bool("engagement.allow_unscoped",
                                "PHANTOM_ALLOW_UNSCOPED")
    detail = "scope enforced: a target outside the engagement is refused"
    if allowed:
        detail = "UNSCOPED TARGETS ALLOWED (lab escape hatch)"
    elif not scope:
        detail = ("gate ON, but no scope declared yet - every remote target "
                  "is refused until `scope add <cidr>`")
    return Guardrail(
        "scope_gate", "Scope gate", not allowed,
        overridable=True, detail=detail, source=source,
        remedy="phantom setup -> engagement.allow_unscoped  (or unset "
               "PHANTOM_ALLOW_UNSCOPED)")


def _g_network_range(force_network: bool) -> Guardrail:
    """A CIDR/range engages discovery only unless the operator forces more."""
    if force_network:
        return Guardrail(
            "network_range", "Network range policy", False,
            overridable=True,
            detail="FULL RANGE ENGAGEMENT (--force-network): every host in "
                   "the range is an engagement target",
            source=RUN,
            remedy="drop --force-network; a range is discovery-only by default")
    return Guardrail(
        "network_range", "Network range policy", True,
        detail="a range engages host discovery only; engagement stays "
               "per-target",
        source=DEFAULT,
        remedy="")


def _g_beacon_auth() -> Guardrail:
    enabled, source = _flag("PHANTOM_BEACON_AUTH_REQUIRED", True)
    return Guardrail(
        "beacon_auth", "Beacon HMAC identity", enabled,
        overridable=True,
        detail=("every check-in must carry its per-beacon HMAC identity"
                if enabled else "UNAUTHENTICATED BEACON CHECK-INS ACCEPTED"),
        source=source,
        remedy="PHANTOM_BEACON_AUTH_REQUIRED=1")


def _g_mtls() -> Guardrail:
    enabled, source = _flag("PHANTOM_MTLS_REQUIRED", True)
    return Guardrail(
        "mtls", "mTLS transport", enabled,
        overridable=True,
        detail=("HTTPS + client certificate, server pin verified"
                if enabled else "PLAINTEXT OR UNPINNED C2 TRANSPORT"),
        source=source,
        remedy="PHANTOM_MTLS_REQUIRED=1")


def _g_api_auth() -> Guardrail:
    """API token present.

    This is the silent one: `PHANTOM_API_TOKEN=""` makes the C2 REST surface
    unprotected without saying so. The module cannot fix that (that is the
    server's read path), but it can make it visible in the report.
    """
    present, source = _secret("PHANTOM_API_TOKEN")
    # When absent, the source is DEFAULT whatever the environment says: an
    # EMPTY PHANTOM_API_TOKEN means "use the persisted one", not "the operator
    # switched auth off". Crediting an empty variable to the operator would
    # put a phantom override in every report and train the reader to ignore
    # the ones that matter.
    return Guardrail(
        "api_auth", "API bearer auth", present,
        overridable=True,
        detail=("REST endpoints require a bearer token"
                if present else
                "NO API TOKEN: /api/v1/beacons|queue|results are UNPROTECTED"),
        source=source if present else DEFAULT,
        remedy="phantom setup -> rotate the API token, or unset "
               "PHANTOM_API_TOKEN so the persisted one is used")


def _g_payload_token() -> Guardrail:
    present, source = _secret("PHANTOM_PAYLOAD_TOKEN")
    return Guardrail(
        "payload_token", "Payload delivery token", present,
        overridable=True,
        detail=("payload delivery requires a token"
                if present else "PAYLOAD ENDPOINTS HAVE NO TOKEN"),
        source=source,
        remedy="PHANTOM_PAYLOAD_TOKEN")


def _g_c2_encryption() -> Guardrail:
    key, key_src = _secret("PHANTOM_C2_KEY")
    nonce, nonce_src = _secret("PHANTOM_C2_NONCE")
    ok = key and nonce
    return Guardrail(
        "c2_encryption", "C2 payload encryption", ok,
        overridable=True,
        detail=("beacon config is encrypted at build time"
                if ok else "BEACON CONFIG NOT ENCRYPTED (key or nonce absent)"),
        source=key_src if ok else DEFAULT,
        remedy="rotate the C2 key/nonce (they are generated on first use)")


def _g_strict() -> Guardrail:
    """Lock mode: refuse to START a run while any override is in place.

    The escape hatches above exist for lab work. Some engagements do not want
    them available at all, and today the only thing standing between "a flag
    someone set weeks ago" and "a run outside the agreed scope" is the
    operator remembering. This turns that into a refusal.
    """
    locked, source = _cfg_bool("engagement.strict_guardrails",
                              "PHANTOM_STRICT_GUARDRAILS")
    return Guardrail(
        "strict_guardrails", "Strict guardrails", locked,
        overridable=True,
        detail=("a run REFUSES to start while any other control is overridden"
                if locked else
                "overrides are allowed (an operator can carry one into a run)"),
        source=source,
        remedy="phantom setup -> engagement.strict_guardrails = true")


def _g_driver_approval() -> Guardrail:
    """Discovered drivers must be approved before the planner may load them."""
    try:
        from phantom.automation.runtime.capability_registry import (
            CapabilityRegistry)
        rows = CapabilityRegistry().all()
    except Exception:
        return Guardrail(
            "driver_approval", "Driver approval gate", True,
            detail="registry unavailable - default deny applies",
            source=DEFAULT, remedy="")
    if not rows:
        return Guardrail(
            "driver_approval", "Driver approval gate", True,
            detail="no discovered drivers: only built-in capabilities load",
            source=DEFAULT, remedy="")
    enabled_rows = [r for r in rows if r.enabled]
    return Guardrail(
        "driver_approval", "Driver approval gate", True,
        detail=f"{len(enabled_rows)}/{len(rows)} discovered drivers approved "
               f"and loadable; the rest are refused by the planner",
        source=STATE,
        remedy="tool list / tool enable (see the runtime trust registry)")


def build(*, scope: Any = None, targets: Any = None,
          force_network: bool = False, engagement: str = "") -> Manifest:
    """Compute the manifest for right now.

    Read-only: this never flips a control, it only observes them.
    """
    guards = [
        _g_scope_gate(scope),
        _g_network_range(bool(force_network)),
        _g_beacon_auth(),
        _g_mtls(),
        _g_api_auth(),
        _g_payload_token(),
        _g_c2_encryption(),
        _g_strict(),
        _g_driver_approval(),
    ]
    context: Dict[str, Any] = {}
    if engagement:
        context["engagement"] = engagement
    if scope:
        context["scope"] = list(scope) if isinstance(scope, (list, tuple)) \
            else [scope]
    if targets:
        context["targets"] = list(targets) if isinstance(
            targets, (list, tuple)) else [targets]
    return Manifest(guards=guards, context=context)


# ── rendering ───────────────────────────────────────────────────────────────
_ON = {"on": "ON", "off": "OFF"}


def render(manifest: Manifest) -> str:
    """Plain-text block for the terminal and the report.

    Deliberately plain: it goes into a PDF/markdown report that a non-technical
    reader (a client, a lawyer) may have to interpret, so no colour and no
    shorthand.
    """
    lines = ["GUARDRAILS", "=" * 60]
    for g in manifest.guards:
        mark = "!!" if g.overridden else "  "
        lines.append(f"{mark} {g.label:<26} {_ON['on' if g.enabled else 'off']}"
                     f"   [{g.source}]")
        if g.detail:
            lines.append(f"     {g.detail}")
    lines.append("-" * 60)
    lines.append(manifest.summary())
    overrides = manifest.overrides
    if overrides:
        lines.append("")
        lines.append("DISABLED BY THE OPERATOR (this engagement ran with "
                     "less protection than the default):")
        for g in overrides:
            lines.append(f"  - {g.label}: {g.remedy or 'no remedy recorded'}")
    else:
        lines.append("No operator overrides: the engagement ran at default "
                     "protection.")
    return "\n".join(lines)


def report_block(manifest: Manifest) -> str:
    """Markdown for the engagement report (same facts, report formatting)."""
    lines = ["## Guardrails", "",
             f"_{manifest.summary()}_ — digest `{manifest.digest()}`", "",
             "| Control | State | Set by | Detail |",
             "|---|---|---|---|"]
    for g in manifest.guards:
        state = "**ON**" if g.enabled else "**OFF**"
        detail = g.detail.replace("|", "\\|")
        lines.append(f"| {g.label} | {state} | `{g.source}` | {detail} |")
    overrides = manifest.overrides
    lines.append("")
    if overrides:
        lines.append("### Overrides applied by the operator")
        lines.append("")
        for g in overrides:
            lines.append(f"- **{g.label}** — {g.detail} "
                         f"(set via `{g.source}`; restore with: "
                         f"{g.remedy or 'n/a'})")
    else:
        lines.append("No operator overrides. The engagement ran at the "
                     "default protection level.")
    return "\n".join(lines)


# ── toggling ────────────────────────────────────────────────────────────────
#: Which store each toggle writes to, and whether the stored value is the
#: guard's state or its inverse. The polarity is data, not a branch inside
#: set_guardrail: `scope_gate` is ON when `allow_unscoped` is FALSE, so a
#: switch that forgot this would write the exact opposite of what it says it
#: does — the worst possible failure for a control.
#: key -> (config dotted path, env var, inverted)
_TOGGLES: Dict[str, Tuple[str, Optional[str], bool]] = {
    "scope_gate": ("engagement.allow_unscoped", "PHANTOM_ALLOW_UNSCOPED", True),
    "beacon_auth": (None, "PHANTOM_BEACON_AUTH_REQUIRED", False),
    "mtls": (None, "PHANTOM_MTLS_REQUIRED", False),
    "strict_guardrails": ("engagement.strict_guardrails",
                          "PHANTOM_STRICT_GUARDRAILS", False),
}


def toggleable() -> List[Dict[str, str]]:
    """What the CLI/UI may switch, with the knob each one writes to."""
    out = []
    for key, (cfg_key, env, invert) in _TOGGLES.items():
        out.append({
            "key": key,
            "label": key.replace("_", " "),
            "config_key": cfg_key or "",
            "env": env,
            "inverted": "true" if invert else "false",
            "note": (f"config: {cfg_key}" if cfg_key else f"env only: {env}"),
        })
    return out


def set_guardrail(key: str, enabled: bool) -> Tuple[bool, str]:
    """Flip a toggleable guardrail. Returns (ok, message).

    `enabled` is always the GUARD's state ("the scope gate must be enforced"),
    never the raw stored value. The inversion is applied here so a caller
    cannot get it backwards.

    Refuses anything not in the toggle table rather than guessing: a switch
    that appears to work but writes nowhere is worse than an error.
    """
    if key not in _TOGGLES:
        return False, (f"'{key}' is not operator-toggleable. Toggleable: "
                       f"{', '.join(sorted(_TOGGLES))}. For the rest, see "
                       f"`guardrails why`.")
    cfg_key, env, invert = _TOGGLES[key]
    stored = (not enabled) if invert else bool(enabled)
    try:
        if cfg_key:
            from phantom.utils import config as cfg
            cfg.set(cfg_key, stored)
        else:
            from phantom.utils import state as st
            st.set_flag(env, stored)
    except Exception as exc:
        return False, f"{type(exc).__name__}: {exc}"
    where = f"config ({cfg_key})" if cfg_key else f"state ({env})"
    return True, f"{key} -> {'ON' if enabled else 'OFF'} ({where})"


def snapshot_to_audit(manifest: Manifest, *, event: str = "guardrails",
                      **fields: Any) -> Optional[Dict[str, Any]]:
    """Append the manifest to the hash-chained audit log.

    Best-effort by design: a report must still be produced when the audit
    store is unwritable, so a failure here returns None instead of raising.
    The report always carries the manifest text either way — the audit log is
    the tamper-evident copy, not the only copy.
    """
    try:
        from phantom.utils.audit_log import audit_log
        payload = manifest.to_dict()
        # A dict key literally called "key" is treated by phantom.utils.redact
        # as a credential name and replaced with [REDACTED] — which would have
        # made every audit record useless ("which control?" answered by a
        # redacted blob). The redactor is right to be suspicious of "key", so
        # the audit copy names the field "control" instead.
        payload["guards"] = [
            {("control" if k == "key" else k): v for k, v in g.items()}
            for g in payload.get("guards", [])
        ]
        payload.update(fields)
        return audit_log.append(event, **payload)
    except Exception:
        return None