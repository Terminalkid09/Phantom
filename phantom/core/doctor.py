"""doctor.py — `phantom doctor`: one-command environmental self-check.

The preflight of the AUTOMATION guards scope/opsec; the doctor guards the
ENVIRONMENT: when a tool is missing, the config incoherent or a data file
unreadable, the operator learns it NOW instead of discovering a silent
half-broken run. Every check is offline by default; --net adds the active
probes (C2, msf rpc, dead drop) — nothing is executed against targets.

Checks (each returns a Check):
  PASS  ok          — green, nothing to do
  WARN  degraded    — works, but a capability is limited (yellow)
  FAIL  broken      — this will bite mid-run (red), with a fix hint

The doctor never mutates anything, never touches targets, and works on a
fresh checkout with zero configuration (that state is itself reported).
"""

from __future__ import annotations

import os
import shutil
import socket
from dataclasses import dataclass, field
from typing import Callable, List, Optional, Tuple


@dataclass
class Check:
    name: str
    status: str            # "pass" | "warn" | "fail"
    detail: str = ""
    hint: str = ""

    @property
    def mark(self) -> str:
        return {"pass": "✔", "warn": "!", "fail": "✘"}.get(self.status, "?")


@dataclass
class DoctorReport:
    checks: List[Check] = field(default_factory=list)

    @property
    def fails(self) -> List[Check]:
        return [c for c in self.checks if c.status == "fail"]

    @property
    def warns(self) -> List[Check]:
        return [c for c in self.checks if c.status == "warn"]

    def ok(self) -> bool:
        return not self.fails


CheckFn = Callable[[], Check]


def _config_base_url() -> Tuple[str, int, bool]:
    """(host, port, ssl) of the configured C2 listener."""
    from phantom.utils import config as cfg
    host = cfg.get_str("c2.host", "127.0.0.1")
    port = cfg.get_int("c2.port", 8443)
    ssl = cfg.get_bool("c2.ssl", True)
    return host, port, ssl


def _python_check() -> Check:
    import sys
    if sys.version_info >= (3, 10):
        return Check("python", "pass",
                     f"{sys.version_info.major}.{sys.version_info.minor}"
                     f".{sys.version_info.micro}")
    return Check("python", "fail", f"{sys.version_info.major}"
                 f".{sys.version_info.minor}",
                 hint="Phantom targets Python 3.10+ (3.10 is what the "
                      "suite runs on)")


def _core_deps_check() -> Check:
    """The imports the core path cannot run without."""
    missing: List[str] = []
    for mod in ("rich", "requests", "aiohttp", "cryptography"):
        try:
            __import__(mod)
        except ImportError:
            missing.append(mod)
    if missing:
        return Check("core-deps", "fail",
                     "missing: " + ", ".join(missing),
                     hint="pip install -r requirements.txt")
    return Check("core-deps", "pass", "rich, requests, aiohttp, cryptography")


def _buildable_platforms() -> List[str]:
    """Platforms the beacon can actually be BUILT for on this box.

    Each target class needs its own toolchain; discovering that only when
    `generate <platform>` runs mid-engagement is too late, so the doctor
    lists them up front.
    """
    out: List[str] = []
    if shutil.which("g++"):
        out.append("linux")
    if shutil.which("x86_64-w64-mingw32-g++") or shutil.which("g++"):
        out.append("windows")
    osxcross = os.environ.get("OSXCROSS_ROOT", "")
    if shutil.which("o64-clang++") or shutil.which("xcrun") or osxcross:
        out.append("macos")
    ndk = os.environ.get("ANDROID_NDK_HOME", "/opt/android-ndk")
    if os.path.isdir(ndk):
        out.append("android")
    return out


def _toolchain_check() -> Check:
    """Beacon build toolchain: what we can build, not just "is g++ there"."""
    platforms = _buildable_platforms()
    if not platforms:
        return Check("beacon-toolchain", "warn", "no g++/mingw on PATH",
                     hint="beacon builds need a C++ compiler (MSYS2 mingw on "
                          "Windows: pacman -S mingw-w64-x86_64-gcc); other "
                          "features work without it")
    detail = "buildable: " + ", ".join(platforms)
    missing = [p for p in ("linux", "windows", "macos", "android")
               if p not in platforms]
    if missing:
        return Check("beacon-toolchain", "pass",
                     detail + f" (no toolchain for: {', '.join(missing)})")
    return Check("beacon-toolchain", "pass", detail)


def _ad_tools_check() -> Check:
    """AD tooling, resolved through the alias map (impacket-* counts)."""
    try:
        from phantom.automation.runtime.toolchain import ToolRegistry
        reg = ToolRegistry()
    except Exception as exc:
        return Check("ad-tools", "warn", f"registry unavailable: {exc}")
    logical = ("GetUserSPNs.py", "GetNPUsers.py", "secretsdump.py",
               "psexec.py")
    missing = [n for n in logical if not reg.has(n)]
    if not missing:
        return Check("ad-tools", "pass", "kerberoast, asreproast, dcsync, "
                                           "psexec resolve")
    return Check("ad-tools", "warn", "missing: " + ", ".join(missing),
                 hint="pip install impacket provides impacket-* entry points; "
                      "the AD chain (ad/crack/deep) needs them")


def _c2_hardening_check() -> Check:
    """Transport posture: bind, TLS, client-cert requirement."""
    from phantom.utils import config as cfg
    try:
        bind = cfg.get_str("c2.bind", "0.0.0.0",
                           env="PHANTOM_C2_BIND") or "0.0.0.0"
        ssl_on = cfg.get_bool("c2.ssl", True, env="PHANTOM_C2_SSL")
        require_cert = cfg.get_bool("c2.mtls_require_client_cert", True,
                                    env="PHANTOM_MTLS_REQUIRE_CLIENT_CERT")
        allow_plain = cfg.get_bool("c2.allow_plaintext", False,
                                   env="PHANTOM_ALLOW_PLAINTEXT")
    except Exception as exc:
        return Check("c2-transport", "warn", f"config unreadable: {exc}")
    if (not ssl_on or allow_plain) and bind not in ("127.0.0.1", "::1",
                                                    "localhost"):
        return Check("c2-transport", "fail",
                     f"plaintext C2 on {bind}",
                     hint="a clear-text listener on a non-loopback bind is "
                          "readable and hijackable: enable TLS (default) or "
                          "set c2.allow_plaintext=false")
    if not require_cert:
        return Check("c2-transport", "warn",
                     f"TLS on {bind}, client certs OPTIONAL",
                     hint="without a required client certificate the only gate "
                          "is the app-layer HMAC — set "
                          "c2.mtls_require_client_cert=true")
    return Check("c2-transport", "pass",
                 f"TLS + required client cert, bind {bind}")


def _c2_backend_check() -> Check:
    """Which data plane is selected, and is it actually available?

    `c2.transport_backend` picks between the in-tree Python listener and the
    `c2d` Go binary. Selecting a backend that is not built is a silent
    no-listener run, so it is reported here.
    """
    import os
    from phantom.utils import config as cfg
    try:
        backend = str(cfg.get("c2.transport_backend", "python")
                      or "python").strip().lower()
    except Exception as exc:
        return Check("c2-backend", "warn", f"config unreadable: {exc}")
    if backend not in ("python", "go"):
        return Check("c2-backend", "warn", f"unknown backend '{backend}'",
                     hint="c2.transport_backend must be 'python' (default) "
                          "or 'go'")
    if backend == "go":
        from phantom.utils.paths import project_root
        name = "c2d.exe" if os.name == "nt" else "c2d"
        if not os.path.exists(os.path.join(project_root(), "c2d", name)):
            return Check("c2-backend", "warn", "backend 'go' selected but "
                         "c2d is not built",
                         hint="build it: cd c2d && go build -o " + name + " .")
        return Check("c2-backend", "pass", "go data plane (c2d)")
    return Check("c2-backend", "pass", "python data plane (default)")


def _c2_operator_auth_check() -> Check:
    """C-4: refuse an operator API with no authentication on a public bind.

    The listener's REST control surface is guarded by mTLS AND/OR the API
    token. On a non-loopback bind with NEITHER, anyone who can reach the port
    can drive the engagement (queue tasks, revoke identities). The Python
    listener and c2d both refuse to start in that shape; the doctor flags it
    so it is caught at setup time, not at bind time.
    """
    from phantom.utils import config as cfg
    try:
        bind = cfg.get_str("c2.bind", "0.0.0.0",
                           env="PHANTOM_C2_BIND") or "0.0.0.0"
        mtls = cfg.get_bool("c2.mtls", True)
    except Exception as exc:
        return Check("c2-operator-auth", "warn", f"config unreadable: {exc}")
    try:
        from phantom.utils.c2_crypto import get_api_token
        token = str(get_api_token() or "").strip()
    except Exception:
        token = ""
    loopback = bind.strip().lower() in ("127.0.0.1", "::1", "localhost")
    if loopback:
        return Check("c2-operator-auth", "pass", f"bind {bind} (loopback only)")
    if mtls or token:
        gate = "mTLS" if mtls else "API token"
        return Check("c2-operator-auth", "pass",
                     f"bind {bind}; {gate} required")
    return Check("c2-operator-auth", "warn",
                 f"bind {bind} with NEITHER mTLS nor an API token",
                 hint="the operator REST API would be unauthenticated; set "
                      "c2.mtls=true or generate an API token")


def _c2d_capabilities_check() -> Check:
    """C-3/D-2: which surfaces the Go data plane does NOT port.

    c2d answers /api/v1/capabilities; anything false there stays in the
    Python control plane and returns 501 from the Go listener. Reported so a
    `transport_backend=go` run does not discover the boundary mid-engagement.
    """
    from phantom.utils import config as cfg
    try:
        backend = str(cfg.get("c2.transport_backend", "python")
                      or "python").strip().lower()
    except Exception:
        backend = "python"
    if backend != "go":
        return Check("c2d-capabilities", "pass",
                     "python data plane (full surface)")
    gaps = "task policy (capability/grant), /s/android stager"
    return Check("c2d-capabilities", "warn",
                 f"go data plane: {gaps} stay in Python (answered 501)",
                 hint="audit trail and replay persistence ARE ported; see "
                      "GET /api/v1/capabilities on the listener")


def _secrets_at_rest_check() -> Check:
    """D-3: the state files hold every secret IN THE CLEAR.

    Encrypting the file contents is not possible without giving Node and Go
    a matching DPAPI reader, so the protection is FILE PERMISSIONS. This
    check confirms the owner-only hardening actually took (Windows used to be
    a silent no-op because `chmod` only toggles the read-only bit there).
    """
    from phantom.utils.secret_store import locked_down
    paths = []
    try:
        from phantom.utils.state import state_file
        paths.append(state_file())
    except Exception:
        pass
    try:
        from phantom.utils.beacon_auth import registry_path
        paths.append(registry_path())
    except Exception:
        pass
    present = [p for p in paths if p and os.path.exists(p)]
    if not present:
        return Check("secrets-at-rest", "pass", "no state file yet")
    weak = [p for p in present if not locked_down(p)]
    if weak:
        return Check("secrets-at-rest", "warn",
                     "owner-only perms not confirmed",
                     hint="the C2 key / API token / beacon secrets sit in the "
                          "clear in these files — restrict them to the owner "
                          "(POSIX chmod 0600, Windows icacls)")
    return Check("secrets-at-rest", "pass",
                 f"owner-only perms on {len(present)} state file(s)"
                 " (values are plaintext at rest)")


def _c2_front_check() -> Check:
    """Redirector-first: is the backend kept OUT of the compiled beacon?

    A beacon carries whatever endpoint it was built with. Without a
    disposable `c2.front` that is the operator's own listener, so an analyst
    who captures a beacon has the backend to attack. The front is what makes
    a captured beacon point at a hop you can burn and rotate.
    """
    from phantom.utils.network import (c2_pin_cert_path, front_guard_reason,
                                       get_c2_front)
    try:
        front = get_c2_front()
    except Exception as exc:
        return Check("c2-front", "warn", f"config unreadable: {exc}")
    if not front:
        return Check("c2-front", "warn", "no redirector front configured",
                     hint="beacons are built with the operator's own C2 "
                          "address, so a captured beacon points at the "
                          "backend — set c2.front to a throwaway "
                          "redirector/CDN")
    reason = front_guard_reason(front[0])
    if reason:
        return Check("c2-front", "warn", "front misconfigured", hint=reason)
    # Which certificate the beacon will PIN: a TLS-terminating front has its
    # own, so the backend pin would fail every check-in there.
    if not front[2]:
        pin_src = "n/a (plaintext front)"
    elif c2_pin_cert_path():
        pin_src = "front certificate"
    else:
        pin_src = ("backend certificate — set c2.front_cert if the front "
                   "terminates TLS")
    return Check("c2-front", "pass",
                 f"beacons dial the front {front[0]}:{front[1]}"
                 f" ({'https' if front[2] else 'http'}); pin={pin_src}"
                 " — backend not embedded")


def _data_usage_check() -> Check:
    """Disk the engagement is actually paying for (artifact classes)."""
    from phantom.utils.paths import data_dir
    try:
        from phantom.core.artifact_policy import usage_report
        rows = usage_report(data_dir())
    except Exception as exc:
        return Check("data-usage", "warn", f"unavailable: {exc}")
    if not rows:
        return Check("data-usage", "pass", "no artifacts yet")
    rows.sort(key=lambda r: -r["bytes"])
    total = sum(r["bytes"] for r in rows)
    detail = ", ".join(f"{r['dir']}={_human_bytes(r['bytes'])}"
                       for r in rows[:4])
    keep = [r for r in rows if not r["ttl_days"] and r["bytes"] > 2 * 1024**3]
    if keep:
        return Check("data-usage", "warn",
                     f"{_human_bytes(total)} total ({detail})",
                     hint="; ".join(f"{r['dir']} has no TTL "
                                    f"({_human_bytes(r['bytes'])})"
                                    for r in keep)
                     + " — prune old runs manually")
    return Check("data-usage", "pass", f"{_human_bytes(total)} ({detail})")


def _human_bytes(n: float) -> str:
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if n < 1024 or unit == "TB":
            return f"{n:.0f}{unit}" if unit == "B" else f"{n:.1f}{unit}"
        n /= 1024
    return f"{n:.1f}TB"


def _toolbelt_check(belt=None) -> Check:
    """Which implementer the run will actually pick per capability.

    The planner routes each capability to the best INSTALLED tool for the
    target's surface (``brain/toolbelt.py``). A capability with no
    implementer on this box is a move the run can never make, so it is
    named up front instead of surfacing as a mid-run ``tool_missing``.
    ``belt`` is injectable so the check is testable without spawning WSL
    probes for every catalogue entry.
    """
    try:
        from phantom.automation.brain.toolbelt import Toolbelt
        from phantom.automation.runtime.toolchain import ToolRegistry
        # native PATH only by default: WSL resolution costs a probe per tool
        # and the toolbelt scans ~9 capabilities, so the bulk check stays
        # fast. A tool that only exists in WSL is reported by _ad_tools_check
        # (which does resolve through WSL) — this check is the native map.
        belt = belt or Toolbelt(ToolRegistry(wsl=False))
        status = belt.status()
    except Exception as exc:
        return Check("toolbelt", "warn", f"selection unavailable: {exc}")
    if not status:
        return Check("toolbelt", "pass", "no capabilities to route")
    unrouted = sorted(cap for cap, ch in status.items() if ch.tool is None)
    if unrouted:
        hint = "; ".join(
            f"{cap} \u2190 {', '.join(status[cap].alternatives_missing)}"
            for cap in unrouted[:4])
        return Check(
            "toolbelt", "warn",
            f"{len(unrouted)} capability(ies) with no installed tool: "
            f"{', '.join(unrouted)}",
            hint=hint + " — these moves are unavailable (others fall back)")
    return Check("toolbelt", "pass",
                 f"{len(status)} capability(ies) routed to an installed tool")


def _external_services_check() -> Check:
    """Which passive external-intel services the operator can lean on.

    These augment a local scan with the wider internet's view: Shodan
    exposure, crt.sh CT-log subdomains, NVD CVE correlation, BGP netblocks.
    They are called by the capabilities that need them, never speculatively.
    This check is OFFLINE: it reports what is wired and whether an optional
    Shodan key upgrades the keyless InternetDB host lookup.
    """
    try:
        from phantom.utils import api as ext
        wired = [label for fn, label in (
            (ext.shodan_lookup, "shodan/internetdb"),
            (ext.crtsh_lookup, "crt.sh"),
            (ext.nvd_lookup, "nvd"),
            (ext.bgp_lookup, "bgp")) if callable(fn)]
    except Exception as exc:
        return Check("external-services", "warn", f"unavailable: {exc}")
    if not wired:
        return Check("external-services", "warn", "no external intel wired")
    key = os.environ.get("SHODAN_API_KEY", "")
    if not key:
        try:
            from phantom.core.session import session
            key = str(session.results.get("config", {})
                      .get("shodan_key", "") or "")
        except Exception:
            key = ""
    detail = ("available: " + ", ".join(wired)
              + " (shodan keyless InternetDB)")
    if key:
        return Check("external-services", "pass",
                     detail + "; authenticated Shodan search enabled")
    return Check("external-services", "pass", detail,
                 hint="set a Shodan key (`set-key <key>`) for search/stats "
                      "beyond the keyless InternetDB host lookup")


def _data_dir_check() -> Check:
    from phantom.utils.paths import data_dir
    d = data_dir()
    if not os.path.isdir(d):
        try:
            os.makedirs(d, exist_ok=True)
        except OSError as exc:
            return Check("data-dir", "fail", f"{d}: {exc}",
                         hint="check permissions, or set PHANTOM_DATA_DIR "
                              "to a writable directory")
    probe = os.path.join(d, ".doctor_probe")
    try:
        with open(probe, "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(probe)
    except OSError as exc:
        return Check("data-dir", "fail", f"{d}: not writable ({exc})",
                     hint="set PHANTOM_DATA_DIR to a writable directory")
    return Check("data-dir", "pass", d)


def _config_check() -> Check:
    from phantom.utils import config as cfg
    problems: List[str] = []
    port = cfg.get_int("c2.port", 8443)
    if not (1 <= port <= 65535):
        problems.append(f"c2.port={port} out of range")
    url = ""
    try:
        from phantom.utils.dead_drop import configured_url
        url = configured_url()
    except Exception:
        pass
    if url and not url.lower().startswith(("http://", "https://")):
        problems.append("c2.dead_drop is not an http(s) URL")
    if problems:
        return Check("config", "fail", "; ".join(problems),
                     hint="fix data/config.json (or `config` to inspect)")
    return Check("config", "pass", "c2 endpoint + dead drop coherent")


def _experience_check() -> Check:
    """The learning-memory store: readable, writable, healthy."""
    from phantom.automation.brain.experience.cases import (
        CaseStore, experience_path)
    path = experience_path()
    store = CaseStore(enabled=True)   # load probe only; save() below reverts
    stats = store.stats()
    n = int(stats.get("episodes", 0) or 0)
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path + ".doctor_probe", "w", encoding="utf-8") as fh:
            fh.write("ok")
        os.remove(path + ".doctor_probe")
    except OSError as exc:
        return Check("experience", "warn", f"store not writable: {exc}",
                     hint="learning falls back to run-only; check "
                          "data/ permissions")
    detail = f"{n} episode(s), {path}"
    return Check("experience", "pass", detail)


def _llm_check() -> Check:
    from phantom.utils import config as cfg
    if not cfg.get_bool("llm.enabled", False):
        return Check("llm-advisor", "pass", "off (optional feature)")
    model = cfg.get_str("llm.model_path", "")
    if model and not os.path.exists(model):
        return Check("llm-advisor", "fail", f"model file missing: {model}",
                     hint="point llm.model_path at a local .gguf file")
    return Check("llm-advisor", "pass", "enabled"
                 + (f", {os.path.basename(model)}" if model else ""))


def _scopes_check() -> Check:
    """Transports that only matter when configured: flag half-configs."""
    from phantom.utils import config as cfg
    issues: List[str] = []
    smtp_user = cfg.get_str("transports.smtp.username", "")
    smtp_pass = cfg.get_str("transports.smtp.password", "")
    if bool(smtp_user) != bool(smtp_pass):
        issues.append("smtp: username without password (or vice versa)")
    if issues:
        return Check("transports", "warn", "; ".join(issues),
                     hint="complete the credentials or leave them empty")
    return Check("transports", "pass", "no half-configured credentials")


# ── active probes (--net) ────────────────────────────────────────────────

def _probe_tcp(host: str, port: int, timeout: float = 3.0) -> bool:
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except OSError:
        return False


def _c2_reachable_check() -> Check:
    host, port, _ssl = _config_base_url()
    if _probe_tcp(host, port):
        return Check("c2-listener", "pass", f"{host}:{port} accepting")
    return Check("c2-listener", "warn", f"{host}:{port} not accepting now",
                 hint="start the listener (`c2` -> listen, or it auto-starts "
                      "on demand) — not an error until you need beacons")


def _msf_check() -> Check:
    from phantom.utils import config as cfg
    host = cfg.get_str("c2.host", "127.0.0.1")
    if _probe_tcp(host, 55553, timeout=2.0):
        return Check("msf-rpc", "pass", f"{host}:55553 accepting")
    return Check("msf-rpc", "warn", "not reachable (optional)",
                 hint="only needed for msf-driven modules")


def _dead_drop_net_check() -> Check:
    try:
        from phantom.utils.dead_drop import configured_url, fetch
        url = configured_url()
    except Exception:
        url = ""
    if not url:
        return Check("dead-drop", "pass", "not configured (last ring unused)")
    try:
        rec = fetch(url)
    except Exception as exc:
        return Check("dead-drop", "warn", f"{url}: unreachable ({exc})",
                     hint="a beacon whose ladder died would have no ring "
                          "to rotate to")
    if rec:
        return Check("dead-drop", "pass",
                     f"{url} -> {rec['host']}:{rec['port']}")
    return Check("dead-drop", "warn", f"{url}: no readable record",
                 hint="publish one: config dead-drop publish <host> <port>")


# ── runner ───────────────────────────────────────────────────────────────

def run_doctor(net: bool = False) -> DoctorReport:
    """Run the checks and return the report (never raises)."""
    fns: List[CheckFn] = [
        _python_check, _core_deps_check, _toolchain_check, _ad_tools_check,
        _data_dir_check, _config_check, _c2_hardening_check, _toolbelt_check,
        _external_services_check,
        _c2_operator_auth_check, _c2_front_check,
        _c2_backend_check, _c2d_capabilities_check, _secrets_at_rest_check,
        _experience_check, _llm_check, _scopes_check, _data_usage_check,
    ]
    if net:
        fns += [_c2_reachable_check, _msf_check, _dead_drop_net_check]
    report = DoctorReport()
    for fn in fns:
        try:
            report.checks.append(fn())
        except Exception as exc:   # a doctor must diagnose, not crash
            report.checks.append(
                Check(fn.__name__.replace("_check", "").lstrip("_"),
                      "warn", f"check errored: {exc}"))
    return report


def render(report: DoctorReport) -> None:
    """Render the report with the uniform notifier styling."""
    from rich.table import Table
    from phantom.utils.notifier import console, notifier
    t = Table(title="[bold white]phantom doctor[/]", border_style="blue",
              show_lines=False)
    t.add_column("", no_wrap=True)
    t.add_column("Check", style="cyan", no_wrap=True)
    t.add_column("Result", style="white")
    for c in report.checks:
        t.add_row(c.mark, c.name, c.detail
                  + (f"\n[yellow]↳ {c.hint}[/]" if c.hint else ""))
    console.print(t)
    if report.ok():
        if report.warns:
            notifier.warn(f"{len(report.warns)} warning(s): "
                          "usable, with the limits above.")
        else:
            notifier.success("Environment healthy: nothing will bite "
                             "mid-run.")
    else:
        notifier.error(f"{len(report.fails)} check(s) FAILED — fix them "
                       "before a real engagement.",
                       hint="every FAIL above carries the fix in ↳")
