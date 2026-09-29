import ipaddress
import os
import socket
from typing import Optional

# Addresses that mean "this machine", never "somewhere the target can
# reach". Dialing them from a beacon points the beacon at ITSELF: the
# listener sees no check-in and the run burns its stall recoveries on a
# deploy that could never work.
_UNROUTABLE = {"", "0.0.0.0", "::", "::0"}


def _addr_kind(host: str) -> str:
    """'unroutable' | 'loopback' | 'private' | 'public' | 'name'."""
    h = (host or "").strip().lower()
    if h in _UNROUTABLE:
        return "unroutable"
    if h in ("localhost",):
        return "loopback"
    try:
        ip = ipaddress.ip_address(h)
    except ValueError:
        return "name"
    if ip.is_loopback:
        return "loopback"
    if ip.is_private or ip.is_link_local:
        return "private"
    return "public"


# names that are internal BY CONVENTION: deciding "is this domain external?"
# with a DNS lookup would make a preflight network-dependent (and slow
# offline), so the check stays deterministic and offline.
_INTERNAL_SUFFIXES = (".local", ".lan", ".internal", ".intranet", ".corp",
                      ".home", ".test", ".localdomain")


def _looks_internal(name: str) -> bool:
    """True for names that are internal by convention (no DNS involved)."""
    n = (name or "").strip().lower()
    if not n:
        return False
    host = n.split("//")[-1].split("/")[0].split(":")[0]
    if host in ("localhost",):
        return True
    if "." not in host:          # single label (srv01, intra, dc)
        return True
    return host.endswith(_INTERNAL_SUFFIXES)


def callback_plausibility(target: str, advertised_host: str) -> tuple:
    """Can a beacon on ``target`` realistically dial ``advertised_host``?

    Returns ``(ok, reason)``. This is the pre-flight that catches the
    single most common real-deploy failure: the beacon's compiled-in
    endpoint cannot be reached from the target (unset host, 0.0.0.0, or a
    private/loopback address while the target lives on the internet), so
    the beacon deploys, never checks in, and the operator only sees "no
    beacon established" much later.

    Deliberately conservative: a LAN target with a private endpoint is
    plausible (that is the normal lab/engagement setup), and identity
    targets have no callback yet, so they are always plausible.
    """
    from phantom.automation.guidance.targets import classify_target
    try:
        ttype = classify_target(target)
    except Exception:
        ttype = "ip"
    if ttype not in ("ip", "domain", "url"):
        return True, "identity target: no callback yet"
    adv = _addr_kind(advertised_host)
    tgt = _addr_kind(target if ttype == "ip" else "")
    if adv == "unroutable":
        return False, (
            f"c2.host is unset/{advertised_host or 'empty'}: the beacon would "
            "dial its OWN loopback. Set the operator address the target can "
            "reach (c2.host, or PHANTOM_C2_HOST)")
    if adv == "loopback":
        return False, (
            f"c2.host={advertised_host} is loopback: a beacon on {target} "
            "cannot call it back. Set a routable address (LAN IP for a lab "
            "target, public IP/domain + port-forward for a remote one)")
    if adv == "private":
        external_target = (tgt == "public"
                           or (ttype in ("domain", "url")
                               and not _looks_internal(target)))
        if external_target:
            return False, (
                f"c2.host={advertised_host} is a PRIVATE address but the "
                f"target {target} is not on a private network: the beacon "
                "cannot route back. Use the public address (and open the "
                "port) or a tunnel/VPN")
        return True, "LAN-internal callback (private endpoint)"
    if adv == "name":
        return True, f"hostname endpoint ({advertised_host})"
    return True, "public endpoint"


def get_lhost() -> str:
    """
    Rileva l'IP locale (LHOST). Priorità:
    1. session.lhost (se impostato manualmente)
    2. dummy socket verso 8.8.8.8
    3. hostname fallback
    """
    from phantom.core.session import session
    if session.lhost:
        return session.lhost

    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            # Usiamo un IP pubblico standard solo per triggerare la tabella di routing del sistema
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        # Se siamo in una rete totalmente isolata senza gateway, proviamo a enumerare le interfacce
        try:
            # Fallback standard: risolve l'hostname locale
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"


def own_ips() -> set:
    """All local IPv4 addresses (excluding loopback) plus 127.0.0.1.

    Used to tell "a beacon that checked in from the outside" apart from
    operator-local traffic when matching registrations by source IP.
    """
    addrs = {"127.0.0.1"}
    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            addrs.add(info[4][0])
    except Exception:
        pass
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        try:
            s.connect(("8.8.8.8", 80))
            addrs.add(s.getsockname()[0])
        finally:
            s.close()
    except Exception:
        pass
    return addrs


def get_c2_fallbacks() -> list:
    """Fallback endpoints to embed behind the primary C2 host.

    A single compiled-in endpoint is a single point of failure: one filtered
    address, one retired redirector or one provider outage ends the
    engagement. Priority: PHANTOM_C2_FALLBACK (comma-separated) then the
    `c2.fallback` config key. The primary is never duplicated here — the
    beacon's own ladder removes duplicates.
    """
    from phantom.utils import config as cfg

    raw = str(os.getenv("PHANTOM_C2_FALLBACK", "")).strip()
    if not raw:
        raw = str(cfg.get("c2.fallback", "") or "").strip()
    out = []
    for item in raw.split(","):
        host = item.strip()
        if host and host not in out:
            out.append(host)
    return out


def get_c2_proxy() -> str:
    """Explicit proxy URL to embed ("" = let the beacon use the system one).

    Empty is the right default: the beacon then follows the endpoint's own
    proxy configuration (PAC/WPAD on Windows, http(s)_proxy on POSIX), which
    is the only thing that works unconfigured. An explicit value overrides it
    for engagements where the operator knows the egress.
    """
    from phantom.utils import config as cfg

    proxy = str(os.getenv("PHANTOM_C2_PROXY", "")).strip()
    if not proxy:
        proxy = str(cfg.get("c2.proxy", "") or "").strip()
    return proxy


def beacon_pin(cert_path: str = "") -> str:
    """Pinned C2 certificate fingerprint to embed in the beacon, or "".

    TLS without a pin completes a handshake with ANY server, so the pin is
    what authenticates the peer. It is resolved from the C2's own certificate
    (the same file the listener loads), which makes the default HTTPS build
    pinned without requiring mTLS — previously `BEACON_SERVER_FINGERPRINT`
    was emitted only on the mTLS path, so the runtime verifier was dead code
    in every ordinary build. ``cert_path`` pins a DIFFERENT certificate: the
    TLS-terminating FRONT's, when the front does not pass the raw TLS through.

    Opt-out: `PHANTOM_BEACON_PIN=0` / `c2.pin=0`. That is the honest escape
    hatch for the one real cost of pinning — regenerating the C2 certificate
    (deleting data/certs) invalidates every already-deployed beacon, which is
    the correct behaviour but needs to be a deliberate choice, not a
    surprise mid-engagement.
    """
    from phantom.utils import config as cfg

    raw = str(os.getenv("PHANTOM_BEACON_PIN", "")).strip()
    if not raw:
        raw = str(cfg.get("c2.pin", "") or "").strip()
    if raw.lower() in ("0", "false", "no", "off"):
        return ""
    from phantom.utils.c2_crypto import server_cert_fingerprint
    return server_cert_fingerprint(cert_path)


def _pins_disabled() -> bool:
    """Shared kill-switch for every pin shape (PHANTOM_BEACON_PIN=0)."""
    from phantom.utils import config as cfg

    raw = str(os.getenv("PHANTOM_BEACON_PIN", "")).strip()
    if not raw:
        raw = str(cfg.get("c2.pin", "") or "").strip()
    return raw.lower() in ("0", "false", "no", "off")


def beacon_pubkey_pin(cert_path: str = "") -> str:
    """SPKI pin (``sha256//<base64>``) for the macOS/libcurl transport, or "".

    The macOS branch reaches the C2 through libcurl, whose only pinning
    primitive covers the public key. Same certificate, same peer — just the
    one shape that transport can enforce. Honours the same kill-switch as
    :func:`beacon_pin`, so `PHANTOM_BEACON_PIN=0` disables pinning everywhere.
    """
    if _pins_disabled():
        return ""
    from phantom.utils.c2_crypto import server_cert_pubkey_pin
    return server_cert_pubkey_pin(cert_path)


def _pin_list(env: str, key: str) -> list:
    """Positional pin list from env then config, preserving empty fields.

    Empty fields are meaningful here ("inherit the fallback pin"), so a bare
    `split(",")` is kept instead of the usual skip-empty loop.
    """
    from phantom.utils import config as cfg

    raw = str(os.getenv(env, "")).strip()
    if not raw:
        raw = str(cfg.get(key, "") or "").strip()
    if not raw:
        return []
    return [item.strip() for item in raw.split(",")]


def get_c2_host_pins() -> list:
    """Per-endpoint DER pins aligned with [primary] + fallbacks (may be []).

    A ladder of independent redirectors each present their OWN certificate,
    so one shared pin cannot authenticate them all. Operator-provided via
    `PHANTOM_C2_PINS` / `c2.pins`, comma-separated, positionally aligned with
    `[primary] + PHANTOM_C2_FALLBACK`. An empty field means "use the fallback
    pin"; an unset list means "one pin for the whole ladder".
    """
    return _pin_list("PHANTOM_C2_PINS", "c2.pins")


def get_c2_pubkey_pins() -> list:
    """Per-endpoint SPKI pins (macOS shape), aligned like :func:`get_c2_host_pins`."""
    return _pin_list("PHANTOM_C2_PUBKEY_PINS", "c2.pubkey_pins")


def get_c2_front() -> Optional[tuple]:
    """(host, port, use_ssl) of the disposable public front, or None.

    `c2.front` is the redirector / CDN the beacons are built against INSTEAD
    of the real listener: the operator can burn and rotate it in minutes
    without rebuilding a beacon, and the backend address never enters the
    binary. Accepts "host" or "host:port" (a pasted scheme/path is
    tolerated and stripped); the port falls back to `c2.port` and the TLS
    flag to `c2.ssl` (default on).
    """
    from phantom.utils import config as cfg

    raw = str(os.getenv("PHANTOM_C2_FRONT", "")).strip()
    if not raw:
        raw = str(cfg.get("c2.front", "") or "").strip()
    if not raw:
        return None
    lowered = raw.lower()
    for scheme in ("https://", "http://"):
        if lowered.startswith(scheme):
            raw = raw[len(scheme):]
            break
    raw = raw.split("/", 1)[0].strip()
    if not raw:
        return None
    host, port = raw, None
    # host:port — a single colon; IPv6 literals keep theirs and use the
    # default port (a front is a name or a v4 address in practice).
    if raw.count(":") == 1:
        candidate, _, tail = raw.partition(":")
        if tail.isdigit() and 0 < int(tail) < 65536:
            host, port = candidate.strip(), int(tail)
    if not host:
        return None
    if port is None:
        try:
            port = int(cfg.get("c2.port", 8080) or 8080)
        except (TypeError, ValueError):
            port = 8080
    return host, port, bool(cfg.get("c2.ssl", True))


def get_c2_front_cert() -> str:
    """Path to the TLS-terminating front's certificate, or "".

    A front that PASSES THROUGH raw TLS shows the beacon the backend's
    certificate, so the backend pin is correct. A front that TERMINATES TLS
    presents its own certificate, and the pin must then come from THAT file —
    otherwise every check-in fails the moment the front's certificate stops
    matching the backend's.

    Resolution: explicit `c2.front_cert` / PHANTOM_C2_FRONT_CERT, else the
    conventional `certs/front.crt` / `front.pem` when present. Rotating the
    front is therefore "drop the new certificate and rebuild", not a manual
    fingerprint edit.
    """
    from phantom.utils import config as cfg

    raw = str(os.getenv("PHANTOM_C2_FRONT_CERT", "")).strip()
    if not raw:
        raw = str(cfg.get("c2.front_cert", "") or "").strip()
    if raw:
        return raw if os.path.exists(raw) else ""
    try:
        from phantom.utils.paths import certs_dir
        for name in ("front.crt", "front.pem"):
            candidate = os.path.join(certs_dir(), name)
            if os.path.exists(candidate):
                return candidate
    except Exception:
        pass
    return ""


def c2_pin_cert_path() -> str:
    """The certificate the build must pin: the front's when it terminates TLS.

    Returns "" when the pin should come from the listener's own certificate
    (the passthrough case, and the single-endpoint default).
    """
    cert = get_c2_front_cert()
    if cert and get_c2_front():
        return cert
    return ""


def front_guard_reason(embedded_host: str = "") -> Optional[str]:
    """Why a beacon build leaks the backend, or None when a front covers it.

    This is the guardrail behind the redirector-first posture: a beacon that
    carries the operator's own listener address hands an analyst who
    captures it the backend to attack. Returns a human reason for the build
    warning and the `doctor` check, or None when the build is covered by a
    disposable `c2.front`.
    """
    from phantom.utils import config as cfg

    front = get_c2_front()
    try:
        backend = (str(os.getenv("PHANTOM_C2_HOST", "")).strip()
                   or str(cfg.get("c2.host", "") or "").strip())
    except Exception:
        backend = ""
    if front:
        if backend and front[0].lower() == backend.lower():
            return (f"c2.front and c2.host are both '{backend}': the front "
                    "must be a DISPOSABLE hop (redirector/CDN), not the "
                    "listener itself")
        if embedded_host and embedded_host.lower() != front[0].lower():
            return (f"the beacon embeds '{embedded_host}' but c2.front is "
                    f"'{front[0]}': beacons should only ever carry the front")
        return None
    if embedded_host:
        kind = _addr_kind(embedded_host)
        if kind in ("public", "name", "private"):
            return (f"no c2.front configured: the beacon embeds "
                    f"'{embedded_host}' — a captured beacon points straight "
                    "at the backend. Set c2.front to a throwaway redirector "
                    "so the binary only carries a hop you can burn")
    return None


def get_c2_endpoint() -> tuple:
    """Best C2 (host, port) to embed in a beacon so the TARGET can reach us.

    Priority:
      1. explicit env PHANTOM_C2_HOST / PHANTOM_C2_PORT (operator override)
      2. `c2.front` (the disposable public hop the beacons dial)
      3. stored c2.host, session.lhost / session.lport
      4. auto-derived operator address (get_lhost) and port 8080

    The critical fix over the old hardcoded 127.0.0.1 default: a beacon
    deployed on a REMOTE target pointing at 127.0.0.1 dials its OWN loopback
    and can never check in. The auto-derived address is the operator's
    source IP on the route toward the internet, which is the address a
    remote target can use to reach back (LAN peer, or NAT/public when the
    operator sets PHANTOM_C2_HOST).
    """
    from phantom.core.session import session
    from phantom.utils import config as cfg

    # An EXPLICIT env override always wins (even loopback: a local lab run
    # may genuinely want it). A loopback value coming from the config FILE
    # is treated as unset: older installs stored 127.0.0.1 as the default
    # and a beacon carrying it dials its own loopback — a dead beacon and
    # a dead dropper link nobody notices until the engagement fails.
    host = str(os.getenv("PHANTOM_C2_HOST", "")).strip()
    # A configured public FRONT is what beacons dial when set — the
    # disposable hop that keeps the listener out of the binary. It wins over
    # `c2.host` (the backend) but never over an explicit override.
    if not host:
        front = get_c2_front()
        if front:
            return front[0], front[1]
    if not host:
        stored = str(cfg.get("c2.host", "") or "").strip()
        if stored and stored not in ("127.0.0.1", "localhost", "::1",
                                     "0.0.0.0"):
            host = stored
    if not host:
        host = session.lhost or get_lhost()

    port = str(cfg.get("c2.port", "", env="PHANTOM_C2_PORT")).strip()
    if port:
        try:
            port = int(port)
        except ValueError:
            port = 8080
    else:
        port = session.lport or 8080
    return host, port
