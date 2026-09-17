import os
import socket


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


def beacon_pin() -> str:
    """Pinned C2 certificate fingerprint to embed in the beacon, or "".

    TLS without a pin completes a handshake with ANY server, so the pin is
    what authenticates the peer. It is resolved from the C2's own certificate
    (the same file the listener loads), which makes the default HTTPS build
    pinned without requiring mTLS — previously `BEACON_SERVER_FINGERPRINT`
    was emitted only on the mTLS path, so the runtime verifier was dead code
    in every ordinary build.

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
    return server_cert_fingerprint()


def get_c2_endpoint() -> tuple:
    """Best C2 (host, port) to embed in a beacon so the TARGET can reach us.

    Priority:
      1. explicit env PHANTOM_C2_HOST / PHANTOM_C2_PORT (operator override)
      2. session.lhost / session.lport (set by the operator)
      3. auto-derived operator address (get_lhost) and port 8080

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
