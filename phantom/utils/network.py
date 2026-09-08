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

    host = os.getenv("PHANTOM_C2_HOST", "").strip()
    if not host:
        host = session.lhost or get_lhost()

    port = os.getenv("PHANTOM_C2_PORT", "").strip()
    if port:
        port = int(port)
    else:
        port = session.lport or 8080
    return host, port
