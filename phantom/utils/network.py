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
