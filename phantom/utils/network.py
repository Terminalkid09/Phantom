import socket

def get_lhost() -> str:
    """
    Rileva l'IP locale (LHOST) che verrà usato per connettersi al target.
    
    Il metodo del 'dummy socket' è il più affidabile:
    1. Crea un socket UDP (non orientato alla connessione).
    2. Tenta di 'connettersi' a un IP esterno (8.8.8.8). 
       NOTA: Non vengono inviati pacchetti in rete e l'IP non deve essere raggiungibile.
    3. Chiede al sistema operativo: 'Quale interfaccia useresti per raggiungere questo IP?'.
    4. getsockname() restituisce l'IP di quell'interfaccia.
    """
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # Usiamo un IP pubblico standard solo per triggerare la tabella di routing del sistema
        s.connect(("8.8.8.8", 80))
        lhost = s.getsockname()[0]
        s.close()
        return lhost
    except Exception:
        # Se siamo in una rete totalmente isolata senza gateway, proviamo a enumerare le interfacce
        try:
            # Fallback standard: risolve l'hostname locale
            return socket.gethostbyname(socket.gethostname())
        except Exception:
            return "127.0.0.1"
