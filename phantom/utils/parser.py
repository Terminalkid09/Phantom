import xml.etree.ElementTree as ET
from dataclasses import dataclass
from typing import List

@dataclass
class ServiceInfo:
    """Represents an open port with service detection details."""
    ip: str
    port: str
    protocol: str
    state: str
    service: str
    product: str
    version: str

def parse_nmap_xml(xml_path: str) -> List[ServiceInfo]:
    """
    Parse an Nmap XML file (generated with -oX) and return a list of ServiceInfo
    for each open port that has service detection.
    """
    services = []
    try:
        tree = ET.parse(xml_path)
        root = tree.getroot()
        for host in root.findall("host"):
            # Get IP address
            addr = host.find("address")
            if addr is None:
                continue
            ip = addr.get("addr", "")
            # Iterate over ports
            for port_elem in host.findall(".//port"):
                state_elem = port_elem.find("state")
                if state_elem is None or state_elem.get("state") != "open":
                    continue
                port = port_elem.get("portid", "")
                protocol = port_elem.get("protocol", "tcp")
                service_elem = port_elem.find("service")
                if service_elem is None:
                    # No service detection, but still record basic info
                    services.append(ServiceInfo(
                        ip=ip,
                        port=port,
                        protocol=protocol,
                        state="open",
                        service="unknown",
                        product="",
                        version=""
                    ))
                else:
                    services.append(ServiceInfo(
                        ip=ip,
                        port=port,
                        protocol=protocol,
                        state="open",
                        service=service_elem.get("name", ""),
                        product=service_elem.get("product", ""),
                        version=service_elem.get("version", "")
                    ))
    except Exception as e:
        print(f"[!] Error parsing Nmap XML: {e}")
    return services