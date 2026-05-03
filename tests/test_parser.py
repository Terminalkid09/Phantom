import os
import tempfile

import pytest

from phantom.utils.parser import parse_nmap_xml


@pytest.fixture
def nmap_xml_file(tmp_path):
    path = tmp_path / "scan.xml"
    yield path


def test_parse_nmap_xml_with_open_ports_and_service_detection(nmap_xml_file):
    """parse_nmap_xml should extract open ports and service metadata from valid XML."""
    nmap_xml_file.write_text(
        """<?xml version='1.0'?>
<nmaprun>
  <host>
    <address addr='10.0.0.1'/>
    <ports>
      <port protocol='tcp' portid='22'>
        <state state='open'/>
        <service name='ssh' product='OpenSSH' version='7.6'/>
      </port>
      <port protocol='tcp' portid='80'>
        <state state='closed'/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    services = parse_nmap_xml(str(nmap_xml_file))
    assert len(services) == 1
    service = services[0]
    assert service.ip == "10.0.0.1"
    assert service.port == "22"
    assert service.service == "ssh"
    assert service.product == "OpenSSH"
    assert service.version == "7.6"


def test_parse_nmap_xml_returns_empty_for_no_open_ports(nmap_xml_file):
    """XML with no open ports should return an empty list."""
    nmap_xml_file.write_text(
        """<?xml version='1.0'?>
<nmaprun>
  <host>
    <address addr='10.0.0.1'/>
    <ports>
      <port protocol='tcp' portid='80'>
        <state state='closed'/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    services = parse_nmap_xml(str(nmap_xml_file))
    assert services == []


def test_parse_nmap_xml_handles_missing_service_element(nmap_xml_file):
    """If a port has no service element, parse_nmap_xml should still return basic service info."""
    nmap_xml_file.write_text(
        """<?xml version='1.0'?>
<nmaprun>
  <host>
    <address addr='10.0.0.1'/>
    <ports>
      <port protocol='tcp' portid='443'>
        <state state='open'/>
      </port>
    </ports>
  </host>
</nmaprun>
""",
        encoding="utf-8",
    )

    services = parse_nmap_xml(str(nmap_xml_file))
    assert len(services) == 1
    assert services[0].service == "unknown"
    assert services[0].product == ""
    assert services[0].version == ""


def test_parse_nmap_xml_handles_malformed_xml_without_crashing(nmap_xml_file):
    """Malformed XML should not raise an exception and should return an empty list."""
    nmap_xml_file.write_text("<nmaprun><host><address addr='10.0.0.1'></host>")
    services = parse_nmap_xml(str(nmap_xml_file))
    assert services == []


def test_parse_nmap_xml_handles_nonexistent_file():
    """A missing XML file should be handled gracefully and return an empty list."""
    nonexistent = os.path.join(tempfile.gettempdir(), "phantom_missing_scan.xml")
    if os.path.exists(nonexistent):
        os.remove(nonexistent)
    services = parse_nmap_xml(nonexistent)
    assert services == []
