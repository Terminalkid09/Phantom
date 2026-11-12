"""Auto-mode must prepare the C2 certificate for the address beacons dial.

The listener loads its TLS context at startup. The beacon builder regenerates
the certificate when the SAN does not cover the dialed host; if that happens
after the listener started, the listener keeps serving the old certificate and
the pin in the new beacon rejects every check-in.
"""

from unittest.mock import patch

from phantom.core import automode


class _Server:
    thread = None
    cert_dir = "/tmp/phantom-certs-test"

    def __init__(self):
        self.started = []

    def start(self, **kwargs):
        self.started.append(kwargs)


def test_listener_certificate_is_prepared_before_start():
    server = _Server()
    cert_calls = []

    with patch.object(automode, "_probe_bind", return_value=True), \
            patch("phantom.utils.network.get_c2_endpoint",
                  return_value=("10.0.0.5", 8443)), \
            patch("phantom.core.c2_server.listener_bind_host",
                  return_value="0.0.0.0"), \
            patch("phantom.utils.config.get",
                  side_effect=lambda key, default=None, **kw: (
                      "python" if key == "c2.transport_backend" else default)), \
            patch("phantom.utils.state.use_mtls", return_value=True), \
            patch("phantom.utils.beacon_auth.ensure_mtls_material",
                  side_effect=lambda directory, host: cert_calls.append(
                      (directory, host))):
        assert automode._ensure_c2_listener(server=server) is True

    assert cert_calls == [("/tmp/phantom-certs-test", "10.0.0.5")]
    assert server.started == [{"host": "0.0.0.0", "port": 8443,
                               "use_ssl": True}]
