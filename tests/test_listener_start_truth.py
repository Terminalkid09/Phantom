"""`listeners start` must not announce a listener that is not there.

Live evidence (2026-10-16, this host, mTLS on):

    C2 > listeners start 9443 127.0.0.1 false
    [OK] Started HTTP listener on 127.0.0.1:9443      <-- the shell said this
    C2  listener STOPPED ...                          <-- the footer said this
    [!] WARNING: no listener is running ...           <-- `generate` said this

`C2Server.start()` refused (mTLS requires HTTPS) by LOGGING and returning, so
its documented contract — "started only when the site actually accepted the
bind; RuntimeError otherwise" — was broken, and the caller printed success
unconditionally. Three surfaces, two of them lying, and the operator walks
away with a dropper aimed at a closed port.
"""
import unittest
from unittest import mock

from phantom.core.c2_server import C2Server


class TestServerStartRaises(unittest.TestCase):

    def test_mtls_demanding_https_raises_and_starts_no_thread(self):
        srv = C2Server()
        with mock.patch("phantom.core.c2_server.use_mtls", return_value=True):
            with self.assertRaises(RuntimeError) as ctx:
                srv.start(host="127.0.0.1", port=9443, use_ssl=False)
        self.assertIn("mTLS", str(ctx.exception))
        self.assertIsNone(srv.thread)

    def test_missing_tls_material_raises_and_starts_no_thread(self):
        srv = C2Server()
        with mock.patch("phantom.core.c2_server.use_mtls",
                        return_value=False), \
             mock.patch.object(C2Server, "_get_ssl_context",
                               return_value=None):
            with self.assertRaises(RuntimeError) as ctx:
                srv.start(host="127.0.0.1", port=9443, use_ssl=True)
        self.assertIn("TLS material", str(ctx.exception))
        self.assertIsNone(srv.thread)


class TestShellReportsTheTruth(unittest.TestCase):

    def _shell(self):
        from phantom.core.c2_shell import C2Shell
        return C2Shell()

    def test_a_refused_start_is_an_error_not_a_success(self):
        shell = self._shell()
        fake = mock.MagicMock()
        fake.thread = None
        fake.start.side_effect = RuntimeError("mTLS is required: use HTTPS")
        with mock.patch("phantom.core.c2_shell.server_instance", fake), \
             mock.patch("phantom.core.c2_shell.notifier") as nt:
            shell.do_listeners("start 9443 127.0.0.1 false")
        nt.error.assert_called()
        nt.success.assert_not_called()
        self.assertIn("mTLS", str(nt.error.call_args_list[0]))

    def test_a_silent_no_start_is_caught_too(self):
        """Belt and braces: even a start() that returns without raising must
        not earn a green tick unless the thread is alive."""
        shell = self._shell()
        fake = mock.MagicMock()
        fake.start.return_value = None
        fake.thread = None
        with mock.patch("phantom.core.c2_shell.server_instance", fake), \
             mock.patch("phantom.core.c2_shell.notifier") as nt:
            shell.do_listeners("start 9443 127.0.0.1 false")
        nt.error.assert_called()
        nt.success.assert_not_called()
        self.assertIn("did NOT start", str(nt.error.call_args_list[0]))


if __name__ == "__main__":
    unittest.main()
