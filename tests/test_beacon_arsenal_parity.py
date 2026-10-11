"""The arsenal headers must keep a non-Windows code path.

A reader who sees ``#ifdef _WIN32`` at the top of ``browser_pivot.h``,
``netstat.h``, ``camera.h`` … can reasonably conclude the capability is
Windows-only. It is not: that guard is only the **include** block, and every
collection/action capability has a real POSIX branch (Linux, and often Android
and macOS too).

``docs/beacon_platform_matrix.md`` is the contract for what runs where; this
test pins the two halves of it so it cannot silently regress:

* each cross-platform header keeps an ``#else``/``#elif`` POSIX branch;
* the genuinely NT-specific headers stay Windows-only (the accepted list).

It is a source-level pin on purpose: the payload is cross-compiled, and the CI
``beacon-smoke`` jobs build the real artefact per platform — this runs offline
and fails loudly the moment someone wraps a shared header in ``#ifdef _WIN32``.
"""
import pathlib
import unittest

_SRC = pathlib.Path("phantom/payloads/beacon/src")
_DOC = pathlib.Path("docs/beacon_platform_matrix.md")

# Capabilities with a REAL POSIX branch. Losing the branch is the regression.
_CROSS_PLATFORM = (
    "screenshot.h", "screen_record.h", "camera.h", "audio.h", "gps.h",
    "netstat.h", "cookie_stealer.h", "wlan_scan.h", "bt_scan.h",
    "browser_pivot.h", "cdp_pivot.h", "proxy.h", "portfwd.h",
)

# NT-specific mechanisms with no POSIX analogue — Windows-only ON PURPOSE,
# and listed as "accepted" in the platform matrix.
_WINDOWS_ONLY = (
    "syscalls.h", "apc_injection.h", "smb.h", "ppid_spoof.h",
    "sleep_ekko.h", "winhttp_dynamic.h", "wasapi_capture.h",
)


def _read(name: str) -> str:
    return (_SRC / name).read_text(encoding="utf-8", errors="replace")


class TestArsenalHasPosix(unittest.TestCase):
    def test_each_arsenal_header_has_a_non_windows_branch(self):
        for name in _CROSS_PLATFORM:
            text = _read(name)
            self.assertIn("#ifdef _WIN32", text,
                          f"{name} lost its Windows include guard")
            self.assertTrue("#else" in text or "#elif" in text,
                            f"{name} has no POSIX branch — it became "
                            f"Windows-only, which the matrix denies")

    def test_socket_shims_keep_the_same_body_compiling_on_posix(self):
        # the four socket-based capabilities share one body through these
        # shims; removing one breaks the POSIX build, not just the docs
        for name in ("browser_pivot.h", "cdp_pivot.h", "proxy.h",
                     "portfwd.h"):
            text = _read(name)
            self.assertIn("#define SOCKET int", text, name)
            self.assertIn("closesocket", text, name)


class TestLinuxToolFallbacks(unittest.TestCase):
    """Linux/Android lean on external tools; the WIDELY-present ones must be
    among the fallbacks, not only the niche/X11-only ones."""

    def test_screenshot_covers_wayland_and_x11(self):
        text = _read("screenshot.h")
        # Wayland-first (grim, gnome-screenshot, spectacle), then X11 scrot,
        # then ImageMagick/xwd, then Android's screencap.
        for tool in ("grim", "gnome-screenshot", "spectacle", "scrot",
                     "import", "xwd", "screencap"):
            self.assertIn(tool, text, tool)

    def test_wlan_prefers_networkmanager(self):
        # nmcli needs no interface name and no CAP_NET_ADMIN, so it is tried
        # BEFORE iw/iwlist, which are often not installed anymore.
        text = _read("wlan_scan.h")
        self.assertIn("nmcli", text)
        self.assertIn("scan_access_points_nmcli", text)


class TestOnlyTheAcceptedListIsWindowsOnly(unittest.TestCase):
    def test_windows_only_headers_stay_guarded(self):
        for name in _WINDOWS_ONLY:
            self.assertIn("_WIN32", _read(name),
                          f"{name} should stay behind a _WIN32 guard")

    def test_the_matrix_documents_the_arsenal(self):
        doc = _DOC.read_text(encoding="utf-8")
        self.assertIn("Advanced arsenal", doc)
        for needle in ("browser", "cdp", "netstat", "cookie", "wlan",
                       "bluetooth", "screenshot", "camera", "audio", "gps"):
            self.assertIn(needle, doc.lower(), needle)


if __name__ == "__main__":
    unittest.main()
