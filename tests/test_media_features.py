"""Tests for the modular beacon media capture feature integration."""
import unittest

from phantom.core.automode import _STEP_MAP


class TestMediaCommandCoverage(unittest.TestCase):
    """Verify that the beacon deploy executor is integrated into automode."""

    def test_deploy_beacon_has_executor(self):
        self.assertIn("deploy_beacon", _STEP_MAP)
        self.assertTrue(callable(_STEP_MAP["deploy_beacon"]))


class TestModularMediaHeaders(unittest.TestCase):
    """Verify that media.h has been split into modular header files."""

    def setUp(self):
        self.src_dir = "phantom/payloads/beacon/src"

    def test_media_utils_h_exists(self):
        import os
        self.assertTrue(os.path.isfile(f"{self.src_dir}/media_utils.h"))

    def test_gps_h_exists(self):
        import os
        self.assertTrue(os.path.isfile(f"{self.src_dir}/gps.h"))

    def test_camera_h_exists(self):
        import os
        self.assertTrue(os.path.isfile(f"{self.src_dir}/camera.h"))

    def test_audio_h_exists(self):
        import os
        self.assertTrue(os.path.isfile(f"{self.src_dir}/audio.h"))

    def test_screen_record_h_exists(self):
        import os
        self.assertTrue(os.path.isfile(f"{self.src_dir}/screen_record.h"))

    def test_old_media_h_removed(self):
        import os
        self.assertFalse(os.path.isfile(f"{self.src_dir}/media.h"))


class TestMainCppIntegration(unittest.TestCase):
    """Verify that main.cpp includes the new modular headers and commands."""

    def setUp(self):
        with open("phantom/payloads/beacon/src/main.cpp", "r") as f:
            self.content = f.read()

    def test_includes_media_utils(self):
        self.assertIn('#include "media_utils.h"', self.content)

    def test_includes_gps(self):
        self.assertIn('#include "gps.h"', self.content)

    def test_includes_camera(self):
        self.assertIn('#include "camera.h"', self.content)

    def test_includes_audio(self):
        self.assertIn('#include "audio.h"', self.content)

    def test_includes_screen_record(self):
        self.assertIn('#include "screen_record.h"', self.content)

    def test_gps_command(self):
        self.assertIn('action == "gps"', self.content)

    def test_camera_command(self):
        self.assertIn('action == "camera"', self.content)

    def test_audio_command(self):
        self.assertIn('action == "audio"', self.content)

    def test_screen_record_command(self):
        self.assertIn('action == "screen-record"', self.content)

    def test_screen_record_live_command(self):
        self.assertIn('action == "screen-record-live"', self.content)

    def test_screen_dump_command(self):
        self.assertIn('action == "screen-dump"', self.content)

    def test_uses_new_namespaces(self):
        self.assertIn("media_gps::get_gps_info()", self.content)
        self.assertIn("media_camera::capture_image()", self.content)
        self.assertIn("media_audio::record_audio", self.content)
        self.assertIn("media_screen::record_screen_passive", self.content)
        self.assertIn("media_screen::record_screen_live", self.content)
        self.assertIn("media_screen::dump_live_recording()", self.content)


class TestModularMediaContent(unittest.TestCase):
    """Verify modular headers contain the right functions."""

    def test_gps_module_has_get_gps_info(self):
        with open("phantom/payloads/beacon/src/gps.h", "r") as f:
            content = f.read()
        self.assertIn("get_gps_info", content)
        self.assertIn("namespace media_gps", content)
        self.assertIn("#ifdef _WIN32", content)
        self.assertIn("ANDROID", content)

    def test_camera_module_has_capture_image(self):
        with open("phantom/payloads/beacon/src/camera.h", "r") as f:
            content = f.read()
        self.assertIn("capture_image", content)
        self.assertIn("namespace media_camera", content)

    def test_audio_module_has_record_audio(self):
        with open("phantom/payloads/beacon/src/audio.h", "r") as f:
            content = f.read()
        self.assertIn("record_audio", content)
        self.assertIn("namespace media_audio", content)

    def test_screen_record_module_has_passive_and_live(self):
        with open("phantom/payloads/beacon/src/screen_record.h", "r") as f:
            content = f.read()
        self.assertIn("record_screen_passive", content)
        self.assertIn("record_screen_live", content)
        self.assertIn("dump_live_recording", content)
        self.assertIn("namespace media_screen", content)


class TestCrossPlatformGuards(unittest.TestCase):
    """Verify cross-platform compilation guards are present in all modules."""

    def test_gps_has_platform_guards(self):
        with open("phantom/payloads/beacon/src/gps.h", "r") as f:
            content = f.read()
        self.assertIn("#ifdef _WIN32", content)
        self.assertIn("ANDROID", content)

    def test_camera_has_platform_guards(self):
        with open("phantom/payloads/beacon/src/camera.h", "r") as f:
            content = f.read()
        self.assertIn("#ifdef _WIN32", content)
        self.assertIn("ANDROID", content)

    def test_audio_has_platform_guards(self):
        with open("phantom/payloads/beacon/src/audio.h", "r") as f:
            content = f.read()
        self.assertIn("#ifdef _WIN32", content)
        self.assertIn("ANDROID", content)

    def test_screen_record_has_platform_guards(self):
        with open("phantom/payloads/beacon/src/screen_record.h", "r") as f:
            content = f.read()
        self.assertIn("#ifdef _WIN32", content)
        self.assertIn("ANDROID", content)


if __name__ == "__main__":
    unittest.main()
