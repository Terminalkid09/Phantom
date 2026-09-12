"""Tests for the Android Remote Session module.

The APK itself is built by Gradle + the NDK (not available in CI), so these
tests cover the parts that ARE deterministic:

  * the source tree has the Android-only pieces the module requires
    (MediaProjection service, AccessibilityService, JNI bridge)
  * the builder registers android as an APK target and FAILS HONESTLY when
    the SDK/NDK are missing (never a fake success)
  * iOS is explicitly unsupported
  * the input dispatcher understands the same command grammar as desktop
  * a wrong platform is refused by compile_remote
"""
import contextlib
import io
import os
import re
import unittest

_HERE = os.path.dirname(os.path.abspath(__file__))
_ROOT = os.path.dirname(_HERE)
_ANDROID = os.path.join(_ROOT, "phantom", "payloads", "remote", "android")


def _read(path):
    with open(path, encoding="utf-8") as f:
        return f.read()


class AndroidModuleSourceTests(unittest.TestCase):

    def test_manifest_declares_both_android_only_services(self):
        manifest = _read(os.path.join(
            _ANDROID, "app", "src", "main", "AndroidManifest.xml"))
        self.assertIn(".RemoteService", manifest)
        self.assertIn("foregroundServiceType=\"mediaProjection\"", manifest)
        self.assertIn(".RemoteAccessibilityService", manifest)
        self.assertIn("android.permission.BIND_ACCESSIBILITY_SERVICE", manifest)
        self.assertIn("android.accessibilityservice.AccessibilityService", manifest)

    def test_accessibility_config_grants_gesture_and_screenshot(self):
        cfg = _read(os.path.join(
            _ANDROID, "app", "src", "main", "res", "xml",
            "accessibility_service_config.xml"))
        self.assertIn('android:canPerformGestures="true"', cfg)
        self.assertIn('android:canTakeScreenshot="true"', cfg)

    def test_service_sources_exist(self):
        for rel in (
            os.path.join("app", "src", "main", "java", "com", "phantom",
                         "remote", "RemoteService.java"),
            os.path.join("app", "src", "main", "java", "com", "phantom",
                         "remote", "RemoteAccessibilityService.java"),
            os.path.join("app", "src", "main", "java", "com", "phantom",
                         "remote", "C2Native.java"),
            os.path.join("app", "src", "main", "java", "com", "phantom",
                         "remote", "MainActivity.java"),
            os.path.join("app", "src", "main", "jni", "native_bridge.cpp"),
            os.path.join("app", "src", "main", "jni", "CMakeLists.txt"),
            "settings.gradle",
        ):
            p = os.path.join(_ANDROID, rel)
            self.assertTrue(os.path.getsize(p) > 0, rel)

    def test_native_bridge_reuses_shared_wire_protocol(self):
        """The JNI bridge must reuse remote_net.h (same crypto + HMAC) rather
        than re-implementing the protocol, so it stays wire-compatible."""
        bridge = _read(os.path.join(
            _ANDROID, "app", "src", "main", "jni", "native_bridge.cpp"))
        self.assertIn('#include "remote_net.h"', bridge)
        self.assertIn("remote_net::checkin", bridge)
        self.assertIn("remote_net::send_result", bridge)

    def test_service_uses_media_projection_and_image_reader(self):
        svc = _read(os.path.join(
            _ANDROID, "app", "src", "main", "java", "com", "phantom",
            "remote", "RemoteService.java"))
        self.assertIn("MediaProjectionManager", svc)
        self.assertIn("ImageReader", svc)
        self.assertIn("createVirtualDisplay", svc)
        self.assertIn("FRAME_PREFIX", svc)

    def test_ios_documented_unsupported(self):
        readme = _read(os.path.join(_ANDROID, "README.md"))
        self.assertIn("iOS", readme)
        self.assertRegex(readme, r"(?i)not supported")


class AndroidBuilderTests(unittest.TestCase):

    def test_android_registered_as_apk(self):
        from phantom.utils.builder import _REMOTE_OUT
        self.assertEqual(_REMOTE_OUT["android"], "remote.apk")

    def test_compile_remote_missing_toolchain_fails_honestly(self):
        """With no NDK/SDK configured, compile_remote returns None and says
        which variable is missing — it must never pretend the APK was built."""
        from phantom.utils import builder
        import phantom
        pkg_root = os.path.dirname(os.path.abspath(phantom.__file__))
        buf = io.StringIO()
        saved = {k: os.environ.pop(k, None)
                 for k in ("ANDROID_NDK_HOME", "ANDROID_SDK_ROOT", "ANDROID_HOME")}
        try:
            with contextlib.redirect_stdout(buf):
                result = builder.compile_remote("android", pkg_root, force_rebuild=True)
        finally:
            for k, v in saved.items():
                if v is not None:
                    os.environ[k] = v
        self.assertIsNone(result)
        out = buf.getvalue()
        self.assertRegex(out, r"ANDROID_NDK_HOME|ANDROID_SDK_ROOT")

    def test_ios_is_refused(self):
        from phantom.utils import builder
        import phantom
        pkg_root = os.path.dirname(os.path.abspath(phantom.__file__))
        buf = io.StringIO()
        with contextlib.redirect_stdout(buf):
            result = builder.compile_remote("ios", pkg_root, force_rebuild=True)
        self.assertIsNone(result)


class AndroidInputGrammarTests(unittest.TestCase):
    """The dispatch parser must accept the desktop-compatible grammar."""

    def _dispatch(self, args):
        # Importing the Java service is impossible; probe the documented
        # command shapes through the source (the service returns an error
        # string when not enabled, which the C2 surfaces verbatim).
        src = _read(os.path.join(
            _ANDROID, "app", "src", "main", "java", "com", "phantom",
            "remote", "RemoteAccessibilityService.java"))
        return src

    def test_grammar_covers_tap_swipe_text_key(self):
        src = self._dispatch("")
        for sub in ("tap", "swipe", "text", "key"):
            self.assertIn(f'case "{sub}"', src)

    def test_desktop_aliases_present(self):
        src = self._dispatch("")
        self.assertIn('case "click"', src)   # desktop: remote input click x y
        self.assertIn('case "type"', src)    # desktop: remote input type text

    def test_returns_clear_error_when_not_enabled(self):
        src = self._dispatch("")
        self.assertIn("accessibility service not enabled", src)


if __name__ == "__main__":
    unittest.main()
