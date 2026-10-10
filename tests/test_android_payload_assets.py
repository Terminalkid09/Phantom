"""The Android module's XML files are SOURCE, not documents.

`.gitignore` carries `*.xml` under a "Documents" heading, which is right for
exported scan reports and wrong for the payload: it hid `AndroidManifest.xml`,
`res/xml/accessibility_service_config.xml` and `res/values/strings.xml` from
every clone. The module existed on the developer's disk and nowhere else, so
`tests/test_remote_android.py` and `tests/test_mobile_chain.py` passed locally
and died on CI with FileNotFoundError — the same present-but-untracked failure
mode as the report template (see tests/test_report_assets.py).

Both halves are pinned here: the assets are on disk AND the ignore rules let
git see them.
"""
import os
import subprocess

import pytest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ANDROID_MAIN = os.path.join("phantom", "payloads", "remote", "android",
                            "app", "src", "main")

# every XML file the Android remote module builds from
ANDROID_XML = (
    os.path.join(ANDROID_MAIN, "AndroidManifest.xml"),
    os.path.join(ANDROID_MAIN, "res", "xml", "accessibility_service_config.xml"),
    os.path.join(ANDROID_MAIN, "res", "values", "strings.xml"),
)


def _git(*args):
    """Run git in the repo; None when git (or the repo) is not available."""
    try:
        out = subprocess.run(["git"] + list(args), cwd=ROOT,
                             capture_output=True, text=True)
    except OSError:
        return None
    return out.stdout if out.returncode == 0 else None


class TestTheAndroidModuleIsOnDisk:
    def test_the_tree_the_tests_read_exists(self):
        for path in ANDROID_XML:
            assert os.path.isfile(path), path

    def test_the_manifest_declares_the_two_services(self):
        """The content the AndroidModuleSourceTests read, not just the path."""
        text = open(os.path.join(ANDROID_MAIN, "AndroidManifest.xml"),
                    encoding="utf-8").read()
        assert "RemoteAccessibilityService" in text
        assert "RemoteService" in text


class TestTheAndroidModuleIsTrackedNotJustPresent:
    """The local-only failure mode: present on disk, absent from the repo."""

    def test_gitignore_no_longer_swallows_the_module_xml(self):
        text = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read()
        for path in ANDROID_XML:
            assert f"!{path.replace(os.sep, '/')}" in text or (
                "!phantom/payloads/remote/android/app/src/main/res/**/*.xml" in text
                and "/res/" in path.replace(os.sep, "/")), (
                f"{path} is ignored by the `*.xml` document rule with no "
                f"negation: it will exist only on the developer's disk")

    def test_the_xml_rule_itself_stays(self):
        """Exported scan reports must keep being ignored."""
        text = open(os.path.join(ROOT, ".gitignore"), encoding="utf-8").read()
        assert "\n*.xml\n" in text

    def test_the_build_caches_stay_ignored(self):
        """The negation must not expose Gradle's cache as product source."""
        if _git("rev-parse", "--git-dir") is None:
            pytest.skip("not a git checkout")
        out = subprocess.run(
            ["git", "check-ignore", "-v",
             "phantom/payloads/remote/android/.gradle/x"],
            cwd=ROOT, capture_output=True, text=True)
        assert out.returncode == 0 and ".gradle" in out.stdout, out.stdout

    def test_git_reports_the_xml_as_tracked(self):
        if _git("rev-parse", "--git-dir") is None:
            pytest.skip("not a git checkout")
        for path in ANDROID_XML:
            tracked = _git("ls-files", "--", path)
            assert tracked and tracked.strip(), (
                f"{path} is on disk but NOT tracked: a fresh clone (CI) has "
                f"no Android module and the tree tests fail there")

    def test_check_ignore_agrees(self):
        if _git("rev-parse", "--git-dir") is None:
            pytest.skip("not a git checkout")
        out = subprocess.run(["git", "check-ignore", *ANDROID_XML],
                             cwd=ROOT, capture_output=True, text=True)
        # exit 1 is "nothing matched an ignore rule", which is what we want
        assert out.returncode == 1 and not out.stdout.strip(), (
            f"still ignored: rc={out.returncode} {out.stdout}")
