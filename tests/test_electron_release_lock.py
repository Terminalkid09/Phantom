"""P1: the Electron release must be reproducible from the repository.

The defect this closes: `.github/workflows/electron-release.yml` installs
with `npm ci`, which FAILS outright without a lockfile — and
`electron/package-lock.json` was listed in `.gitignore`, so it existed only
on the machine that generated it. The ordinary CI stayed green because it
uses `npm install`, so nothing caught the mismatch until a release was cut
from a fresh clone.

These pin the three things that have to agree: the lockfile is present, it
is committable (not ignored), and every workflow that runs `npm ci` has a
lockfile to run it against.
"""
import json
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_ELECTRON = _ROOT / "electron"
_LOCK = _ELECTRON / "package-lock.json"
_PKG = _ELECTRON / "package.json"
_GITIGNORE = _ROOT / ".gitignore"
_WORKFLOWS = _ROOT / ".github" / "workflows"


class TestTheLockfileExists(unittest.TestCase):
    def test_the_lockfile_is_committed_to_the_repository(self):
        self.assertTrue(
            _LOCK.exists(),
            "electron/package-lock.json is missing: `npm ci` cannot run, so "
            "the release workflow cannot install on a fresh clone")

    def test_the_lockfile_parses_and_matches_package_json(self):
        lock = json.loads(_LOCK.read_text(encoding="utf-8"))
        pkg = json.loads(_PKG.read_text(encoding="utf-8"))
        self.assertEqual(lock.get("name"), pkg.get("name"))
        self.assertEqual(lock.get("version"), pkg.get("version"))
        self.assertGreaterEqual(lock.get("lockfileVersion", 0), 2)
        # every dependency declared in package.json must be resolved in the
        # lock, or `npm ci` refuses ("package.json and lock are not in sync")
        for section in ("dependencies", "devDependencies"):
            for name in (pkg.get(section) or {}):
                self.assertIn(
                    name, lock.get("packages", {}).get("", {}).get(section, {}),
                    f"{name} is declared in package.json but absent from the "
                    f"lock's root package")

    def test_the_packages_section_covers_the_tree(self):
        lock = json.loads(_LOCK.read_text(encoding="utf-8"))
        # `npm ci` installs FROM `packages`; an empty section means the lock
        # is a stub, not a resolution.
        self.assertGreater(len(lock.get("packages", {})), 10)


class TestTheLockfileIsNotIgnored(unittest.TestCase):
    def test_gitignore_does_not_ignore_the_lockfile(self):
        lines = [ln.strip() for ln in
                 _GITIGNORE.read_text(encoding="utf-8").splitlines()]
        offenders = [ln for ln in lines
                     if ln and not ln.startswith("#")
                     and ln.rstrip("/") in ("electron/package-lock.json",
                                            "package-lock.json",
                                            "*.lock", "**/package-lock.json")]
        self.assertEqual(
            offenders, [],
            "these .gitignore rules would keep the release lockfile out of "
            f"the repository again: {offenders}")


class TestEveryNpmCiHasALockfile(unittest.TestCase):
    def test_a_workflow_using_npm_ci_has_a_committed_lock(self):
        users = []
        for wf in sorted(_WORKFLOWS.glob("*.yml")):
            text = wf.read_text(encoding="utf-8")
            if re.search(r"\bnpm ci\b", text):
                users.append(wf.name)
        if not users:
            self.skipTest("no workflow uses `npm ci`")
        # the lock lives beside the manifest the workflows install from
        self.assertTrue(_LOCK.exists(),
                        f"{users} run `npm ci` without a committed lockfile")

    def test_the_release_workflow_points_at_the_lock_that_exists(self):
        wf = _WORKFLOWS / "electron-release.yml"
        if not wf.exists():
            self.skipTest("release workflow absent")
        text = wf.read_text(encoding="utf-8")
        for rel in re.findall(r"cache-dependency-path:\s*(\S+)", text):
            self.assertTrue(
                (_ROOT / rel).exists(),
                f"cache-dependency-path points at {rel!r}, which does not "
                f"exist in the repository")


class TestTheRendererLogicIsActuallyExecuted(unittest.TestCase):
    """Audit §4.3.4: the two files that EXECUTE `api.ts` skip without node.

    `test_electron_job_state.py` and `test_electron_schema_mismatch.py`
    compile `electron/src/lib/api.ts` with the project's tsc and drive the
    parsers under node; both `skipif` on a missing `electron/node_modules`.
    In every Python test job that directory is absent, so the renderer's
    parsing logic — including the schema-mismatch reporting — was asserted
    by NOTHING on a clean runner: they passed by skipping.

    The fix belongs in the workflow that DOES install node deps, so these
    pin the wiring rather than the behaviour (the behaviour is pinned by the
    tests themselves, which now get a chance to run).
    """

    _EXECUTING = ("tests/test_electron_job_state.py",
                  "tests/test_electron_schema_mismatch.py")

    @staticmethod
    def _electron_job():
        text = (_WORKFLOWS / "ci.yml").read_text(encoding="utf-8")
        marker = re.search(r"^  electron-build:\s*$", text, re.M)
        if not marker:                                # pragma: no cover
            raise AssertionError("no `electron-build` job in ci.yml")
        after = text[marker.end():]
        nxt = re.search(r"^  [A-Za-z0-9_-]+:\s*$", after, re.M)
        return after if nxt is None else after[:nxt.start()]

    def test_the_job_that_has_node_runs_the_executing_tests(self):
        job = self._electron_job()
        for path in self._EXECUTING:
            self.assertIn(path, job,
                          f"{path} skips on a clean runner unless this job "
                          f"runs it")

    def test_it_installs_the_renderer_deps_first(self):
        job = self._electron_job()
        self.assertIn("npm ci", job,
                      "the lockfile is the artifact the release trusts")
        self.assertIn("tsc", job, "the executed tests need the project's tsc")

    def test_the_executing_tests_keep_their_skip_guard(self):
        """Wiring them into CI must not be done by REMOVING the skip: a
        developer without node still has to be able to run the suite."""
        for path in self._EXECUTING:
            text = (_ROOT / path).read_text(encoding="utf-8")
            self.assertIn("skipif", text, f"{path} lost its skip guard")


if __name__ == "__main__":
    unittest.main()
