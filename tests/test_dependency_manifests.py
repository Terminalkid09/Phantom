"""P1: one dependency set, and it is pinned somewhere.

Measured defect this closes: `setup.py` declared 11 runtime dependencies
while `requirements.txt` declared 13 — `pip install .` and `pip install -r
requirements.txt` installed different sets, and the packaging path could not
run the DB-backed capabilities. Meanwhile `.gitlab-ci.yml` installed from the
divergent manifest plus a hand-typed subset of the test dependencies, so that
job errored with "fixture 'mocker' not found".

These pin the invariants, not the file contents: setup.py must DERIVE its
list from requirements.txt, every declared dependency must be pinned in
constraints.txt, and no workflow may install from the packaging manifest.
"""
import importlib.util
import pathlib
import re
import unittest

_ROOT = pathlib.Path(__file__).resolve().parent.parent


def _specs(path):
    """Top-level requirement specs in a requirements file (name + specifier)."""
    out = []
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line or line.startswith("-"):
            continue
        out.append(line)
    return out


def _name(spec):
    return re.split(r"[<>=!~\[]", spec, maxsplit=1)[0].strip().lower()


def _constraints():
    return {_name(s): s for s in _specs(_ROOT / "constraints.txt")}


class TestSetupDerivesItsListFromRequirements(unittest.TestCase):
    def test_setup_exposes_the_runtime_requirements(self):
        spec = importlib.util.spec_from_file_location(
            "phantom_setup_probe", _ROOT / "setup.py")
        module = importlib.util.module_from_spec(spec)
        # exec_module must NOT run setup(): the module guards it behind
        # `if __name__ == "__main__"`.
        spec.loader.exec_module(module)
        self.assertTrue(callable(getattr(module, "runtime_requirements", None)))

    def test_the_two_install_paths_are_the_same_list(self):
        spec = importlib.util.spec_from_file_location(
            "phantom_setup_probe2", _ROOT / "setup.py")
        module = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(module)
        declared = {_name(s): s for s in module.runtime_requirements()}
        from_file = {_name(s): s for s in _specs(_ROOT / "requirements.txt")}
        self.assertEqual(
            set(declared), set(from_file),
            "setup.py and requirements.txt declare different packages: "
            f"only in setup.py: {sorted(set(declared) - set(from_file))}, "
            f"only in requirements.txt: {sorted(set(from_file) - set(declared))}")
        for name, spec_text in from_file.items():
            self.assertEqual(declared[name], spec_text,
                             f"{name}: setup.py and requirements.txt floors "
                             f"differ")

    def test_the_db_drivers_are_no_longer_dropped(self):
        # the exact two that were missing
        names = {_name(s) for s in _specs(_ROOT / "requirements.txt")}
        self.assertIn("mysql-connector-python", names)
        self.assertIn("psycopg2-binary", names)


class TestEverythingIsPinned(unittest.TestCase):
    def test_every_runtime_dependency_is_pinned(self):
        pins = _constraints()
        for spec in _specs(_ROOT / "requirements.txt"):
            name = _name(spec)
            self.assertIn(name, pins, f"{name} has no pin in constraints.txt")
            self.assertIn("==", pins[name],
                          f"{name} is constrained without `==`: {pins[name]}")

    def test_every_dev_dependency_is_pinned(self):
        pins = _constraints()
        for spec in _specs(_ROOT / "requirements-dev.txt"):
            name = _name(spec)
            self.assertIn(name, pins,
                          f"{name} (dev) has no pin in constraints.txt")
            self.assertIn("==", pins[name])

    def test_a_constraint_never_widens_the_declared_floor(self):
        pins = _constraints()
        for spec in (_specs(_ROOT / "requirements.txt")
                     + _specs(_ROOT / "requirements-dev.txt")):
            name = _name(spec)
            pin = pins.get(name)
            if not pin:
                continue
            floor = re.search(r">=\s*([0-9][\w.]*)", spec)
            if floor:
                self.assertGreaterEqual(
                    _version_tuple(pin.split("==")[1]),
                    _version_tuple(floor.group(1)),
                    f"{name}: constraint {pin} is BELOW the declared floor "
                    f"{spec} — a constraint may only narrow")


def _version_tuple(text):
    parts = []
    for chunk in re.split(r"[.\-+]", str(text)):
        if chunk.isdigit():
            parts.append(int(chunk))
        else:
            break
    return tuple(parts) or (0,)


class TestNoWorkflowInstallsFromThePackagingManifest(unittest.TestCase):
    """`pip install .` / `-e .` pulls setup.py's list (now derived, but still a
    second install path). CI installs from the requirements files only."""

    @staticmethod
    def _active(text):
        """The workflow's EXECUTABLE lines: a YAML comment that explains the
        old command must not be mistaken for the command itself."""
        return "\n".join(
            ln for ln in text.splitlines()
            if not ln.strip().startswith("#"))

    def _workflow_texts(self):
        out = []
        for wf in sorted((_ROOT / ".github" / "workflows").glob("*.yml")):
            out.append((wf.name, self._active(wf.read_text(encoding="utf-8"))))
        gitlab = _ROOT / ".gitlab-ci.yml"
        if gitlab.exists():
            out.append((gitlab.name, self._active(gitlab.read_text(encoding="utf-8"))))
        return out

    def test_no_workflow_pip_installs_the_package(self):
        offenders = [name for name, text in self._workflow_texts()
                     if re.search(r"pip install\s+(-e\s+)?\.\s*$", text,
                                  re.MULTILINE)]
        self.assertEqual(offenders, [],
                         f"these install from setup.py instead of the "
                         f"requirements files: {offenders}")

    def test_the_gitlab_unit_job_installs_the_dev_set(self):
        gitlab = _ROOT / ".gitlab-ci.yml"
        if not gitlab.exists():
            self.skipTest("no gitlab pipeline")
        active = self._active(gitlab.read_text(encoding="utf-8"))
        # the pytest-mock omission made three tests error on every run
        self.assertIn("requirements-dev.txt", active)
        self.assertNotIn("pip install pytest pytest-asyncio pytest-cov", active)


if __name__ == "__main__":
    unittest.main()
