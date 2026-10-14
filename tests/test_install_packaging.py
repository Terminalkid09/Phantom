"""The "get it without cloning" paths must stay lean and honest.

The audit's §5.4/§5.6: the Docker build context was the whole working tree (no
`.dockerignore`, `COPY . .`) and the one-line installer copied the ENTIRE
tarball into `~/.phantom` — docs, tests, the Electron app, `data/`. Both are the
difference between "install it" and "please clone my repository", and neither
cost was visible from the outside.

Also pinned here: the two installers must DOWNLOAD the branch you asked for,
CHECK the archive before they touch the filesystem (a size check says nothing
about what arrived), and keep the whole-tree copy as an explicit opt-in.

These are source-level contracts on purpose: running `curl | sh` or a Docker
build is not something a unit test should do to the operator's machine.
"""
import os
import re

import pytest

REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts):
    with open(os.path.join(REPO, *parts), encoding="utf-8") as handle:
        return handle.read()


@pytest.fixture(scope="module")
def dockerignore():
    return _read(".dockerignore")


class TestTheDockerContextIsNotTheWholeTree:
    @pytest.mark.parametrize("excluded", [
        ".git",             # history nobody builds from
        "data/",            # the operator's engagement state
        "tests/",
        "electron/",
        "**/node_modules/",
        "build/",
        "dist/",
        "*.egg-info/",
        "__pycache__/",
    ])
    def test_the_local_state_is_excluded(self, dockerignore, excluded):
        lines = [line.strip() for line in dockerignore.splitlines()]
        assert excluded in lines, \
            f"{excluded} is still sent to the docker daemon on every build"

    def test_the_image_still_gets_what_it_builds(self):
        """Over-excluding would break the build instead of speeding it up."""
        text = _read(".dockerignore")
        rules = [line.strip() for line in text.splitlines()
                 if line.strip() and not line.strip().startswith("#")]
        for kept in ("phantom/", "setup.py", "MANIFEST.in",
                     "requirements.txt"):
            assert kept not in rules, \
                f"{kept} is excluded but the Dockerfile installs the package"

    def test_the_dockerfile_copies_the_tree_on_purpose(self):
        """`COPY . .` stays — the ignore file is what trims it."""
        assert "COPY . ." in _read("Dockerfile")


class TestTheInstallerDownloadsWhatItSays:
    def test_the_branch_is_explicit_and_overridable(self):
        sh = _read("install", "install.sh")
        assert "PHANTOM_BRANCH" in sh, "the branch must be selectable"
        assert "${PHANTOM_BRANCH:-dev}" in sh, \
            "the default must be the line these docs describe ('dev')"
        assert re.search(r'BRANCH="main"', sh) is None, \
            "hardcoding 'main' installs the old release line silently"
        ps = _read("install", "install.ps1")
        assert "PHANTOM_BRANCH" in ps
        assert '$env:PHANTOM_BRANCH' in ps

    def test_the_archive_is_checked_before_anything_is_written(self):
        """Size alone is not an integrity check: gzip/tar + expected files."""
        sh = _read("install", "install.sh")
        assert "gzip -t" in sh, "a truncated/captive-portal download must fail"
        assert "tar -tzf" in sh
        assert "phantom/main.py" in sh, "the archive must contain the package"
        ps = _read("install", "install.ps1")
        assert "phantom\\main.py" in ps

    def test_a_bad_branch_says_so_instead_of_installing_nothing(self):
        for name in ("install.sh", "install.ps1"):
            text = _read("install", name)
            assert "wrong branch" in text, \
                f"{name} must name the likely cause of a bad archive"

    def test_the_whole_tree_copy_is_an_explicit_opt_in(self):
        sh = _read("install", "install.sh")
        assert "PHANTOM_FULL_TREE" in sh
        # `cp -a "$SRC/."` is the whole-tree copy: it must sit behind the flag
        opt_in = sh.index("PHANTOM_FULL_TREE=1")
        whole_tree = sh.index('cp -a "$SRC/."')
        assert whole_tree > opt_in, "the whole-tree copy is the default again"
        assert "KEEP=" in sh, "the lean install needs an explicit keep-list"

    def test_the_lean_install_keeps_everything_a_run_needs(self):
        sh = _read("install", "install.sh")
        keep = sh.split("KEEP=", 1)[1].splitlines()[0]
        for needed in ("phantom", "setup.py", "MANIFEST.in",
                       "requirements.txt"):
            assert needed in keep, f"{needed} must survive the lean copy"

    def test_the_launcher_still_points_at_the_installed_package(self):
        sh = _read("install", "install.sh")
        assert '"$DEST/phantom/main.py"' in sh
        assert "$DEST/.venv/bin/python" in sh


def _job_block(name):
    """The YAML text of ONE job in ci.yml, sliced at 2-space indentation.

    Deliberately source-level: "the docker job is a no-op" is a property of
    the WORKFLOW text, and the way it regressed (a `|| true` nobody read) is
    exactly what a reader of this file must be able to catch.
    """
    text = _read(".github", "workflows", "ci.yml")
    marker = re.search(rf"^  {re.escape(name)}:\s*$", text, re.M)
    assert marker, f"no `{name}` job in ci.yml"
    after = text[marker.end():]
    nxt = re.search(r"^  [A-Za-z0-9_-]+:\s*$", after, re.M)
    return after if nxt is None else after[:nxt.start()]


class TestTheDockerJobActuallyChecksSomething:
    """Audit §2.8.5: the job printed "Dockerfile exists and checked" while
    running nothing that could fail (`|| true`), so the Docker path was not
    gated: a broken Dockerfile shipped green."""

    @staticmethod
    def _executable_lines():
        """The job without its comments (which may QUOTE the old mistake)."""
        return [line for line in _job_block("docker-test").splitlines()
                if not line.strip().startswith("#")]

    def test_it_does_not_swallow_its_own_failure(self):
        assert not [line for line in self._executable_lines()
                    if "|| true" in line], \
            "a step that cannot fail is not a gate"

    def test_it_lints_the_dockerfile_with_a_real_linter(self):
        job = _job_block("docker-test")
        assert "hadolint" in job
        # shfmt checks SHELL scripts; running it on the repo root was what
        # the old step actually did while claiming to check the Dockerfile.
        assert "shfmt" not in job

    def test_it_builds_the_cheapest_real_stage(self):
        job = _job_block("docker-test")
        assert "docker build" in job
        assert "--target ci-smoke" in job
        dockerfile = _read("Dockerfile")
        assert re.search(r"^FROM \S+ AS ci-smoke\s*$", dockerfile, re.M), \
            "the job names a stage the Dockerfile must actually define"
        # and the stage resolves the runtime requirements INSIDE the image,
        # which is the part that catches a pin the base image cannot satisfy
        assert "requirements.txt" in dockerfile.split("AS ci-smoke", 1)[1]

    def test_the_final_image_is_still_the_default_build_target(self):
        """Adding stages must not change what a plain `docker build` makes."""
        stages = re.findall(r"^FROM \S+(?: AS (\S+))?", _read("Dockerfile"),
                            re.M)
        assert stages, "no FROM in the Dockerfile"
        assert stages[-1] == "runtime", \
            f"the last stage ({stages[-1]!r}) is what a plain build produces"

    def test_the_job_says_what_it_does_NOT_build(self):
        """The honest half: the full image is 30+ minutes and is NOT the gate."""
        job = _job_block("docker-test")
        assert "NOT built here" in job


class TestTheInstallersAreSyntacticallySound:
    def test_the_shell_installer_parses(self):
        """`sh -n` is cheap and catches the classic quoting slip."""
        import shutil
        import subprocess

        sh = shutil.which("sh")
        if sh is None:                        # pragma: no cover
            pytest.skip("no POSIX shell available")
        result = subprocess.run([sh, "-n", os.path.join(REPO, "install",
                                                        "install.sh")],
                                capture_output=True, text=True)
        assert result.returncode == 0, result.stdout + result.stderr
