"""setup.py — packaging metadata.

The runtime dependency list is NOT duplicated here: it is READ from
``requirements.txt``. It used to be a hand-maintained copy that had drifted —
this file was missing ``mysql-connector-python`` and ``psycopg2-binary``, so
``pip install .`` (the packaging path) installed a DIFFERENT set from
``pip install -r requirements.txt`` (the path CI and the installers use), and
a package install could not exercise the DB-backed capabilities.

Reading the one file removes the whole class of defect: the two install paths
are the same list by construction.

``setup()`` is called only under ``if __name__ == "__main__"`` so the module
can be inspected (by tests, or by a human) without triggering a build;
setuptools' legacy backend runs ``setup.py`` as ``__main__``, so packaging is
unaffected.
"""
import os

from setuptools import find_packages, setup

_ROOT = os.path.dirname(os.path.abspath(__file__))


def runtime_requirements():
    """The runtime dependency specs, straight from requirements.txt."""
    path = os.path.join(_ROOT, "requirements.txt")
    with open(path, "r", encoding="utf-8") as handle:
        lines = handle.read().splitlines()
    specs = []
    for line in lines:
        spec = line.split("#", 1)[0].strip()
        if not spec or spec.startswith("-"):
            continue                      # blanks, comments, pip options
        specs.append(spec)
    return specs


if __name__ == "__main__":
    setup(
        name="phantom",
        version="3.0.0",
        description="Offensive Security Framework — CLI shell per penetration testing",
        author="Terminalkid09",
        packages=find_packages(),
        include_package_data=True,
        install_requires=runtime_requirements(),
        entry_points={
            "console_scripts": [
                "phantom=phantom.main:main",
                "phantom.c2=phantom.main:main",
                "phantom.auto=phantom.main:main",
            ],
        },
        python_requires=">=3.10",
    )
