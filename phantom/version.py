"""The application version — ONE declaration, read by every surface.

``setup.py``, the AUTO banner, the report footer and the Electron About card
used to disagree (``3.0.0`` in the package metadata, ``v3.5.0`` in the AUTO
screen, ``3.7.3`` in an About card). An operator quoting a version in a report
could be wrong whichever surface they looked at, and a support request could
not be matched to a build.

The rule is the one ``electron/src/hooks/useAppVersion.ts`` already states:
the number lives in one place and every surface reads it. Change it HERE, and
update ``electron/package.json`` in the same commit — ``tests/
test_version_single_source.py`` fails if the two drift apart.
"""

__version__ = "3.0.0"

__all__ = ["__version__"]
