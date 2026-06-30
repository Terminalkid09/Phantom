"""Project-root-relative path helpers."""
import os

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def project_root() -> str:
    return os.path.dirname(_PKG_ROOT)


def data_dir() -> str:
    return os.path.join(project_root(), "data")


def sessions_dir() -> str:
    return os.path.join(data_dir(), "sessions")


def scan_xml_path(target: str) -> str:
    safe = target.replace("/", "_").replace("\\", "_")
    return os.path.join(sessions_dir(), f"scan_{safe}.xml")


def cve_cache_dir() -> str:
    return os.path.join(data_dir(), "cache")


def cve_cache_path() -> str:
    return os.path.join(cve_cache_dir(), "nvd_cache.json")
