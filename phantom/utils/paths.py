"""Project-root-relative path helpers."""
import os
import re

_PKG_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def project_root() -> str:
    return os.path.dirname(_PKG_ROOT)


def data_dir() -> str:
    """Return writable runtime data directory.

    Packaged Electron builds set ``PHANTOM_DATA_DIR`` to the per-user app
    data directory. Source/CLI runs keep the project-local ``data/`` layout.
    """
    override = os.getenv("PHANTOM_DATA_DIR", "").strip()
    return override or os.path.join(project_root(), "data")


def certs_dir() -> str:
    return os.path.join(data_dir(), "certs")


def certs_exist() -> bool:
    legacy = (os.path.exists(os.path.join(certs_dir(), "server.crt"))
              and os.path.exists(os.path.join(certs_dir(), "server.key")))
    mtls = (os.path.exists(os.path.join(certs_dir(), "mtls_server.crt"))
            and os.path.exists(os.path.join(certs_dir(), "mtls_server.key"))
            and os.path.exists(os.path.join(certs_dir(), "client_ca.crt")))
    return legacy or mtls


def sessions_dir() -> str:
    return os.path.join(data_dir(), "sessions")


def reports_dir() -> str:
    return os.path.join(data_dir(), "reports")


def scan_xml_path(target: str) -> str:
    safe = re.sub(r"[^A-Za-z0-9._\-]", "_", target)
    return os.path.join(sessions_dir(), f"scan_{safe}.xml")


def cve_cache_dir() -> str:
    return os.path.join(data_dir(), "cache")


def cve_cache_path() -> str:
    return os.path.join(cve_cache_dir(), "nvd_cache.json")
