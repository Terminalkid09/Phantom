"""
provider_contract.py — explicit contracts for the external data providers.

Phantom talks to a handful of public services (NVD, crt.sh, Shodan /
InternetDB, GitHub, bgpview, local ExploitDB) through
:mod:`phantom.utils.api`. That module called ``requests.get`` inline, which
made three things hard:

  * attributing a finding to the service that produced it — the belief
    model's ``source_reliability`` (see :mod:`phantom.automation.belief`);
  * running the unit suite fully offline and deterministically;
  * reproducing an AutoMode decision without reaching the live internet.

This module gives every provider a small, DECLARED contract (name,
reliability, whether it needs a key, a default timeout, a cache TTL) and a
single transport seam, :func:`http_get`, that the external calls go
through. Two modes make the network optional:

  * REPLAY — when a fixtures directory is configured
    (``providers.fixtures_dir`` / ``PHANTOM_PROVIDER_FIXTURES``) and a
    matching fixture exists, the stored response is returned with NO
    network call. The key is a hash of the redacted request, so a fixture
    recorded with one API key replays with another (or none).
  * RECORD — when recording is on (``providers.record`` /
    ``PHANTOM_PROVIDER_RECORD``) a live response is written back as a
    fixture. Secrets (``key``/``token``/``Authorization`` …) are redacted
    BEFORE the file is written.

The seam is deliberately thin: :func:`http_get` still calls
``requests.get`` itself, so a ``monkeypatch.setattr(requests, "get", ...)``
keeps intercepting exactly as it did before.
"""

from __future__ import annotations

import hashlib
import json
import os
import tempfile
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Tuple
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

import requests

from phantom.utils import config

# Request fields that carry a secret and must never be persisted to a
# fixture (case-insensitive match against param / header names).
SECRET_FIELDS = frozenset({
    "key", "apikey", "api_key", "token", "access_token", "auth",
    "authorization", "x-api-key", "x-auth-token", "password",
})
_REDACTED = "REDACTED"


@dataclass(frozen=True)
class ProviderSpec:
    """The declared contract for one external data provider.

    ``reliability`` is the belief model's ``source_reliability`` for facts
    that originate here: a service's own output is not the same evidence as
    a value a public API merely reports.
    """

    name: str
    reliability: float
    requires_auth: bool = False
    timeout: int = 10
    cache_ttl: int = 0
    description: str = ""
    endpoints: Tuple[str, ...] = field(default=())

    def as_dict(self) -> Dict[str, Any]:
        return {
            "name": self.name,
            "reliability": self.reliability,
            "requires_auth": self.requires_auth,
            "timeout": self.timeout,
            "cache_ttl": self.cache_ttl,
            "description": self.description,
            "endpoints": list(self.endpoints),
        }


# The catalog: every outbound data source Phantom knows about. Reliability
# is a starting rank, not a verdict — the merge in automation/belief.py can
# still be overridden by stronger evidence.
PROVIDERS: Dict[str, ProviderSpec] = {
    "nvd": ProviderSpec(
        name="nvd", reliability=0.9, requires_auth=False, timeout=15,
        cache_ttl=86400,
        description="NIST NVD CVE feed",
        endpoints=("https://services.nvd.nist.gov/rest/json/cves/2.0",),
    ),
    "crtsh": ProviderSpec(
        name="crtsh", reliability=0.6, requires_auth=False, timeout=15,
        description="crt.sh certificate-transparency subdomain search",
        endpoints=("https://crt.sh/",),
    ),
    "shodan": ProviderSpec(
        name="shodan", reliability=0.7, requires_auth=True, timeout=10,
        description="Shodan host API (key required)",
        endpoints=("https://api.shodan.io/",),
    ),
    "shodan_internetdb": ProviderSpec(
        name="shodan_internetdb", reliability=0.6, requires_auth=False,
        timeout=10,
        description="Shodan InternetDB (free, no key)",
        endpoints=("https://internetdb.shodan.io/",),
    ),
    "github": ProviderSpec(
        name="github", reliability=0.55, requires_auth=False, timeout=10,
        description="GitHub code/repo search for public PoCs",
        endpoints=("https://api.github.com/",),
    ),
    "bgpview": ProviderSpec(
        name="bgpview", reliability=0.7, requires_auth=False, timeout=10,
        description="bgpview.io ASN / prefix data",
        endpoints=("https://api.bgpview.io/",),
    ),
    "exploitdb": ProviderSpec(
        name="exploitdb", reliability=0.8, requires_auth=False, timeout=10,
        description="Local searchsploit ExploitDB index",
        endpoints=(),
    ),
}


def get_provider(name: str) -> Optional[ProviderSpec]:
    """The declared contract for ``name`` (None when unknown)."""
    return PROVIDERS.get(str(name or "").strip().lower())


def reliability_of(name: str, default: float = 0.5) -> float:
    """``source_reliability`` for findings attributed to ``name``.

    Unknown providers fall back to the neutral ``default`` so a new source
    is never silently treated as trustworthy.
    """
    spec = get_provider(name)
    return spec.reliability if spec else default


def list_providers() -> List[ProviderSpec]:
    return list(PROVIDERS.values())


# ── Fixture directory / mode resolution ───────────────────────────────────

def fixtures_dir() -> str:
    """The configured fixtures directory, or "" when replay is disabled."""
    try:
        return config.get_str("providers.fixtures_dir", "",
                              env="PHANTOM_PROVIDER_FIXTURES").strip()
    except Exception:
        return ""


def record_enabled() -> bool:
    """True when live responses should be captured as fixtures."""
    try:
        return config.get_bool("providers.record", False,
                               env="PHANTOM_PROVIDER_RECORD")
    except Exception:
        return False


# ── Redaction ─────────────────────────────────────────────────────────────

def redact_params(params: Optional[Dict[str, Any]]) -> Dict[str, Any]:
    if not params:
        return {}
    out: Dict[str, Any] = {}
    for k, v in params.items():
        out[k] = _REDACTED if str(k).lower() in SECRET_FIELDS else v
    return out


def redact_headers(headers: Optional[Dict[str, Any]]) -> Dict[str, str]:
    if not headers:
        return {}
    out: Dict[str, str] = {}
    for k, v in headers.items():
        out[str(k)] = _REDACTED if str(k).lower() in SECRET_FIELDS else str(v)
    return out


def redact_url(url: str) -> str:
    """Strip secret query values from ``url`` (path is preserved)."""
    if not url:
        return url
    parts = urlsplit(url)
    if not parts.query:
        return url
    pairs = [(k, _REDACTED if k.lower() in SECRET_FIELDS else v)
             for k, v in parse_qsl(parts.query, keep_blank_values=True)]
    query = urlencode(pairs)
    return urlunsplit((parts.scheme, parts.netloc, parts.path, query,
                       parts.fragment))


def fixture_key(provider: str, url: str, params: Optional[Dict[str, Any]] = None) -> str:
    """A stable, secret-free key for one request.

    Determined from the REDACTED request so the same fixture replays no
    matter which API key (or none) the caller uses.
    """
    normalized = (
        f"{str(provider or '').lower()}\n"
        f"GET\n{redact_url(url)}\n"
        f"{json.dumps(redact_params(params), sort_keys=True, default=str)}"
    )
    return hashlib.sha256(normalized.encode("utf-8")).hexdigest()


# ── Response wrapper ──────────────────────────────────────────────────────

class ProviderResponse:
    """A minimal drop-in for the subset of ``requests.Response`` the API
    wrappers use: ``status_code``, ``headers``, ``text``, ``json()`` and
    ``raise_for_status()``."""

    def __init__(self, status_code: int = 200,
                 headers: Optional[Dict[str, str]] = None,
                 body: Any = None, text: str = "",
                 url: str = "", from_fixture: bool = False) -> None:
        self.status_code = int(status_code)
        self.headers = dict(headers or {})
        self._body = body
        self._text = text
        self.url = url
        self.from_fixture = from_fixture

    @property
    def ok(self) -> bool:
        return 200 <= self.status_code < 400

    @property
    def text(self) -> str:
        if self._text:
            return self._text
        if self._body is not None:
            try:
                return json.dumps(self._body)
            except (TypeError, ValueError):
                return str(self._body)
        return ""

    def json(self) -> Any:
        if self._body is not None:
            return self._body
        return json.loads(self._text)

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise requests.HTTPError(
                f"{self.status_code} response for {self.url or 'provider'}")


# ── Transport seam ────────────────────────────────────────────────────────

def _fixture_path(directory: str, provider: str, key: str) -> str:
    safe = str(provider or "unknown").lower().replace(os.sep, "_")
    return os.path.join(directory, safe, f"{key}.json")


def _load_fixture(path: str) -> Optional[ProviderResponse]:
    try:
        with open(path, "r", encoding="utf-8") as fh:
            data = json.load(fh)
    except (OSError, ValueError):
        return None
    if not isinstance(data, dict):
        return None
    return ProviderResponse(
        status_code=data.get("status_code", 200),
        headers=data.get("headers", {}),
        body=data.get("body"),
        text=data.get("text", ""),
        url=data.get("request", {}).get("url", ""),
        from_fixture=True,
    )


def _write_fixture(directory: str, provider: str, key: str, url: str,
                   params: Optional[Dict[str, Any]], resp: Any) -> None:
    """Persist ``resp`` as a redacted fixture (best-effort; never raises)."""
    try:
        body: Any = None
        text = ""
        try:
            body = resp.json()
        except Exception:
            text = getattr(resp, "text", "") or ""
        payload = {
            "provider": provider,
            "recorded_at": time.time(),
            "request": {"method": "GET", "url": redact_url(url),
                        "params": redact_params(params)},
            "status_code": getattr(resp, "status_code", 200),
            "headers": redact_headers(getattr(resp, "headers", {})),
            "body": body,
            "text": text,
        }
        path = _fixture_path(directory, provider, key)
        os.makedirs(os.path.dirname(path), exist_ok=True)
        fd, tmp = tempfile.mkstemp(dir=os.path.dirname(path),
                                   prefix=".fixture.", suffix=".tmp")
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2, sort_keys=True)
        os.replace(tmp, path)
    except Exception:
        pass


def http_get(provider: str, url: str,
             params: Optional[Dict[str, Any]] = None,
             headers: Optional[Dict[str, Any]] = None,
             timeout: Optional[int] = None) -> Any:
    """GET ``url`` through the provider seam, replaying a fixture when one
    exists and recording the live response when recording is enabled."""
    spec = get_provider(provider)
    if timeout is None:
        timeout = spec.timeout if spec else 10

    directory = fixtures_dir()
    key = fixture_key(provider, url, params) if directory else ""

    if directory:
        cached = _load_fixture(_fixture_path(directory, provider, key))
        if cached is not None:
            return cached

    resp = requests.get(url, params=params, headers=headers, timeout=timeout)

    if directory and record_enabled():
        _write_fixture(directory, provider, key, url, params, resp)
    return resp
