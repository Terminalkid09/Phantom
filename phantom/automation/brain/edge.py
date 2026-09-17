"""
phantom.automation.brain.edge — is this address the TARGET, or someone
else's CDN edge?

This module exists because of a real property of the modern internet: a
public IP or a domain very often resolves to a reverse proxy (Cloudflare,
Akamai, Fastly, CloudFront, Imperva, …), not to the organisation's own
machine. Scanning that address is:

  * pointless — you footprint the provider's point of presence, and every
    customer of that provider looks identical from there;
  * out of scope — you are now sending packets at a THIRD PARTY's
    infrastructure, which is exactly the kind of collateral an authorised
    engagement cannot afford.

So the doctrine treats edge detection as a GATE on the whole footprint
stage:

    edge detected, origin unknown  ->  target-touching probes are refused
                                       and origin discovery becomes the
                                       next move
    origin known                   ->  the chain resumes against the origin

Detection is deliberately multi-signal and evidence-carrying (CNAME,
response headers, curated provider ranges), never a single heuristic: a
false positive would silently stop an engagement, and a false negative
would scan a CDN. The curated IP list is intentionally small — it is a
GATE, not an ASN database; environment analysis is where a full ASN lookup
belongs.

The module is pure: every I/O (DNS, HTTP) is a caller-supplied callable, so
the whole decision can be unit-tested offline.
"""

from __future__ import annotations

import ipaddress
import re
from dataclasses import dataclass, field
from typing import Callable, Dict, Iterable, List, Mapping, Optional, Sequence, Tuple

# ── finding kinds ──────────────────────────────────────────────────────────

EDGE_FACT = "edge"       # value: {address, provider, confidence, evidence}
ORIGIN_FACT = "origin"   # value: {host, ip, reason, confidence}

# ── confidence model ───────────────────────────────────────────────────────

CONF_HEADER_STRONG = 0.95   # cf-ray / x-amz-cf-id / x-iinfo / x-sucuri-id
CONF_HEADER_WEAK = 0.60     # via: varnish, x-cache alone
CONF_CNAME = 0.90           # *.cloudflare.net, *.akamaiedge.net, ...
CONF_IP = 0.80              # curated provider range

# Below this the signal is "interesting" but NOT a gate: shared hosting and
# transit ranges produce too many near-misses to stop a run on.
EDGE_THRESHOLD = 0.75

# An origin candidate below this is a NAME, not a discovery: the chain waits
# for a better one instead of aiming the engagement at a guess.
ORIGIN_MIN_CONFIDENCE = 0.55


# ── naming ─────────────────────────────────────────────────────────────────

# provider -> regex matched against a CNAME / a resolved name
CNAME_PATTERNS: Tuple[Tuple[str, str], ...] = (
    ("cloudflare", r"\.cloudflare\.net$|\.cloudflare\.com$|cdn\.cloudflare\.net$"),
    ("akamai", r"\.akamaiedge\.net$|\.akamaitechnologies\.com$|"
               r"\.edgekey\.net$|\.edgesuite\.net$|\.akamai\.net$|"
               r"\.akamaiedge-staging\.net$"),
    ("fastly", r"\.fastly\.net$|\.fastlylb\.net$|\.fastly-edge\.com$"),
    ("cloudfront", r"\.cloudfront\.net$"),
    ("imperva", r"\.incapdns\.net$|\.impervadns\.net$|\.incapsula\.com$"),
    ("azure-front-door", r"\.azureedge\.net$|\.azurefd\.net$|"
                         r"\.trafficmanager\.net$|\.azurefd\.us$"),
    ("sucuri", r"\.sucuri\.net$|cloudproxy\.sucuri\.net$"),
    ("stackpath", r"\.hwcdn\.net$|\.stackpathdns\.com$|\.stackpathcdn\.com$"),
    ("bunny", r"\.b-cdn\.net$|\.bunnycdn\.com$"),
    ("gcore", r"\.gcdn\.co$|\.gcorelabs\.com$"),
    ("keycdn", r"\.kxcdn\.com$"),
    ("cdn77", r"\.cdn77\.org$|\.cdn77\.net$"),
    ("limelight", r"\.llnwd\.net$|\.llnw\.net$"),
    ("edgecast", r"\.edgecastcdn\.net$|\.systemcdn\.net$|"
                 r"\.transactcdn\.com$"),
    ("alibaba", r"\.alicdn\.com$|\.kunlun\.com$|\.kunlungr\.com$"),
    ("ddos-guard", r"\.ddos-guard\.net$"),
)

_CNAME_COMPILED: Tuple[Tuple[str, "re.Pattern[str]"], ...] = tuple(
    (provider, re.compile(pattern, re.I)) for provider, pattern in CNAME_PATTERNS)


# provider -> (header, value regex or "" for presence-only)
HEADER_PATTERNS: Tuple[Tuple[str, str, str], ...] = (
    ("cloudflare", "cf-ray", ""),
    ("cloudflare", "cf-cache-status", ""),
    ("cloudflare", "server", r"^cloudflare$"),
    ("akamai", "x-akamai-transformed", ""),
    ("akamai", "x-akamai-request-id", ""),
    ("akamai", "akamai-grn", ""),
    ("akamai", "server", r"^akamaighost$"),
    ("fastly", "x-served-by", r"^cache-"),
    ("fastly", "x-fastly-request-id", ""),
    ("cloudfront", "x-amz-cf-id", ""),
    ("cloudfront", "x-amz-cf-pop", ""),
    ("cloudfront", "server", r"^cloudfront$"),
    ("imperva", "x-iinfo", ""),
    ("imperva", "x-cdn", r"incapsula"),
    ("azure-front-door", "x-azure-ref", ""),
    ("azure-front-door", "x-fd-int", ""),
    ("sucuri", "x-sucuri-id", ""),
    ("sucuri", "server", r"^sucuri"),
    ("stackpath", "x-hw", ""),
    ("bunny", "server", r"^bunny"),
)

# Headers that only SUGGEST a shared cache: presence alone must not gate a run.
HEADER_WEAK: Tuple[Tuple[str, str, str], ...] = (
    ("varnish", "via", r"varnish"),
    ("varnish", "x-cache", r"(hit|miss)"),
    ("varnish", "x-varnish", ""),
)

_HEADER_COMPILED: Tuple[Tuple[str, str, "re.Pattern[str]", float], ...] = tuple(
    (provider, header, re.compile(value, re.I) if value else re.compile(r".*"),
     CONF_HEADER_STRONG if header not in ("server", "x-cache-status") else CONF_HEADER_STRONG)
    for provider, header, value in HEADER_PATTERNS) + tuple(
    (provider, header, re.compile(value, re.I) if value else re.compile(r".*"),
     CONF_HEADER_WEAK)
    for provider, header, value in HEADER_WEAK)


# ── curated ranges ─────────────────────────────────────────────────────────
#
# Well-known public ranges of the large reverse proxies. Curated on purpose:
# every entry must be one an operator can recognise, and the list is a GATE,
# not an ASN database.

IPV4_RANGES: Dict[str, Tuple[str, ...]] = {
    "cloudflare": (
        "103.21.244.0/22", "103.22.200.0/22", "103.31.4.0/22",
        "104.16.0.0/13", "104.24.0.0/14", "108.162.192.0/18",
        "131.0.72.0/22", "141.101.64.0/18", "162.158.0.0/15",
        "172.64.0.0/13", "173.245.48.0/20", "188.114.96.0/20",
        "190.93.240.0/20", "197.234.240.0/22", "198.41.128.0/17",
    ),
    "akamai": (
        "23.32.0.0/11", "23.192.0.0/11", "72.246.0.0/15", "96.6.0.0/15",
        "104.64.0.0/10", "184.24.0.0/13", "184.50.0.0/15", "23.0.0.0/12",
    ),
    "fastly": (
        "23.235.32.0/20", "43.249.72.0/22", "103.244.50.0/24",
        "151.101.0.0/16", "157.52.64.0/18", "167.82.0.0/17",
        "185.31.16.0/22", "199.232.0.0/16",
    ),
    "cloudfront": (
        "3.160.0.0/14", "13.32.0.0/15", "13.35.0.0/16", "13.224.0.0/14",
        "18.64.0.0/12", "52.84.0.0/15", "54.182.0.0/16", "54.192.0.0/16",
        "54.230.0.0/16", "54.239.128.0/18", "99.84.0.0/16",
        "108.138.0.0/15", "108.156.0.0/14", "204.246.164.0/22",
    ),
    "imperva": (
        "45.64.64.0/22", "103.28.248.0/22", "107.154.0.0/16",
        "149.126.72.0/21", "185.11.124.0/22", "192.230.64.0/18",
        "198.143.32.0/19", "199.83.128.0/21",
    ),
    "sucuri": (
        "66.248.200.0/22", "185.93.228.0/22", "192.88.134.0/23",
        "208.109.0.0/22",
    ),
}


def _compile_ranges() -> Tuple[Tuple[str, "ipaddress.IPv4Network"], ...]:
    out = []
    for provider, nets in IPV4_RANGES.items():
        for cidr in nets:
            try:
                out.append((provider, ipaddress.ip_network(cidr, strict=False)))
            except ValueError:            # pragma: no cover — bad literal
                continue
    return tuple(out)


_RANGES_COMPILED: Tuple[Tuple[str, "ipaddress.IPv4Network"], ...] = _compile_ranges()


# ── origin naming knowledge ────────────────────────────────────────────────

# Sub-domain labels that historically indicate the machine BEHIND the edge
# rather than another edge-hosted name.
ORIGIN_HINTS: Tuple[str, ...] = (
    "origin", "origin-www", "direct", "backend", "back", "internal",
    "intranet", "web1", "web2", "web01", "app", "apps", "api-origin",
    "dev", "development", "staging", "stage", "test", "qa", "uat",
    "preprod", "old", "legacy", "archive", "mail", "smtp", "imap", "ftp",
    "sftp", "ssh", "gitlab", "jenkins", "ci", "vpn", "remote", "gateway",
    "cpanel", "webmail", "portal", "admin", "db", "database", "ns1",
)

# Hosts that are ALMOST CERTAINLY the edge: never propose them as origins.
_NEVER_ORIGIN = re.compile(
    r"^(www|cdn|static|assets|img|images|media|edge|proxy|"
    r"cache|cache-\d+|waf)\b|"
    r"\.(cloudflare|akamaiedge|fastly|cloudfront|incapdns|azureedge|"
    r"edgekey|edgesuite|hwcdn|b-cdn|gcdn|kxcdn|cdn77)\.", re.I)


# ── verdicts ───────────────────────────────────────────────────────────────

@dataclass(frozen=True)
class EdgeVerdict:
    """Whether an address belongs to a reverse-proxy provider, and the
    evidence that says so. `bool(verdict)` is `is_edge`."""

    is_edge: bool = False
    provider: str = ""
    confidence: float = 0.0
    evidence: Tuple[str, ...] = ()

    def __bool__(self) -> bool:
        return self.is_edge

    def to_dict(self) -> dict:
        return {"is_edge": self.is_edge, "provider": self.provider,
                "confidence": round(self.confidence, 3),
                "evidence": list(self.evidence)}

    def summary(self) -> str:
        if not self.is_edge:
            return "not an edge"
        return (f"{self.provider} edge (confidence {self.confidence:.2f}: "
                f"{', '.join(self.evidence)})")

    def markers(self, address: str = "") -> List[str]:
        """Marker lines for the shared interpreter (no spaces in values)."""
        if not self.is_edge:
            return [f"EDGE: address={address or '-'} is_edge=false"]
        ev = "|".join(e.replace(" ", "_") for e in self.evidence) or "-"
        return [f"EDGE: address={address or '-'} provider={self.provider} "
                f"confidence={self.confidence:.2f} is_edge=true evidence={ev}"]


@dataclass(frozen=True)
class OriginCandidate:
    """A host that plausibly IS the machine behind the edge."""

    host: str
    ip: str = ""
    reason: str = ""
    confidence: float = 0.0

    def to_dict(self) -> dict:
        return {"host": self.host, "ip": self.ip, "reason": self.reason,
                "confidence": round(self.confidence, 3)}

    def markers(self) -> List[str]:
        return [f"ORIGIN: host={self.host} ip={self.ip or '-'} "
                f"reason={self.reason or '-'} "
                f"confidence={self.confidence:.2f}"]


@dataclass
class EdgeReport:
    """Everything one origin-discovery pass produced."""

    address: str = ""
    verdict: EdgeVerdict = field(default_factory=EdgeVerdict)
    candidates: List[OriginCandidate] = field(default_factory=list)

    @property
    def is_edge(self) -> bool:
        return self.verdict.is_edge

    def best(self) -> Optional[OriginCandidate]:
        if not self.candidates:
            return None
        return max(self.candidates, key=lambda c: c.confidence)

    def markers(self) -> List[str]:
        out = self.verdict.markers(self.address)
        for c in sorted(self.candidates, key=lambda c: -c.confidence)[:12]:
            out.extend(c.markers())
        return out


# ── detection ──────────────────────────────────────────────────────────────

def provider_for_cname(cname: str) -> Tuple[str, str]:
    """(provider, evidence) for a CNAME target, or ("", "")."""
    name = (cname or "").strip().strip(".").lower()
    if not name:
        return "", ""
    for provider, pattern in _CNAME_COMPILED:
        if pattern.search(name):
            return provider, f"cname:{name}"
    return "", ""


def provider_for_ip(ip: str) -> Tuple[str, str]:
    """(provider, evidence) for an IPv4 address in a curated provider range."""
    addr = (ip or "").strip()
    if not addr:
        return "", ""
    try:
        obj = ipaddress.ip_address(addr)
    except ValueError:
        return "", ""
    if obj.version != 4:                  # v6 provider ranges are not curated
        return "", ""
    for provider, network in _RANGES_COMPILED:
        if obj in network:
            return provider, f"range:{network}"
    return "", ""


def provider_for_headers(headers: Mapping[str, str]) -> Tuple[str, float, str]:
    """(provider, confidence, evidence) for a response header set."""
    if not headers:
        return "", 0.0, ""
    lowered = {str(k).strip().lower(): str(v).strip() for k, v in headers.items()}
    best = ("", 0.0, "")
    for provider, header, pattern, confidence in _HEADER_COMPILED:
        value = lowered.get(header)
        if value is None:
            continue
        if pattern.pattern != ".*" and not pattern.search(value):
            continue
        if confidence > best[1]:
            best = (provider, confidence,
                    f"header:{header}={value[:24] or 'present'}")
    return best


def detect(*, address: str = "", ip: str = "", cname: str = "",
           headers: Optional[Mapping[str, str]] = None) -> EdgeVerdict:
    """Merge every available signal into one verdict.

    The strongest signal wins the provider name; the confidence is the
    maximum of the signals that agree (a CNAME to cloudflare.net plus a
    cf-ray header is not "more than certain", it is certain twice).
    """
    evidence: List[str] = []
    provider = ""
    confidence = 0.0

    h_provider, h_conf, h_ev = provider_for_headers(headers or {})
    if h_provider:
        provider, confidence = h_provider, h_conf
        evidence.append(h_ev)

    c_provider, c_ev = provider_for_cname(cname)
    if c_provider:
        evidence.append(c_ev)
        if c_provider == provider or not provider:
            provider = provider or c_provider
            confidence = max(confidence, CONF_CNAME)

    i_provider, i_ev = provider_for_ip(ip)
    if i_provider:
        evidence.append(i_ev)
        if i_provider == provider or not provider:
            provider = provider or i_provider
            confidence = max(confidence, CONF_IP)

    # a provider disagreement is exactly the case where a scan would hit the
    # wrong party: keep the strongest signal, but record the conflict
    return EdgeVerdict(is_edge=confidence >= EDGE_THRESHOLD,
                       provider=provider,
                       confidence=confidence,
                       evidence=tuple(evidence))


def is_edge_ip(ip: str) -> bool:
    return provider_for_ip(ip)[0] != ""


def is_edge_headers(headers: Mapping[str, str]) -> bool:
    return provider_for_headers(headers)[1] >= EDGE_THRESHOLD


# ── origin discovery ───────────────────────────────────────────────────────

ResolveFn = Callable[[str], Tuple[str, List[str]]]


def origin_candidates(
    hosts: Iterable[str],
    *,
    domain: str = "",
    resolve: Optional[ResolveFn] = None,
    edge_verdict: Optional[EdgeVerdict] = None,
) -> List[OriginCandidate]:
    """Rank the hosts that plausibly are the machine behind the edge.

    Two rules, both evidence-based:

      * a host that is ITSELF an edge (by name or by refused resolution) is
        never a candidate — proposing `cdn.example.com` as the origin would
        just re-scan another provider PoP;
      * a host whose name carries an origin hint (origin/direct/vpn/mail/…)
        or that resolves to an address OUTSIDE the edge ranges scores higher.

    `resolve(host) -> (cname, [ips])` is injected (the agent wires `dig`
    behind it); with no resolver, naming alone decides, at lower confidence.
    """
    apex = (domain or "").strip().lower()
    out: List[OriginCandidate] = []
    seen: set = set()
    for raw in hosts:
        host = (raw or "").strip().strip(".").lower()
        if not host or host in seen or "." not in host:
            continue
        if apex and not host.endswith(apex):
            continue                     # not part of this asset's namespace
        if _NEVER_ORIGIN.search(host):
            continue
        seen.add(host)

        cname, ips = ("", [])
        if resolve is not None:
            try:
                cname, ips = resolve(host)
            except Exception:
                cname, ips = ("", [])

        # the host itself is an edge: not an origin, ever
        c_provider, _ = provider_for_cname(cname)
        if c_provider and (edge_verdict is None
                           or c_provider == edge_verdict.provider):
            continue

        ip = ""
        if ips:
            ip = str(ips[0])
            if is_edge_ip(ip):
                continue

        label = host.split(".")[0]
        hint = label in ORIGIN_HINTS or any(
            label.startswith(f"{h}-") or label.endswith(f"-{h}")
            for h in ORIGIN_HINTS)
        reasons: List[str] = []
        # Confidence is EVIDENCE, not enthusiasm. A name that merely looks
        # like an origin (`gateway.example.com`) stays BELOW the floor: it is
        # a lead for the next pass, not grounds to aim an engagement at a
        # guess. Resolving outside the provider's ranges is evidence; the
        # naming hint makes that evidence much stronger.
        conf = 0.30                                  # nothing checked
        if ip:
            reasons.append("resolves")
            conf = 0.60
        if hint:
            reasons.append("naming")
            conf = 0.85 if ip else 0.45              # 0.45 < floor on purpose
        out.append(OriginCandidate(host=host, ip=ip,
                                   reason="+".join(reasons) or "candidate",
                                   confidence=conf))
    return sorted(out, key=lambda c: -c.confidence)


def discover(
    address: str,
    *,
    hosts: Iterable[str] = (),
    domain: str = "",
    ip: str = "",
    cname: str = "",
    headers: Optional[Mapping[str, str]] = None,
    resolve: Optional[ResolveFn] = None,
) -> EdgeReport:
    """One bounded detection + origin-discovery pass."""
    verdict = detect(address=address, ip=ip, cname=cname, headers=headers)
    cands = origin_candidates(hosts, domain=domain or address, resolve=resolve,
                              edge_verdict=verdict)
    return EdgeReport(address=address, verdict=verdict, candidates=cands)
