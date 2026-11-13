"""
phantom.automation.brain.expectations — the predictive world model.

A senior red teamer constantly predicts: "if this is Exchange 2016,
/ews/ exists and returns 401 with NTLM" — and a MISMATCH is a finding
even when nothing 'failed'. This engine generates
fingerprint-conditioned EXPECTATIONS from the WorldModel, checks them
against observations, and reports differentials:

    met        -> the target matches its fingerprint's behaviour
    violated   -> the target behaves unlike its fingerprint: a WAF,
                  a honeypot, a non-standard build, or something
                  misconfigured — every one is an attack signal
    unknown    -> cannot check (no probe ran) — feeds the planner
                  ("visibility gap: probe X to disambiguate")

Expectations are declarative and cheap to evaluate: they never send a
packet themselves; the planner turns violated/unknown expectations into
probe capabilities.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Tuple


@dataclass
class Expectation:
    """One predicted observable for a fingerprint condition."""
    exp_id: str
    # condition: dict of fingerprint claims (any-of matching on product)
    cond_product: str                # lowercase substring match, "" = always
    observe: str                     # observation id (probe capability or check)
    check: str                       # what to verify: "path_exists:/ews" etc.
    expect: dict = field(default_factory=dict)   # expected observation payload
    weight: float = 0.6              # how discriminating this expectation is
    note: str = ""


@dataclass
class Differential:
    exp_id: str
    observe: str
    status: str                      # met | violated | unknown
    detail: str = ""

    def to_dict(self) -> dict:
        return {"id": self.exp_id, "observe": self.observe,
                "status": self.status, "detail": self.detail}


# ── the expectation library ────────────────────────────────────────────────
# Conditions are fingerprint-conditioned: product substring -> predicted
# observables. Keep entries HIGH-signal (a wrong expectation is noise).

def _expectations() -> List[Expectation]:
    out: List[Expectation] = []
    E = Expectation

    # ── IIS / ASP.NET family ────────────────────────────────────────
    out += [
        E("iis-aspnet", "iis", "http_probe",
          "header:iis_aspnet", {"server": "Microsoft-IIS"},
          weight=0.7, note="IIS almost always exposes ASP.NET headers"),
        E("iis-webconfig", "iis", "http_probe",
          "path_status:/web.config", {"status": 403},
          weight=0.8, note="/web.config must be denied — 200 = config leak"),
        E("iis-aspx", "iis", "http_probe",
          "path_status:/default.aspx", {"status_in": (200, 302, 401, 403)},
          weight=0.5, note="an ASPX entry page should answer"),
    ]
    # ── nginx family ────────────────────────────────────────────────
    out += [
        E("nginx-server-header", "nginx", "http_probe",
          "header:server", {"server_contains": "nginx"},
          weight=0.9, note="nginx always sets its Server header"),
        E("nginx-alias-traversal", "nginx", "http_probe",
          "path_status:/..%2f..%2fetc%2fpasswd", {"status_not": 200},
          weight=0.85, note="alias traversal must not leak /etc/passwd"),
    ]
    # ── Exchange ────────────────────────────────────────────────────
    out += [
        E("exchange-ews", "exchange", "http_probe",
          "path_status:/ews/exchange", {"status_in": (401, 403, 404)},
          weight=0.75, note="EWS vroot exists on real Exchange"),
        E("exchange-autodiscover", "exchange", "http_probe",
          "path_status:/autodiscover/autodiscover.xml",
          {"status_in": (200, 401, 403, 405, 404)},
          weight=0.5, note="autodiscover vroot"),
    ]
    # ── PHP family ──────────────────────────────────────────────────
    out += [
        E("php-exposed", "php", "http_probe",
          "path_status:/info.php", {"status_not": 200},
          weight=0.6, note="phpinfo leftovers are common and loud"),
        E("php-adminer", "php", "http_probe",
          "path_status:/adminer.php", {"status_not": 200},
          weight=0.7, note="adminer.php is a classic forgotten file"),
    ]
    # ── cloud metadata reachability (env-based) ─────────────────────
    out += [
        E("aws-imds-v1", "aws", "env_probe",
          "imds_token", {"mode": "v1_or_v2"},
          weight=0.8, note="IMDS reachable from the workload"),
        E("azure-imds", "azure", "env_probe",
          "imds_token", {"mode": "v1_or_v2"},
          weight=0.8, note="Azure IMDS from the workload"),
    ]
    # ── SSH banner coherence ────────────────────────────────────────
    out += [
        E("ssh-ubuntu-version", "ubuntu", "version_detect",
          "ssh_banner_os_hint", {"os_hint_in": ("ubuntu", "debian")},
          weight=0.4, note="OpenSSH on Ubuntu carries an Ubuntu suffix"),
    ]
    return out


_EXPECTATIONS: Optional[List[Expectation]] = None


def all_expectations() -> List[Expectation]:
    global _EXPECTATIONS
    if _EXPECTATIONS is None:
        _EXPECTATIONS = _expectations()
    return _EXPECTATIONS


class ExpectationEngine:
    """Generates and evaluates expectations against the WorldModel."""

    def __init__(self) -> None:
        pass

    # ── generation ─────────────────────────────────────────────────────
    def active(self, wm) -> List[Expectation]:
        """Expectations whose fingerprint condition matches the target."""
        products: List[str] = []
        for kind in ("fingerprint", "web_header", "banner", "os"):
            for f in wm.find(kind):
                v = f.value if isinstance(f.value, dict) else {}
                for key in ("product", "server", "software", "name"):
                    if v.get(key):
                        products.append(str(v[key]).lower())
                if isinstance(f.value, str):
                    products.append(f.value.lower())
        for f in wm.find("os"):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("name"):
                products.append(str(v["name"]).lower())
        out = []
        for exp in all_expectations():
            if not exp.cond_product:
                out.append(exp)
                continue
            if any(exp.cond_product in p for p in products):
                out.append(exp)
        return out

    # ── evaluation ─────────────────────────────────────────────────────
    def evaluate(self, wm) -> List[Differential]:
        """Expected-vs-observed for every active expectation."""
        diffs: List[Differential] = []
        for exp in self.active(wm):
            observed = self._observe(exp, wm)
            if observed is None:
                diffs.append(Differential(exp.exp_id, exp.observe, "unknown",
                                          "not observed yet"))
                continue
            ok, detail = self._check(exp, observed)
            diffs.append(Differential(exp.exp_id, exp.observe,
                                      "met" if ok else "violated", detail))
        return diffs

    def signals(self, wm) -> List[Differential]:
        """Violated expectations: the interesting differentials."""
        return [d for d in self.evaluate(wm) if d.status == "violated"]

    def visibility_gaps(self, wm) -> List[Differential]:
        """Unknown expectations: what a probe should disambiguate."""
        return [d for d in self.evaluate(wm) if d.status == "unknown"]

    # ── observation extraction ─────────────────────────────────────────
    def _observe(self, exp: Expectation, wm) -> Optional[dict]:
        """Extract the observation the expectation checks, from existing
        findings ONLY (no packets). None = not observed yet."""
        if exp.observe in ("http_probe", "version_detect"):
            # header checks read web_header findings; path checks read
            # hunt_anomaly/path findings when the hunt engine has them
            if exp.check.startswith("header:"):
                name = exp.check.split(":", 1)[1].replace("_", "-").lower()
                for f in wm.find("web_header"):
                    v = f.value if isinstance(f.value, dict) else {}
                    for k, val in v.items():
                        if k.lower() == name:
                            return {"header": {name: str(val)}}
                return None
            if exp.check.startswith("path_status"):
                path = exp.check.split(":", 1)[1]
                for f in wm.find("hunt_anomaly"):
                    v = f.value if isinstance(f.value, dict) else {}
                    if str(v.get("path", "")) == path:
                        return {"status": v.get("status")}
                return None
            if exp.check.startswith("header:iis"):
                for f in wm.find("web_header"):
                    v = f.value if isinstance(f.value, dict) else {}
                    srv = str(v.get("server", "")).lower()
                    return {"header": {"server": srv}} if srv else None
                return None
            return None
        if exp.observe == "env_probe":
            envs = wm.find("environment")
            if not envs:
                return None
            v = envs[0].value if isinstance(envs[0].value, dict) else {}
            return {"cloud": v.get("cloud", "")}
        if exp.observe == "ssh_banner_os_hint":
            for f in wm.find("fingerprint") + wm.find("banner"):
                v = f.value if isinstance(f.value, dict) else {}
                if v.get("product") and "ssh" in str(f.key).lower():
                    return {"os_hint": str(v.get("product", "")).lower()}
            return None
        return None

    @staticmethod
    def _check(exp: Expectation, observed: dict) -> Tuple[bool, str]:
        """Evaluate one expectation against the observed payload."""
        if exp.check.startswith("header:"):
            name = exp.check.split(":", 1)[1].replace("_", "-").lower()
            got = (observed.get("header") or {}).get(name)
            if got is None:
                return False, f"header {name} absent (expected by {exp.exp_id})"
            if "server_contains" in exp.expect:
                ok = exp.expect["server_contains"] in got.lower()
                return ok, f"server={got!r}"
            if "server" in exp.expect:
                ok = exp.expect["server"].lower() in got.lower()
                return ok, f"server={got!r}"
            return True, f"header {name}={got!r}"
        if exp.check.startswith("path_status"):
            status = observed.get("status")
            if status is None:
                return False, f"{exp.check} not observed"
            status = int(status)
            if "status_in" in exp.expect:
                ok = status in tuple(exp.expect["status_in"])
                return ok, f"status={status} expected_in={exp.expect['status_in']}"
            if "status_not" in exp.expect:
                ok = status != int(exp.expect["status_not"])
                return ok, f"status={status} expected_not={exp.expect['status_not']}"
            if "status" in exp.expect:
                ok = status == int(exp.expect["status"])
                return ok, f"status={status} expected={exp.expect['status']}"
            return True, f"status={status}"
        if exp.check == "imds_token":
            cloud = str(observed.get("cloud", "")).lower()
            ok = cloud in ("aws", "azure", "gcp", "imds")
            return ok, f"cloud={cloud!r}"
        if exp.check == "ssh_banner_os_hint":
            got = str(observed.get("os_hint", "")).lower()
            ok = any(h in got for h in exp.expect.get("os_hint_in", ()))
            return ok, f"banner product={got!r}"
        return True, "unchecked"
