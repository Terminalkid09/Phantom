"""
phantom.automation.brain.operators — exploit primitives as typed operators.

A capability is a READY-MADE move. An operator is a PRIMITIVE with typed
pre/post conditions that the composition engine can chain into attack
paths the capability registry never contained:

    sqli UNION (read file) -> password -> ssh_login -> creds
    ssrf -> metadata endpoint -> cloud keys -> console access
    upload + path traversal -> webshell write -> rce

Operators describe WHAT they need (typed facts), WHAT they produce
(typed facts) and WHAT they cost (opsec/noise/time) — the composition
search (composition.py) runs over them, the hypothesis engine
(hypotheses.py) verifies a composed chain with discriminating probes
before the agent ever fires a real exploit.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Dict, List, Optional, Set, Tuple

# ── typed fact space ───────────────────────────────────────────────────────
# Fact tokens are strings of the form "kind.qualifier". The composition
# engine matches operator preconditions against the WorldModel's facts and
# against facts produced EARLIER in the chain (forward effects).

@dataclass(frozen=True)
class FactType:
    """One typed fact in the composition space."""
    token: str            # e.g. "web.upload", "creds.ssh", "rce.webshell"
    desc: str = ""

    def __str__(self) -> str:
        return self.token


# input-space facts (things the world can hold)
WEB_APP = FactType("web.app", "a web application was fingerprinted")
WEB_UPLOAD = FactType("web.upload", "an upload endpoint exists")
WEB_PARAM = FactType("web.param", "an injectable parameter was mapped")
WEB_ADMIN = FactType("web.admin", "an admin panel was found")
WEB_SSRF = FactType("web.ssrf", "a URL-fetch primitive exists")
SERVICE_SSH = FactType("service.ssh", "SSH service discovered")
SERVICE_DB = FactType("service.db", "a database service (mysql/mssql/pg)")
SERVICE_SMB = FactType("service.smb", "SMB service discovered")
CREDS_ANY = FactType("creds.any", "a credential pair (any service)")
CREDS_SSH = FactType("creds.ssh", "an SSH credential pair")
CREDS_DB = FactType("creds.db", "a database credential pair")
CREDS_ADMIN = FactType("creds.admin", "an application admin credential")
RCE_WEB = FactType("rce.web", "remote code execution via the web app")
FILE_READ = FactType("file.read", "arbitrary file read primitive")
FILE_WRITE = FactType("file.write", "arbitrary file write primitive")
SSRF_META = FactType("cloud.metadata", "cloud metadata endpoint reachable")
CLOUD_KEYS = FactType("cloud.keys", "cloud API keys harvested")
OS_KNOWN = FactType("os.known", "the OS is fingerprinted")
HASH_DUMP = FactType("creds.hash", "credential hashes in hand")
ENV_KNOWN = FactType("env.known", "the runtime environment was probed")
BEACON_LIVE = FactType("beacon.live", "a beacon session is established")
PRIV_SYSTEM = FactType("priv.system", "SYSTEM/root on the foothold")
PERSIST_INSTALLED = FactType("persist.installed", "beacon persistence installed")
PIVOT_SMB = FactType("pivot.smb", "lateral movement over SMB done")
PIVOT_WINRM = FactType("pivot.winrm", "lateral movement over WinRM done")
INTERNAL_HOST = FactType("internal.host", "an in-scope internal neighbor discovered")
INTERNAL_SERVICE = FactType("internal.service", "a pivot service on an internal peer")

# every fact an operator may reference
ALL_FACTS: Dict[str, FactType] = {f.token: f for f in (
    WEB_APP, WEB_UPLOAD, WEB_PARAM, WEB_ADMIN, WEB_SSRF,
    SERVICE_SSH, SERVICE_DB, SERVICE_SMB,
    CREDS_ANY, CREDS_SSH, CREDS_DB, CREDS_ADMIN,
    RCE_WEB, FILE_READ, FILE_WRITE, SSRF_META, CLOUD_KEYS,
    OS_KNOWN, HASH_DUMP, ENV_KNOWN,
    BEACON_LIVE, PRIV_SYSTEM, PERSIST_INSTALLED, PIVOT_SMB, PIVOT_WINRM,
    INTERNAL_HOST, INTERNAL_SERVICE,
)}


@dataclass
class Operator:
    """One exploitable primitive with typed pre/post conditions."""
    op_id: str
    requires: Tuple[str, ...]          # fact tokens needed
    produces: Tuple[str, ...]          # fact tokens produced
    # probe: a CHEAP discriminating test that proves the operator's
    # precondition claim on THIS target (runs before the exploit)
    probe: Optional[Callable[[object], bool]] = None
    # exploit: the actual execution (registered lazily — composition
    # reasons WITHOUT it, execution binds it)
    exploit: Optional[Callable[[object], Optional[str]]] = None
    cost: float = 1.0                  # opsec cost
    noise: float = 0.2                 # detection risk 0..1
    desc: str = ""

    def viable(self, have: Set[str]) -> bool:
        return all(r in have for r in self.requires)


# ── the operator registry ──────────────────────────────────────────────────

class OperatorRegistry:
    """All known primitives. Extensible: register() adds operator packs
    (web, cloud, ad) without touching the search engine."""

    def __init__(self) -> None:
        self._ops: Dict[str, Operator] = {}

    def register(self, op: Operator) -> None:
        self._ops[op.op_id] = op

    def register_all(self, ops) -> None:
        for op in ops:
            self.register(op)

    def get(self, op_id: str) -> Optional[Operator]:
        return self._ops.get(op_id)

    def all(self) -> List[Operator]:
        return list(self._ops.values())

    def producing(self, fact: str) -> List[Operator]:
        return [o for o in self._ops.values() if fact in o.produces]

    def __len__(self) -> int:
        return len(self._ops)


def default_operators() -> OperatorRegistry:
    """The built-in primitive pack. Deliberately SHORTER than the
    capability registry: primitives compose, capabilities execute."""
    reg = OperatorRegistry()

    def reg_web_probe(wm) -> bool:
        return bool(wm.find("web_app") or wm.find("web_header"))

    def reg_upload_probe(wm) -> bool:
        for f in wm.find("hunt_anomaly") + wm.find("web_app"):
            v = f.value if isinstance(f.value, dict) else {}
            if "upload" in str(v.get("endpoint", "")).lower() or \
               "upload" in str(v.get("path", "")).lower():
                return True
        return False

    def reg_param_probe(wm) -> bool:
        return bool(wm.find("hunt_anomaly"))

    def reg_ssrf_probe(wm) -> bool:
        for f in wm.find("hunt_anomaly"):
            v = f.value if isinstance(f.value, dict) else {}
            if str(v.get("class", "")).lower() in ("ssrf", "url_fetch"):
                return True
        return False

    def reg_meta_probe(wm) -> bool:
        for f in wm.find("environment"):
            v = f.value if isinstance(f.value, dict) else {}
            if v.get("cloud"):
                return True
        return False

    def reg_creds_probe(wm) -> bool:
        return bool(wm.find("creds", valid=True))

    def reg_service_probe(kind: str):
        def _probe(wm) -> bool:
            for f in wm.find("service"):
                v = f.value if isinstance(f.value, dict) else {}
                if str(v.get("service", "")).lower().startswith(kind):
                    return True
            return False
        return _probe

    # ── web primitives ─────────────────────────────────────────────
    reg.register(Operator(
        "web.enum_params", (WEB_APP.token,), (WEB_PARAM.token,),
        probe=reg_web_probe, cost=0.6, noise=0.15,
        desc="map injectable parameters on a fingerprinted web app"))
    reg.register(Operator(
        "web.find_uploads", (WEB_APP.token,), (WEB_UPLOAD.token,),
        probe=reg_web_probe, cost=0.6, noise=0.15,
        desc="discover upload endpoints on the mapped app"))
    reg.register(Operator(
        "web.find_admin", (WEB_APP.token,), (WEB_ADMIN.token,),
        probe=reg_web_probe, cost=0.5, noise=0.1,
        desc="locate the admin panel / auth surface"))
    reg.register(Operator(
        "web.sqli_read", (WEB_PARAM.token,), (FILE_READ.token, CREDS_ANY.token),
        probe=reg_param_probe, cost=1.4, noise=0.35,
        desc="SQLi on a mapped parameter -> file read + credential dump"))
    reg.register(Operator(
        "web.upload_shell", (WEB_UPLOAD.token, WEB_PARAM.token),
        (FILE_WRITE.token,), probe=reg_upload_probe, cost=1.6, noise=0.45,
        desc="upload + traversal -> arbitrary file write (webshell)"))
    reg.register(Operator(
        "web.write_rce", (FILE_WRITE.token,), (RCE_WEB.token,),
        probe=reg_upload_probe, cost=1.2, noise=0.5,
        desc="webshell written -> remote code execution"))
    reg.register(Operator(
        "web.ssrf_meta", (WEB_SSRF.token,), (SSRF_META.token,),
        probe=reg_ssrf_probe, cost=1.0, noise=0.3,
        desc="SSRF -> reach the cloud metadata endpoint"))
    reg.register(Operator(
        "web.sqli_admin", (WEB_PARAM.token,), (CREDS_ADMIN.token,),
        probe=reg_param_probe, cost=1.2, noise=0.3,
        desc="SQLi auth-bypass -> application admin credentials"))
    # ── cloud primitives ───────────────────────────────────────────
    reg.register(Operator(
        "cloud.harvest_keys", (SSRF_META.token,), (CLOUD_KEYS.token,),
        probe=reg_meta_probe, cost=1.0, noise=0.25,
        desc="metadata IMDS -> instance role keys"))
    # ── service primitives ─────────────────────────────────────────
    reg.register(Operator(
        "ssh.use_creds", (SERVICE_SSH.token, CREDS_ANY.token),
        (CREDS_SSH.token,), probe=reg_service_probe("ssh"),
        cost=0.8, noise=0.4,
        desc="reuse harvested credentials against SSH"))
    reg.register(Operator(
        "db.use_creds", (SERVICE_DB.token, CREDS_ANY.token),
        (CREDS_DB.token,), probe=reg_service_probe("mysql"),
        cost=0.8, noise=0.35,
        desc="reuse harvested credentials against the database"))
    reg.register(Operator(
        "db.read_file", (CREDS_DB.token,), (FILE_READ.token,),
        probe=reg_service_probe("mysql"), cost=1.1, noise=0.3,
        desc="DB file-read primitive (LOAD_FILE) -> /etc/shadow"))
    reg.register(Operator(
        "creds.from_files", (FILE_READ.token,), (CREDS_ANY.token,),
        probe=reg_creds_probe, cost=1.0, noise=0.2,
        desc="read config/shadow through a file-read primitive"))

    # ── post-exploitation primitives ─────────────────────────────────
    # the kill chain does not stop at the first shell: with a live beacon
    # the composition engine can now plan escalation, persistence and
    # lateral movement the same way it plans web/creds chains.

    def reg_beacon_probe(wm) -> bool:
        return bool(wm.find("beacon"))

    def reg_priv_probe(wm) -> bool:
        return bool(wm.find("system_privilege"))

    reg.register(Operator(
        "post.escalate", (BEACON_LIVE.token,), (PRIV_SYSTEM.token,),
        probe=reg_beacon_probe, cost=1.8, noise=0.6,
        desc="live beacon -> SYSTEM/root escalation (service/sudo vectors)"))
    reg.register(Operator(
        "post.persist", (BEACON_LIVE.token,), (PERSIST_INSTALLED.token,),
        probe=reg_beacon_probe, cost=1.2, noise=0.5,
        desc="live beacon -> persistence install (runkey/cron/systemd)"))
    reg.register(Operator(
        "post.escalate_persist", (PRIV_SYSTEM.token,),
        (PERSIST_INSTALLED.token,), probe=reg_priv_probe, cost=0.9, noise=0.4,
        desc="SYSTEM session -> boot-level persistence (service)"))
    def reg_internal_probe(wm) -> bool:
        return bool(wm.find("internal_host") or wm.find("internal_service"))

    reg.register(Operator(
        "recon.internal", (BEACON_LIVE.token,), (INTERNAL_HOST.token,),
        probe=reg_beacon_probe, cost=0.3, noise=0.1,
        desc="live beacon -> internal snapshot (interfaces/routes/ARP peers)"))
    reg.register(Operator(
        "probe.internal", (BEACON_LIVE.token, INTERNAL_HOST.token),
        (INTERNAL_SERVICE.token,), probe=reg_internal_probe,
        cost=0.6, noise=0.25,
        desc="internal peers -> bounded pivot-service probe (ssh/smb/winrm)"))

    reg.register(Operator(
        "smb.pivot", (SERVICE_SMB.token, CREDS_ANY.token, BEACON_LIVE.token),
        (PIVOT_SMB.token,),
        probe=lambda wm: (bool(reg_service_probe("smb")(wm))
                          and reg_beacon_probe(wm)),
        cost=2.2, noise=0.8,
        desc="SMB creds + live beacon -> PsExec deploy to the peer"))
    reg.register(Operator(
        "winrm.pivot", (CREDS_ANY.token, BEACON_LIVE.token),
        (PIVOT_WINRM.token,), probe=reg_beacon_probe, cost=2.0, noise=0.7,
        desc="creds + live beacon -> evil-winrm deploy to the peer"))
    return reg
