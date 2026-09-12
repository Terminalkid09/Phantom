"""
phantom.core.session_bridge — the ONE bridge between the manual core and
the autonomous agent.

Before this module the two halves of Phantom kept separate memories:

  * the auto-mode discovered services, creds, beacons, internal peers,
    cloud findings, EDR gaps … and only a couple of `os_info`/`status`
    keys reached `session.knowledge_base`, so the MANUAL core (map,
    suggest, exploit, payload) could not see anything the agent learned;
  * the auto-mode always started from zero, re-scanning a host the
    operator had already scanned by hand.

This module makes the flow bidirectional and lossless:

    merge_agent_into_session(agent)   auto-mode -> core   (facts + WM)
    seed_findings_from_session(t)     core -> auto-mode   (facts)

Both directions are idempotent: facts are keyed and de-duplicated, so a
merge never double-counts and a re-seed never overwrites a real finding
with an older one.
"""
from __future__ import annotations

from typing import Any, Dict, List, Optional

# WorldModel kinds the auto-mode produces that the manual core must be able
# to consume (suggest / exploit / report). Kept explicit so a new kind is
# never silently dropped.
_BRIDGED_KINDS = (
    "service", "os", "creds", "beacon", "persistence", "system_privilege",
    "injection", "rce_foothold", "ad_domain", "ad_creds", "cracked",
    "pivot", "internal_host", "internal_service", "defensive_gap",
    "cloud_creds", "cloud_access", "cloud_lateral", "k8s_escape",
    "environment", "mobile", "mdm_vendor", "mobile_platform",
    "hunt_anomaly", "rce_vector", "web_header", "web_app", "victim_ip",
)


def _val(f) -> Dict[str, Any]:
    v = getattr(f, "value", None)
    return v if isinstance(v, dict) else {}


def merge_agent_into_session(agent, target: str = "") -> Dict[str, int]:
    """Write everything the agent learned into the manual session.

    Populates `session.knowledge_base`, `session.results["auto_mode"]` and
    the manual WorldModel (`phantom.core.knowledge.session_wm`) so the
    manual core — map, suggest, exploit, payload, report — sees the same
    truth as the auto-mode. Returns per-section counts for logging/tests.
    """
    from phantom.core.session import session

    if agent is None:
        return {}
    wm = getattr(agent, "wm", None)
    if wm is None:
        return {}

    target = target or getattr(agent, "target", "") or session.target
    if target and not session.target:
        session.target = target

    kb = session.knowledge_base
    kb.setdefault("services", [])
    kb.setdefault("creds_found", [])
    kb.setdefault("rce_vectors", [])
    kb.setdefault("next_targets", [])
    counts: Dict[str, int] = {}

    # ── services ───────────────────────────────────────────────────────
    known = {int(s.get("port", 0)) for s in kb["services"]}
    added = 0
    for f in wm.find("service"):
        v = _val(f)
        try:
            port = int(str(v.get("port", f.key)).split("/")[0])
        except (TypeError, ValueError):
            continue
        if port in known:
            continue
        known.add(port)
        kb["services"].append({
            "port": port,
            "protocol": str(v.get("proto") or v.get("protocol") or "tcp"),
            "service": str(v.get("service") or ""),
            "version": str(v.get("version") or v.get("banner") or ""),
            "host": str(v.get("host") or target),
            "source": "auto_mode",
        })
        added += 1
    counts["services"] = added

    # ── OS ─────────────────────────────────────────────────────────────
    os_findings = wm.find("os")
    if os_findings:
        v = _val(os_findings[-1])
        if v.get("name") or v.get("os"):
            kb["os_info"] = {
                "name": str(v.get("name") or v.get("os")),
                "accuracy": int(v.get("accuracy") or 0),
                "source": "auto_mode",
            }
            kb.setdefault("status", {})["os_detected"] = True
            counts["os"] = 1

    # ── credentials (operator-side only; never in the client report) ───
    seen_creds = {
        (str(c.get("username")), str(c.get("password")))
        for c in kb["creds_found"] if isinstance(c, dict)
    }
    added = 0
    try:
        cred_findings = wm.find("creds", valid=True)
    except TypeError:                       # older WorldModel signature
        cred_findings = wm.find("creds")
    for f in cred_findings:
        v = _val(f)
        pair = (str(v.get("username", "")), str(v.get("password", "")))
        if not pair[0] or pair in seen_creds:
            continue
        seen_creds.add(pair)
        kb["creds_found"].append({
            "username": pair[0], "password": pair[1],
            "service": str(v.get("service") or ""),
            "host": str(v.get("host") or target),
            "source": "auto_mode",
        })
        added += 1
    counts["creds"] = added

    # ── compromise state ───────────────────────────────────────────────
    if wm.find("beacon"):
        kb["beacon_deployed"] = True
        counts["beacon"] = 1
    if wm.find("persistence"):
        kb["persistence_set"] = True
        counts["persistence"] = 1
    if wm.find("rce_foothold"):
        vec = [f.key for f in wm.find("rce_foothold")]
        kb["rce_vectors"] = sorted(set(list(kb["rce_vectors"]) + vec))
        counts["rce"] = len(vec)
    if wm.find("ad_domain"):
        kb["domain_environment"] = True
        kb["domain_enumerated"] = True
        counts["ad"] = 1

    # ── internal recon -> pivot candidates the operator can act on ─────
    pivots = []
    for f in wm.find("internal_service"):
        v = _val(f)
        host = str(v.get("host") or "")
        svc = str(v.get("service") or "")
        if host:
            pivots.append({"ip": host, "service": svc, "via": "internal_probe"})
    for f in wm.find("internal_host"):
        v = _val(f)
        host = str(v.get("ip") or v.get("host") or "")
        if host and not any(p["ip"] == host for p in pivots):
            pivots.append({"ip": host, "service": "", "via": "internal_recon"})
    if pivots:
        existing = {n.get("ip") for n in kb["next_targets"]
                    if isinstance(n, dict)}
        kb["next_targets"] = list(kb["next_targets"]) + [
            p for p in pivots if p["ip"] not in existing]
        counts["pivots"] = len(pivots)

    # ── defensive gaps / cloud / mobile (new enterprise surfaces) ──────
    gaps = [f.key for f in wm.find("defensive_gap")]
    if gaps:
        kb["edr_gaps"] = sorted(set(kb.get("edr_gaps", []) + gaps))
        counts["defensive_gap"] = len(gaps)
    cloud = {}
    for kind, bucket in (("cloud_creds", "creds"),
                         ("cloud_access", "access"),
                         ("cloud_lateral", "lateral")):
        entries = [_val(f) for f in wm.find(kind)]
        if entries:
            cloud.setdefault(bucket, []).extend(entries)
    if cloud:
        kb["cloud_findings"] = cloud
        counts["cloud"] = sum(len(v) for v in cloud.values())
    mobile = {}
    if wm.find("mdm_vendor"):
        mobile["mdm"] = [_val(f) for f in wm.find("mdm_vendor")]
    if wm.find("mobile_platform"):
        plats = []
        for f in wm.find("mobile_platform"):
            plats.extend(_val(f).get("platforms") or [])
        mobile["platforms"] = sorted(set(plats))
    if wm.find("mobile"):
        mobile["surface"] = [_val(f) for f in wm.find("mobile")]
    if mobile:
        kb["mobile_surface"] = mobile
        counts["mobile"] = 1
    if wm.find("k8s_escape"):
        kb["k8s_escape"] = True
        counts["k8s"] = 1

    # ── results slot: the operator-facing auto-mode summary ────────────
    session.add_result("auto_mode", {
        "target": target,
        "agent": getattr(agent, "target", ""),
        "services": counts.get("services", 0),
        "creds": counts.get("creds", 0),
        "beacon": bool(wm.find("beacon")),
        "findings_total": sum(len(wm.find(k)) for k in _BRIDGED_KINDS),
    })

    # ── manual WorldModel: same facts, so suggest/exploit/map see them ─
    try:
        from phantom.core.knowledge import session_wm
        mwm = session_wm()
        if target and not getattr(mwm, "target", ""):
            mwm.target = target
        _copy_findings(wm, mwm)
    except Exception:
        pass

    return counts


def _copy_findings(src_wm, dst_wm) -> int:
    """Copy bridged findings from one WorldModel into another, skipping
    keys the destination already has (idempotent merge)."""
    copied = 0
    for kind in _BRIDGED_KINDS:
        for f in src_wm.find(kind):
            if dst_wm.get(kind, f.key) is not None:
                continue
            try:
                dst_wm.add_finding(
                    kind, f.key, f.value,
                    confidence=getattr(f, "confidence", 0.6),
                    source=getattr(f, "source", "auto_mode"),
                    target=getattr(f, "target", ""))
                copied += 1
            except Exception:
                continue
    return copied


def seed_findings_from_session(target: str = "") -> List[Dict[str, Any]]:
    """Read what the manual core already knows and turn it into seed facts
    for the auto-mode, so an agent launched after manual recon does not
    repeat work and immediately has the operator's findings.

    Sources: `session.knowledge_base` (services / os / creds) and the
    manual WorldModel (every bridged kind).
    """
    from phantom.core.session import session

    target = target or session.target or ""
    out: List[Dict[str, Any]] = []

    def _add(kind, key, value, source, confidence=0.6):
        out.append({"kind": kind, "key": key, "value": value,
                    "source": source, "confidence": confidence})

    kb = session.knowledge_base or {}
    for s in (kb.get("services") or []):
        port = s.get("port")
        if port is None:
            continue
        key = f"tcp/{port}"
        _add("service", key, {
            "port": int(port),
            "proto": s.get("protocol", "tcp"),
            "service": s.get("service", ""),
            "version": s.get("version", ""),
            "host": s.get("host") or target,
        }, "manual_core_scan", 0.8)

    os_info = kb.get("os_info") or {}
    if os_info.get("name"):
        _add("os", "os", {"name": os_info["name"],
                          "accuracy": os_info.get("accuracy", 0)},
             "manual_core_os", 0.8)

    for c in (kb.get("creds_found") or []):
        if not isinstance(c, dict):
            continue
        user, pw = c.get("username"), c.get("password")
        if not user or not pw:
            continue
        svc = c.get("service") or "ssh"
        _add("creds", f"{svc}:{user}",
             {"username": user, "password": pw, "valid": True,
              "service": svc}, "manual_core_creds", 0.8)

    # manual WorldModel findings (the operator's own chain facts)
    try:
        from phantom.core.knowledge import session_wm
        mwm = session_wm()
        for kind in _BRIDGED_KINDS:
            for f in mwm.find(kind):
                out.append({"kind": kind, "key": f.key, "value": f.value,
                            "source": f"manual:{getattr(f, 'source', '')}",
                            "confidence": getattr(f, "confidence", 0.6)})
    except Exception:
        pass
    return out


def seed_agent_wm(agent, target: str = "") -> int:
    """Apply the session seed to a live agent's WorldModel. Returns the
    number of facts injected (0 when the session is empty)."""
    if agent is None:
        return 0
    seeds = seed_findings_from_session(target or getattr(agent, "target", ""))
    applied = 0
    wm = getattr(agent, "wm", None)
    if wm is None:
        return 0
    for s in seeds:
        # never overwrite a stronger fact the agent already produced
        existing = wm.get(s["kind"], s["key"])
        if existing is not None:
            continue
        try:
            wm.add_finding(s["kind"], s["key"], s["value"],
                           confidence=s["confidence"], source=s["source"],
                           target=getattr(agent, "target", "") or target)
            applied += 1
        except Exception:
            continue
    return applied
