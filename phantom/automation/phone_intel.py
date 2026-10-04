"""
phone_intel.py — passive phone-number / geolocation intel engine.

Phantom could already resolve a phone target end-to-end (the identity chain
turns a phone into carrier + region via the ``osint_identity`` capability),
but that enrichment was welded onto the manual social channel and never
became a first-class, planner-visible fact: nothing downstream could aim at
"we know the number, its line type and its region" and the automatic chain
had no phone step of its own.

This is the in-process engine behind the ``phone_osint`` capability. It is
PASSIVE and OFFLINE: it uses the already-declared ``phonenumbers`` metadata
database (no request ever leaves the box, no packet at the target) to turn
a phone number — the engagement target itself, or a number a breach /
identity finding surfaced — into structured ``phone`` and ``geolocation``
facts (E.164, validity, line type, carrier, region and timezone).

The value it adds over the raw ``IDENTITY:`` marker:
  * a canonical E.164 key so the same number from two sources dedupes;
  * line TYPE (mobile vs fixed vs VoIP) — a fixed/geo line reshapes the
    pretext, a VoIP line is the disposable-number tell;
  * a timezone band ("only call 09:00-18:00 local") the engagement planner
    and the report writer both need.

Markers it prints are turned into findings by ``phone_intel_interp``; like
``external_recon`` it never raises — an unparseable number is a comment.
"""

from __future__ import annotations

import os
from typing import Any, Dict, List, Optional

from phantom.automation.belief import Finding


# Region hint for national-format numbers ("02 1234 5678") that carry no
# country code. A number in international format ("+39...") needs none.
_DEFAULT_REGIONS = ("US", "GB", "IT", "DE", "FR", "ES", "NL")


def _region_hint() -> str:
    try:
        from phantom.utils import config as cfg
        hint = str(cfg.get("osint.default_region", "", env=None) or "").strip()
        if hint:
            return hint.upper()
    except Exception:
        pass
    return str(os.environ.get("PHANTOM_DEFAULT_REGION", "") or "").strip().upper()


def _candidate_numbers(wm, slots: Dict[str, Any]) -> List[str]:
    """Every phone number this target makes available, deduped, in order.

    Priority: an explicit slot, then the engagement target when it IS a
    phone, then any number a breach/identity finding already surfaced (a
    leaked number is a phone-OSINT lead exactly like a supplied one).
    """
    out: List[str] = []

    def add(raw: Any) -> None:
        text = str(raw or "").strip()
        if text and text not in out:
            out.append(text)

    add((slots or {}).get("phone"))
    if getattr(wm, "target_type", "") == "phone":
        add(getattr(wm, "target", ""))
    try:
        for kind in ("phone", "identity"):
            for finding in wm.find(kind):
                v = finding.value if isinstance(finding.value, dict) else {}
                add(v.get("phone") or v.get("e164"))
    except Exception:
        pass
    return out


def _parse(raw: str):
    """Parse a number, tolerating a missing country code (region hint)."""
    import phonenumbers
    tries: List[Optional[str]] = []
    if raw.startswith("+"):
        tries.append(None)
    else:
        hint = _region_hint()
        if hint:
            tries.append(hint)
        if None not in tries:
            tries.append(None)
        for region in _DEFAULT_REGIONS:
            if region not in tries:
                tries.append(region)
    for region in tries:
        try:
            parsed = phonenumbers.parse(raw, region)
        except Exception:
            continue
        if phonenumbers.is_possible_number(parsed):
            return parsed
    return None


def _line_type(parsed) -> str:
    """Coarse line class: mobile | fixed | voip | tollfree | unknown."""
    try:
        import phonenumbers
        from phonenumbers import PhoneNumberType as T
        t = phonenumbers.number_type(parsed)
        if t == T.MOBILE:
            return "mobile"
        if t == T.FIXED_LINE:
            return "fixed"
        if t == T.FIXED_LINE_OR_MOBILE:
            return "mobile"
        if t == T.VOIP:
            return "voip"
        if t in (T.TOLL_FREE, T.PREMIUM_RATE, T.SHARED_COST):
            return "service"
        if t in (T.PERSONAL_NUMBER, T.PAGER, T.UAN, T.VOICEMAIL):
            return "service"
    except Exception:
        pass
    return "unknown"


def phone_intel_engine(wm, slots: Dict[str, Any]) -> str:
    """Offline ``phonenumbers`` lookup -> markers. Never raises."""
    try:
        import phonenumbers
        from phonenumbers import carrier as _carrier
        from phonenumbers import geocoder as _geocoder
        from phonenumbers import timezone as _timezone
    except Exception:
        return "# phone intel: phonenumbers not installed"

    numbers = _candidate_numbers(wm, slots)
    if not numbers:
        return "# phone intel: no phone number available"

    lines: List[str] = []
    for raw in numbers[:5]:
        parsed = _parse(raw)
        if parsed is None:
            lines.append(f"# phone intel: unparseable number ({raw})")
            continue
        e164 = phonenumbers.format_number(
            parsed, phonenumbers.PhoneNumberFormat.E164)
        valid = phonenumbers.is_valid_number(parsed)
        region = phonenumbers.region_code_for_number(parsed) or ""
        carrier = _carrier.name_for_number(parsed, "en") or ""
        geo = _geocoder.description_for_number(parsed, "en") or ""
        line_type = _line_type(parsed)
        try:
            zones = ",".join(sorted(_timezone.time_zones_for_number(parsed)))
        except Exception:
            zones = ""
        # a "|"-free, space-separated marker: values are whitespace-safe
        # because carrier/geo names contain spaces — encode them last so a
        # naive split still finds the key=value pairs.
        lines.append(
            "PHONE: e164={e164} valid={valid} type={typ} region={region} "
            "carrier={carrier} geo={geo} tz={tz}".format(
                e164=e164, valid="true" if valid else "false",
                typ=line_type, region=region or "-",
                carrier=carrier or "-", geo=geo or "-", tz=zones or "-"))
    return "\n".join(lines)


def _parse_marker(line: str) -> Dict[str, str]:
    kv: Dict[str, str] = {}
    for chunk in (line or "").split():
        if "=" in chunk:
            k, v = chunk.split("=", 1)
            kv[k.strip()] = v.strip()
    return kv


def phone_intel_interp(output: str, wm, slots: Dict[str, Any]) -> List[Finding]:
    """``PHONE:`` markers -> ``phone`` (strong) + ``geolocation`` (coarse).

    The phone fact is high-confidence: the metadata database either knows a
    number or it does not. The geolocation fact stays LOW-confidence on
    purpose — a carrier's number range pins a REGION, never a device; a
    later, real location (a lure's victim IP) must always outrank it.
    """
    findings: List[Finding] = []
    for line in (output or "").splitlines():
        if not line.startswith("PHONE:"):
            continue
        kv = _parse_marker(line[len("PHONE:"):])
        e164 = kv.get("e164", "").strip()
        if not e164:
            continue
        carrier = "" if kv.get("carrier") in ("", "-") else kv.get("carrier", "")
        region = "" if kv.get("region") in ("", "-") else kv.get("region", "")
        geo = "" if kv.get("geo") in ("", "-") else kv.get("geo", "")
        zones = "" if kv.get("tz") in ("", "-") else kv.get("tz", "")
        valid = kv.get("valid", "") == "true"
        findings.append(Finding(
            kind="phone", key=f"phone:{e164}",
            value={"e164": e164, "valid": valid,
                   "type": kv.get("type", "unknown"),
                   "region": region, "carrier": carrier},
            confidence=0.8 if valid else 0.5,
            source="phone_osint", target=wm.target))
        if region or geo:
            findings.append(Finding(
                kind="geolocation", key=f"geo:{e164}",
                value={"e164": e164, "region": region, "geo": geo,
                       "timezones": zones, "carrier": carrier,
                       "derived": "phone_number_metadata"},
                confidence=0.4, source="phone_osint", target=wm.target))
    return findings
