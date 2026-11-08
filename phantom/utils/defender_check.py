"""Which antivirus is in the way, and what that means for a drop.

MEASURED 2026-11-03 on the operator's own Windows 11 box: this module was
Defender-only, and that was wrong twice over. ``root\\SecurityCenter2::
AntiVirusProduct`` reported TWO registered products — ``Windows Defender`` and
``McAfee`` — while ``Get-Service`` showed only ``McAfee WebAdvisor`` running and
``WinDefend`` STOPPED. The warning was therefore built on a service that was
not even running (so it could be silent on a machine with a live product) and
it could never mention McAfee at all (so it said nothing about the product that
was actually installed). "Is Defender there" is the wrong question: the drop
runs against an antivirus STACK, and SecurityCenter2 is the one interface
Windows provides that enumerates it — Defender, McAfee, Kaspersky, ESET,
Bitdefender, Norton, Avast, Sophos, Trend, CrowdStrike, SentinelOne alike.

TWO questions, and they used to be ONE (measured 2026-11-02/03):

  * does the TARGET platform ship Defender?  Every supported Windows build
    does, so this answer comes from the platform token alone — no registry
    read, no guess about the edition, no dependence on the operator's box.
  * does THIS machine have a local Defender that can be used as a SCANNER
    for the built payload?  That is a registry probe and it is Windows-only.

`defender_note()` answered the second question and used its answer for the
first, so it returned "" unless the OPERATOR's machine had ``Windefend``: a
Linux or macOS operator deploying to a Windows target got no warning at all,
i.e. the warning disappeared in exactly the case where nothing local could
scan the payload. That is backwards, and it is what
``target_defender_note()`` fixes.

Nothing here takes a decision. It answers a question and, in
``phantom.modules.payload.do_deploy``, the answer is PRINTED next to the
dropper. No injection path is disabled and no exit code changes: a beacon
that silently changes behaviour on an antivirus guess cannot be measured or
explained afterwards.
"""

from __future__ import annotations

#: Platform tokens that mean "the target is Windows". The CLI accepts
#: ``windows``; the aliases cost nothing and stop a caller from silently
#: getting no warning because it passed ``win``.
_WINDOWS_TOKENS = ("windows", "win", "win32", "win64")

#: Why the note exists at all. Kept as one sentence so the two public
#: functions cannot drift into two different explanations of one fact.
_QUARANTINE = (
    "Windows targets ship Defender: the dropped beacon may be quarantined on "
    "write or on first execution, and a missing check-in is NOT proof the "
    "payload failed to run — check the target's Protection history "
    "(Get-MpThreatDetection) before re-deploying.")

#: Appended when nothing on THIS machine can scan the build. "No scanner"
#: must never be read as "clean": that is the difference between an unknown
#: verdict and an approved one, and it is the ambiguity the 2026-11-02
#: release blocker lived in (process alive, no check-in, no way to tell
#: whether the drop was ever executed).
_NO_SCANNER = (
    "No local Defender is available to scan this build, so its detection "
    "verdict is UNKNOWN — not clean.")

#: Appended when this machine can scan it (the sandbox preflight line says
#: the outcome; this function never claims the result).
_LOCAL_SCANNER = (
    "A local Defender is available and scans the built payload (see the "
    "sandbox preflight line).")

#: Where an operator looks when a drop "did not run". Naming the product's own
#: log is the difference between a caveat and an instruction.
_WHERE = (
    "the product's quarantine/activity log (Defender: Protection history, "
    "`Get-MpThreatDetection`; McAfee: Quarantine / Activity; anything else: "
    "its own quarantine view)")

#: ``productState`` is a 3-byte value. The documented layout is
#: ``[provider][scanner 0x10=on][signature 0x00=current]``, but real builds
#: ship other provider bytes (Defender measured 0x060100 here), so ONLY the
#: documented values are decoded: anything else yields ``None`` (unknown) with
#: the raw ``state`` kept beside it. A guessed "enabled" is exactly the kind of
#: fact an operator would act on wrongly.
_SCANNER_ON = 0x10
_SCANNER_OFF = 0x00
_SIG_CURRENT = 0x00
_SIG_OUTDATED = 0x10


def is_target_windows(platform: str) -> bool:
    """Is ``platform`` a Windows target token?

    A plain membership test on purpose: the question is about the PLATFORM,
    so it must not depend on what this machine runs.
    """
    token = str(platform or "").strip().lower()
    return token in _WINDOWS_TOKENS


def is_defender_present() -> bool:
    """Return ``True`` if the Windows Defender service is registered.

    The function tries to open ``HKLM\\SYSTEM\\CurrentControlSet\\Services\\Windefend``.
    If the key exists, Defender is present (even if disabled). Any exception —
    including ``ImportError`` on non-Windows platforms — results in ``False``.
    """
    try:
        import winreg  # type: ignore
        with winreg.OpenKey(winreg.HKEY_LOCAL_MACHINE,
                            r"SYSTEM\CurrentControlSet\Services\Windefend"):
            return True
    except Exception:
        return False


def target_defender_note(platform: str, *,
                         local_present: "bool | None" = None) -> str:
    """The warning for a TARGET platform, independent of this machine.

    ``local_present`` is injectable so the sentence about scanning can be
    tested without touching the registry (and so a caller that already
    probed once does not pay for the probe again). ``None`` means "probe
    now".

    Returns ``""`` for a non-Windows target: a Linux drop has no Defender,
    and inventing a caveat there is noise that teaches an operator to skip
    the ones that matter.
    """
    if not is_target_windows(platform):
        return ""
    local = is_defender_present() if local_present is None else bool(local_present)
    tail = _LOCAL_SCANNER if local else _NO_SCANNER
    return f"{_QUARANTINE} {tail}"


def defender_note(platform: str, *,
                  local_present: "bool | None" = None) -> str:
    """LOCAL-gated note (the pre-2026-11-03 behaviour), kept for callers.

    It answers "is there a Defender here that may eat the drop", so it says
    nothing when this machine has none. Prefer :func:`target_defender_note`
    on a deploy path: the target is where the payload runs, and that
    question must be answered even when the operator is on Linux.

    Detection that cannot read the registry returns ``""`` rather than a
    guess — this variant only speaks about the machine it can see.
    """
    local = is_defender_present() if local_present is None else bool(local_present)
    if not local:
        return ""
    return target_defender_note(platform, local_present=True)


def decode_product_state(state) -> dict:
    """``{state, enabled, up_to_date}`` from a Windows ``productState``.

    ``enabled``/``up_to_date`` are ``True``, ``False`` or ``None`` (undecodable
    byte) — never a guess. Tests pin each documented value.
    """
    try:
        value = int(state)
    except (TypeError, ValueError):
        return {"state": state, "enabled": None, "up_to_date": None}
    scanner = (value >> 8) & 0xFF
    signature = value & 0xFF
    enabled = {_SCANNER_ON: True, _SCANNER_OFF: False}.get(scanner)
    up_to_date = {_SIG_CURRENT: True, _SIG_OUTDATED: False}.get(signature)
    return {"state": value, "enabled": enabled, "up_to_date": up_to_date}


def _read_security_center() -> list:
    """Raw rows from ``root\\SecurityCenter2::AntiVirusProduct``, or ``[]``.

    PowerShell rather than a new dependency: ``win32com``/``wmi`` are not
    installed everywhere, ``Get-CimInstance`` is on every supported Windows
    build, and the call is bounded — a probe that can hang must never sit in
    front of a deploy.
    """
    import platform as _platform
    if not str(_platform.system() or "").lower().startswith("win"):
        return []
    import json
    import subprocess
    command = (
        "$ErrorActionPreference='SilentlyContinue';"
        "Get-CimInstance -Namespace root/SecurityCenter2 "
        "-ClassName AntiVirusProduct | "
        "Select-Object displayName,productState | ConvertTo-Json -Compress")
    try:
        done = subprocess.run(
            ["powershell", "-NoProfile", "-NonInteractive", "-Command",
             command],
            capture_output=True, timeout=8, encoding="utf-8",
            errors="replace")
    except Exception:
        return []
    body = (done.stdout or "").strip()
    if not body:
        return []
    try:
        data = json.loads(body)
    except ValueError:
        return []
    if isinstance(data, dict):
        data = [data]
    return [row for row in data if isinstance(row, dict)]


def av_products(reader=None) -> list:
    """``[{name, state, enabled, up_to_date}]`` registered on THIS machine.

    Empty means "could not be read" — never "nothing installed" — and every
    caller must keep those two apart. ``reader`` is injectable so no test (and
    no non-Windows host) ever starts a PowerShell to answer it.
    """
    try:
        rows = reader() if reader is not None else _read_security_center()
    except Exception:
        # A deploy must not die because a probe did. An empty list is the
        # honest answer here: "could not be read", which av_note() says out
        # loud instead of turning it into "nothing installed".
        rows = []
    out = []
    for row in rows or []:
        if not isinstance(row, dict):
            continue
        name = str(row.get("displayName") or row.get("name") or "").strip()
        if not name:
            continue
        decoded = decode_product_state(row.get("productState", row.get("state")))
        out.append({"name": name, **decoded})
    return out


def av_note(platform: str, *, products=None, local_present=None) -> str:
    """The caveat naming EVERY antivirus product registered on the target kind.

    ``products`` injects the enumeration (tests, or a caller that already read
    it once). ``None`` reads it here; on a non-Windows host that read returns
    ``[]``, which the text must report as UNKNOWN rather than as "clean" —
    that distinction is the whole reason this module exists.

    Still a WARNING: nothing is disabled, no technique changes, no exit code
    moves. Returns ``""`` for a non-Windows target.
    """
    if not is_target_windows(platform):
        return ""
    found = av_products() if products is None else list(products or [])
    if found:
        names = ", ".join(str(p.get("name") or "?") for p in found)
        who = f"Windows targets run an antivirus stack: {names}"
    else:
        # "could not be read" is not "none installed": every supported
        # Windows build ships Defender, and SecurityCenter2 can be unavailable
        # on a stripped image or from a context that cannot query CIM.
        who = ("No antivirus product could be read from SecurityCenter2, so "
               "the target's protection is UNKNOWN (every supported Windows "
               "build ships Defender) — not clean")
    local = is_defender_present() if local_present is None else bool(local_present)
    tail = _LOCAL_SCANNER if local else _NO_SCANNER
    return (f"{who}: the dropped beacon may be quarantined on write or on "
            f"first execution, and a missing check-in is NOT proof the "
            f"payload failed to run — check {_WHERE} before re-deploying. "
            f"{tail}")


def preflight_record(verdict) -> dict:
    """The sandbox verdict as DATA, so it can be recorded instead of printed.

    ``scanned`` is the honest half: ``SandboxVerdict.skipped`` is true when
    no backend was applicable or available, and in that case ``approved`` is
    meaningless. A caller that records ``approved`` alone turns "nothing ran"
    into "it passed", which is the one reading this whole module exists to
    prevent.

    Tolerates a duck-typed verdict (tests use a two-attribute stand-in): a
    missing ``skipped`` is read as "the object cannot report coverage", and
    then only an explicit approval counts as scanned.
    """
    def _attr(name, default=None):
        return getattr(verdict, name, default)

    skipped = _attr("skipped", None)
    approved = bool(_attr("approved", False))
    try:
        summary = str(verdict.summary())
    except Exception:
        summary = ""
    if skipped is None:
        scanned = bool(approved)
    else:
        scanned = not bool(skipped)
    results = _attr("results", None) or []
    backend = ""
    for row in results:
        backend = str(getattr(row, "backend", "") or getattr(row, "name", "")
                      or backend)
    return {"backend": backend,
            "approved": bool(approved) and scanned,
            "summary": summary,
            "scanned": scanned}
