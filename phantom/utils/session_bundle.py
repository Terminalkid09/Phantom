"""
session_bundle.py — portable .pm session files.

A `.pm` is ONE shareable file that captures an entire engagement so another
operator (or another machine, or the same operator weeks later) can pick it
up exactly where it stopped:

  * session state          target, mode, scope, notes, history, results,
                           knowledge base (OSINT/services/creds/breaches...)
  * the last auto-mode
    checkpoint             the world model (findings, hypotheses, dead
                           capabilities) -> `auto <target> --resume <file>`
                           continues the kill chain from the last wave
  * a report index         the raw-operator + sanitized-client reports
                           written during the engagement

Boundaries (honest): a .pm carries the C2 beacon ids and config, but it
cannot "adopt" live beacons — a beacon still checks in to the listener
that was configured when it was deployed. If the new operator controls the
same listener infrastructure the beacons reconnect; otherwise the .pm gives
complete engagement intelligence (targets, creds, victim IPs, campaign
stats, report skeleton) to continue from.

Security: bundles are ENCRYPTED by default (AES-256-GCM). The key is the
operator-local `PHANTOM_PM_KEY` secret (auto-generated and persisted in
`data/phantom_state.json`, gitignored, 0600 — override with the env var),
so a .pm full of credentials/notes is never plaintext on disk or in
transit. Legacy plaintext bundles are still read for backwards
compatibility.

The format is gzipped JSON (inside the AES-GCM envelope) with a magic
marker so a corrupted or foreign file is rejected cleanly instead of
misparsed.
"""

from __future__ import annotations

import gzip
import json
import os
import time
from typing import Any, Dict, List, Optional

_FORMAT = "phantom.pm"
_VERSION = 1
_MAGIC = "PHANTOM-PM"


# ── encryption (AES-256-GCM, key = operator-local PHANTOM_PM_KEY) ──────────

def _pm_key() -> bytes:
    """32-byte key for .pm bundles: operator-local secret, auto-generated
    once and persisted in data/phantom_state.json (gitignored), env override
    PHANTOM_PM_KEY. Same derivation used by the C2 crypto layer."""
    import secrets as _secrets
    from phantom.utils.c2_crypto import _derive_to_length
    from phantom.utils.state import get_secret
    value = get_secret("PHANTOM_PM_KEY", lambda: _secrets.token_hex(16))
    return _derive_to_length(value.encode(), 32)


def _encrypt_payload(payload: dict) -> str:
    """AES-256-GCM(gzip(json(payload))); returns base64(nonce||ct||tag)."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    raw = json.dumps(payload, default=str).encode("utf-8")
    import gzip as _gz
    compressed = _gz.compress(raw)
    aesgcm = AESGCM(_pm_key())
    nonce = os.urandom(12)
    return base64.b64encode(nonce + aesgcm.encrypt(nonce, compressed, None)).decode()


def _decrypt_payload(encoded: str) -> dict:
    """Reverse of _encrypt_payload. Raises ValueError on key mismatch / tamper."""
    import base64
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
    try:
        raw = base64.b64decode(encoded, validate=True)
        if len(raw) < 12 + 16:
            raise ValueError("corrupt .pm ciphertext")
        nonce, ciphertext = raw[:12], raw[12:]
        aesgcm = AESGCM(_pm_key())
        plain = aesgcm.decrypt(nonce, ciphertext, None)
        import gzip as _gz
        data = json.loads(_gz.decompress(plain).decode("utf-8"))
        if not isinstance(data, dict):
            raise ValueError("decrypted .pm payload is not an object")
        return data
    except ValueError:
        raise
    except Exception as e:
        raise ValueError(f"cannot decrypt .pm (wrong PHANTOM_PM_KEY or tampered file): {e}") from e

# checkpoint / report dirs that make an engagement resumable / shareable
_AUTO_GLOBS = ("auto_*", "agent_*")


def _sessions_root() -> str:
    from phantom.utils.paths import sessions_dir
    return sessions_dir()


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def _jsonable(obj: Any) -> Any:
    return json.loads(json.dumps(obj, default=str))


# ---------------------------------------------------------------------------
# discovery of engagement artifacts
# ---------------------------------------------------------------------------

def latest_checkpoint(root: Optional[str] = None,
                     target: Optional[str] = None) -> Optional[str]:
    """Path of the newest auto-mode checkpoint under data/sessions/.

    `target` restricts the search to checkpoints of a specific engagement
    target — otherwise exporting a fresh session would embed a stale
    checkpoint (different target, wrong world model).
    """
    root = root or _sessions_root()
    best: Optional[str] = None
    best_mtime = 0.0
    for sub in _AUTO_GLOBS:
        try:
            names = os.listdir(root)
        except OSError:
            continue
        for n in names:
            if not n.startswith(sub.split("*")[0]):
                continue
            cp = os.path.join(root, n, "checkpoint.json")
            if not os.path.isfile(cp):
                continue
            if target:
                try:
                    with open(cp, "r", encoding="utf-8") as f:
                        cp_target = json.load(f).get("target")
                except (OSError, ValueError):
                    continue
                if cp_target != target:
                    continue
            mt = os.path.getmtime(cp)
            if mt > best_mtime:
                best, best_mtime = cp, mt
    return best


def _report_index(root: Optional[str] = None) -> List[Dict[str, str]]:
    root = root or _sessions_root()
    out: List[Dict[str, str]] = []
    try:
        names = sorted(os.listdir(root))
    except OSError:
        return out
    for n in names:
        full = os.path.join(root, n)
        if not os.path.isdir(full):
            continue
        if not (n.startswith("auto_") or n.startswith("agent_")):
            continue
        try:
            files = sorted(os.listdir(full))
        except OSError:
            continue
        for f in files:
            if f.endswith((".md", ".json", ".html")):
                out.append({"dir": n, "file": f, "path": os.path.join(full, f)})
    return out


# ---------------------------------------------------------------------------
# export / import
# ---------------------------------------------------------------------------

def _session_payload() -> Dict[str, Any]:
    from phantom.core.session import session
    data = _jsonable(session.__dict__)
    try:
        from phantom.core.knowledge import session_wm
        data["_wm"] = json.loads(session_wm().to_json())
    except Exception:
        pass
    return data


def _engagement_id() -> str:
    """Stable id for the CURRENT engagement: target + opening timestamp.
    Auto-session uses it to decide whether a dated .pm copy belongs to the
    same engagement (overwrite) or a new one (new file)."""
    from phantom.core.session import session
    started = getattr(session, "engagement_started", "") or ""
    target = (session.target or "untargeted").replace("\\", "_").replace("/", "_")
    return f"{target}|{started}"


# keys that must NEVER appear in an exported bundle (defense in depth:
# today C2State.beacons holds no secrets, but any future field that smells
# like a key is scrubbed before the .pm is written)
_C2_SECRET_KEYS = {"hmac_secret", "auth_key", "secret", "key", "token",
                   "api_token", "psk", "password"}


def _scrub_secrets(obj: Any) -> Any:
    """Recursively drop secret-looking keys from serializable structures."""
    if isinstance(obj, dict):
        return {k: _scrub_secrets(v) for k, v in obj.items()
                if str(k).lower() not in _C2_SECRET_KEYS}
    if isinstance(obj, list):
        return [_scrub_secrets(v) for v in obj]
    return obj


def _c2_payload() -> Dict[str, Any]:
    """Live C2 state snapshot for team handoff.

    Carries the beacon table (ids, host info, last_seen), the full task
    history and the task results so the importing operator gets complete
    engagement intelligence. secrets are NEVER exported: beacon HMAC keys
    stay on the operator box (a .pm holder must never be able to
    impersonate beacons to someone else's C2); the listener endpoint is
    exported so the new operator knows which infrastructure the beacons
    call back to.
    """
    try:
        from phantom.core.c2_server import c2_state, server_instance
    except Exception:
        return {}
    try:
        with c2_state.lock:
            beacons = {bid: dict(info) for bid, info in c2_state.beacons.items()}
            tasks = {bid: [dict(t) for t in c2_state.tasks.get(bid, [])]
                     for bid in c2_state.tasks}
            results = {bid: [dict(r) for r in c2_state.results.get(bid, [])]
                       for bid in c2_state.results}
    except Exception:
        return {}
    listener = None
    try:
        if server_instance.thread and server_instance.thread.is_alive():
            listener = {"host": server_instance.host,
                        "port": server_instance.port,
                        "ssl": bool(server_instance.ssl_context)}
    except Exception:
        pass
    return {
        "beacons": _scrub_secrets(_jsonable(beacons)),
        "tasks": _scrub_secrets(_jsonable(tasks)),
        "results": _scrub_secrets(_jsonable(results)),
        "listener": listener,
        "note": "beacon HMAC keys are NOT exported (operator-local secrets); "
                "live beacons keep checking in to the ORIGINAL listener — "
                "adopt them by running the same listener config, or use the "
                "beacon intel here to redeploy",
    }


def export_session(out_path: Optional[str] = None,
                   checkpoint: Optional[str] = None,
                   encrypt: bool = True) -> str:
    """Write the current engagement to a single .pm file.

    `checkpoint` overrides the auto-discovered newest auto checkpoint;
    `encrypt=False` writes the legacy plaintext format (tests / explicit
    interop). Returns the written path.
    """
    from phantom.core.session import session
    cp = checkpoint or latest_checkpoint(
        target=(session.target or "") or None)
    payload = {
        "magic": _MAGIC,
        "format": _FORMAT,
        "version": _VERSION,
        "exported_at": _now(),
        "engagement_id": _engagement_id(),
        "session": _session_payload(),
        "c2": _c2_payload(),
        "checkpoint": None,
        "checkpoint_source": os.path.basename(cp) if cp else "",
        "reports": _report_index(),
    }
    if cp and os.path.isfile(cp):
        try:
            with open(cp, "r", encoding="utf-8") as f:
                payload["checkpoint"] = json.load(f)
        except (OSError, ValueError):
            payload["checkpoint"] = None
    if not out_path:
        out_path = os.path.join(_sessions_root(),
                                f"phantom_{int(time.time())}.pm")
    out_path = os.path.abspath(out_path)
    os.makedirs(os.path.dirname(out_path), exist_ok=True)
    if encrypt:
        envelope = {
            "magic": _MAGIC,
            "format": _FORMAT,
            "version": _VERSION,
            "enc": 1,
            "exported_at": _now(),
            "payload": _encrypt_payload(payload),
        }
        raw = json.dumps(envelope, default=str).encode("utf-8")
        with gzip.open(out_path, "wb") as f:
            f.write(raw)
    else:
        raw = json.dumps(payload, default=str).encode("utf-8")
        with gzip.open(out_path, "wb") as f:
            f.write(raw)
    return out_path


def read_bundle(path: str) -> Dict[str, Any]:
    """Parse + validate a .pm file. Raises ValueError on foreign/corrupt.
    Handles both encrypted (v2) and legacy plaintext (v1) bundles."""
    path = os.path.abspath(path)
    if not os.path.isfile(path):
        raise FileNotFoundError(path)
    try:
        with gzip.open(path, "rb") as f:
            data = json.loads(f.read().decode("utf-8"))
    except (OSError, ValueError) as e:
        raise ValueError(f"not a valid .pm bundle ({e})") from e
    if not isinstance(data, dict) or data.get("magic") != _MAGIC:
        raise ValueError("not a Phantom .pm bundle (magic marker missing)")
    if data.get("enc") == 1:
        return _decrypt_payload(data.get("payload", ""))
    return data


def _hydrate_world_model(wm_data: Optional[dict]) -> int:
    """Replace the live shared WorldModel with a restored one.

    Returns the number of findings restored (0 when nothing to restore).
    Mirrors `Session.load`: a `.pm` import must bring back the reasoning
    state, not just the scalars.
    """
    if not wm_data:
        return 0
    try:
        from phantom.automation.belief import WorldModel
        from phantom.core.knowledge import set_wm
        set_wm(WorldModel.from_dict(wm_data))
        return len(wm_data.get("findings", []) or [])
    except Exception:
        return 0


def import_session(path: str, resume_dir: Optional[str] = None) -> Dict[str, Any]:
    """Load a .pm bundle and apply it to the current session.

    Restores the session scalars AND the reasoning state: the manual
    world model (`_wm`) and, when present, the auto-mode checkpoint's
    world model (richer findings) are hydrated into the live knowledge
    base via `set_wm`, exactly like `Session.load` does.

    Returns {target, scope, mode, checkpoint_source, resume_path,
    reports, notes, history, findings, session} — the caller decides
    how to surface it.
    """
    data = read_bundle(path)
    sess = data.get("session") or {}
    from phantom.core.session import session
    for key in ("target", "lhost", "lport", "mode", "scope", "notes",
                "history", "results", "active_wordlist", "knowledge_base"):
        if key in sess:
            setattr(session, key, sess[key])
    resume_path = ""
    cp = data.get("checkpoint")
    # world model: the checkpoint's WM is the richer one for auto-mode
    # engagements; fall back to the manual session `_wm` otherwise
    wm_data = None
    if isinstance(cp, dict) and cp.get("wm"):
        wm_data = cp.get("wm")
    else:
        wm_data = sess.get("_wm")
    findings_restored = _hydrate_world_model(wm_data)
    c2_restored = _restore_c2_intel(data.get("c2"))
    if isinstance(cp, dict) and cp:
        base = resume_dir or _sessions_root()
        os.makedirs(base, exist_ok=True)
        resume_path = os.path.join(base, "imported_checkpoint.json")
        with open(resume_path, "w", encoding="utf-8") as f:
            json.dump(cp, f, indent=2, default=str)
    return {
        "target": sess.get("target", ""),
        "scope": list(sess.get("scope") or []),
        "mode": sess.get("mode", ""),
        "checkpoint_source": data.get("checkpoint_source", ""),
        "resume_path": resume_path,
        "reports": data.get("reports", []),
        "notes": len(sess.get("notes") or []),
        "history": len(sess.get("history") or []),
        "findings": findings_restored,
        "c2_intel": c2_restored,
        "session": sess,
    }


def _restore_c2_intel(c2_data: Optional[dict]) -> Dict[str, int]:
    """Surface the imported C2 intelligence in the live session.

    A .pm from another operator brings beacon identities, task history and
    outputs: instead of silently dropping them, they are stored under
    session.knowledge_base["c2_intel"] where the report writer, the
    suggest engine and the C2 shell can read them. Live beacons are NOT
    adopted (they still check in to their original listener).
    """
    counts = {"beacons": 0, "tasks": 0, "results": 0}
    if not isinstance(c2_data, dict):
        return counts
    try:
        from phantom.core.session import session
        kb = session.knowledge_base
        kb["c2_intel"] = {
            "beacons": c2_data.get("beacons") or {},
            "tasks": c2_data.get("tasks") or {},
            "results": c2_data.get("results") or {},
            "listener": c2_data.get("listener"),
            "imported_at": _now(),
        }
        counts["beacons"] = len(kb["c2_intel"]["beacons"])
        counts["tasks"] = sum(len(v) for v in kb["c2_intel"]["tasks"].values())
        counts["results"] = sum(len(v) for v in kb["c2_intel"]["results"].values())
    except Exception:
        pass
    return counts


def summarize(data: Dict[str, Any]) -> str:
    """One-line human summary of an imported bundle."""
    lines = [
        f"target={data.get('target') or '-'}",
        f"scope={','.join(data.get('scope') or []) or '-'}",
        f"mode={data.get('mode') or '-'}",
        f"notes={data.get('notes', 0)}",
        f"findings={data.get('findings', 0)}",
        f"checkpoint={'yes' if data.get('resume_path') else 'no'}",
        f"reports={len(data.get('reports') or [])}",
        f"c2_beacons={data.get('c2_intel', {}).get('beacons', 0)}",
    ]
    return " | ".join(lines)
