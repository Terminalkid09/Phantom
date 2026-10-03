"""Contract test: the Electron renderer's API surface vs. its allowlist.

C-2 (endpoint allowlist drift). The `api-request` IPC handler in
`electron/electron/main.ts` only forwards endpoints that
`electron/electron/endpoint_allowlist.ts` allows. The allowlist is hand
maintained, so the two drift silently: the UI starts calling `/api/foo`,
the main process answers 403, and the feature looks broken (or, worse, a
route the UI needs is never reachable).

This test parses BOTH sides from source — the allowlist rules and every
literal method+endpoint the UI actually issues — and refuses to pass when a
call the UI makes would be blocked. It also pins the C-1 destructive-confirm
flags so a refactor cannot quietly drop the operator confirmation.

Nothing here runs Electron or TypeScript: it is a static contract check, so
it stays fast and runs in the normal pytest suite.
"""
from __future__ import annotations

import os
import re

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
ALLOWLIST = os.path.join(ROOT, "electron", "electron", "endpoint_allowlist.ts")
UI_DIR = os.path.join(ROOT, "electron", "src")

_RULE_RE = re.compile(
    r"\{\s*pattern:\s*'([^']+)'\s*,\s*methods:\s*\[([^\]]*)\]\s*,"
    r"\s*group:\s*'([^']+)'(?:\s*,\s*confirm:\s*(true|false))?\s*\}")
_PREFIX_RE = re.compile(
    r"\{\s*prefix:\s*'([^']+)'\s*,\s*methods:\s*\[([^\]]*)\]\s*,"
    r"\s*group:\s*'([^']+)'\s*\}")
_METHODS_RE = re.compile(r"'([A-Z]+)'")

# the UI reaches the backend through these two helpers: `requestApi(...)`
# directly, and its `api(...)` alias used by the panels.
_CALL_RE = re.compile(
    r"(?:requestApi|(?<![\w.])api)\(\s*"
    r"(['\"`])(GET|POST|PUT|DELETE|PATCH)\1\s*,\s*"
    r"(['\"`])((?:\\.|(?!\3).)*)\3",
    re.DOTALL)


def _methods(blob: str) -> list:
    return _METHODS_RE.findall(blob)


def _load_allowlist():
    with open(ALLOWLIST, "r", encoding="utf-8") as handle:
        raw = handle.read()
    rules = []
    for pattern, methods_blob, group, confirm in _RULE_RE.findall(raw):
        rules.append({
            "pattern": pattern,
            "methods": _methods(methods_blob),
            "group": group,
            "confirm": confirm == "true",
        })
    prefixes = []
    for prefix, methods_blob, group in _PREFIX_RE.findall(raw):
        prefixes.append({
            "prefix": prefix,
            "methods": _methods(methods_blob),
            "group": group,
        })
    return rules, prefixes


def _normalize(path: str) -> str:
    """Drop the query string and every template placeholder, trim `/`.

    A JS template literal may NEST another one (``${x ? `?a` : ''}``), so we
    cut at the first ``${`` rather than trying to balance braces — everything
    dynamic becomes part of the matched prefix.
    """
    path = path.split("?", 1)[0]
    path = path.split("${", 1)[0]
    path = path.replace("*", "")
    path = re.sub(r"/+$", "", path)
    return path or "/"


def _allowed(rules, prefixes, method: str, endpoint: str) -> bool:
    """Mirror of checkEndpoint() in endpoint_allowlist.ts."""
    path = _normalize(endpoint)
    m = (method or "GET").upper()
    for rule in rules:
        pat = re.sub(r"/+$", "", rule["pattern"])
        if pat.endswith("*"):
            if path.startswith(pat[:-1]) and m in rule["methods"]:
                return True
            continue
        if path == pat and m in rule["methods"]:
            return True
    for prefix in prefixes:
        base = re.sub(r"/+$", "", prefix["prefix"].replace("?", ""))
        if (path + "/").startswith(base + "/") and m in prefix["methods"]:
            return True
    return False


def _ui_calls():
    """Every literal (method, endpoint) pair the renderer issues."""
    calls = []
    for dirpath, _dirs, files in os.walk(UI_DIR):
        for name in files:
            if not name.endswith((".ts", ".tsx")):
                continue
            full = os.path.join(dirpath, name)
            with open(full, "r", encoding="utf-8") as handle:
                text = handle.read()
            for _q1, method, _q2, endpoint in _CALL_RE.findall(text):
                endpoint = endpoint.replace("\\`", "`")
                if endpoint.startswith("/api/"):
                    calls.append((method, endpoint, os.path.relpath(full, ROOT)))
    return calls


def test_ui_endpoints_are_all_allowlisted():
    rules, prefixes = _load_allowlist()
    assert rules, "no allowlist rules parsed — did the TS shape change?"
    blocked = []
    for method, endpoint, origin in _ui_calls():
        if not _allowed(rules, prefixes, method, endpoint):
            blocked.append(f"{method} {endpoint} ({origin})")
    assert not blocked, (
        "the renderer calls endpoints the main-process allowlist would "
        "refuse (C-2 drift):\n  " + "\n  ".join(sorted(set(blocked))))


def test_every_ui_path_literal_is_reachable():
    """Second net: scan EVERY `/api/...` literal, even ones passed through a
    variable, so a route added to the UI is caught even if the (method,
    endpoint) pair is not a literal adjacent call."""
    rules, prefixes = _load_allowlist()
    # only a QUOTED path literal counts: prose like "run api/launcher.py"
    # (App.tsx) is not an endpoint the UI fetches.
    path_re = re.compile(r"(?<=['\"`])/api/[A-Za-z0-9_./-]*")
    missing = set()
    for dirpath, _dirs, files in os.walk(UI_DIR):
        for name in files:
            if not name.endswith((".ts", ".tsx")):
                continue
            with open(os.path.join(dirpath, name), "r", encoding="utf-8") as fh:
                for match in path_re.findall(fh.read()):
                    if match in ("/api/",):
                        continue
                    if not any(_allowed(rules, prefixes, m, match)
                               for m in ("GET", "POST")):
                        missing.add(match)
    assert not missing, (
        "UI references backend paths that are in NO allowlist rule "
        "(C-2 drift):\n  " + "\n  ".join(sorted(missing)))


def test_allowlist_groups_are_valid():
    rules, prefixes = _load_allowlist()
    for rule in rules:
        assert rule["group"] in ("readonly", "mutating"), rule
        assert rule["methods"], rule
    for prefix in prefixes:
        assert prefix["group"] in ("readonly", "mutating"), prefix
        assert prefix["methods"], prefix


def test_destructive_endpoints_require_confirmation():
    """C-1: the operator confirmation is load-bearing — it must stay attached
    to the irreversible calls."""
    rules, _prefixes = _load_allowlist()
    flagged = {(r["pattern"], m)
               for r in rules if r["confirm"] for m in r["methods"]}
    expected = {
        ("/api/c2/listener/stop", "POST"),
        ("/api/c2/beacon-auth/revoke", "POST"),
        ("/api/c2/beacon-auth/rotate", "POST"),
        ("/api/c2/certs/uninstall", "POST"),
        ("/api/c2/config/rotate-api-token", "POST"),
        ("/api/session/knowledge/reset", "POST"),
        ("/api/learning/reset", "POST"),
    }
    assert expected <= flagged, (
        "destructive endpoints lost their operator confirmation: "
        + str(sorted(expected - flagged)))


def test_no_destructive_endpoint_is_missing_from_allowlist():
    """A guard so the destructive set cannot be silently deleted: the C-1
    flags must exist AND the endpoints they protect must still be reachable."""
    rules, prefixes = _load_allowlist()
    for pattern, method in (
        ("/api/c2/listener/stop", "POST"),
        ("/api/c2/config/rotate-api-token", "POST"),
    ):
        assert _allowed(rules, prefixes, method, pattern), (
            f"{method} {pattern} is no longer allowlisted")
