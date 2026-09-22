"""Electron/IPC contract test: every backend endpoint the UI calls must
be reachable through the main-process allowlist.

This is the regression test for the drift that 403'd ~14 UI features:
the allowlist (endpoint_allowlist.ts) was written once and the UI kept
moving. The test re-derives the UI's endpoint set by grep over
electron/src and replays main's checkEndpoint logic in Python.
"""
import os
import re
import unittest

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
SRC = os.path.join(ROOT, "electron", "src")
ALLOWLIST = os.path.join(ROOT, "electron", "electron",
                         "endpoint_allowlist.ts")


def _load_rules():
    text = open(ALLOWLIST, encoding="utf-8").read()
    rules = []
    for pattern, methods in re.findall(
            r"\{\s*pattern:\s*'([^']+)'\s*,\s*methods:\s*\[([^\]]*)\]",
            text):
        meths = [m.strip().strip("'\"") for m in methods.split(",")]
        rules.append((pattern.rstrip("/"), [m.upper() for m in meths],
                      False))
    for prefix, methods in re.findall(
            r"\{\s*prefix:\s*'([^']+)'\s*,\s*methods:\s*\[([^\]]*)\]",
            text):
        meths = [m.strip().strip("'\"") for m in methods.split(",")]
        base = prefix.rstrip("?").rstrip("/")
        rules.append((base, [m.upper() for m in meths], True))
    assert rules, "no rules parsed from the allowlist"
    return rules


def _scan_template(text, j):
    """Scan a `...` template starting AFTER the opening backtick.
    Returns (path_shape, index_after_closing_backtick): every ${...}
    interpolation is dropped and '//' collapsed, so the shape is the
    realistic request path checkEndpoint will see."""
    n = len(text)
    buf: list = []
    while j < n:
        ch = text[j]
        if ch == "`":
            break
        if ch == "\\" and j + 1 < n:
            buf.append(text[j + 1])
            j += 2
            continue
        if ch == "$" and j + 1 < n and text[j + 1] == "{":
            j = _scan_expr(text, j + 2)
            continue
        buf.append(ch)
        j += 1
    shape = re.sub(r"/{2,}", "/", "".join(buf))
    return shape, (j + 1 if j < n else j)


def _scan_expr(text, j):
    """Scan a ${...} expression starting AFTER '${'. Returns the index
    just past the matching '}'."""
    n = len(text)
    while j < n:
        ch = text[j]
        if ch == "}":
            return j + 1
        if ch in ("'", '"'):
            j += 1
            while j < n and text[j] != ch:
                j += 2 if text[j] == "\\" else 1
            j += 1
            continue
        if ch == "`":
            _, j = _scan_template(text, j + 1)
            continue
        if ch == "{":
            j = _scan_expr(text, j + 1)
            continue
        j += 1
    return j


def _extract_calls(text):
    """Find api('METHOD', endpoint) calls (single-quoted or template).

    Matches the renderer's three spellings: useApi's api(), the
    requestApi() helper, and window.phantom?.request() (App boot)."""
    out = []
    for m in re.finditer(r"(?:api|requestApi|request)\(\s*'(GET|POST|PUT|DELETE)'"
                         r"\s*,\s*", text):
        j = m.end()
        while j < len(text) and text[j] in " \t":
            j += 1
        if j >= len(text):
            continue
        if text[j] == "'":
            k = j + 1
            buf = []
            while k < len(text) and text[k] != "'":
                if text[k] == "\\" and k + 1 < len(text):
                    buf.append(text[k + 1])
                    k += 2
                    continue
                buf.append(text[k])
                k += 1
            out.append((m.group(1), "".join(buf)))
        elif text[j] == "`":
            tpl, _ = _scan_template(text, j + 1)
            out.append((m.group(1), tpl))
    return out


def _ui_calls():
    """(method, path-template) pairs referenced by the renderer."""
    calls = set()
    for dirpath, _dirs, files in os.walk(SRC):
        for name in files:
            if not name.endswith((".ts", ".tsx")):
                continue
            text = open(os.path.join(dirpath, name), encoding="utf-8").read()
            for method, tpl in _extract_calls(text):
                tpl = tpl.split("?")[0].rstrip("/") or "/"
                if tpl.startswith("/api/"):
                    calls.add((method.upper(), tpl))
    assert calls, "no UI endpoint calls found"
    return sorted(calls)


def _allowed(rules, method, path):
    path = path.split("?")[0].rstrip("/") or "/"
    for pattern, methods, is_prefix in rules:
        if method not in methods:
            continue
        if is_prefix:
            if (path + "/").startswith(pattern + "/"):
                return True
        elif path == pattern:
            return True
    return False


class TestAllowlistSync(unittest.TestCase):
    def test_every_ui_endpoint_is_allowlisted(self):
        rules = _load_rules()
        missing = [(m, p) for m, p in _ui_calls()
                   if not _allowed(rules, m, p)]
        self.assertEqual(
            missing, [],
            f"{len(missing)} UI endpoint(s) would 403 in the app: "
            + ", ".join(f"{m} {p}" for m, p in missing))


if __name__ == "__main__":
    unittest.main()
