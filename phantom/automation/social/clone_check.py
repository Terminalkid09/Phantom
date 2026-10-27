"""clone_check.py — would this clone be spotted before the first click?

A lure page is not judged by how much it looks like the real one in a
screenshot; it is judged by the tells a browser (and a careful human) can
check in two seconds: the title, the form destination, the password field,
the assets, the language, the TLS. This module compares the REAL page's
markup with the clone's and names every difference that matters.

Design: pure function, stdlib HTML parser, no network. The caller supplies
both documents (fetched however it likes), so the check works offline, in
tests, and against a saved capture. It never fetches anything itself — that
is deliberate: a pre-launch check must not touch the target.

The report is a *score with reasons*, not a veto. `strict` belongs to the
caller: a kit path may refuse a blocking report when the operator asked for
strict mode, and must stay report-only otherwise.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from html.parser import HTMLParser
from typing import Dict, List, Optional, Tuple
from urllib.parse import urlsplit

_SEV = ("critical", "high", "medium", "low")
_PENALTY = {"critical": 35, "high": 18, "medium": 8, "low": 3}
_ASSET_TAGS = {"img": "src", "script": "src", "link": "href",
               "source": "src", "video": "src", "audio": "src"}


@dataclass
class Issue:
    severity: str
    code: str
    detail: str
    fix: str = ""

    def line(self) -> str:
        return f"[{self.severity}] {self.code}: {self.detail}"


@dataclass
class CloneReport:
    score: int = 100
    issues: List[Issue] = field(default_factory=list)
    real_url: str = ""
    clone_url: str = ""

    @property
    def grade(self) -> str:
        v = self.score
        if v >= 90:
            return "A"
        if v >= 75:
            return "B"
        if v >= 60:
            return "C"
        if v >= 40:
            return "D"
        return "F"

    @property
    def blocking(self) -> bool:
        """A critical difference means the clone is worse than no clone."""
        return any(i.severity == "critical" for i in self.issues)

    @property
    def ready(self) -> bool:
        return not self.blocking and self.score >= 60

    def codes(self, severity: Optional[str] = None) -> List[str]:
        return [i.code for i in self.issues
                if severity is None or i.severity == severity]

    def top_fix(self) -> str:
        for sev in _SEV:
            for i in self.issues:
                if i.severity == sev and i.fix:
                    return f"{i.code}: {i.fix}"
        return ""

    def marker(self) -> str:
        return (f"CLONE_CHECK: score={self.score} grade={self.grade} "
                f"blocking={int(self.blocking)} "
                f"issues={','.join(self.codes()) or 'none'}")

    def report(self) -> List[str]:
        out = [self.marker()]
        for i in sorted(self.issues, key=lambda x: _SEV.index(x.severity)):
            out.append("  " + i.line() + (f" -> {i.fix}" if i.fix else ""))
        return out

    def to_dict(self) -> Dict[str, object]:
        return {
            "score": self.score, "grade": self.grade,
            "blocking": self.blocking, "ready": self.ready,
            "real_url": self.real_url, "clone_url": self.clone_url,
            "marker": self.marker(),
            "issues": [{"severity": i.severity, "code": i.code,
                        "detail": i.detail, "fix": i.fix}
                       for i in self.issues],
        }


class _Doc(HTMLParser):
    """Everything the checks need, in one tolerant pass."""

    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title = ""
        self.lang = ""
        self.viewport = False
        self.forms: List[str] = []
        self.inputs: List[Tuple[str, str]] = []
        self.assets: List[str] = []
        self.text: List[str] = []
        self._in_title = False

    def handle_starttag(self, tag: str, attrs) -> None:
        a = {str(k).lower(): (v or "") for k, v in attrs}
        tag = tag.lower()
        if tag == "html":
            self.lang = a.get("lang", "")
        elif tag == "title":
            self._in_title = True
        elif tag == "meta" and a.get("name", "").lower() == "viewport":
            self.viewport = True
        elif tag == "form":
            self.forms.append(a.get("action", ""))
        elif tag == "input":
            self.inputs.append((a.get("type", "").lower(),
                                a.get("name", "")))
        elif tag in _ASSET_TAGS:
            ref = a.get(_ASSET_TAGS[tag], "")
            if ref:
                self.assets.append(ref)

    def handle_endtag(self, tag: str) -> None:
        if tag.lower() == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._in_title:
            self.title += data
        elif data.strip():
            self.text.append(data.strip())


def _parse(html: str) -> _Doc:
    doc = _Doc()
    try:
        doc.feed(html or "")
        doc.close()
    except Exception:
        # a malformed document is still a document: keep whatever parsed
        pass
    return doc


def _norm(text: str) -> str:
    return " ".join(str(text or "").lower().split())


def _host(url: str) -> str:
    try:
        return (urlsplit(url or "").hostname or "").lower()
    except Exception:
        return ""


def _asset_host(ref: str) -> str:
    if ref.startswith("//"):
        return ref[2:].split("/", 1)[0].lower()
    if ref.startswith(("http://", "https://")):
        return _host(ref)
    return ""


def _clean_action(action: str) -> str:
    a = (action or "").strip()
    if not a:
        return ""
    a = a.split("#", 1)[0].split("?", 1)[0]
    if a.startswith("./"):
        a = a[2:]
    return a


def _password_names(doc: _Doc) -> List[str]:
    return [name for typ, name in doc.inputs if typ == "password"]


def _brand_words(title: str) -> List[str]:
    return [w for w in re.findall(r"[a-z0-9]{3,}", _norm(title))
            if w not in ("sign", "login", "log", "your", "account", "the",
                         "and", "for", "with", "page")]


def check_clone(real_html: str, clone_html: str, *, real_url: str = "",
                clone_url: str = "", headers: Optional[Dict[str, str]] = None,
                ) -> CloneReport:
    """Compare the real page with its clone. Pure; never fetches anything."""
    rep = CloneReport(real_url=str(real_url or ""),
                      clone_url=str(clone_url or ""))
    issues = rep.issues

    def add(severity: str, code: str, detail: str, fix: str = "") -> None:
        issues.append(Issue(severity, code, detail, fix))

    if not (clone_html or "").strip():
        add("critical", "no_clone", "the clone document is empty",
            "capture the real page and serve its markup")
        rep.score = 0
        return rep
    if not (real_html or "").strip():
        add("high", "no_real", "the real page was not supplied, so nothing "
            "can be compared", "fetch the real page first")
        rep.score = 40
        return rep

    real = _parse(real_html)
    clone = _parse(clone_html)
    real_host = _host(real_url)
    clone_host = _host(clone_url)

    # ── TLS / address bar ──────────────────────────────────────────────
    if clone_url and not str(clone_url).lower().startswith("https://"):
        add("critical", "no_tls",
            "the clone is served over plain HTTP — browsers warn and the "
            "real service is HTTPS",
            "put a domain with a valid certificate in front")

    # ── title and brand ────────────────────────────────────────────────
    real_title, clone_title = _norm(real.title), _norm(clone.title)
    if real_title and not clone_title:
        add("high", "no_title", "the clone has no <title>",
            f"use the real title: {real.title.strip()[:80]!r}")
    elif real_title and clone_title != real_title:
        add("high", "title_mismatch",
            f"title differs: real {real.title.strip()[:60]!r} vs clone "
            f"{clone.title.strip()[:60]!r}",
            "copy the real title verbatim")
    brand = _brand_words(real.title)
    if brand:
        clone_text = _norm(" ".join(clone.text) + " " + clone.title)
        if not any(word in clone_text for word in brand):
            add("high", "brand_mismatch",
                f"the clone never mentions the real brand "
                f"({', '.join(brand[:3])})",
                "copy the heading and footer the real page shows")

    # ── form destination / fields ──────────────────────────────────────
    real_actions = [a for a in (_clean_action(x) for x in real.forms) if a]
    clone_actions = [a for a in (_clean_action(x) for x in clone.forms) if a]
    if real.forms and not clone.forms:
        add("critical", "no_form",
            "the real page has a login form, the clone has none",
            "copy the form (fields and destination)")
    elif real_actions and clone_actions and \
            set(real_actions) != set(clone_actions):
        add("high", "form_action_mismatch",
            f"form action differs: real {sorted(set(real_actions))[:2]} vs "
            f"clone {sorted(set(clone_actions))[:2]}",
            "post to the same path the real page posts to")
    if clone_actions and clone_host:
        external = [a for a in clone_actions
                    if _host(a) and _host(a) not in (clone_host, real_host)]
        if external:
            add("high", "form_action_external",
                f"the clone posts credentials to {external[0]}",
                "keep the submission on the clone's own host")
    real_pw, clone_pw = _password_names(real), _password_names(clone)
    if real_pw and not clone_pw:
        add("critical", "missing_password_field",
            "the real form has a password field, the clone does not",
            "copy the password input (type=password, same name)")
    elif clone_pw and not real_pw:
        add("medium", "extra_password_field",
            "the clone asks for a password the real page does not",
            "remove the extra field")

    # ── assets ─────────────────────────────────────────────────────────
    if real.assets and clone.assets:
        missing = [a for a in real.assets if a not in clone.assets]
        ratio = len(missing) / max(1, len(real.assets))
        if ratio >= 0.3:
            add("high", "missing_assets",
                f"{len(missing)}/{len(real.assets)} real assets are absent "
                f"(e.g. {missing[0]})",
                "copy every asset the real page loads")
    elif real.assets and not clone.assets:
        add("high", "no_assets",
            "the real page loads assets, the clone loads none — it will "
            "render broken", "copy the asset URLs (or serve local copies)")
    allowed_hosts = {h for h in (real_host, clone_host) if h}
    allowed_hosts |= {_asset_host(a) for a in real.assets if _asset_host(a)}
    external_assets = [a for a in clone.assets
                       if _asset_host(a) and _asset_host(a) not in allowed_hosts]
    if external_assets:
        add("medium", "external_asset",
            f"the clone loads {len(external_assets)} asset(s) from a third "
            f"host (e.g. {_asset_host(external_assets[0])})",
            "serve assets from the clone's host, not a stranger's")

    # ── mobile / language ──────────────────────────────────────────────
    if real.viewport and not clone.viewport:
        add("medium", "no_viewport",
            "the real page declares a mobile viewport, the clone does not",
            "copy the viewport meta tag")
    real_lang, clone_lang = (real.lang or "").lower(), (clone.lang or "").lower()
    if real_lang and clone_lang and real_lang != clone_lang:
        add("medium", "language_mismatch",
            f"lang differs: real {real_lang!r} vs clone {clone_lang!r}",
            "use the same language tag and copy")
    elif real_lang and not clone_lang:
        add("low", "no_language", "the clone has no lang attribute",
            f'use lang="{real_lang}"')

    if not any(t for t in clone.text):
        add("medium", "empty_text",
            "the clone shows no visible text",
            "copy the real page's copy, not just its form")

    # ── headers (optional, only what the caller supplied) ──────────────
    if headers:
        ctype = ""
        for key, value in headers.items():
            if str(key).lower() == "content-type":
                ctype = str(value).lower()
        if ctype and "html" not in ctype:
            add("low", "not_html",
                f"the real response content-type is {ctype!r}",
                "clone the HTML document, not an asset")

    rep.score = max(0, min(100, 100 - sum(_PENALTY[i.severity]
                                          for i in issues)))
    return rep
