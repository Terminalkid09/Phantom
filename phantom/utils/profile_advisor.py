"""Profile advisor — AI-free target-aware malleable C2 profile recommendations.

Analyses the detected target environment (OS, services, network position, risk
level) and recommends URI paths, user-agent pools, sleep cadence, and header
sets that blend optimally with the target's expected traffic.

Design: rule-driven, no LLM — the logic is a decision tree over target facts.
Historical success is tracked per profile family with Beta-Binomial posteriors
so recommendations improve with every engagement.
"""

from __future__ import annotations

import json as _json
import os as _os
from typing import Optional as _Optional
from dataclasses import dataclass, field

# ────────────────────────────────────────────────────────────────────────────
#  Profile families — each is a curated set of URIs / UAs / headers that
#  mimics a specific traffic profile.
# ────────────────────────────────────────────────────────────────────────────

@dataclass
class ProfileRecipe:
    family: str
    description: str
    get_paths: list[str] = field(default_factory=list)
    post_paths: list[str] = field(default_factory=list)
    decoy_paths: list[str] = field(default_factory=list)
    user_agents: list[str] = field(default_factory=list)
    extra_headers: list[str] = field(default_factory=list)
    sleep_ms: int = 5000
    jitter: int = 30
    # Which target factors this family scores for
    os_tags: list[str] = field(default_factory=list)         # windows, linux, macos, android
    service_tags: list[str] = field(default_factory=list)    # iis, apache, nginx, exchange, sharepoint, tomcat, node, django, flask, wordpress
    env_tags: list[str] = field(default_factory=list)        # corporate, cloud, dmz, dev, iot
    risk_tags: list[str] = field(default_factory=list)       # stealth, default, aggressive


# ═══════════════════════════════════════════════════════════════════════════
#  RECIPE DATABASE
# ═══════════════════════════════════════════════════════════════════════════

RECIPES: list[ProfileRecipe] = [
    # ── Generic / CDN (stealthy — blends with any target) ──────────────────
    ProfileRecipe(
        family="generic_cdn",
        description="Generic CDN / common web assets. Blends with any target.",
        get_paths=[
            "/js/main.bundle.js",
            "/static/css/styles.css",
            "/fonts/inter-roman.woff2",
            "/api/v1/health",
        ],
        post_paths=[
            "/api/v1/analytics",
            "/telemetry",
            "/api/v1/events",
        ],
        decoy_paths=[
            "/index.html",
            "/favicon.ico",
            "/robots.txt",
            "/assets/logo.svg",
        ],
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
        ],
        extra_headers=[
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
        ],
        os_tags=["*"],
        service_tags=["*"],
        risk_tags=["stealth"],
    ),

    # ── Microsoft / Corporate (Windows + IIS/Exchange) ─────────────────────
    ProfileRecipe(
        family="ms_corporate",
        description="Microsoft corporate: Office 365, Azure, Exchange paths. Best for Windows AD environments.",
        get_paths=[
            "/owa/auth/ev.owa2",
            "/ecp/HealthCheck.htm",
            "/autodiscover/autodiscover.xml",
            "/Microsoft-Server-ActiveSync/default.eas",
            "/api/data/v9.2/",
            "/_windows/default.aspx",
        ],
        post_paths=[
            "/owa/auth.owa",
            "/ecp/ReportingWebService.asmx",
            "/api/data/v9.2/$batch",
            "/ews/Exchange.asmx",
        ],
        decoy_paths=[
            "/owa/",
            "/ecp/",
            "/mapi/",
            "/rpc/",
            "/remote.ico",
        ],
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64; Trident/7.0; rv:11.0) like Gecko",
        ],
        extra_headers=[
            "Accept: application/json, text/plain, */*",
            "X-OWA-ClientBuildVersion: 15.20",
            "X-OWA-ClientFlavor: Web",
        ],
        sleep_ms=8000,
        jitter=40,
        os_tags=["windows"],
        service_tags=["iis", "microsoft", "exchange", "sharepoint"],
        env_tags=["corporate", "dmz"],
        risk_tags=["default", "aggressive"],
    ),

    # ── Linux / DevOps (nginx, Node, Docker) ───────────────────────────────
    ProfileRecipe(
        family="linux_devops",
        description="Linux DevOps: npm/CDN, API, Docker paths. Best for Linux web servers.",
        get_paths=[
            "/api/v1/health",
            "/api/v1/metrics",
            "/api/graphql",
            "/static/js/chunk-vendors.js",
            "/sockjs-node/info",
        ],
        post_paths=[
            "/api/v1/query",
            "/api/v1/mutation",
            "/api/auth/login",
            "/graphql",
        ],
        decoy_paths=[
            "/.env",
            "/index.html",
            "/package.json",
            "/static/css/app.css",
        ],
        user_agents=[
            "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
            "curl/8.7.1",
        ],
        extra_headers=[
            "Accept: application/json",
            "X-Requested-With: XMLHttpRequest",
        ],
        os_tags=["linux"],
        service_tags=["nginx", "apache", "node", "django", "flask", "tomcat", "spring"],
        env_tags=["cloud", "dev", "dmz"],
        risk_tags=["default"],
    ),

    # ── WordPress / CMS (Apache/PHP) ───────────────────────────────────────
    ProfileRecipe(
        family="wordpress_cms",
        description="WordPress / CMS: wp-admin, wp-json, plugin paths. Best for Apache+PHP targets.",
        get_paths=[
            "/wp-json/wp/v2/posts",
            "/wp-content/themes/twentytwentyfive/style.css",
            "/wp-includes/js/wp-embed.min.js",
        ],
        post_paths=[
            "/wp-admin/admin-ajax.php",
            "/wp-login.php",
            "/xmlrpc.php",
        ],
        decoy_paths=[
            "/",
            "/wp-admin/",
            "/wp-content/uploads/",
            "/sitemap.xml",
        ],
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36",
        ],
        extra_headers=[
            "Accept: text/html,application/xhtml+xml",
            "Referer: https://www.google.com/",
        ],
        os_tags=["linux", "windows"],
        service_tags=["apache", "nginx", "wordpress", "joomla", "drupal"],
        env_tags=["corporate", "cloud"],
        risk_tags=["default", "aggressive"],
    ),

    # ── Apple / macOS (Safari, iCloud) ─────────────────────────────────────
    ProfileRecipe(
        family="apple_macos",
        description="Apple ecosystem: Safari UA, iCloud-like paths. Best for macOS targets.",
        get_paths=[
            "/setup/ios/configuration",
            "/api/v1/device/checkin",
            "/library/test/success.html",
            "/1/mobile/dataclasses",
        ],
        post_paths=[
            "/setup/ios/configuration",
            "/api/v1/device/register",
            "/1/mobile/dataclasses",
        ],
        decoy_paths=[
            "/",
            "/captive.apple.com",
            "/hotspot-detect.html",
            "/success.txt",
        ],
        user_agents=[
            "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_5) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.5 Safari/605.1.15",
            "Mozilla/5.0 (iPhone; CPU iPhone OS 18_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/18.0 Mobile/15E148 Safari/604.1",
        ],
        extra_headers=[
            "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
            "Accept-Language: en-us",
        ],
        os_tags=["macos", "ios"],
        service_tags=["*"],
        env_tags=["corporate", "cloud"],
        risk_tags=["default"],
    ),

    # ── Android / Mobile ───────────────────────────────────────────────────
    ProfileRecipe(
        family="android_mobile",
        description="Android / Mobile: Google APIs, Firebase. Best for Android targets.",
        get_paths=[
            "/gcm/send",
            "/cpe/checkin",
            "/generate_204",
            "/connectivity_check.html",
        ],
        post_paths=[
            "/gcm/send",
            "/batch",
            "/v1/projects/",
        ],
        decoy_paths=[
            "/generate_204",
            "/gen_204",
            "/favicon.ico",
        ],
        user_agents=[
            "Dalvik/2.1.0 (Linux; U; Android 14; Pixel 8 Build/UQ1A)",
            "Mozilla/5.0 (Linux; Android 14; Pixel 8) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.6422.165 Mobile Safari/537.36",
        ],
        extra_headers=[
            "Accept: */*",
        ],
        sleep_ms=30000,
        jitter=60,
        os_tags=["android"],
        service_tags=["*"],
        env_tags=["iot", "cloud"],
        risk_tags=["stealth", "default"],
    ),

    # ── SharePoint / O365 (very corporate, aggressive) ─────────────────────
    ProfileRecipe(
        family="sharepoint_o365",
        description="SharePoint + Office 365: aggressive corporate blend. Best for Windows AD + SharePoint.",
        get_paths=[
            "/_layouts/15/viewlsts.aspx",
            "/_api/web/lists",
            "/_vti_bin/client.svc",
            "/sites/company/_api/web",
        ],
        post_paths=[
            "/_vti_bin/client.svc/ProcessQuery",
            "/_api/contextinfo",
            "/_layouts/15/Upload.aspx",
            "/_api/web/GetFolderByServerRelativeUrl",
        ],
        decoy_paths=[
            "/",
            "/_layouts/15/start.aspx",
            "/SitePages/Home.aspx",
            "/Style Library/",
        ],
        user_agents=[
            "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/125.0.0.0 Safari/537.36 Edg/125.0.0.0",
        ],
        extra_headers=[
            "Accept: application/json; odata=verbose",
            "X-RequestDigest: SHAREPOINT_FORM_DIGEST",
        ],
        os_tags=["windows"],
        service_tags=["sharepoint", "iis", "exchange"],
        env_tags=["corporate"],
        risk_tags=["aggressive"],
    ),
]


# ═══════════════════════════════════════════════════════════════════════════
#  SCORING ENGINE
# ═══════════════════════════════════════════════════════════════════════════

def _tag_match(recipe_tags: list[str], target_tags: list[str]) -> int:
    """Score how many recipe tags match target tags. '*' matches everything."""
    if "*" in recipe_tags:
        return 1  # base match, wildcard
    score = 0
    for rt in recipe_tags:
        if rt in target_tags:
            score += 2  # explicit match = higher weight
        elif rt == "*":
            score += 1
    return score


@dataclass
class Recommendation:
    recipe: ProfileRecipe
    score: float       # 0-100 composite score
    reasoning: str     # human-readable why this was recommended


class ProfileAdvisor:
    """Target-aware malleable profile recommender.

    Usage:
        advisor = ProfileAdvisor()
        recs = advisor.recommend(
            os="windows",
            services=["iis", "microsoft-exchange"],
            risk_level="default",
        )
        for r in recs:
            print(f"{r.recipe.family}: {r.score} — {r.reasoning}")
    """

    def __init__(self, history_path: str = "data/profile_effectiveness.json"):
        self._history_path = history_path
        self._history: dict[str, dict] = self._load_history()

    # ── History persistence ─────────────────────────────────────────────────

    def _load_history(self) -> dict[str, dict]:
        if _os.path.exists(self._history_path):
            try:
                with open(self._history_path, "r") as f:
                    return _json.load(f)
            except (_json.JSONDecodeError, OSError):
                pass
        return {}

    def _save_history(self) -> None:
        _os.makedirs(_os.path.dirname(self._history_path) or ".", exist_ok=True)
        with open(self._history_path, "w") as f:
            _json.dump(self._history, f, indent=2)

    def record_effectiveness(self, family: str, success: bool) -> None:
        """Record whether a profile family succeeded in an engagement."""
        entry = self._history.setdefault(family, {"wins": 0, "trials": 0})
        entry["trials"] += 1
        if success:
            entry["wins"] += 1
        self._save_history()

    def _beta_score(self, family: str) -> float:
        """Beta-Binomial posterior mean: (wins + 1) / (trials + 2)."""
        entry = self._history.get(family, {})
        wins = entry.get("wins", 0)
        trials = entry.get("trials", 0)
        return (wins + 1.0) / (trials + 2.0) if trials > 0 else 0.5

    # ── Target parsing ─────────────────────────────────────────────────────

    @staticmethod
    def _parse_os(os_hint: str) -> list[str]:
        os_lower = os_hint.lower()
        tags = []
        if "windows" in os_lower:
            tags.append("windows")
        if "linux" in os_lower or "unix" in os_lower or "ubuntu" in os_lower or "debian" in os_lower or "centos" in os_lower or "rhel" in os_lower or "fedora" in os_lower:
            tags.append("linux")
        if "mac" in os_lower or "darwin" in os_lower or "apple" in os_lower:
            tags.append("macos")
        if "android" in os_lower:
            tags.append("android")
        if "ios" in os_lower or "iphone" in os_lower:
            tags.append("macos")  # shares Apple ecosystem
        return tags or ["*"]

    @staticmethod
    def _parse_services(services: list[str]) -> list[str]:
        """Normalize service names to tags recipes understand."""
        mapping = {
            "iis": ["iis", "microsoft"],
            "microsoft-iis": ["iis", "microsoft"],
            "microsoft-httpapi": ["iis", "microsoft"],
            "apache": ["apache"],
            "apache httpd": ["apache"],
            "apache/": ["apache"],
            "nginx": ["nginx"],
            "nginx/": ["nginx"],
            "tomcat": ["tomcat", "java"],
            "apache tomcat": ["tomcat", "java"],
            "node.js": ["node"],
            "node": ["node"],
            "express": ["node"],
            "django": ["django", "python"],
            "gunicorn": ["django", "python"],
            "flask": ["flask", "python"],
            "werkzeug": ["flask", "python"],
            "spring": ["spring", "java", "tomcat"],
            "spring-boot": ["spring", "java"],
            "exchange": ["exchange", "microsoft"],
            "microsoft-exchange": ["exchange", "microsoft"],
            "sharepoint": ["sharepoint", "microsoft"],
            "wordpress": ["wordpress"],
            "joomla": ["joomla"],
            "drupal": ["drupal"],
            "php": ["wordpress"],  # most PHP is CMS-related
            "mysql": ["wordpress"],  # correlates with PHP/CMS
        }
        tags = []
        seen = set()
        for s in services:
            s_lower = s.lower().strip()
            # Strip version suffix (e.g. "nginx/1.24.0" -> "nginx")
            if "/" in s_lower:
                base = s_lower.split("/")[0]
                if base in mapping:
                    s_lower = base
            matched = False
            if s_lower in mapping:
                for t in mapping[s_lower]:
                    if t not in seen:
                        tags.append(t)
                        seen.add(t)
                matched = True
            for key in mapping:
                if s_lower.startswith(key + "/") or s_lower == key:
                    if not matched:
                        for t in mapping[key]:
                            if t not in seen:
                                tags.append(t)
                                seen.add(t)
                        matched = True
                    break
            if not matched and s_lower not in seen:
                tags.append(s_lower)
                seen.add(s_lower)
        return tags or ["*"]

    # ── Recommendation engine ──────────────────────────────────────────────

    def recommend(
        self,
        os_hint: str = "",
        services: list[str] | None = None,
        risk_level: str = "default",
        env: str = "",
        target_ip: str = "",
        limit: int = 3,
    ) -> list[Recommendation]:
        """Return ranked profile recommendations for a given target.

        Args:
            os_hint: Detected OS string (nmap -O or beacon sysinfo).
            services: Detected service names ("Microsoft IIS", "nginx", etc.).
            risk_level: "stealth", "default", or "aggressive".
            env: Environment hint ("corporate", "cloud", "dmz", "dev", "iot").
            target_ip: Target IP (used for network position heuristics).
            limit: Max recommendations to return.
        """
        target_os = self._parse_os(os_hint)
        target_svc = self._parse_services(services or [])
        target_env = [env] if env else []

        scored: list[tuple[ProfileRecipe, float, list[str]]] = []

        for recipe in RECIPES:
            reasons: list[str] = []
            score = 0.0

            # 1. OS match (weight: 30)
            os_match = _tag_match(recipe.os_tags, target_os)
            if os_match > 0:
                score += 30.0 * (os_match / max(1, len(target_os) + len(recipe.os_tags)))
            reasons.append(f"OS: {'matched' if os_match > 0 else 'neutral'}")

            # 2. Service match (weight: 35)
            svc_match = _tag_match(recipe.service_tags, target_svc)
            if svc_match > 0:
                score += 35.0 * (svc_match / max(1, len(target_svc) + len(recipe.service_tags)))
            reasons.append(f"Services: {'+%d'%svc_match if svc_match else 'neutral'}")

            # 3. Risk level match (weight: 20)
            risk_match = _tag_match(recipe.risk_tags, [risk_level])
            if risk_match > 0:
                score += 20.0
            reasons.append(f"Risk: {'matched' if risk_match > 0 else 'mismatch'}")

            # 4. Environment match (weight: 10)
            if target_env:
                env_match = _tag_match(recipe.env_tags, target_env)
                if env_match > 0:
                    score += 10.0
                reasons.append(f"Env: {'matched' if env_match else 'neutral'}")

            # 5. Historical effectiveness (weight: 5, bonus)
            beta = self._beta_score(recipe.family)
            hist_bonus = beta * 5.0
            score += hist_bonus
            if beta > 0.5:
                reasons.append(f"History: {beta:.0%} success rate")

            # 6. Network position heuristics
            if target_ip:
                if target_ip.startswith("10.") or target_ip.startswith("172.16.") or target_ip.startswith("192.168."):
                    # internal network -> corporate blends work well
                    if "corporate" in recipe.env_tags:
                        score += 3.0
                        reasons.append("Network: internal IP -> corporate blend")

            scored.append((recipe, min(100.0, score), reasons))

        # Sort by score descending
        scored.sort(key=lambda x: x[1], reverse=True)

        return [
            Recommendation(
                recipe=r,
                score=s,
                reasoning=", ".join(rs),
            )
            for r, s, rs in scored[:limit]
        ]

    def recommend_best(self, **kwargs) -> Recommendation:
        """Return the single best recommendation.

        If no target data is available (empty os_hint and no services),
        defaults to the generic_cdn profile — the safest blend for any target.
        """
        # If no target data at all, default to generic_cdn explicitly
        if not kwargs.get("os_hint") and not kwargs.get("services"):
            return Recommendation(
                recipe=RECIPES[0],  # generic_cdn is first
                score=40.0,
                reasoning="No target data -- generic CDN profile (safest blend).",
            )
        recs = self.recommend(**kwargs, limit=1)
        if not recs:
            return Recommendation(
                recipe=RECIPES[0],
                score=40.0,
                reasoning="No target data -- generic CDN profile (safest blend).",
            )
        return recs[0]

    def generate_profile(self, os_hint: str = "", services: list[str] | None = None,
                         risk_level: str = "default", **kwargs) -> dict:
        """Recommend a profile and render it as a JSON-compatible dict."""
        best = self.recommend_best(os_hint=os_hint, services=services,
                                  risk_level=risk_level, **kwargs)
        r = best.recipe
        return {
            "family": r.family,
            "description": r.description,
            "score": best.score,
            "reasoning": best.reasoning,
            "profile": {
                "get_paths": list(r.get_paths),
                "post_paths": list(r.post_paths),
                "decoy_paths": list(r.decoy_paths),
                "user_agents": list(r.user_agents),
                "extra_headers": list(r.extra_headers),
                "sleep_ms": r.sleep_ms,
                "jitter": r.jitter,
                "randomize_uri_casing": True,
                "prepend_slash": True,
            },
        }


# ── Convenience singleton ───────────────────────────────────────────────────
_advisor: ProfileAdvisor | None = None


def get_advisor() -> ProfileAdvisor:
    global _advisor
    if _advisor is None:
        _advisor = ProfileAdvisor()
    return _advisor