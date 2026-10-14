"""The operator's OSINT scope on a username target: PIN one network, or
EXCLUDE the five top socials.

The defect this closes: `platform` was an OPTIONAL capability slot nobody
ever filled, so every run silently probed instagram AND mixed the same
handle from every other network into the identity graph — where the same
handle is very often a different person (the wrong-person trap the operator
flagged). And `_search_dorks` accepted `full_name` and then IGNORED it, so
a person was never looked up by their real name.

Three layers are covered here, because the scope is only real if it
survives all of them:

  1. the engine (`recon.deep_recon`) actually stays where it was put;
  2. the social engine's `profile_recon` reads the same value;
  3. the agent hands it to the capability, and `/api/automode/run` carries
     it on the wire.
"""
from __future__ import annotations

import os
from types import SimpleNamespace

import pytest

from phantom.automation.social import recon as R

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


def _read(*parts: str) -> str:
    with open(os.path.join(ROOT, *parts), "r", encoding="utf-8") as handle:
        return handle.read()


# ── the one wire value ────────────────────────────────────────────────────

def test_normalize_scope_is_total_and_never_guesses():
    assert R.normalize_scope("") == ("auto", "")
    assert R.normalize_scope("instagram") == ("pin", "instagram")
    assert R.normalize_scope("@Instagram") == ("pin", "instagram")
    assert R.normalize_scope("other") == ("other", "")
    assert R.normalize_scope("ALT") == ("other", "")
    # an unknown value must NOT become a pin (or a platform)
    assert R.normalize_scope("myspace") == ("auto", "")
    # an explicit scope wins; "auto" keeps the legacy "primary only" reading
    assert R.normalize_scope("instagram", "auto") == ("auto", "instagram")
    assert R.normalize_scope("instagram", "other") == ("other", "")


def test_the_five_and_the_alternatives_are_disjoint_and_supported():
    assert len(R.TOP_SOCIALS) == 5
    assert set(R.TOP_SOCIALS).isdisjoint(R.ALT_PLATFORMS)
    assert set(R.TOP_SOCIALS) <= set(R.SUPPORTED_PLATFORMS)


# ── layer 1: the recon engine stays where it was put ──────────────────────

def test_pin_probes_only_the_pinned_network(monkeypatch):
    seen: list = []

    def fake_vote(username, platform, jar=None):
        seen.append(platform)
        return "public", 0.9, ""

    monkeypatch.setattr(R, "_state_vote", fake_vote)
    ok, lines = R.deep_recon("jane", "instagram", variants=False,
                             wayback=False, search=False, second_hop=False)
    assert ok
    assert set(seen) == {"instagram"}, seen
    scope = [l for l in lines if l.startswith("RECON_SCOPE:")]
    assert scope and "mode=pin" in scope[0] and "platform=instagram" in scope[0]
    # the four others are named as excluded, so the operator can see them
    for other in ("tiktok", "x", "github", "telegram"):
        assert other in scope[0]


def test_pin_keeps_variants_on_the_same_network(monkeypatch):
    """Variant probing must not leak back onto the other networks."""
    seen: list = []

    def fake_vote(username, platform, jar=None):
        seen.append(platform)
        return "public", 0.9, ""

    monkeypatch.setattr(R, "_state_vote", fake_vote)
    ok, _ = R.deep_recon("jane", "github", variants=True, wayback=False,
                         search=False, second_hop=False)
    assert ok
    assert set(seen) == {"github"}, seen


def test_auto_still_probes_every_platform(monkeypatch):
    """The legacy behaviour is untouched: `""` is not a silent pin."""
    seen: list = []

    def fake_vote(username, platform, jar=None):
        seen.append(platform)
        return "public", 0.9, ""

    monkeypatch.setattr(R, "_state_vote", fake_vote)
    ok, lines = R.deep_recon("jane", "", variants=False, wayback=False,
                             search=False, second_hop=False)
    assert ok
    assert set(seen) == set(R.TOP_SOCIALS)
    assert not [l for l in lines if l.startswith("RECON_SCOPE:")]


def test_other_excludes_the_five_top_socials(monkeypatch):
    seen: list = []
    urls: list = []

    def fake_vote(username, platform, jar=None):
        seen.append(platform)
        return "public", 0.9, ""

    def fake_fetch(url, timeout=15.0, ua="", cookies=""):
        urls.append(url)
        return ""

    monkeypatch.setattr(R, "_state_vote", fake_vote)
    monkeypatch.setattr(R, "_fetch", fake_fetch)
    monkeypatch.setattr(R.time, "sleep", lambda *_: None)
    ok, lines = R.deep_recon("jane", "other", variants=False, wayback=False,
                             search=True, second_hop=False)
    assert ok
    assert not (set(seen) & set(R.TOP_SOCIALS)), seen
    assert set(seen) <= set(R.ALT_PLATFORMS)
    scope = [l for l in lines if l.startswith("RECON_SCOPE:")]
    assert scope and "mode=other" in scope[0]
    for top in R.TOP_SOCIALS:
        assert top in scope[0]
    # the dorks carry a real `-site:` exclusion for each of the five
    assert any("-site%3Ainstagram.com" in u for u in urls), urls
    assert any("-site%3Atiktok.com" in u for u in urls), urls


# ── name + handle dorks (the ignored parameter) ───────────────────────────

def test_dork_queries_lookup_the_person_by_name_too():
    q = R._dork_queries("mario.rossi", "Mario Rossi")
    assert any("Mario Rossi" in s for s in q)
    assert any("mario.rossi" in s for s in q)


def test_a_pinned_dork_set_stays_inside_that_one_site():
    q = R._dork_queries("mario.rossi", "Mario Rossi", scope="pin",
                        platform="instagram")
    assert q and all("site:instagram.com" in s for s in q), q
    assert any("Mario Rossi" in s for s in q)


def test_an_other_dork_set_excludes_all_five():
    q = R._dork_queries("mario.rossi", "", scope="other")
    for top in R.TOP_SOCIALS:
        assert f"-site:{R._site_of(top)}" in q[0], q


def test_the_real_name_reaches_the_network_call(monkeypatch):
    """`full_name` used to be accepted and then dropped on the floor."""
    from urllib.parse import quote_plus
    urls: list = []

    def fake_fetch(url, timeout=15.0, ua="", cookies=""):
        urls.append(url)
        return ""

    monkeypatch.setattr(R, "_fetch", fake_fetch)
    monkeypatch.setattr(R.time, "sleep", lambda *_: None)
    R._search_dorks("mario.rossi", "Mario Rossi")
    assert any(quote_plus('"Mario Rossi"') in u for u in urls), urls
    assert any(quote_plus("mario.rossi") in u for u in urls), urls


def test_a_search_hit_is_labelled_with_its_network():
    assert R._platform_of_url("https://www.instagram.com/jane/") == "instagram"
    assert R._platform_of_url("https://www.linkedin.com/in/jane") == "linkedin"
    assert R._platform_of_url("https://news.example.com/jane") == ""


def test_search_hits_emit_the_network_in_the_marker():
    r = R.ReconResult(username="jane", platform="instagram")
    r.leads.append(R.Lead("search_hit", "https://www.linkedin.com/in/jane",
                          "linkedin", "ddg_dork", 0.5))
    markers = r.markers()
    assert any(l.startswith("SEARCH_HIT:") and "platform=linkedin" in l
               for l in markers)


def test_the_scope_and_the_hits_become_findings():
    """A receipt nothing interprets is a receipt nobody reads: the scope,
    the dork hits and the wayback snapshots used to be plain output lines."""
    from phantom.automation.belief import WorldModel
    from phantom.automation.guidance.kit import _social_interp
    wm = WorldModel(target="jane", target_type="username")
    out = "\n".join([
        "RECON_SCOPE: mode=pin platform=instagram "
        "excluded=tiktok,x,github,telegram contact_scope=operator",
        "SEARCH_HIT: url=https://www.linkedin.com/in/jane platform=linkedin "
        "evidence=ddg_dork",
        "WAYBACK: url=http://web.archive.org/web/1/https://instagram.com/jane "
        "evidence=snapshot:202401",
    ])
    findings = _social_interp(out, wm, {})
    kinds = {f.kind for f in findings}
    assert {"recon_scope", "search_hit", "wayback"} <= kinds, kinds
    scope = next(f for f in findings if f.kind == "recon_scope")
    assert scope.value["mode"] == "pin"
    assert scope.value["platform"] == "instagram"
    assert "tiktok" in scope.value["excluded"]
    hit = next(f for f in findings if f.kind == "search_hit")
    assert hit.value["platform"] == "linkedin"
    assert hit.value["url"].endswith("/in/jane")


def test_the_correspondences_reach_the_operator_end_to_end(monkeypatch):
    """`--platform other` is only useful if the hits it finds land where the
    operator reads them: recon markers -> findings."""
    from phantom.automation.belief import WorldModel
    from phantom.automation.guidance.kit import _social_interp
    page = ('<a class="result__url" href="x">'
            'linkedin.com/in/mario-rossi</a>')

    monkeypatch.setattr(R, "_state_vote",
                        lambda u, p, jar=None: ("missing", 0.0, ""))
    monkeypatch.setattr(R, "_fetch",
                        lambda url, timeout=15.0, ua="", cookies="": page)
    monkeypatch.setattr(R.time, "sleep", lambda *_: None)
    ok, lines = R.deep_recon("mario.rossi", "other", variants=False,
                             wayback=False, search=True, second_hop=False)
    assert ok and len(lines) > 1
    wm = WorldModel(target="mario.rossi", target_type="username")
    findings = _social_interp("\n".join(lines), wm, {})
    kinds = [f.kind for f in findings]
    assert "recon_scope" in kinds, kinds
    assert "search_hit" in kinds, kinds
    hits = [f for f in findings if f.kind == "search_hit"]
    assert any("linkedin" in h.value["platform"] for h in hits), hits


# ── layer 2: profile_recon reads the same value ───────────────────────────

def test_profile_recon_pins_the_pass_to_one_network(monkeypatch):
    from phantom.automation.social.engine import SocialEngine
    cmds: list = []

    def fake_exec(cmd, timeout=0, **kw):
        cmds.append(cmd)
        return SimpleNamespace(stdout="<html>this account is private</html>",
                               returncode=0, stderr="")

    monkeypatch.setattr("phantom.core.executor.execute_quiet", fake_exec)
    ok, lines = SocialEngine().profile_recon("victim", platform="instagram")
    assert ok, lines
    assert any("SCOPE: mode=pin platform=instagram" in l for l in lines), lines
    assert cmds and all("instagram.com" in c for c in cmds), cmds


# ── layer 3: the agent forwards it, the wire carries it ───────────────────

class _Cap:
    """The minimum a capability has to look like to `_autofill_slots`."""

    def __init__(self, cid):
        self.id = cid
        self.inputs: tuple = ()


def _agent(**kw):
    from phantom.automation.agent import AutonomousAgent
    return AutonomousAgent(target="someuser", target_type="username",
                           on_event=None, **kw)


def test_the_agent_forwards_the_operator_scope_to_the_social_slot():
    agent = _agent(social_platform="Instagram")
    slots = agent._autofill_slots(_Cap("deep_recon"), {})
    assert slots.get("platform") == "instagram"


def test_the_scope_never_overrides_a_platform_the_plan_already_chose():
    agent = _agent(social_platform="instagram")
    slots = agent._autofill_slots(_Cap("deep_recon"), {"platform": "other"})
    assert slots["platform"] == "other"


def test_no_scope_means_auto_and_no_slot():
    agent = _agent()
    assert agent.social_platform == ""
    assert "platform" not in agent._autofill_slots(_Cap("deep_recon"), {})


def test_the_scope_is_an_osint_input_only():
    agent = _agent(social_platform="instagram")
    assert "platform" not in agent._autofill_slots(_Cap("scan_tcp"), {})


def test_the_run_endpoint_forwards_the_scope_on_the_wire():
    """The JSON the UI sends is the keyword `run_auto_mode` receives. A scope
    the wire drops is a checkbox that lies.

    Called on the handler directly, NOT through a live server: booting the
    app binds the C2 listener port, and a test that holds 8080 makes an
    unrelated auto-mode test fail on socket contention.
    """
    import asyncio
    from unittest.mock import patch

    import phantom.api.server as server

    class _Req:
        async def json(self):
            return {"targets": ["someuser"], "goal": "identity",
                    "platform": "Instagram"}

    async def scenario():
        with patch.object(server, "run_auto_mode", return_value=None) as m_run:
            resp = await server.automode_run(_Req())
            assert resp.status == 200
            job = server.auto_jobs.active()
            deadline = 30.0
            while not job.done and deadline > 0:
                await asyncio.sleep(0.2)
                deadline -= 0.2
            assert job.done
            assert m_run.call_count == 1
            assert m_run.call_args.kwargs.get("social_platform") == "instagram"
            server.auto_jobs._jobs.pop(job.id, None)
            if server.auto_jobs._active_id == job.id:
                server.auto_jobs._active_id = None

    asyncio.run(scenario())


def test_the_run_endpoint_carries_the_scope_to_the_engine():
    """A scope the wire drops is a checkbox that lies."""
    import phantom.api.server as server
    src = _read(os.path.relpath(server.__file__, ROOT))
    block = src[src.index("async def automode_run"):][:6000]
    assert 'body.get("platform"' in block
    assert "social_platform=platform" in block


def test_the_plan_endpoint_states_the_scope_it_would_run_with():
    import phantom.api.server as server
    src = _read(os.path.relpath(server.__file__, ROOT))
    block = src[src.index("async def automode_plan"):][:9000]
    assert 'body.get("platform"' in block
    assert '"scope"' in block


def test_the_cli_passes_the_flag_through_and_gates_on_a_real_pin():
    src = _read("phantom", "core", "shell", "commands", "auto.py")
    assert "social_platform=args.platform" in src
    # the start-gate preview only makes sense on a PINNED platform: `other`
    # has no single profile page to show.
    assert '_pin_scope == "pin"' in src


if __name__ == "__main__":                     # pragma: no cover
    pytest.main([__file__, "-q"])
