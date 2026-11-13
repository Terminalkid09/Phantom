"""Tool provisioning is consent-gated.

Installing a tool is an operator action. Without consent the helper must
return the PLAN and touch no installer; the CLI only passes consent for
an explicit `--allow-install`, and never mid-engagement.
"""
import pytest


class _Shell:
    auto_run = True


class _Tools:
    def __init__(self, have):
        self._have = set(have)

    def has(self, name):
        return name in self._have


class TestProvision:
    def test_without_consent_no_installer_is_called(self):
        from phantom.automation.runtime.provision import provision
        calls = []
        report = provision(["nmap", "hydra"], consent=False,
                           installer=lambda t: calls.append(t) or {"ok": True})
        assert calls == []
        assert report["plan"] == ["nmap", "hydra"]
        assert report["installed"] == []
        assert report["reason"] == "consent required"

    def test_with_consent_each_tool_is_installed(self):
        from phantom.automation.runtime.provision import provision
        calls = []
        report = provision(["nmap", "hydra"], consent=True,
                           installer=lambda t: calls.append(t) or {"ok": True})
        assert calls == ["nmap", "hydra"]
        assert report["installed"] == ["nmap", "hydra"]

    def test_failed_install_is_recorded_not_raised(self):
        from phantom.automation.runtime.provision import provision
        def _fail(tool):
            raise RuntimeError("apt exploded")
        report = provision(["nmap"], consent=True, installer=_fail)
        assert report["installed"] == []
        assert report["results"]["nmap"]["ok"] is False

    def test_missing_respects_the_toolchain(self):
        from phantom.automation.runtime.provision import missing
        assert missing(_Tools({"nmap"}), ["nmap", "curl"]) == ["curl"]

    def test_provision_missing_only_touches_the_gaps(self):
        from phantom.automation.runtime.provision import provision_missing
        calls = []
        report = provision_missing(_Tools({"nmap"}), consent=True,
                                   tools=["nmap", "curl"],
                                   installer=lambda t: calls.append(t) or {"ok": True})
        assert calls == ["curl"]
        assert report["plan"] == ["curl"]


class TestCliWiring:
    def _patch(self, monkeypatch, provision_missing):
        import phantom.automation.runtime.provision as prov
        monkeypatch.setattr(prov, "provision_missing", provision_missing)
        monkeypatch.setattr(prov, "missing", lambda *a, **k: [])
        import phantom.automation.swarm as sp
        monkeypatch.setattr(
            sp, "run_swarm",
            lambda *a, **k: {"ok": True, "tasks": [], "added": 0})

    def test_without_the_flag_nothing_installs(self, monkeypatch):
        called = []
        self._patch(monkeypatch,
                    lambda *a, **k: called.append(1) or {"installed": [],
                                                         "results": {}})
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "10.0.0.5 --swarm")
        assert called == []

    def test_with_the_flag_consent_is_granted(self, monkeypatch):
        seen = {}
        def _fake(toolchain, consent, **kw):
            seen["consent"] = consent
            return {"installed": [], "results": {}}
        self._patch(monkeypatch, _fake)
        from phantom.core.shell.commands.auto import cmd_auto
        cmd_auto(_Shell(), "10.0.0.5 --swarm --allow-install")
        assert seen.get("consent") is True
