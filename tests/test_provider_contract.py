"""Contract + offline-fixture tests for the external data providers.

These pin the three properties Fase 3.2 is about: every wrapped service is
DECLARED (name, reliability, timeout), the transport seam can REPLAY a
stored response with no network, and recording never persists a secret.
"""
import json
import os

from phantom.utils import provider_contract as pc


class DummyResponse:
    def __init__(self, status_code=200, data=None, headers=None, text=""):
        self.status_code = status_code
        self._data = data
        self.headers = headers or {}
        self.text = text

    def json(self):
        if self._data is None:
            raise ValueError("not json")
        return self._data

    def raise_for_status(self):
        if self.status_code >= 400:
            raise Exception("HTTP error")


KNOWN = ("nvd", "crtsh", "shodan", "shodan_internetdb", "github",
         "bgpview", "exploitdb")


class TestContracts:
    def test_every_wrapped_provider_is_declared(self):
        for name in KNOWN:
            spec = pc.get_provider(name)
            assert spec is not None, name
            assert 0.0 <= spec.reliability <= 1.0, name
            assert spec.timeout > 0, name

    def test_unknown_provider_reliability_is_neutral(self):
        assert pc.reliability_of("does-not-exist", default=0.5) == 0.5
        assert pc.reliability_of("nvd") == pc.get_provider("nvd").reliability

    def test_catalog_is_non_empty_and_namespaced(self):
        providers = pc.list_providers()
        assert providers
        assert {p.name for p in providers} >= set(KNOWN)


class TestRedaction:
    def test_params_and_headers_are_redacted(self):
        params = pc.redact_params({"key": "secret", "q": "x"})
        assert params["key"] == "REDACTED"
        assert params["q"] == "x"
        headers = pc.redact_headers({"Authorization": "Bearer abc",
                                     "Accept": "application/json"})
        assert headers["Authorization"] == "REDACTED"
        assert headers["Accept"] == "application/json"

    def test_url_secret_query_is_stripped(self):
        out = pc.redact_url("https://api.example/x?key=secret&q=ok")
        assert "secret" not in out
        assert "ok" in out

    def test_fixture_key_is_independent_of_the_key(self):
        a = pc.fixture_key("shodan", "https://x", {"key": "one", "q": "y"})
        b = pc.fixture_key("shodan", "https://x", {"key": "two", "q": "y"})
        assert a == b

    def test_fixture_key_varies_by_provider_and_request(self):
        base = pc.fixture_key("shodan", "https://x", {"q": "y"})
        assert base != pc.fixture_key("crtsh", "https://x", {"q": "y"})
        assert base != pc.fixture_key("shodan", "https://x", {"q": "z"})


class TestReplay:
    def test_records_then_replays_without_network(self, tmp_path, monkeypatch):
        monkeypatch.setenv("PHANTOM_PROVIDER_FIXTURES", str(tmp_path))
        monkeypatch.setenv("PHANTOM_PROVIDER_RECORD", "1")
        monkeypatch.setattr(
            pc.requests, "get",
            lambda *a, **k: DummyResponse(data={"ports": [22]}))
        live = pc.http_get("shodan", "https://api.shodan.io/x", {"key": "k"})
        assert live.json() == {"ports": [22]}

        monkeypatch.delenv("PHANTOM_PROVIDER_RECORD", raising=False)

        def boom(*a, **k):
            raise AssertionError("network used during replay")

        monkeypatch.setattr(pc.requests, "get", boom)
        # a DIFFERENT key still hits the same fixture (key is secret-free)
        replayed = pc.http_get("shodan", "https://api.shodan.io/x",
                               {"key": "another"})
        assert replayed.from_fixture is True
        assert replayed.json() == {"ports": [22]}

    def test_recorded_fixture_never_contains_a_secret(self, tmp_path,
                                                       monkeypatch):
        monkeypatch.setenv("PHANTOM_PROVIDER_FIXTURES", str(tmp_path))
        monkeypatch.setenv("PHANTOM_PROVIDER_RECORD", "1")
        monkeypatch.setattr(
            pc.requests, "get",
            lambda *a, **k: DummyResponse(
                data={"total_count": 1},
                headers={"Authorization": "Bearer SECRETHEADER"}))
        pc.http_get("github", "https://api.github.com/search",
                    params={"q": "cve", "key": "SECRETQUERY"})
        blob = ""
        for root, _dirs, files in os.walk(str(tmp_path)):
            for name in files:
                with open(os.path.join(root, name), encoding="utf-8") as fh:
                    blob += fh.read()
        assert blob  # something was written
        assert "SECRETQUERY" not in blob
        assert "SECRETHEADER" not in blob
        assert "REDACTED" in blob

    def test_without_fixtures_dir_the_network_is_used(self, monkeypatch):
        monkeypatch.delenv("PHANTOM_PROVIDER_FIXTURES", raising=False)
        called = {}

        def fake(*a, **k):
            called["hit"] = True
            return DummyResponse(data={"x": 1})

        monkeypatch.setattr(pc.requests, "get", fake)
        pc.http_get("nvd", "https://services.nvd.nist.gov/x")
        assert called.get("hit") is True


class TestApiRouting:
    def test_crtsh_lookup_replays_offline(self, tmp_path, monkeypatch):
        from phantom.utils import api
        monkeypatch.setenv("PHANTOM_PROVIDER_FIXTURES", str(tmp_path))
        monkeypatch.setenv("PHANTOM_PROVIDER_RECORD", "1")
        monkeypatch.setattr(
            pc.requests, "get",
            lambda *a, **k: DummyResponse(
                data=[{"name_value": "a.example.com"}]))
        assert api.crtsh_lookup("example.com") == ["a.example.com"]

        monkeypatch.delenv("PHANTOM_PROVIDER_RECORD", raising=False)
        monkeypatch.setattr(
            pc.requests, "get",
            lambda *a, **k: (_ for _ in ()).throw(Exception("offline")))
        assert api.crtsh_lookup("example.com") == ["a.example.com"]


class TestReliabilityWiring:
    def test_external_intel_findings_carry_provider_reliability(self):
        from phantom.automation.external_intel import external_intel_interp
        from phantom.automation.belief import WorldModel
        wm = WorldModel(target="10.0.0.9")
        findings = external_intel_interp(
            "SHODAN: host=10.0.0.9 port=22\n"
            "HOSTNAME: host=a.example.com source=crtsh\n"
            "BGP: host=10.0.0.9 prefix=10.0.0.0/8", wm, {})
        by_kind = {f.kind: f for f in findings}
        assert (by_kind["service"].source_reliability
                == pc.reliability_of("shodan"))
        assert (by_kind["hostname"].source_reliability
                == pc.reliability_of("crtsh"))
        assert (by_kind["netblock"].source_reliability
                == pc.reliability_of("bgpview"))
