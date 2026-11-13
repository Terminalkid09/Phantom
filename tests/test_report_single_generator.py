"""Section E1 — there is ONE report generator.

The repo had three ways to produce a report (``reporting.ClientReport``, the
inline f-string in ``api/server.reports_generate`` and
``modules.report.ReportModule``) and they had drifted: only ClientReport
carried the guardrail manifest, so a report produced from the UI could not
show which protection controls the engagement had actually run with.

The API now delegates to ReportModule and the inline generator is gone. These
tests pin both halves: the source has no second generator left, and the
artifact the endpoint writes really contains the manifest and is still valid.
"""
import asyncio
import json
import os
import pathlib
import tempfile
import unittest

from aiohttp.test_utils import TestClient, TestServer

_ROOT = pathlib.Path(__file__).resolve().parent.parent
_SERVER = (_ROOT / "phantom" / "api" / "server.py").read_text(encoding="utf-8")

_ENV_KEYS = ("PHANTOM_STATE_FILE", "PHANTOM_API_TOKEN", "PHANTOM_C2_KEY",
             "PHANTOM_C2_NONCE", "PHANTOM_PAYLOAD_TOKEN",
             "PHANTOM_ALLOW_UNSCOPED", "PHANTOM_DATA_DIR")


class TestTheInlineGeneratorIsGone(unittest.TestCase):
    def test_no_second_generator_survives_in_the_api(self):
        for gone in ("_client_findings", "_build_raw_report",
                     "_build_client_report"):
            self.assertNotIn(
                gone, _SERVER,
                f"{gone} still exists in server.py: the API has a second "
                "report generator again")

    def test_the_endpoint_delegates_to_the_module(self):
        block = _SERVER[_SERVER.index("async def reports_generate"):][:900]
        self.assertIn("ReportModule", block)
        self.assertIn(".generate(", block)

    def test_export_all_uses_the_same_generator(self):
        block = _SERVER[_SERVER.index("async def reports_export_all"):][:900]
        self.assertIn("ReportModule", block)
        self.assertIn(".generate(", block)

    def test_the_campaign_zip_uses_the_same_builders(self):
        # The campaign export used to write its own pair of reports too.
        block = _SERVER[_SERVER.index("zf.writestr(\"raw_audit.txt\""):][:400]
        self.assertIn("_build_operator_markdown", block)
        self.assertIn("_build_client_markdown", block)


class TestTheModuleIsTheGenerator(unittest.TestCase):
    def _module(self):
        from phantom.modules.report import ReportModule
        return ReportModule()

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        self._tmp = tempfile.mkdtemp(prefix="phantom-report-")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    def test_the_client_report_names_its_protection_level(self):
        from phantom.core.session import session
        session.target = "10.0.0.5"
        session.scope = ["10.0.0.0/24"]
        try:
            out = self._module().generate("html")
        finally:
            session.target = ""
            session.scope = []
        self.assertIn("## Guardrails", out["client"])
        self.assertIn("Scope gate", out["client"])
        self.assertIn("Network range policy", out["client"])

    def test_html_is_still_valid(self):
        from phantom.core.session import session
        session.target = "10.0.0.5"
        try:
            out = self._module().generate("html")
        finally:
            session.target = ""
        with open(out["client_path"], encoding="utf-8") as f:
            client = f.read()
        with open(out["raw_path"], encoding="utf-8") as f:
            raw = f.read()
        for page in (client, raw):
            self.assertTrue(page.lstrip().startswith("<!DOCTYPE html>"),
                            "not an HTML document")
            self.assertIn("</html>", page)
        self.assertIn("Guardrails", client)

    def test_json_is_still_valid_json(self):
        from phantom.core.session import session
        session.target = "10.0.0.5"
        try:
            out = self._module().generate("json")
        finally:
            session.target = ""
        with open(out["client_path"], encoding="utf-8") as f:
            data = json.load(f)
        self.assertIn("client_report", data)
        self.assertIn("## Guardrails", data["client_report"])


class TestTheEndpointServesIt(unittest.TestCase):
    """The artifact through the interface the operator uses: the HTTP API."""

    def setUp(self):
        self._saved_env = {k: os.environ.get(k) for k in _ENV_KEYS}
        for k in _ENV_KEYS:
            os.environ.pop(k, None)
        self._tmp = tempfile.mkdtemp(prefix="phantom-report-api-")
        os.environ["PHANTOM_STATE_FILE"] = os.path.join(self._tmp, "state.json")
        os.environ["PHANTOM_DATA_DIR"] = self._tmp

    def tearDown(self):
        for k, v in self._saved_env.items():
            if v is None:
                os.environ.pop(k, None)
            else:
                os.environ[k] = v

    @staticmethod
    def _scenario(coro):
        return asyncio.run(coro)

    def _generate(self, fmt):
        from phantom.api.server import create_app
        from phantom.core.session import session
        from phantom.utils import c2_crypto

        async def scenario():
            client = TestClient(TestServer(create_app()))
            await client.start_server()
            try:
                session.target = "10.0.0.5"
                session.scope = ["10.0.0.0/24"]
                token = c2_crypto.get_api_token()
                r = await client.post("/api/reports/generate",
                                      json={"format": fmt},
                                      headers={"Authorization":
                                               f"Bearer {token}"})
                body = await r.json()
                with open(body["client_path"], encoding="utf-8") as f:
                    content = f.read()
                return r.status, body, content
            finally:
                await client.close()

        try:
            return self._scenario(scenario())
        finally:
            session.target = ""
            session.scope = []

    def test_the_client_report_from_the_api_carries_the_manifest(self):
        status, body, content = self._generate("html")
        self.assertEqual(status, 200)
        self.assertTrue(body["client_path"])
        self.assertIn("Guardrails", content)
        self.assertIn("Scope gate", content)

    def test_the_endpoint_builds_through_the_module(self):
        # A marker only ReportModule can produce: the operator document header.
        _status, body, _content = self._generate("html")
        self.assertIn("Phantom Operator Report", body["raw"])


if __name__ == "__main__":
    unittest.main()
