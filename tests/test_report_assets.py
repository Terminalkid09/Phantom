"""The report template is a PRODUCT ASSET, and CI proved that the hard way.

`phantom/data/` was ignored as a whole, so `templates/report/professional.html`
lived on every developer's disk and in nobody's clone: the report tests passed
locally and the unit-test step failed on CI for months with "Template not
found", skipping all fourteen other jobs behind it. These tests pin the two
halves of the fix — the file exists WITH the placeholders the renderer
substitutes, and the module renders real HTML instead of returning silently.
"""
import os
import re

import pytest

TEMPLATE = os.path.join("phantom", "data", "templates", "report",
                        "professional.html")

# every placeholder `_export_html` substitutes; a template that drops one would
# render a report with the raw token in it, which no test would notice
REQUIRED_PLACEHOLDERS = (
    "{{ target }}", "{{ date_str }}", "{{ summary }}", "{{ vuln_content }}",
    "{{ service_section }}", "{{ analyzer_section }}", "{{ notes_section }}",
    "{{ history_section }}",
)


class TestTheTemplateIsThere:
    def test_the_template_exists_where_the_renderer_looks_for_it(self):
        assert os.path.isfile(TEMPLATE), (
            "the professional report template is missing: a clone without it "
            "fails the report tests, which is exactly how CI stayed red")

    def test_it_carries_every_placeholder_the_renderer_substitutes(self):
        text = open(TEMPLATE, "r", encoding="utf-8").read()
        missing = [p for p in REQUIRED_PLACEHOLDERS if p not in text]
        assert missing == []

    def test_the_renderer_replaces_exactly_those_names(self):
        """Template and renderer must not drift apart silently."""
        source = open(os.path.join("phantom", "modules", "report.py"),
                      encoding="utf-8").read()
        replaced = set(re.findall(r"replace\(\"\{\{ ([a-z_]+) \}\}\"", source))
        template_names = set(re.findall(r"\{\{ ([a-z_]+) \}\}",
                                        open(TEMPLATE, encoding="utf-8").read()))
        assert template_names <= replaced, (
            "the template carries a token the renderer never substitutes: it "
            f"would ship raw in the client report ({sorted(template_names - replaced)})")


class TestTheTemplateIsTrackedNotJustPresent:
    """The local-only failure mode: present on disk, absent from the repo."""

    def test_gitignore_does_not_swallow_the_templates_directory(self):
        text = open(".gitignore", encoding="utf-8").read()
        assert "!phantom/data/templates/" in text, (
            "without the negation, `phantom/data/*` keeps the template out of "
            "the repository and CI fails again")
        # the broad pattern that caused the outage must be gone
        assert not re.search(r"^phantom/data/$", text, re.M)

    def test_the_state_side_stays_ignored(self):
        from phantom.utils.paths import data_dir
        # the runtime state must still be outside the tracked tree
        assert "phantom/data/*" in open(".gitignore", encoding="utf-8").read()
        assert data_dir()  # importable and resolvable, not a git concern

    def test_a_missing_template_is_reported_never_silent(self, monkeypatch):
        """A missing template made `_export_html` return with an ERROR line and
        no file: the ERROR is what the operator (and CI) sees."""
        from phantom.modules import report as report_mod
        calls = []
        monkeypatch.setattr(report_mod.notifier, "error",
                            lambda *a, **k: calls.append(a))
        module = report_mod.ReportModule()
        monkeypatch.setattr(module, "template_dir", os.path.join("no", "such"))
        assert module._load_template("professional.html") == ""
        assert calls, "a missing template must be REPORTED, never silent"

    def test_the_real_template_loads_non_empty(self):
        from phantom.modules import report as report_mod
        text = report_mod.ReportModule()._load_template("professional.html")
        assert text and "{{ target }}" in text
