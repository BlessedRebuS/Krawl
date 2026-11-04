"""The raw-request modal shows the YARA rules that matched, from the API data."""

import re
from pathlib import Path

TEMPLATES = Path(__file__).resolve().parent.parent / "src" / "templates"
PARTIAL = (
    TEMPLATES / "jinja2" / "dashboard" / "partials" / "raw_request_detections.html"
)
DASHBOARD_JS = TEMPLATES / "static" / "js" / "dashboard.js"
INCLUDE = '{% include "dashboard/partials/raw_request_detections.html" %}'


def test_both_raw_request_modals_include_the_detection_legend():
    for template in (
        TEMPLATES / "jinja2" / "dashboard" / "partials" / "raw_request_modal.html",
        TEMPLATES / "jinja2" / "dashboard" / "ip.html",
    ):
        text = template.read_text(encoding="utf-8")
        body = text.index("raw-request-content")
        footer = text.index("raw-request-modal-footer", body)
        assert INCLUDE in text[body:footer], template.name


def test_legend_never_renders_rule_or_evidence_data_as_html():
    # matched_pattern is attacker-controlled; every value goes through x-text.
    assert "x-html" not in PARTIAL.read_text(encoding="utf-8")


def test_legend_shows_the_analyst_fields():
    text = PARTIAL.read_text(encoding="utf-8")

    for field in (
        "rawModal.detections",
        "rule.description",
        "rule.rule",
        "rule.confidence",
        "rule.mitre_attack",
        "rule.cve",
        "rule.references",
        "rule.false_positives",
        "matched_pattern",
    ):
        assert field in text, field


def test_view_raw_request_keeps_the_detections_and_close_clears_them():
    js = DASHBOARD_JS.read_text(encoding="utf-8")
    view = js[js.index("async viewRawRequest(") : js.index("escapeHtml(value)")]
    close = js[js.index("closeRawModal() {") :]
    close = close[: close.index("},")]

    assert re.search(r"rawModal\.detections\s*=\s*data\.detections\s*\|\|\s*\[\]", view)
    assert "rawModal.detections = []" in close


def test_mitre_and_cve_links_point_at_the_public_catalogues():
    js = DASHBOARD_JS.read_text(encoding="utf-8")

    assert "https://attack.mitre.org/techniques/" in js
    assert "https://nvd.nist.gov/vuln/detail/" in js
