"""Attacks tab fragments: period attackers columns, severity chips, rule picker, time format."""

import re
import sys
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from dependencies import _format_num, _format_ts, get_templates  # noqa: E402
from period import resolve_period, time_only  # noqa: E402

PAGE = {"page": 1, "total_pages": 1, "total": 1234, "page_size": 10}


def _render(name, **ctx):
    return get_templates().env.get_template(f"dashboard/partials/{name}").render(
        dashboard_path="", period_qs="", range_label="", **ctx
    )


def _cols(html):
    return len(re.findall(r"<th\b", html.split("</thead>")[0]))


def test_period_attackers_columns_and_filter_button():
    item = {
        "ip": "203.0.113.9",
        "hits": 5,
        "top_type": "sql_injection",
        "worst_band": "high",
        "category": "bad_crawler",
        "last_seen": datetime(2026, 10, 27, 12),
    }
    html = _render(
        "attackers_table.html",
        items=[item],
        pagination=PAGE,
        in_period=True,
        filter_qs="",
        sort_by="",
        sort_order="",
    )
    assert _cols(html) == 8
    assert "SQL injection" in html and "sev-fg-high" in html and ">High<" in html
    assert "category-bad-crawler" in html
    assert "Show only this IP&#39;s requests" in html or "Show only this IP's requests" in html
    assert "1.234 attackers" in html
    empty = _render(
        "attackers_table.html", items=[], pagination=PAGE, in_period=True, filter_qs="", sort_by="", sort_order=""
    )
    assert 'colspan="8"' in empty
    legacy = _render(
        "attackers_table.html", items=[], pagination=PAGE, in_period=False, filter_qs="", sort_by="", sort_order=""
    )
    assert _cols(legacy) == 7 and 'colspan="7"' in legacy


def test_attacks_table_severity_chips_and_rule_picker():
    facets = {
        "severities": {"critical": 1200, "high": 3, "medium": 0, "low": 1},
        "rules": [
            {"rule": "r_sqli", "attack_type": "sql_injection", "band": "critical", "hits": 1200},
            {"rule": "credential_fields", "attack_type": "login_attempt", "band": "low", "hits": 1, "label": "Credential capture"},
        ],
    }
    html = _render(
        "attack_types_table.html",
        items=[],
        pagination=PAGE,
        facets=facets,
        severities=["high"],
        rule_filter="credential_fields",
        ts_time_only=None,
        sort_by="timestamp",
        sort_order="desc",
        exclude_terms=[],
    )
    assert "toggleAttacksSeverity('critical')" in html and "1.200" in html
    assert re.search(r'class="facet-chip active" aria-pressed="true"\s+onclick="toggleAttacksSeverity\(\'high\'\)"', html)
    assert re.search(r'value="credential_fields" selected>&#9679; Credential capture \(1\)', html)
    assert "R sqli (1.200)" in html


def test_time_column_forms():
    ts = datetime(2020, 1, 2, 3, 4, 5)
    assert _format_ts(ts, time_only=True) == "03:04:05"
    assert _format_ts(ts, time_only=False) == "2020-01-02 03:04:05"
    assert _format_ts(datetime.now().replace(microsecond=0), time_only=False).count("-") == 2
    assert _format_num(12166543) == "12.166.543"


def test_time_only_when_window_sits_in_one_utc_day():
    now = datetime(2026, 10, 27, 12, 30)
    assert time_only(None) is None
    assert time_only(resolve_period(1, 0, now=now)) is False  # rolling 24h crosses midnight
    assert time_only(resolve_period(7, 0, "2026-10-27T04", now=now)) is True
    assert time_only(resolve_period(30, 0, "2026-10-26T00", now=now)) is True
