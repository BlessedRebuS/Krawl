"""The IP Insight scoreboard: per-IP stats, behaviour axes and the page itself."""

from datetime import datetime, timedelta

import pytest
from test_pages_routing import app_client  # noqa: F401

from database import get_database, initialize_database
from ip_overview import (
    behaviour_axes,
    build_ip_overview,
    score_scale,
    template_stats,
)
from models import (
    AccessLog,
    AttackDetection,
    CapturedPayload,
    CredentialAttempt,
    IpStats,
)

IP = "192.0.2.70"


def _log(s, path, method="GET", **fields):
    row = AccessLog(
        ip=IP,
        path=path,
        method=method,
        user_agent="UA",
        timestamp=fields.pop("timestamp", datetime.now()),
        **fields,
    )
    s.add(row)
    s.flush()
    return row


@pytest.fixture
def db(tmp_path):
    initialize_database(str(tmp_path / "o.db"))
    return get_database()


def _attack(s, log, attack_type, rule=None):
    s.add(
        AttackDetection(access_log_id=log.id, attack_type=attack_type, rule_name=rule)
    )


def _seed(s):
    s.add(IpStats(ip=IP, total_requests=100, pruned_total=40))
    bad = _log(s, "/index.php", "POST", is_suspicious=True, referer="http://x/")
    _attack(s, bad, "sql_injection")
    _attack(s, bad, "sql_injection")
    _attack(s, bad, "xss")
    trap = _log(s, "/admin", is_suspicious=True, is_honeypot_trigger=True)
    _log(s, "/backup", is_suspicious=True, is_honeypot_trigger=True)
    _log(s, "/test", timestamp=datetime.now() - timedelta(days=1))
    s.add(CredentialAttempt(ip=IP, path="/login", username="a", password="b"))  # noqa: S106
    s.add(CredentialAttempt(ip=IP, path="/login", username="a", password="b"))  # noqa: S106
    s.add(CredentialAttempt(ip=IP, path="/login", username="c", password="d"))  # noqa: S106
    s.add(
        CapturedPayload(
            access_log_id=trap.id, ip=IP, filename="x.php", size=10, cluster_id=None
        )
    )
    s.commit()


def test_counts(db):
    _seed(db.session)
    o = build_ip_overview(IP, {"total_requests": 100, "pruned_total": 40})
    assert o["total"] == 100
    assert o["bad"] == 3
    assert o["good"] == 97
    assert o["deleted"] == 40
    assert o["honeypot_hits"] == 2
    assert o["honeypot_traps"] == 2
    assert o["credentials"] == 3
    assert o["credentials_unique"] == 2
    assert o["files"] == 1
    assert o["referers"] == 1
    assert o["access_rows"] == 4


def test_attacks_are_ranked_by_count(db):
    _seed(db.session)
    o = build_ip_overview(IP, {"total_requests": 100})
    assert o["attacks"] == 3
    assert [(a["type"], a["count"]) for a in o["attack_types"]] == [
        ("sql_injection", 2),
        ("xss", 1),
    ]
    assert o["attack_types"][0]["share"] == 100
    assert o["attack_types"][1]["share"] == 50


def test_severity_uses_the_rule_then_the_type(db, monkeypatch):
    class Yara:
        rule_details = {
            "sqli": [{"rule": "low_one", "severity": 2}, {"rule": "top", "severity": 9}]
        }

    class Coordinator:
        yara = Yara()

        def attack_type_severity(self, attack_type):
            return 9 if attack_type == "sqli" else 0

    monkeypatch.setattr("detection.loaded_detection", lambda: Coordinator())
    s = db.session
    s.add(IpStats(ip=IP, total_requests=3))
    log = _log(s, "/x", is_suspicious=True)
    _attack(s, log, "sqli", rule="low_one")  # severity 2, from its own rule
    _attack(s, log, "sqli")  # no rule stored: the type's highest, 9
    _attack(s, log, "unknown_type")  # severity 0: left out of the average
    s.commit()
    o = build_ip_overview(IP, {"total_requests": 3})
    assert o["severity_avg"] == 5.5
    assert o["severity_peak"] == 9


def test_no_detections_has_no_severity(db):
    db.session.add(IpStats(ip=IP, total_requests=1))
    db.session.commit()
    o = build_ip_overview(IP, {"total_requests": 1})
    assert o["attacks"] == 0
    assert o["severity_avg"] is None
    assert o["severity_peak"] is None
    assert o["attack_types"] == []


def test_good_never_goes_negative(db):
    # Suspicious rows can outlive a stale counter.
    s = db.session
    s.add(IpStats(ip=IP, total_requests=0))
    _log(s, "/x", is_suspicious=True)
    s.commit()
    assert build_ip_overview(IP, {"total_requests": 0})["good"] == 0


def test_axes_scale_each_metric_to_100():
    axes = behaviour_axes(
        {
            "risky_http_methods": 0.62,
            "robots_violations": 0.18,
            "request_timing_cv": 0.45,
            "different_user_agents": ["a", "b", "c"],
            "attack_url": ["sqli", "xss"],
        },
        evidence=7,
    )
    assert {a["key"]: a["value"] for a in axes} == {
        "risky": 62,
        "robots": 18,
        "timing": 45,
        "agents": 60,
        "attacks": 20,
        "evidence": 60,
    }
    assert len(axes) == 6


def test_axes_cap_at_100_and_tolerate_missing_metrics():
    capped = behaviour_axes(
        {
            "risky_http_methods": 3,
            "request_timing_cv": 9,
            "different_user_agents": list("abcdefgh"),
            "attack_url": list("abcdefghijklmnop"),
        },
        evidence=100_000,
    )
    assert {a["key"]: a["value"] for a in capped} == {
        "risky": 100,
        "robots": 0,
        "timing": 100,
        "agents": 100,
        "attacks": 100,
        "evidence": 100,
    }
    assert all(a["value"] == 0 for a in behaviour_axes({}, evidence=0))
    assert all(a["value"] == 0 for a in behaviour_axes(None, evidence=0))


def _render(stats=None, overview=None):
    from dependencies import get_templates

    stats = {"category": "attacker", "category_history": [], **(stats or {})}
    return (
        get_templates()
        .env.get_template("dashboard/partials/ip_insight.html")
        .render(
            dashboard_path="/d",
            stats=stats,
            overview=overview,
            ip_address=IP,
            is_tracked=False,
        )
    )


def _overview(**fields):
    base = {
        "total": 1284,
        "bad": 412,
        "good": 872,
        "bad_share": 32,
        "deleted": 640,
        "access_rows": 644,
        "honeypot_hits": 23,
        "honeypot_traps": 4,
        "referers": 27,
        "credentials": 14,
        "credentials_unique": 9,
        "files": 3,
        "campaigns": 2,
        "axes": behaviour_axes(
            {
                "risky_http_methods": 0.62,
                "robots_violations": 0.18,
                "request_timing_cv": 0.45,
                "different_user_agents": ["a"],
                "attack_url": ["sqli"],
            },
            evidence=7,
        ),
        "analysed": True,
        "scores": {
            "attacker": 22,
            "regular_user": 8,
            "bad_crawler": 7,
            "good_crawler": 1,
        },
        "attacks": 386,
        "attack_types": [
            {"type": "sql_injection", "count": 142, "share": 100, "band": "critical"},
            {"type": "<img src=x>", "count": 15, "share": 11, "band": None},
        ],
        "severity_avg": 6.4,
        "severity_peak": 9,
        "severity_band": "medium",
        "score_max": 30,
        "severity_counts": {"critical": 142, "high": 0, "medium": 0, "low": 0},
        "rules": [{"rule": "krawl_sqli", "count": 142, "band": "critical"}],
    }
    return {**base, **fields}


def test_page_shows_every_requested_stat():
    html = _render(overview=_overview())
    for expected in (
        "Total requests",
        "872 good · 412 bad",
        "Attacks",
        "Avg severity",
        "peak 9",
        "Requests deleted",
        "Honeypot hits",
        "Credentials",
        "Captured files",
    ):
        assert expected in html
    assert "6,4" in html
    assert "var(--sev-medium)" in html


def test_page_draws_hexagon_and_ranked_bars_not_the_old_charts():
    html = _render(overview=_overview())
    assert html.count('class="ip-hex-pip"') == 6
    assert html.count('class="ip-atk ') == 2
    assert "<canvas" not in html
    assert "generateRadarChart" not in html
    assert "loadAttackTypesChart" not in html


def test_one_segment_is_one_point():
    html = _render(overview=_overview())
    assert html.count('<i class="on">') == 22 + 8 + 7 + 1
    assert html.count("<i></i>") == 4 * 30 - 38


def test_a_score_above_the_scale_fills_the_bar_and_stops():
    html = _render(overview=_overview(scores={"attacker": 500, "good_crawler": 1}))
    assert html.count('<i class="on">') == 31


def test_unscored_attack_type_has_no_band():
    html = _render(overview=_overview())
    assert '<span class="ip-atk-band">critical</span>' in html
    assert '<span class="ip-atk-band">–</span>' in html


def test_zero_value_axes_draw_no_pip():
    axes = behaviour_axes({"risky_http_methods": 0.5}, evidence=0)
    html = _render(overview=_overview(axes=axes))
    assert html.count('class="ip-hex-pip"') == 1


def test_axis_meanings_are_readable_without_hover():
    html = _render(overview=_overview())
    assert "Share of requests under a robots.txt Disallow path" in html
    assert '<details class="ip-hex-help">' in html


def test_static_tiles_add_no_tab_stops():
    assert 'class="tile' in _render(overview=_overview())
    assert 'tabindex="0"' not in _render(overview=_overview())


def test_score_scale_comes_from_the_weights():
    from config import get_config

    weights = get_config().scoring_weights
    expected = max(sum(v.values()) for v in weights.values())
    assert score_scale(weights) == expected


def test_type_severity_and_avg_band(db, monkeypatch):
    class Yara:
        rule_details = {"sqli": [{"rule": "low_one", "severity": 2}]}

    class Coordinator:
        yara = Yara()

        def attack_type_severity(self, attack_type):
            return 2 if attack_type == "sqli" else 0

    monkeypatch.setattr("detection.loaded_detection", lambda: Coordinator())
    s = db.session
    s.add(IpStats(ip=IP, total_requests=2))
    log = _log(s, "/x", is_suspicious=True)
    _attack(s, log, "sqli")
    _attack(s, log, "not_a_rule")
    s.commit()
    o = build_ip_overview(IP, {"total_requests": 2})
    bands = {a["type"]: a["band"] for a in o["attack_types"]}
    assert bands == {"sqli": "low", "not_a_rule": None}
    assert o["severity_band"] == "low"


@pytest.mark.parametrize(
    "key,label",
    [
        ("xss", "XSS"),
        ("ssti", "SSTI"),
        ("log4shell", "Log4Shell"),
        ("nosql_injection", "NoSQL injection"),
    ],
)
def test_attack_label_casing(key, label):
    from dependencies import _attack_label

    assert _attack_label(key) == label


def test_unscored_attack_type_takes_no_severity_hue():
    html = _render(overview=_overview())
    scored, unscored = html.split('class="ip-atk ')[1:3]
    assert scored.startswith("atk-sev-")
    assert unscored.startswith("is-unscored")


def test_long_axis_label_wraps_to_two_lines():
    html = _render(overview=_overview())
    assert ">Attack</tspan>" in html
    assert ">variety</tspan>" in html


def test_unanalysed_ip_has_no_hexagon():
    html = _render(overview=_overview(analysed=False, scores={}))
    assert "Not analysed yet" in html
    assert "ip-hex-pip" not in html


def test_attacker_controlled_values_are_escaped():
    html = _render(
        {"city": "<script>alert(1)</script>", "asn_org": "<b>x</b>"},
        overview=_overview(),
    )
    assert "<script>alert(1)</script>" not in html
    assert "<b>x</b>" not in html
    assert "<img src=x>" not in html


def test_top_panes_are_details_behaviour_attack_types_timeline():
    html = _render(
        {"category_history": [{"new_category": "attacker", "timestamp": "2026-11-05"}]},
        overview=_overview(),
    )
    order = [
        html.index(f"<h2>{name}")
        for name in ("Details", "Behaviour", "Attack types", "Timeline")
    ]
    assert order == sorted(order)
    assert ">Latest requests<" not in html


def test_details_shows_facts_and_map_on_load():
    html = _render(
        {"latitude": 35.68, "longitude": 139.69, "first_seen": "2026-11-01T10:00:00"},
        overview=_overview(),
    )
    assert 'id="insight-ip-map"' in html
    assert "setTimeout(initMap" in html
    assert ">First Seen<" in html
    assert ">Total Requests<" not in html  # the tile already shows it


def test_no_location_means_no_map():
    assert "-ip-map" not in _render(overview=_overview()).split("<script>")[0]


def test_timeline_empty_state():
    assert "No category changes recorded." in _render(overview=_overview())


def test_unknown_ip_page_renders(app_client):  # noqa: F811
    from config import get_config

    path = get_config().dashboard_secret_path.lstrip("/")
    response = app_client.get(f"/{path}/htmx/ip-insight/203.0.113.250")
    assert response.status_code == 200
    assert "Total requests" in response.text


def test_template_stats_keep_what_the_page_reads():
    prepared = template_stats(
        {
            "total_requests": 3,
            "list_on": {"feed__x": "1"},
            "category_history": [{"new_category": "attacker"}],
            "analyzed_metrics": {"a": 1},
        }
    )
    assert prepared["blocklist_memberships"] == ["feed__x"]
    assert prepared["category_history"] == [{"new_category": "attacker"}]
    assert "analyzed_metrics" not in prepared and "list_on" not in prepared


def test_decimal_severity_is_left_out_of_the_tile_count_up():
    # The count-up strips non-digits, which would turn 6,4 into 64.
    from pathlib import Path

    js = Path("src/templates/static/js/dashboard.js").read_text()
    assert "'.tile-value:not([data-static])'" in js
    assert '<span class="tile-value" data-static>6,4</span>' in _render(
        overview=_overview()
    )


def test_two_tabs_requests_then_evidence():
    html = _render(overview=_overview())
    assert html.count('<button type="button" role="tab"') == 2
    assert html.index('id="insight-tab-requests"') < html.index(
        'id="insight-tab-evidence"'
    )


def test_tab_counts():
    html = _render(
        overview=_overview(access_rows=644, credentials=14, files=3, referers=27)
    )
    requests, evidence = html.split('class="ip-tab-count">')[1:3]
    assert requests.startswith("644")
    assert evidence.startswith("44")


def test_evidence_tab_stacks_its_three_sections():
    html = _render(overview=_overview(credentials=14, files=3, referers=27))
    evidence = html[html.index('id="insight-panel-evidence"') :]
    order = [
        evidence.index(f">{name}") for name in ("Credentials", "Files", "Referers")
    ]
    assert order == sorted(order)
    for url in ("/htmx/credentials?", "/htmx/ip-payloads?", "/htmx/ip-referers?"):
        assert url in evidence


def test_only_access_history_loads_right_away():
    html = _render(overview=_overview())
    assert html.count('hx-trigger="load"') == 1
    box = html.split('hx-trigger="load"')[0].rsplit("<div", 1)[1]
    assert "/htmx/access-logs?page=1" in box
    assert html.count(' hx-trigger="krawl-open once"') == 3


def test_filter_bar_has_the_detected_attacks_controls():
    html = _render(overview=_overview())
    assert html.count('class="term-mode"') == 2
    for label in ("All requests", "Only attacks", ">Only<", ">Hide<", "Any method"):
        assert label in html
    assert 'class="panel-filter-input"' in html


def test_attack_only_filters_are_scoped_to_this_ip():
    html = _render(overview=_overview())
    assert '<option value="sql_injection">SQL injection (142)</option>' in html
    assert 'value="krawl_sqli"' in html
    assert 'data-severity="critical"' in html
    assert '<span class="facet-count">142</span>' in html
    assert "data-attacks-only" in html


def test_empty_severity_chip_is_disabled():
    html = _render(overview=_overview())
    chip = html[html.index('data-severity="high"') :]
    assert "disabled" in chip[: chip.index(">")]


def test_only_attacks_switch_is_disabled_without_attacks():
    html = _render(
        overview=_overview(
            attacks=0,
            attack_types=[],
            severity_avg=None,
            severity_peak=None,
            severity_band=None,
            rules=[],
            severity_counts={"critical": 0, "high": 0, "medium": 0, "low": 0},
        )
    )
    switch = html[html.index('data-view="attacks"') :]
    assert "disabled" in switch[: switch.index(">")]
    assert "No attacks detected for this IP." in html


def test_overview_counts_severity_and_rules(db, monkeypatch):
    class Yara:
        rule_details = {"sqli": [{"rule": "r1", "severity": 9}]}

    class Coordinator:
        yara = Yara()

        def attack_type_severity(self, attack_type):
            return 9 if attack_type == "sqli" else 0

    monkeypatch.setattr("detection.loaded_detection", lambda: Coordinator())
    s = db.session
    s.add(IpStats(ip=IP, total_requests=3))
    log = _log(s, "/x", is_suspicious=True)
    _attack(s, log, "sqli", rule="r1")
    _attack(s, log, "sqli", rule="r1")
    _attack(s, log, "other")
    s.commit()
    o = build_ip_overview(IP, {"total_requests": 3})
    assert o["severity_counts"] == {"critical": 2, "high": 0, "medium": 0, "low": 0}
    assert o["rules"] == [{"rule": "r1", "count": 2, "band": "critical"}]


def test_access_logs_filter_by_text_and_method(db):
    s = db.session
    s.add(IpStats(ip=IP, total_requests=3))
    _log(s, "/admin", "POST")
    _log(s, "/admin/x", "GET")
    _log(s, "/test", "GET")
    s.commit()
    get = db.access_logs.get_paginated
    paths = lambda **k: sorted(r["path"] for r in get(ip_filter=IP, **k)["access_logs"])
    assert paths(search="admin") == ["/admin", "/admin/x"]
    assert paths(exclude=["admin"]) == ["/test"]
    assert paths(method_filter="POST") == ["/admin"]
    assert get(ip_filter=IP, search="admin")["pagination"]["total_logs"] == 2


def test_access_logs_route_keeps_filters_in_its_pager(app_client):  # noqa: F811
    from config import get_config

    path = get_config().dashboard_secret_path.lstrip("/")
    html = app_client.get(
        f"/{path}/htmx/access-logs?ip_filter=203.0.113.9&search=adm&exclude=wp&method_filter=GET"
    ).text
    assert "search=adm" in html
    assert "exclude=wp" in html
    assert "method_filter=GET" in html
    assert "<th>Examples</th>" not in html


def test_embedded_attacks_table_has_no_global_handlers(app_client):  # noqa: F811
    from config import get_config

    path = get_config().dashboard_secret_path.lstrip("/")
    html = app_client.get(
        f"/{path}/htmx/attacks?ip_filter=203.0.113.9&embed=1&search=adm&exclude=wp"
    ).text
    assert "removeSearchTerm" not in html
    assert "removeExcludeTerm" not in html
    assert "embed=1" in html


def test_global_attacks_table_keeps_its_pills(app_client):  # noqa: F811
    from config import get_config

    path = get_config().dashboard_secret_path.lstrip("/")
    html = app_client.get(f"/{path}/htmx/attacks?search=adm&exclude=wp").text
    assert "removeSearchTerm" in html
    assert "removeExcludeTerm" in html


def _history(n):
    return [
        {
            "new_category": "attacker",
            "old_category": "bad_crawler",
            "timestamp": f"2026-10-{i + 1:02d}T10:00:00",
        }
        for i in range(n)
    ]


def test_timeline_lists_newest_first_and_counts_changes():
    html = _render({"category_history": _history(20)}, overview=_overview())
    assert html.index("2026-10-20") < html.index("2026-10-01")
    assert '<span class="ip-tab-count">20</span>' in html


def test_long_detail_values_keep_their_full_text_in_a_title():
    long_isp = "International Business Machines Corporation" * 2
    html = _render({"isp": long_isp, "reverse": None}, overview=_overview())
    assert f'title="{long_isp}"' in html


def test_the_page_waits_for_the_deferred_filter_script():
    html = _render(overview=_overview())
    assert "document.addEventListener('DOMContentLoaded', boot)" in html


def test_attacks_with_no_scored_rule_do_not_say_no_attacks():
    html = _render(
        overview=_overview(severity_avg=None, severity_peak=None, severity_band=None)
    )
    assert "not scored" in html
    assert ">no attacks<" not in html


def test_hexagon_keeps_a_small_even_shape_at_zero():
    html = _render(overview=_overview(axes=behaviour_axes({}, evidence=0)))
    assert "0.0,-13.8" in html  # the top axis sits at the floor, not the centre
    assert 'class="ip-hex-pip"' not in html


def test_full_axis_still_reaches_the_rim():
    html = _render(
        overview=_overview(axes=behaviour_axes({"risky_http_methods": 1}, evidence=0))
    )
    fill = html[html.index('class="ip-hex-fill"') :]
    assert "0.0,-92.0" in fill[: fill.index("/>")]


def test_printed_values_stay_real_at_zero():
    html = _render(overview=_overview(axes=behaviour_axes({}, evidence=0)))
    assert html.count('text-anchor="middle">0</text>') == 2


def test_panes_compact_when_there_are_no_attacks():
    quiet = _render(
        overview=_overview(
            attacks=0,
            attack_types=[],
            severity_avg=None,
            severity_peak=None,
            severity_band=None,
        )
    )
    assert 'class="ip-panes no-attacks"' in quiet
    assert 'class="ip-panes"' in _render(overview=_overview())
