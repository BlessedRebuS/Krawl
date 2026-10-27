"""Settings that used to live in wordlists.json are read from config.yaml."""

from datetime import datetime, timedelta

import pytest

PROXY_HEADERS = ["CF-Connecting-IP", "X-Forwarded-For", "X-Real-IP"]
SERVER_HEADERS = [
    "Apache/2.4.41 (Ubuntu)",
    "nginx/1.18.0",
    "Microsoft-IIS/10.0",
    "cloudflare",
    "AmazonS3",
    "gunicorn/20.1.0",
]
USERNAME_FIELDS = ["username", "user", "login", "email", "log", "userid", "account"]
PASSWORD_FIELDS = ["password", "pass", "passwd", "pwd", "passphrase"]
ERROR_CODES = [400, 401, 403, 404, 500, 502, 503]
SCORING_WEIGHTS = {
    "attacker": {
        "risky_http_methods": 6,
        "robots_violations": 4,
        "uneven_request_timing": 3,
        "different_user_agents": 2,
        "attack_url": 15,
    },
    "good_crawler": {
        "risky_http_methods": 1,
        "robots_violations": 0,
        "uneven_request_timing": 0,
        "different_user_agents": 0,
        "attack_url": 0,
    },
    "bad_crawler": {
        "risky_http_methods": 2,
        "robots_violations": 6,
        "uneven_request_timing": 0,
        "different_user_agents": 6,
        "attack_url": 4,
    },
    "regular_user": {
        "risky_http_methods": 0,
        "robots_violations": 0,
        "uneven_request_timing": 8,
        "different_user_agents": 3,
        "attack_url": 0,
    },
}


def _load(tmp_path, monkeypatch, text):
    from config import Config

    config_file = tmp_path / "config.yaml"
    config_file.write_text(text, encoding="utf-8")
    monkeypatch.setenv("CONFIG_LOCATION", str(config_file))
    return Config.from_yaml()


def test_defaults_match_the_old_wordlist():
    from config import Config

    config = Config()
    assert config.proxy_headers == PROXY_HEADERS
    assert config.server_headers == SERVER_HEADERS
    assert config.credential_username_fields == USERNAME_FIELDS
    assert config.credential_password_fields == PASSWORD_FIELDS
    assert config.error_codes == ERROR_CODES
    assert config.scoring_weights == SCORING_WEIGHTS


def test_settings_read_from_yaml(tmp_path, monkeypatch):
    weights = {
        category: dict.fromkeys(SCORING_WEIGHTS["attacker"], 1)
        for category in SCORING_WEIGHTS
    }
    config = _load(
        tmp_path,
        monkeypatch,
        f"""
server:
  proxy_headers: [X-Real-IP]
  server_headers: [Caddy]
credentials:
  username_fields: [acct]
  password_fields: [secret]
behavior:
  error_codes: [418]
analyzer:
  scoring_weights: {weights}
""",
    )

    assert config.proxy_headers == ["X-Real-IP"]
    assert config.server_headers == ["Caddy"]
    assert config.credential_username_fields == ["acct"]
    assert config.credential_password_fields == ["secret"]
    assert config.error_codes == [418]
    assert config.scoring_weights == weights


def test_custom_proxy_header_sets_client_ip(monkeypatch):
    import config as config_module
    from dependencies import get_client_ip_from_scope

    config = config_module.Config(proxy_headers=["X-Test-IP"])
    monkeypatch.setattr(config_module, "_config_instance", config)
    scope = {
        "headers": [
            (b"x-forwarded-for", b"198.51.100.1"),
            (b"x-test-ip", b"203.0.113.9"),
        ],
        "client": ("127.0.0.1", 1),
    }

    assert get_client_ip_from_scope(scope) == "203.0.113.9"
    config.proxy_headers = ["X-Missing"]
    assert get_client_ip_from_scope(scope) == "127.0.0.1"


def test_custom_credential_fields_are_captured(monkeypatch):
    import config as config_module
    from tracker import AccessTracker

    monkeypatch.setattr(
        config_module,
        "_config_instance",
        config_module.Config(
            credential_username_fields=["acct"], credential_password_fields=["secret"]
        ),
    )

    parse = AccessTracker.parse_credentials
    assert parse(None, "acct=bob&secret=x") == ("bob", "x")
    assert parse(None, "username=bob&password=x") == (None, None)


def test_env_overrides_proxy_headers(monkeypatch):
    from config import Config, override_config_from_env

    monkeypatch.setenv("KRAWL_PROXY_HEADERS", "X-Real-IP, X-Forwarded-For")
    config = Config()
    override_config_from_env(config)

    assert config.proxy_headers == ["X-Real-IP", "X-Forwarded-For"]


@pytest.mark.parametrize(
    "text",
    [
        "credentials:\n  username_fields: []\n",
        "credentials:\n  password_fields: []\n",
        "server:\n  proxy_headers: []\n",
        "behavior:\n  error_codes: [99]\n",
        "analyzer:\n  scoring_weights: {attacker: {}, good_crawler: {}, bad_crawler: {}}\n",
    ],
)
def test_invalid_settings_fail_startup(tmp_path, monkeypatch, text):
    with pytest.raises(SystemExit):
        _load(tmp_path, monkeypatch, text)


def test_analyzer_uses_configured_weights(tmp_path, monkeypatch):
    import config as config_module
    from database import get_database, initialize_database
    from models import AccessLog, IpStats
    from tasks import analyze_ips

    weights = {
        category: dict.fromkeys(SCORING_WEIGHTS["attacker"], 0)
        for category in SCORING_WEIGHTS
    }
    # Half the requests are POSTs, which flags risky methods for attacker and
    # bad_crawler; default weights pick attacker, these pick bad_crawler.
    weights["bad_crawler"]["risky_http_methods"] = 100
    config = config_module.Config(scoring_weights=weights)
    monkeypatch.setattr(config_module, "_config_instance", config)

    initialize_database(str(tmp_path / "an.db"))
    db = get_database()
    base = datetime.now() - timedelta(days=8)
    db.session.add(
        IpStats(
            ip="192.0.2.20",
            total_requests=20,
            first_seen=base,
            last_seen=base,
            last_analysis=None,
            need_reevaluation=True,
        )
    )
    for i in range(10):
        for method in ("GET", "POST"):
            db.session.add(
                AccessLog(
                    ip="192.0.2.20",
                    path=f"/form{i}",
                    method=method,
                    user_agent="Mozilla/5.0",
                    timestamp=base + timedelta(seconds=i),
                )
            )
    db.session.commit()
    db.close_session()

    analyze_ips.main()

    row = db.session.query(IpStats).filter_by(ip="192.0.2.20").one()
    assert row.category == "bad_crawler"


@pytest.mark.parametrize(
    "env",
    [
        "KRAWL_PROXY_HEADERS",
        "KRAWL_SERVER_HEADERS",
        "KRAWL_CREDENTIAL_USERNAME_FIELDS",
        "KRAWL_CREDENTIAL_PASSWORD_FIELDS",
    ],
)
def test_empty_env_override_fails_startup(monkeypatch, env):
    from config import Config, override_config_from_env

    monkeypatch.setenv(env, "")
    with pytest.raises(SystemExit):
        override_config_from_env(Config())
