"""The attack-URL signal counts the attack types stored for an IP's requests."""

from datetime import datetime, timedelta

from database import get_database, initialize_database
from models import AccessLog, AttackDetection, IpStats
from tasks import analyze_ips

IP = "192.0.2.30"


def _ip_with(tmp_path, requests):
    """Store IP's requests as (path, attack_types, age_days) and analyse it."""
    initialize_database(str(tmp_path / "an.db"))
    db = get_database()
    s = db.session
    now = datetime.now()
    s.add(
        IpStats(
            ip=IP,
            total_requests=len(requests),
            first_seen=now - timedelta(days=40),
            last_seen=now,
            last_analysis=None,
            need_reevaluation=True,
        )
    )
    for i, (path, attack_types, age_days) in enumerate(requests):
        log = AccessLog(
            ip=IP,
            path=path,
            method="GET",
            user_agent="Mozilla/5.0",
            is_suspicious=bool(attack_types),
            timestamp=now - timedelta(days=age_days, seconds=i),
        )
        s.add(log)
        s.flush()
        for attack_type in attack_types:
            s.add(
                AttackDetection(
                    access_log_id=log.id, attack_type=attack_type, matched_pattern="x"
                )
            )
    s.commit()
    db.close_session()

    analyze_ips.main()

    row = db.session.query(IpStats).filter_by(ip=IP).one()
    return row.analyzed_metrics["attack_url"]


def test_query_only_attack_counts(tmp_path):
    # GET /item?id=1' OR '1'='1 — the path alone shows no attack.
    assert _ip_with(tmp_path, [("/item", ["sql_injection"], 1)]) == ["sql_injection"]


def test_type_without_a_current_rule_counts(tmp_path):
    assert _ip_with(tmp_path, [("/x", ["scanner_probe"], 1)]) == ["scanner_probe"]


def test_repeated_type_counts_once(tmp_path):
    requests = [("/item", ["sql_injection"], 1)] * 3
    assert _ip_with(tmp_path, requests) == ["sql_injection"]


def test_types_are_sorted(tmp_path):
    requests = [("/a", ["xss_attempt"], 1), ("/b", ["command_injection"], 1)]
    assert _ip_with(tmp_path, requests) == ["command_injection", "xss_attempt"]


def test_clean_ip_has_no_attack_url(tmp_path):
    # The old path re-scan would have counted /etc/passwd as path_traversal.
    assert _ip_with(tmp_path, [("/etc/passwd", [], 1), ("/", [], 1)]) == []


def test_detections_outside_window_do_not_count(tmp_path):
    requests = [("/item", ["sql_injection"], 40), ("/", [], 1)]
    assert _ip_with(tmp_path, requests) == []


def test_analyzer_does_not_rescan_paths(tmp_path, monkeypatch):
    def fail():
        raise AssertionError("analyze_ips must not re-scan paths")

    monkeypatch.setattr(analyze_ips, "get_detection", fail, raising=False)

    assert _ip_with(tmp_path, [("/item", ["sql_injection"], 1)]) == ["sql_injection"]
