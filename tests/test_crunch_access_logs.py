import pytest

from tasks.crunch_access_logs import path_template


@pytest.mark.parametrize(
    "path,expected",
    [
        # Krawl trap links (homepage random links)
        ("/Gw2JM958", "/{link}"),
        ("/A0ZUzQqbrhyDm", "/{link}"),
        ("/kpjud", "/kpjud"),  # all lowercase: indistinguishable from a word
        ("/Rsxmhx", "/Rsxmhx"),  # only a leading capital
        # Real paths stay literal
        ("/login", "/login"),
        ("/admin", "/admin"),
        ("/dashboard", "/dashboard"),
        ("/Jenkinsfile", "/Jenkinsfile"),
        ("/wp-login.php", "/wp-login.php"),
        ("/.env", "/.env"),
        ("/", "/"),
        # Segment rules
        ("/post/1234", "/post/{num}"),
        ("/u/550e8400-e29b-41d4-a716-446655440000", "/u/{uuid}"),
        ("/c/9f86d081a2", "/c/{hex}"),
        ("/f/aB3xK9pQ.js", "/f/{rand}.js"),
        ("/x/Zk3Qp9Lm2Vb", "/x/{rand}"),
        # Readable names with a digit stay literal (snake_case, long lowercase runs)
        ("/wp2shell_opt_woocommerce_stripe_settings", "/wp2shell_opt_woocommerce_stripe_settings"),
        ("/plugin2woocommerce", "/plugin2woocommerce"),
        ("/blog/hello-world-2", "/blog/hello-world-2"),
        ("/@fs/home/ec2-user/.aws/credentials", "/@fs/home/ec2-user/.aws/credentials"),
        ("/css/style.css", "/css/style.css"),
        # Query strings: keys kept, values dropped
        ("/search?q=foo&page=2", "/search?q={v}&page={v}"),
        ("/Gw2JM958?x=1", "/{link}?x={v}"),
        ("/p?flag", "/p?flag"),
        # Too long for a trap link, so the segment rule applies instead
        ("/Gw2JM958Gw2JM958X", "/{rand}"),
    ],
)
def test_path_template(path, expected):
    assert path_template(path) == expected


@pytest.mark.parametrize(
    "path", ["/Gw2JM958", "/f/aB3xK9pQ.js", "/search?q=foo", "/post/12/c/9f86d081a2"]
)
def test_path_template_is_idempotent(path):
    once = path_template(path)
    assert path_template(once) == once


from datetime import datetime, timedelta

from database import get_database, initialize_database
from models import AccessLog, AttackDetection, IpStats, RequestAsset
from tasks import crunch_access_logs

IP = "192.0.2.50"


def _setup(tmp_path, last_seen_days=10, total_requests=100):
    initialize_database(str(tmp_path / "crunch.db"))
    db = get_database()
    when = datetime.now() - timedelta(days=last_seen_days)
    db.session.add(
        IpStats(ip=IP, total_requests=total_requests, first_seen=when, last_seen=when)
    )
    db.session.commit()
    return db, when


def _log(db, path, when, **kw):
    row = AccessLog(
        ip=IP,
        path=path,
        method=kw.pop("method", "GET"),
        user_agent=kw.pop("ua", "ua"),
        timestamp=when,
        **kw,
    )
    db.session.add(row)
    db.session.flush()
    return row


def _rows(db):
    db.close_session()
    return db.session.query(AccessLog).order_by(AccessLog.id).all()


def test_merges_trap_links_and_keeps_literals(tmp_path):
    db, when = _setup(tmp_path)
    first_id = _log(db, "/Gw2JM958", when).id
    _log(db, "/A0ZUzQqbrhyDm", when + timedelta(seconds=1), ua="other-ua")
    _log(db, "/WQPjRhEvmPVmm", when + timedelta(seconds=2))
    _log(db, "/X9aaaaaa", when + timedelta(seconds=3))
    _log(db, "/test", when)
    db.session.commit()

    crunch_access_logs.main()

    rows = _rows(db)
    # The other-ua row is its own group of one (user agent is part of the
    # key), so it keeps its real path.
    assert [(r.path, r.hit_count, r.user_agent) for r in rows] == [
        ("/{link}", 3, "ua"),
        ("/A0ZUzQqbrhyDm", 1, "other-ua"),
        ("/test", 1, "ua"),
    ]
    keeper = rows[0]
    assert keeper.id == first_id
    assert keeper.timestamp == when + timedelta(seconds=3)
    assert keeper.path_samples == "/Gw2JM958, /WQPjRhEvmPVmm, /X9aaaaaa"
    assert rows[1].path_samples is None
    assert rows[2].path_samples is None
    assert db.session.get(IpStats, IP).crunched_at is not None


def test_never_touches_evidence_suspicious_or_honeypot(tmp_path):
    db, when = _setup(tmp_path)
    _log(db, "/Gw2JM958", when)
    _log(db, "/A0ZUzQqbrh", when)
    sus = _log(db, "/B1ZUzQqbrh", when, is_suspicious=True)
    db.session.add(AttackDetection(access_log_id=sus.id, attack_type="x"))
    _log(db, "/C2ZUzQqbrh", when, is_honeypot_trigger=True)
    asset = _log(db, "/D3ZUzQqbrh", when)
    db.session.add(RequestAsset(access_log_id=asset.id, url="https://e.example/p"))
    db.session.commit()

    crunch_access_logs.main()

    paths = [r.path for r in _rows(db)]
    assert paths == ["/{link}", "/B1ZUzQqbrh", "/C2ZUzQqbrh", "/D3ZUzQqbrh"]
    assert db.session.query(AttackDetection).count() == 1


def test_skips_active_ip(tmp_path):
    db, when = _setup(tmp_path, last_seen_days=1)
    _log(db, "/Gw2JM958", when)
    _log(db, "/A0ZUzQqbrh", when)
    db.session.commit()

    crunch_access_logs.main()

    assert len(_rows(db)) == 2


def test_second_run_changes_nothing_and_new_activity_recrunches(tmp_path):
    db, when = _setup(tmp_path)
    for i in range(5):
        _log(db, f"/Gw2JM95{i}", when + timedelta(seconds=i))
    db.session.commit()
    crunch_access_logs.main()
    snapshot = [(r.id, r.path, r.hit_count, r.path_samples) for r in _rows(db)]

    crunch_access_logs.main()
    assert [(r.id, r.path, r.hit_count, r.path_samples) for r in _rows(db)] == snapshot

    # New activity after the crunch makes the IP eligible again once it is idle.
    later = datetime.now() - timedelta(days=8)
    _log(db, "/Zz9yyyyy", later)
    stats = db.session.get(IpStats, IP)
    stats.crunched_at = later - timedelta(seconds=1)
    stats.last_seen = later
    db.session.commit()
    crunch_access_logs.main()
    rows = _rows(db)
    assert [(r.path, r.hit_count) for r in rows] == [("/{link}", 6)]
    assert rows[0].path_samples.count(", ") == 2  # still capped at 3


def test_long_paths_samples_truncated(tmp_path):
    db, when = _setup(tmp_path)
    long_a = "/q?" + "a=" + "x" * 1500
    long_b = "/q?" + "a=" + "y" * 1500
    _log(db, long_a, when)
    _log(db, long_b, when)
    db.session.commit()

    crunch_access_logs.main()

    rows = _rows(db)
    assert [(r.path, r.hit_count) for r in rows] == [("/q?a={v}", 2)]
    assert len(rows[0].path_samples) <= 2048


def test_access_table_shows_count_and_samples():
    from dependencies import get_templates

    env = get_templates().env  # the app's env, with every custom filter registered
    html = env.get_template("dashboard/partials/access_by_ip_table.html").render(
        dashboard_path="/d",
        items=[
            {
                "id": 1,
                "ip": IP,
                "path": "/{link}",
                "user_agent": "ua",
                "method": "GET",
                "is_suspicious": False,
                "is_honeypot_trigger": False,
                "timestamp": "2026-10-01T00:00:00",
                "attack_types": [],
                "hit_count": 4,
                "path_samples": "/Gw2JM958, /A0ZUzQqbrhyDm",
            }
        ],
        pagination={"page": 1, "page_size": 25, "total": 1, "total_pages": 1},
        sort_by="timestamp",
        sort_order="desc",
        ip_filter=IP,
    )
    assert "/{link} ×4" in html
    assert "access-row-normal" in html  # crunched rows look like normal rows
    assert 'class="path-truncated path-crunched"' in html  # lighter blue path
    assert '<td class="examples-cell">/Gw2JM958, /A0ZUzQqbrhyDm</td>' in html
    assert "<th>Examples</th>" in html
    assert "<th>Method</th>" in html
    assert '<span class="method-badge method-get">GET</span>' in html


def test_crunched_at_migration_type_is_valid_on_postgres():
    # PostgreSQL has no DATETIME type; the ALTER would fail and every ip_stats
    # query would then hit a missing column on upgraded installs.
    from migrations.runner import COLUMNS

    types = {(t, c): ty for t, c, ty in COLUMNS}
    assert types[("ip_stats", "crunched_at")] == "TIMESTAMP"


def test_template_longer_than_path_column_stays_literal(tmp_path):
    db, when = _setup(tmp_path)
    a = "/" + "1/" * 700
    b = "/" + "2/" * 700
    _log(db, a, when)
    _log(db, b, when)
    db.session.commit()

    crunch_access_logs.main()

    assert sorted(r.path for r in _rows(db)) == sorted([a, b])
    assert db.session.get(IpStats, IP).crunched_at is not None


def test_user_agents_are_kept_apart(tmp_path):
    # analyze-ips counts distinct user agents per IP; merging them away would
    # drop the different_user_agents signal on re-evaluation.
    db, when = _setup(tmp_path)
    _log(db, "/Gw2JM958", when, ua="ua-a")
    _log(db, "/A0ZUzQqbrh", when, ua="ua-a")
    _log(db, "/B1ZUzQqbrh", when, ua="ua-b")
    _log(db, "/C2ZUzQqbrh", when, ua="ua-b")
    db.session.commit()

    crunch_access_logs.main()

    assert sorted((r.user_agent, r.hit_count) for r in _rows(db)) == [
        ("ua-a", 2),
        ("ua-b", 2),
    ]


def test_robots_violating_paths_stay_literal(tmp_path):
    # /info is a Disallow prefix: templating /infoX9a2bc to /{link} would hide
    # the violation from analyze-ips.
    db, when = _setup(tmp_path)
    _log(db, "/infoX9a2bc", when)
    _log(db, "/infoY8b3cd", when)
    db.session.commit()

    crunch_access_logs.main()

    assert sorted(r.path for r in _rows(db)) == ["/infoX9a2bc", "/infoY8b3cd"]


def test_access_table_hides_examples_that_repeat_the_path():
    from dependencies import get_templates

    html = (
        get_templates()
        .env.get_template("dashboard/partials/access_by_ip_table.html")
        .render(
            dashboard_path="/d",
            items=[
                {"id": 1, "ip": IP, "path": "/sitemap.xml", "user_agent": "ua",
                 "method": "GET", "is_suspicious": False,
                 "is_honeypot_trigger": False, "timestamp": "2026-10-01T00:00:00",
                 "attack_types": [], "hit_count": 10, "path_samples": "/sitemap.xml"},
                {"id": 2, "ip": IP, "path": "/test", "user_agent": "ua",
                 "method": "GET", "is_suspicious": False,
                 "is_honeypot_trigger": False, "timestamp": "2026-10-01T00:00:00",
                 "attack_types": [], "hit_count": 1, "path_samples": None},
            ],
            pagination={"page": 1, "page_size": 25, "total": 2, "total_pages": 1},
            sort_by="timestamp", sort_order="desc", ip_filter=IP,
        )
    )
    assert "/sitemap.xml ×10" in html
    assert html.count('<td class="examples-cell"></td>') == 2


def test_single_rows_are_not_rewritten(tmp_path):
    # A group of one saves no row; rewriting it would only cost an UPDATE
    # and hide the real path.
    db, when = _setup(tmp_path)
    _log(db, "/Gw2JM958", when)
    _log(db, "/wp-login.php", when)
    db.session.commit()

    crunch_access_logs.main()

    rows = _rows(db)
    assert sorted((r.path, r.hit_count, r.path_samples) for r in rows) == [
        ("/Gw2JM958", 1, None),
        ("/wp-login.php", 1, None),
    ]
    assert db.session.get(IpStats, IP).crunched_at is not None


def test_ip_with_a_single_request_is_never_selected(tmp_path):
    # One request means one row: nothing can merge, so it is not worth a slot.
    db, when = _setup(tmp_path, total_requests=1)
    _log(db, "/Gw2JM958", when)
    db.session.commit()

    crunch_access_logs.main()

    _rows(db)
    assert db.session.get(IpStats, IP).crunched_at is None


def test_most_recently_idle_ips_go_first(tmp_path, monkeypatch):
    # Retention purges the oldest idle rows soon anyway; crunching the most
    # recently idle IPs first keeps the savings longer.
    from config import get_config

    db, when = _setup(tmp_path, last_seen_days=25)
    recent = datetime.now() - timedelta(days=9)
    db.session.add(
        IpStats(ip="192.0.2.51", total_requests=5, first_seen=recent, last_seen=recent)
    )
    db.session.commit()
    monkeypatch.setattr(get_config(), "tasks_crunch_ips_batch", 1)

    crunch_access_logs.main()

    db.close_session()
    assert db.session.get(IpStats, "192.0.2.51").crunched_at is not None
    assert db.session.get(IpStats, IP).crunched_at is None
