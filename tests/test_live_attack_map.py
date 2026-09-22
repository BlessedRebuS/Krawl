"""Regression coverage for the lightweight live-map attacker query."""

from datetime import datetime, timedelta
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from database.ip_stats import IpStatsRepo
from models import Base, IpStats

ROOT = Path(__file__).resolve().parent.parent


class _FakeDb:
    def __init__(self, session):
        self._session = session

    @property
    def session(self):
        return self._session

    def close_session(self):
        pass


def test_live_attackers_are_geolocated_attackers_newest_first():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    now = datetime.now()
    session.add_all(
        [
            IpStats(
                ip="203.0.113.10",
                category="attacker",
                total_requests=4,
                last_seen=now,
                latitude=52.52,
                longitude=13.405,
                country_code="DE",
                city="Berlin",
            ),
            IpStats(
                ip="203.0.113.11",
                category="attacker",
                last_seen=now - timedelta(seconds=5),
                latitude=40.71,
                longitude=-74.0,
            ),
            # Pending GeoIP must not enter the baseline. Once enriched, the
            # client sees it as new and pulses it on the next poll.
            IpStats(ip="203.0.113.12", category="attacker", last_seen=now),
            IpStats(
                ip="203.0.113.13",
                category="regular_user",
                last_seen=now,
                latitude=51.5,
                longitude=-0.12,
            ),
            # A direct honeypot hit must not wait for the once-a-minute
            # analyzer to assign its final category.
            IpStats(
                ip="203.0.113.14",
                category=None,
                has_triggered_honeypot=True,
                last_seen=now - timedelta(seconds=2),
                latitude=41.9,
                longitude=12.5,
            ),
        ]
    )
    session.commit()

    result = IpStatsRepo(_FakeDb(session)).get_live_attackers(limit=100)

    assert [row["ip"] for row in result] == [
        "203.0.113.10",
        "203.0.113.14",
        "203.0.113.11",
    ]
    assert result[0]["city"] == "Berlin"
    assert result[0]["last_seen"] == now.isoformat()


def test_live_attack_limit_is_applied():
    engine = create_engine("sqlite:///:memory:")
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    now = datetime.now()
    session.add_all(
        [
            IpStats(
                ip=f"198.51.100.{index}",
                category="attacker",
                last_seen=now - timedelta(seconds=index),
                latitude=float(index),
                longitude=float(index),
            )
            for index in range(3)
        ]
    )
    session.commit()

    result = IpStatsRepo(_FakeDb(session)).get_live_attackers(limit=2)
    assert len(result) == 2


def test_live_suspicious_refresh_rejects_deception_fallbacks():
    script = (ROOT / "src/templates/static/js/map.js").read_text()
    fragment = (
        ROOT / "src/templates/jinja2/dashboard/partials/suspicious_expand_table.html"
    ).read_text()

    assert "/htmx/suspicious?page=1&page_size=10&live=1" in script
    assert "/htmx/suspicious/live" not in script
    assert "data-suspicious-fragment" in script
    assert 'data-suspicious-fragment="true"' in fragment


def test_expanded_suspicious_view_has_shared_live_toggle():
    overlay = (
        ROOT / "src/templates/jinja2/dashboard/partials/expand_overlay.html"
    ).read_text()
    assert 'id="expanded-suspicious-live-toggle"' in overlay
    assert 'class="dashboard-live-toggle"' in overlay
    assert 'onclick="toggleMapLiveMode()"' in overlay


def test_live_suspicious_arrivals_are_animated_in_both_tables():
    script = (ROOT / "src/templates/static/js/map.js").read_text()
    styles = (ROOT / "src/templates/static/css/dashboard.css").read_text()
    expanded = (
        ROOT / "src/templates/jinja2/dashboard/partials/suspicious_expand_table.html"
    ).read_text()

    assert "_scheduleSuspiciousArrival(target, previousIds)" in script
    assert "_scheduleSuspiciousArrival(overlayTarget, overlayPreviousIds)" in script
    assert "requestAnimationFrame(() => {" in script
    assert "suspicious-live-row-enter" in styles
    assert "--arrival-index" in styles
    assert 'class="ip-row recent-suspicious-row"' in expanded
    assert "data-log-id=" in expanded
