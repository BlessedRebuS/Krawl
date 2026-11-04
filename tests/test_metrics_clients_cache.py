"""clients_total is served from a 5-minute cache, not recounted per scrape.

Counting big categories reads most of ip_stats (seconds per scrape on millions
of rows), and Prometheus scrapes every pod every 30s.
"""

import database
import metrics


def _clients():
    for family in metrics.KrawlMetricsCollector().collect():
        if family.name == "krawl_clients_total":
            return {s.labels["category"]: s.value for s in family.samples}


def test_clients_total_counts_once_per_ttl(monkeypatch):
    calls = []

    class Repo:
        def count_by_category(self):
            calls.append(1)
            return {"attacker": 3, "good_crawler": 5, None: 7}

    class Db:
        ip_stats = Repo()

    monkeypatch.setattr(database, "get_database", lambda: Db())
    monkeypatch.setattr(metrics, "_enabled", lambda: True)
    monkeypatch.setattr(metrics, "_clients_cache", (float("-inf"), {}))

    expected = {"attacker": 3, "good_crawler": 5, "bad_crawler": 0, "regular_user": 0}
    assert _clients() == expected
    assert _clients() == expected
    assert len(calls) == 1
