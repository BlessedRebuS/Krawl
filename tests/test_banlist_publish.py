#!/usr/bin/env python3

"""One pod fetches the external banlists; the rest adopt what it published.

Without this, N pods fetch every configured URL every hour and end up with
different lists depending on when each fetch landed and which sources failed
for which pod.

Usage: python tests/test_banlist_publish.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

import banlist_sync
import dashboard_cache


class FakeRedis:
    def __init__(self):
        self.store = {}

    def setex(self, key, ttl, value):
        self.store[key] = value
        return True

    def get(self, key):
        return self.store.get(key)


def use_scalable():
    redis_client = FakeRedis()
    dashboard_cache._backend = "scalable"
    dashboard_cache._redis_client = redis_client
    return redis_client


def seed_leader_state(ips, sources):
    banlist_sync._global_banlist = frozenset(ips)
    banlist_sync._banlist_sources.clear()
    banlist_sync._banlist_sources.extend(sources)


def clear_follower_state():
    banlist_sync._global_banlist = frozenset()
    banlist_sync._banlist_sources.clear()


def test_publish_then_adopt_round_trips():
    use_scalable()
    sources = [{"url": "https://example.test/list.txt", "status": "ok", "count": 2}]
    seed_leader_state({"1.2.3.4", "5.6.7.8"}, sources)

    assert banlist_sync.publish(10800) is True

    clear_follower_state()
    assert banlist_sync.load_published() is True
    assert banlist_sync.get_global_banlist() == frozenset({"1.2.3.4", "5.6.7.8"})
    assert banlist_sync.get_banlist_sources() == sources


def test_adopted_list_answers_the_membership_check():
    """The hot path reads the same frozenset, so adoption must feed it."""
    use_scalable()
    seed_leader_state({"9.9.9.9"}, [])
    banlist_sync.publish(10800)

    clear_follower_state()
    assert banlist_sync.is_globally_banned("9.9.9.9") is False
    banlist_sync.load_published()
    assert banlist_sync.is_globally_banned("9.9.9.9") is True


def test_load_published_is_false_when_nothing_was_published():
    use_scalable()
    clear_follower_state()
    assert banlist_sync.load_published() is False
    assert banlist_sync.get_global_banlist() == frozenset()


def test_standalone_never_publishes():
    dashboard_cache._backend = "standalone"
    dashboard_cache._redis_client = None
    seed_leader_state({"1.1.1.1"}, [])
    assert banlist_sync.publish(10800) is False
    assert banlist_sync.load_published() is False


def test_published_key_avoids_the_flushed_cache_prefix():
    redis_client = use_scalable()
    seed_leader_state({"1.1.1.1"}, [])
    banlist_sync.publish(10800)
    assert banlist_sync.PUBLISHED_KEY == "krawl:task:banlist"
    for key in redis_client.store:
        assert not key.startswith("krawl:cache:"), f"{key} is wiped on pod boot"


if __name__ == "__main__":
    test_publish_then_adopt_round_trips()
    test_adopted_list_answers_the_membership_check()
    test_load_published_is_false_when_nothing_was_published()
    test_standalone_never_publishes()
    test_published_key_avoids_the_flushed_cache_prefix()
    print("PASS: banlist publish and adopt")
