import json

import pytest

import dashboard_cache as cache


class RedisLists:
    """Transactional list fake that checks writer-visible cache state."""

    def __init__(self):
        self.data = {}
        self.ttls = {}
        self.batch_sizes = []
        self.before_execute = lambda: None

    def delete(self, key):
        self.data.pop(key, None)
        self.ttls.pop(key, None)

    def pipeline(self):
        owner = self

        class Pipeline:
            def __init__(self):
                self.commands = []

            def __enter__(self):
                return self

            def __exit__(self, *args):
                pass

            def __getattr__(self, command):
                def enqueue(*args):
                    self.commands.append((command, args))

                return enqueue

            def execute(self):
                owner.before_execute()
                for command, args in self.commands:
                    if command == "rpush":
                        key, *items = args
                        owner.batch_sizes.append(len(items))
                        owner.data.setdefault(key, []).extend(items)
                    elif command == "expire":
                        owner.ttls[args[0]] = args[1]
                    elif command == "rename":
                        owner.data[args[1]] = owner.data.pop(args[0])
                        owner.ttls[args[1]] = owner.ttls.pop(args[0])
                self.commands.clear()

        return Pipeline()


def test_batches_publish_atomically_and_clean_staging(monkeypatch):
    redis = RedisLists()
    monkeypatch.setattr(cache, "_backend", "scalable")
    monkeypatch.setattr(cache, "_redis_client", redis)
    monkeypatch.setattr(cache, "_LIST_PUSH_BATCH", 2)
    key = "krawl:cache:list:test"
    redis.data[key] = ["old"]

    def check_old_snapshot():
        assert redis.data[key] == ["old"]

    redis.before_execute = check_old_snapshot
    items = [{"id": i} for i in range(5)]
    cache.set_cached_list("test", items, ttl=42)
    assert redis.batch_sizes == [2, 2, 1]
    assert [json.loads(row) for row in redis.data[key]] == items
    assert redis.ttls == {key: 42}
    assert list(redis.data) == [key]


def test_failed_serialization_leaves_previous_cache_intact(monkeypatch):
    redis = RedisLists()
    monkeypatch.setattr(cache, "_backend", "scalable")
    monkeypatch.setattr(cache, "_redis_client", redis)
    monkeypatch.setattr(cache, "_LIST_PUSH_BATCH", 1)
    key = "krawl:cache:list:test"
    redis.data[key] = ["old"]
    with pytest.raises(TypeError):
        cache.set_cached_list("test", [{"id": 1}, object()])
    assert redis.data == {key: ["old"]}
    assert not redis.ttls
