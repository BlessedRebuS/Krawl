import auth_store


def test_abandoned_auth_records_are_swept(monkeypatch):
    now = [100.0]
    monkeypatch.setattr(auth_store.time, "time", lambda: now[0])
    monkeypatch.setattr(auth_store, "_sessions", {})
    monkeypatch.setattr(auth_store, "_attempts", {})
    monkeypatch.setattr(auth_store, "_next_prune", 0)
    auth_store.create_session("abandoned")
    auth_store.save_attempts("203.0.113.7", {"locked_until": 200})
    now[0] += auth_store.SESSION_TTL + 1
    auth_store.create_session("new")
    assert set(auth_store._sessions) == {"new"}
    assert auth_store._attempts == {}
    assert auth_store.is_valid_session("new")


def test_attempt_records_are_not_shared_mutable_state(monkeypatch):
    monkeypatch.setattr(auth_store, "_attempts", {})
    record = {"count": 1}
    auth_store.save_attempts("203.0.113.7", record)
    record["count"] = 2
    fetched = auth_store.get_attempts("203.0.113.7")
    assert fetched == {"count": 1}
    fetched["count"] = 3
    assert auth_store.get_attempts("203.0.113.7") == {"count": 1}
