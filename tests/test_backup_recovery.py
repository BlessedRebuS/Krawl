import subprocess
from types import SimpleNamespace

import pytest

from tasks import db_dump


@pytest.mark.parametrize("outcome", ["success", "error", "timeout"])
def test_pg_dump_preserves_previous_backup(tmp_path, monkeypatch, outcome):
    monkeypatch.setattr(
        db_dump,
        "config",
        SimpleNamespace(
            backups_path=str(tmp_path),
            postgres_host="localhost",
            postgres_port=5432,
            postgres_user="test",
            postgres_password="",
            postgres_database="test",
        ),
    )
    backup = tmp_path / "db_dump.sql"
    backup.write_text("previous good backup")

    def dump(cmd, **kwargs):
        from pathlib import Path

        Path(cmd[-1]).write_text("new backup")
        if outcome == "timeout":
            raise subprocess.TimeoutExpired(cmd, 300)
        return SimpleNamespace(
            returncode=0 if outcome == "success" else 1, stderr="failed"
        )

    monkeypatch.setattr(db_dump.subprocess, "run", dump)
    db_dump._dump_pg()
    assert backup.read_text() == (
        "new backup" if outcome == "success" else "previous good backup"
    )
    assert not (tmp_path / "db_dump.sql.tmp").exists()
