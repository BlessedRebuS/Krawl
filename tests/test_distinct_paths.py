"""get_distinct_paths returns distinct paths without SQLAlchemy warnings."""

import sys
import warnings
from datetime import datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from sqlalchemy.exc import SAWarning  # noqa: E402

from database import get_database, initialize_database  # noqa: E402
from models import AccessLog  # noqa: E402


def test_distinct_paths_no_warning(tmp_path):
    initialize_database(str(tmp_path / "x.db"))
    db = get_database()
    s = db.session
    for ip, path in [
        ("203.0.113.1", "/a"),
        ("203.0.113.2", "/a"),
        ("203.0.113.3", "/b"),
    ]:
        s.add(AccessLog(ip=ip, path=path, user_agent="x", timestamp=datetime(2026, 10, 27)))
    s.commit()
    db.close_session()

    with warnings.catch_warnings():
        warnings.simplefilter("error", SAWarning)
        paths = db.access_logs.get_distinct_paths()
    assert sorted(paths) == ["/a", "/b"]
