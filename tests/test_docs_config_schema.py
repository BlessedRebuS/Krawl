"""The docs config builder's schema (scripts/docs_hooks.py) matches Config."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "scripts"))

from docs_hooks import build_schema  # noqa: E402

from config import Config  # noqa: E402


def test_every_env_name_is_a_config_field_and_known_keys_map():
    fields = {f["path"]: f for f in build_schema()["fields"]}
    real = {f"KRAWL_{name.upper()}" for name in Config.__dataclass_fields__}

    assert {f["env"] for f in fields.values() if f["env"]} <= real
    assert fields["server.port"]["env"] == "KRAWL_PORT"
    assert fields["logging.level"]["env"] == "KRAWL_LOG_LEVEL"
    assert [fields[k]["envPos"] for k in ("links.min_length", "links.max_length")] == [0, 1]
    assert fields["links.max_length"]["env"] == "KRAWL_LINKS_LENGTH_RANGE"
    assert fields["analyzer.scoring_weights.attacker.attack_url"]["env"] is None
    assert fields["mode"]["kind"] == "enum"
    assert fields["dashboard.password"]["help"].startswith("Protects the dashboard")
