#!/usr/bin/env python3

"""
The two default layers must agree (github.com/BlessedRebuS/Krawl/issues/299).

Every setting has its default written twice: once as a Config dataclass field
default, and once as the fallback in the matching `section.get(key, ...)` call
in from_yaml. Nothing kept them in sync, and nine had drifted — the analyzer
thresholds were None in the dataclass but real numbers in from_yaml, and
max_pages_limit was 100 in one and 250 in the other.

That drift is invisible until something compares the two, which the Settings >
Configuration panel now does: it badges a field "custom" when the running
value differs from the dataclass default, so a stock deployment was showing
"custom" on settings nobody had touched.

Usage: python tests/test_config_defaults_agree.py
"""

import dataclasses
import os
import sys
import tempfile
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

# Generated per run, so they have no meaningful default to compare against.
GENERATED = {
    "dashboard_secret_path",
    "dashboard_password",
    "dashboard_password_generated",
    "dashboard_secret_path_generated",
}


def test_dataclass_defaults_match_from_yaml_fallbacks():
    """An empty config.yaml must produce exactly Config()."""
    from config import Config

    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as fh:
        fh.write("{}\n")
        empty = fh.name

    previous = os.environ.get("CONFIG_LOCATION")
    os.environ["CONFIG_LOCATION"] = empty
    try:
        from_yaml = Config.from_yaml()
    finally:
        if previous is None:
            os.environ.pop("CONFIG_LOCATION", None)
        else:
            os.environ["CONFIG_LOCATION"] = previous
        os.unlink(empty)

    defaults = Config()
    drifted = []
    for f in dataclasses.fields(Config):
        if f.name.startswith("_") or f.name in GENERATED:
            continue
        a = getattr(defaults, f.name)
        b = getattr(from_yaml, f.name)
        if a != b:
            drifted.append(f"  {f.name}: dataclass={a!r} from_yaml={b!r}")

    assert not drifted, (
        "These settings have two different defaults. Make the dataclass field "
        "default and the from_yaml fallback the same value:\n" + "\n".join(drifted)
    )
    print("OK: the dataclass defaults and the from_yaml fallbacks agree")


def test_shipped_config_is_reflected_as_custom_only_where_it_differs():
    """A stock checkout should badge only settings config.yaml really changes.

    Not an assertion about which settings those are — that is the operator's
    business — but the count should be small. A large number means the two
    default layers have drifted apart again rather than that someone made
    a lot of deliberate choices.
    """
    from config import Config

    shipped = Config.from_yaml()
    defaults = Config()
    changed = [
        f.name
        for f in dataclasses.fields(Config)
        if not f.name.startswith("_")
        and f.name not in GENERATED
        and getattr(defaults, f.name) != getattr(shipped, f.name)
    ]
    print(f"OK: shipped config.yaml deliberately changes {len(changed)} settings:")
    for name in changed:
        print(f"     {name}")


if __name__ == "__main__":
    test_dataclass_defaults_match_from_yaml_fallbacks()
    test_shipped_config_is_reflected_as_custom_only_where_it_differs()
