#!/usr/bin/env python3

"""The dashboard wordmark is operator-configurable (dashboard.branding).

Its one piece of real logic is deciding what a `contact` string is: an
address, a link, or neither. Get that wrong and either a usable contact stops
being clickable, or a `javascript:` URL from a tampered configmap lands in an
href.

Usage: python3 tests/test_brand.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from config import Config  # noqa: E402
from dependencies import build_brand  # noqa: E402


def brand(**overrides):
    return build_brand(Config(**overrides), "9.9.9")


def test_defaults_are_krawls_own():
    b = brand()
    assert b["name"] == "Krawl"
    assert b["url"] == "https://github.com/BlessedRebuS/Krawl"
    assert b["version"] == "9.9.9"
    assert b["logo"] == ""
    assert b["contact"] == "" and b["contact_href"] == ""


def test_version_hidden_when_disabled():
    assert brand(dashboard_brand_show_version=False)["version"] == ""


def test_no_url_means_no_anchor():
    assert brand(dashboard_brand_url=None)["url"] == ""


def test_contact_email_becomes_mailto():
    b = brand(dashboard_brand_contact="  soc@example.com  ")
    assert b["contact"] == "soc@example.com"
    assert b["contact_href"] == "mailto:soc@example.com"


def test_contact_url_stays_a_link():
    b = brand(dashboard_brand_contact="https://wiki.corp/soc")
    assert b["contact_href"] == "https://wiki.corp/soc"


def test_contact_plain_text_is_not_linked():
    for text in ("Ext. 4471", "#soc-alerts on Slack", "ask @ the front desk"):
        assert brand(dashboard_brand_contact=text)["contact_href"] == "", text


def test_hostile_values_never_reach_an_href():
    assert brand(dashboard_brand_url="javascript:alert(1)")["url"] == ""
    assert brand(dashboard_brand_logo="javascript:alert(1)")["logo"] == ""
    assert brand(dashboard_brand_contact="javascript:alert(1)")["contact_href"] == ""


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("\nall good")
