#!/usr/bin/env python3

"""The CrowdSec exporter emits what `cscli decisions import` actually reads.

CrowdSec owns enforcement, so Krawl supplies decisions and a duration. The
import command accepts only csv, json or values and picks the parser from the
file extension, so the format is not a style choice: a document that looks like
a decision list but is neither is rejected, or worse, imported as nothing.

Usage: python3 tests/test_firewall_crowdsec.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from firewall import CROWDSEC_BAN_DURATION, FORMATS, format_banlist  # noqa: E402

IPS = ["203.0.113.7", "198.51.100.23", "45.155.205.233"]


def decisions():
    return json.loads(format_banlist("crowdsec", IPS))


def test_output_is_json_and_one_decision_per_ip():
    parsed = decisions()
    assert isinstance(parsed, list)
    assert len(parsed) == len(IPS)


def test_every_decision_carries_the_documented_shape():
    # cscli documents these four keys, lower-case, with ip/ban as the defaults
    # this exporter states explicitly.
    for entry in decisions():
        assert set(entry) == {"duration", "scope", "type", "value"}
        assert entry["scope"] == "ip"
        assert entry["type"] == "ban"
        assert entry["duration"] == CROWDSEC_BAN_DURATION


def test_the_yaml_capitalised_keys_never_come_back():
    # The first version of this exporter emitted YAML with Duration/Scope/Type/
    # Value, which cscli cannot import. Pin the casing that replaced it.
    raw = format_banlist("crowdsec", IPS)
    for legacy in ("Duration:", "Scope:", "Type:", "Value:"):
        assert legacy not in raw, legacy


def test_values_are_the_input_ips_in_order():
    assert [d["value"] for d in decisions()] == IPS


def test_duration_survives_a_round_trip_through_json():
    # CrowdSec parses newline-style durations, so the string must not become a
    # number on the way out.
    parsed = decisions()
    assert all(isinstance(d["duration"], str) for d in parsed)


def test_surrounding_whitespace_is_stripped():
    parsed = json.loads(format_banlist("crowdsec", ["  203.0.113.7\n"]))
    assert parsed[0]["value"] == "203.0.113.7"


def test_empty_list_produces_nothing():
    # A quiet export must be a no-op for the importer, not a header-only file.
    assert format_banlist("crowdsec", []) == ""


def test_crowdsec_is_a_registered_fwtype():
    assert "crowdsec" in FORMATS


def test_unknown_format_still_names_crowdsec():
    try:
        format_banlist("pf", IPS)
    except ValueError as err:
        assert "crowdsec" in str(err)
    else:
        raise AssertionError("expected ValueError for an unknown format")


def test_existing_formats_are_untouched():
    assert format_banlist("raw", IPS) == "\n".join(IPS)
    assert "iptables -A INPUT" in format_banlist("iptables", IPS)
    assert "nft add set inet filter blacklist" in format_banlist("nftables", IPS)


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("\nall good")
