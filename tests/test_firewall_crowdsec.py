#!/usr/bin/env python3

"""The CrowdSec exporter emits decisions, not a ruleset (#148).

CrowdSec owns enforcement, so what it needs from Krawl is the ban list and a
duration; a firewall ruleset would duplicate what CrowdSec already does. The
output has to be something `cscli decisions import` accepts, which means the
YAML decisions dialect: one mapping per IP with Duration, Scope, Type and Value.

Getting the shape wrong is silent — cscli rejects or imports nothing, and the
operators stay unbanned — so the structure is pinned here rather than eyeballed.

Usage: python3 tests/test_firewall_crowdsec.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from firewall import (  # noqa: E402
    CROWDSEC_BAN_DURATION,
    FORMATS,
    format_banlist,
)


def _blocks(output: str) -> list[dict[str, str]]:
    """Parse the emitted decisions back into mappings, without a YAML library."""
    blocks: list[dict[str, str]] = []
    for line in output.splitlines():
        if line.startswith("#") or not line.strip():
            continue
        if line.startswith("- "):
            blocks.append({})
            line = line[2:]
        key, _, value = line.strip().partition(":")
        blocks[-1][key.strip()] = value.strip()
    return blocks


def test_crowdsec_is_a_registered_fwtype():
    assert "crowdsec" in FORMATS
    assert FORMATS["crowdsec"] is not None


def test_one_decision_per_ip():
    ips = ["203.0.113.7", "198.51.100.23", "192.0.2.9"]
    blocks = _blocks(format_banlist("crowdsec", ips))
    assert len(blocks) == len(ips), blocks
    assert [b["Value"] for b in blocks] == ips


def test_every_decision_carries_the_full_shape():
    blocks = _blocks(format_banlist("crowdsec", ["203.0.113.7"]))
    assert blocks[0] == {
        "Duration": CROWDSEC_BAN_DURATION,
        "Scope": "Ip",
        "Type": "ban",
        "Value": "203.0.113.7",
    }, blocks[0]


def test_ban_duration_is_a_crowdsec_duration():
    """cscli only accepts a Go-style duration, not a bare number."""
    assert CROWDSEC_BAN_DURATION[-1] in "smh", CROWDSEC_BAN_DURATION
    assert CROWDSEC_BAN_DURATION[:-1].isdigit(), CROWDSEC_BAN_DURATION


def test_surrounding_whitespace_is_stripped():
    blocks = _blocks(format_banlist("crowdsec", ["  203.0.113.7\n", " 198.51.100.23 "]))
    assert [b["Value"] for b in blocks] == ["203.0.113.7", "198.51.100.23"]


def test_empty_list_produces_nothing():
    """An empty export must not emit a header cscli would try to import."""
    assert format_banlist("crowdsec", []) == ""


def test_unknown_format_still_names_crowdsec():
    try:
        format_banlist("nope", ["203.0.113.7"])
    except ValueError as exc:
        assert "crowdsec" in str(exc), exc
    else:
        raise AssertionError("unknown fwtype must raise")


def test_existing_formats_are_untouched():
    assert "iptables -A INPUT -s 203.0.113.7 -j DROP" in format_banlist(
        "iptables", ["203.0.113.7"]
    )
    assert "nft add table inet filter" in format_banlist("nftables", ["203.0.113.7"])
    assert format_banlist("raw", ["203.0.113.7"]) == "203.0.113.7"


if __name__ == "__main__":
    for name, fn in sorted(globals().items()):
        if name.startswith("test_"):
            fn()
            print(f"ok  {name}")
    print("\nall good")
