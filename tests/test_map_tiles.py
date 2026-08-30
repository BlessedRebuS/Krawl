#!/usr/bin/env python3

"""
Map tile configuration (github.com/BlessedRebuS/Krawl/issues/295).

CARTO began stamping "API KEY REQUIRED" across tiles served without a key, so
the tile source and its key must be configurable rather than hardcoded.

Usage: python tests/test_map_tiles.py
"""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from config import Config
from routes.dashboard import _map_tiles

CARTO = "https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png"


def test_key_is_appended():
    """CARTO and friends take the key as a query parameter."""
    tiles = _map_tiles(Config(map_tile_url=CARTO, map_api_key="abc123"))
    assert tiles["url"] == CARTO + "?key=abc123", tiles["url"]

    # A URL that already carries a query gets & rather than a second ?.
    withq = "https://tiles.example.com/{z}/{x}/{y}.png?style=dark"
    tiles = _map_tiles(Config(map_tile_url=withq, map_api_key="abc123"))
    assert tiles["url"] == withq + "&key=abc123", tiles["url"]

    # No key configured: the URL is untouched, no stray "?key=".
    tiles = _map_tiles(Config(map_tile_url=CARTO))
    assert tiles["url"] == CARTO, tiles["url"]
    assert "key=" not in tiles["url"]
    print("OK: api key appended with ? or & as appropriate, omitted when unset")


def test_default_is_keyless():
    """Out of the box the map must render without an account anywhere."""
    tiles = _map_tiles(Config())
    assert "cartocdn" not in tiles["url"], (
        "default must not be the watermarked provider"
    )
    assert "key=" not in tiles["url"]
    for placeholder in ("{z}", "{x}", "{y}"):
        assert placeholder in tiles["url"], f"{placeholder} missing from default URL"
    assert tiles["attribution"], "attribution is a licence condition, not optional"
    print(f"OK: default is keyless — {tiles['url'].split('/rest/')[0]}…")


def test_operator_override():
    """A fully custom provider needs no code change."""
    tiles = _map_tiles(
        Config(
            map_tile_url="https://tiles.internal/{z}/{x}/{y}.png",
            map_tile_attribution="Internal basemap",
            map_tile_subdomains="",
        )
    )
    assert tiles == {
        "url": "https://tiles.internal/{z}/{x}/{y}.png",
        "attribution": "Internal basemap",
        "subdomains": "",
    }, tiles
    print("OK: a self-hosted tile server is a config change, not a code change")


if __name__ == "__main__":
    test_key_is_appended()
    test_default_is_keyless()
    test_operator_override()
