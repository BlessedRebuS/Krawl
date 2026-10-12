"""Targeted-domain link map keeps DNS levels and request counts connected."""

from domain_map import build_domain_map, root_domain


def test_root_domain_groups_common_suffixes_and_rejects_non_domains():
    assert root_domain("api.shop.example.com") == "example.com"
    assert root_domain("v1.api.example.co.uk") == "example.co.uk"
    assert root_domain("203.0.113.5") is None
    assert root_domain("localhost") is None


def test_link_map_centers_a_root_and_branches_by_dns_level():
    rows = [
        {"domain": "example.com", "count": 8},
        {"domain": "api.example.com", "count": 5},
        {"domain": "v1.api.example.com", "count": 3},
        {"domain": "open.api.example.com", "count": 2},
        {"domain": "other.test", "count": 9},
        {"domain": "203.0.113.5", "count": 30},
    ]
    graph = build_domain_map(rows, selected_root="example.com")
    nodes = {node["domain"]: node for node in graph["nodes"]}
    assert graph["selected_root"] == "example.com"
    assert graph["total_requests"] == 18
    assert nodes["example.com"]["depth"] == 0
    assert (nodes["example.com"]["x"], nodes["example.com"]["y"]) == (500.0, 450.0)
    assert nodes["api.example.com"]["parent"] == "example.com"
    assert nodes["v1.api.example.com"]["parent"] == "api.example.com"
    assert nodes["open.api.example.com"]["depth"] == 2
    assert len(graph["edges"]) == 3
    assert graph["roots"][0]["name"] == "example.com"
    assert build_domain_map(rows, selected_root="missing.test")["selected_root"] == "example.com"


def test_empty_link_map_has_directional_empty_state():
    graph = build_domain_map([{"domain": "203.0.113.5", "count": 2}])
    assert graph["roots"] == []
    assert graph["nodes"] == []
