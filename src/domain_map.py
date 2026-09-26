"""Build a bounded DNS hierarchy for the Targeted Domains link map."""

from collections import defaultdict
from ipaddress import ip_address
from math import cos, pi, sin
import re

# Common two-label public suffixes. The map is a DNS visualization rather than
# a public-suffix authority; these keep the most common country domains intact.
_TWO_LABEL_SUFFIXES = {
    "ac.uk", "co.uk", "gov.uk", "org.uk", "net.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.nz", "net.nz", "org.nz", "govt.nz",
    "com.br", "net.br", "org.br", "com.mx", "com.ar",
    "co.jp", "ne.jp", "or.jp", "co.kr", "or.kr",
    "co.in", "net.in", "org.in", "co.za", "org.za",
    "com.sg", "com.hk", "com.tr", "com.tw", "com.cn",
}
_LABEL = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
_CENTER = (500, 450)
_RADII = (0, 130, 235, 320, 390)


def root_domain(host: str) -> str | None:
    """Return the root to display for a DNS name, excluding IPs and bad hosts."""
    host = (host or "").lower().rstrip(".")
    try:
        ip_address(host)
        return None
    except ValueError:
        pass
    labels = host.split(".")
    if len(labels) < 2 or any(not _LABEL.fullmatch(label) for label in labels):
        return None
    suffix = ".".join(labels[-2:])
    width = 3 if suffix in _TWO_LABEL_SUFFIXES and len(labels) >= 3 else 2
    return ".".join(labels[-width:])


def build_domain_map(
    rows: list[dict], selected_root: str = "", root_limit: int = 8,
    host_limit: int = 28,
) -> dict:
    """Summarize roots and lay out the selected root's observed host tree."""
    counts: dict[str, int] = defaultdict(int)
    for row in rows:
        host = str(row["domain"] or "").lower().rstrip(".")
        if root_domain(host):
            counts[host] += int(row["count"])

    groups: dict[str, list[tuple[str, int]]] = defaultdict(list)
    for host, count in counts.items():
        groups[root_domain(host)].append((host, count))
    roots = sorted(
        ({"name": root, "count": sum(c for _, c in hosts), "hosts": len(hosts)}
         for root, hosts in groups.items()),
        key=lambda item: (-item["count"], item["name"]),
    )
    if not roots:
        return {"roots": [], "selected_root": "", "nodes": [], "edges": [],
                "hidden_hosts": 0, "total_requests": 0}

    selected = selected_root if selected_root in groups else roots[0]["name"]
    visible_roots = roots[:root_limit]
    if selected not in {item["name"] for item in visible_roots}:
        visible_roots.append(next(item for item in roots if item["name"] == selected))

    hosts = groups[selected]
    root_depth = len(selected.split("."))
    ranked = sorted(
        (item for item in hosts if len(item[0].split(".")) - root_depth <= 4),
        key=lambda item: (-item[1], item[0]),
    )
    shown = ranked[:host_limit]
    if selected in counts and selected not in {host for host, _ in shown}:
        shown[-1] = (selected, counts[selected])
    tree = {selected: {"domain": selected, "label": selected, "parent": None,
                       "depth": 0, "own_count": counts.get(selected, 0),
                       "children": []}}
    for host, count in shown:
        if host == selected:
            continue
        prefix = host[: -(len(selected) + 1)].split(".")
        parent = selected
        for label in reversed(prefix):
            domain = f"{label}.{parent}"
            if domain not in tree:
                tree[domain] = {"domain": domain, "label": label,
                                "parent": parent, "depth": tree[parent]["depth"] + 1,
                                "own_count": 0, "children": []}
                tree[parent]["children"].append(domain)
            parent = domain
        tree[host]["own_count"] = count

    def measure(domain: str) -> tuple[int, int]:
        node = tree[domain]
        child_totals = [measure(child) for child in node["children"]]
        node["total"] = node["own_count"] + sum(total for total, _ in child_totals)
        node["leaves"] = sum(leaves for _, leaves in child_totals) or 1
        node["children"].sort(key=lambda child: (-tree[child]["total"], child))
        return node["total"], node["leaves"]

    measure(selected)

    def place(domain: str, start: float, end: float) -> None:
        node = tree[domain]
        angle = (start + end) / 2
        radius = _RADII[min(node["depth"], len(_RADII) - 1)]
        node["x"] = round(_CENTER[0] + radius * cos(angle), 1)
        node["y"] = round(_CENTER[1] + radius * sin(angle), 1)
        node["r"] = 14 if node["depth"] == 0 else 10
        node["observed"] = node["own_count"] > 0
        if node["depth"] == 0:
            node["label_x"] = node["x"] + 20
            node["label_y"] = node["y"] + 4
            node["anchor"] = "start"
        else:
            node["label_x"] = node["x"] + 15
            node["label_y"] = node["y"] + 4
            node["anchor"] = "start"
        cursor = start
        for child in node["children"]:
            width = (end - start) * tree[child]["leaves"] / node["leaves"]
            place(child, cursor, cursor + width)
            cursor += width

    place(selected, -pi, pi)
    edges = []
    for node in tree.values():
        if not node["parent"]:
            continue
        edges.append({"source": node["parent"], "target": node["domain"],
                      "depth": node["depth"]})

    return {"roots": visible_roots, "selected_root": selected,
            "nodes": sorted(tree.values(), key=lambda node: node["depth"]),
            "edges": edges, "hidden_hosts": max(0, len(hosts) - len(shown)),
            "total_requests": sum(count for _, count in hosts)}
