"""Banlist formatters for the firewall export endpoints.

One function per output format; `format_banlist` picks by name.
"""


def _raw(ips: list[str]) -> str:
    """Plain list, one IP per line."""
    return "\n".join(ips)


def _iptables(ips: list[str]) -> str:
    """iptables DROP rules, one per IP."""
    rules = ["#!/bin/bash", "# iptables ban rules", ""]
    rules += [f"iptables -A INPUT -s {ip.strip()} -j DROP" for ip in ips]
    return "\n".join(rules)


def _nftables(ips: list[str]) -> str:
    """nftables blacklist set plus a drop rule referencing it."""
    return "\n".join(
        [
            "#!/bin/bash",
            "# nftables ban rules",
            "",
            "# Create table and chain if they don't exist",
            "nft add table inet filter 2>/dev/null || true",
            r"nft add chain inet filter input { type filter hook input priority 0 \; }",
            "",
            "# Add IPs to blacklist set",
            r"nft add set inet filter blacklist { type ipv4_addr \; elements = {",
            "    " + ", ".join(ip.strip() for ip in ips),
            "} }",
            "",
            "# Add rule to drop packets from blacklist",
            "nft add rule inet filter input ip saddr @blacklist counter drop",
        ]
    )


FORMATS = {"raw": _raw, "iptables": _iptables, "nftables": _nftables}


def format_banlist(fwtype: str, ips: list[str]) -> str:
    """Render IPs in the requested format.

    Raises:
        ValueError: if fwtype is not a known format.
    """
    fmt = FORMATS.get((fwtype or "").lower())
    if fmt is None:
        raise ValueError(
            f"Unknown firewall type: '{fwtype}'. Available: {', '.join(FORMATS)}"
        )
    return fmt(ips) if ips else ""
