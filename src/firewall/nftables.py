from typing_extensions import override
from firewall.fwtype import FWType


class Nftables(FWType):
    @override
    def getBanlist(self, ips) -> str:
        """
        Generate nftables ban rules from an array of IP addresses.

        Args:
            ips: List of IP addresses to ban

        Returns:
            String containing nftables commands for blocking IPs
        """
        if not ips:
            return ""

        rules = []
        rules.append("#!/bin/bash")
        rules.append("# nftables ban rules")
        rules.append("")
        rules.append("# Create table and chain if they don't exist")
        rules.append("nft add table inet filter 2>/dev/null || true")
        rules.append(
            "nft add chain inet filter input { type filter hook input priority 0 \\; }"
        )
        rules.append("")
        rules.append("# Add IPs to blacklist set")
        rules.append(
            "nft add set inet filter blacklist { type ipv4_addr \\; elements = {"
        )

        # Add all IPs to the set
        ip_list = []
        for ip in ips:
            ip = ip.strip()
            ip_list.append(ip)

        if ip_list:
            rules.append("    " + ", ".join(ip_list))

        rules.append("} }")
        rules.append("")
        rules.append("# Add rule to drop packets from blacklist")
        rules.append("nft add rule inet filter input ip saddr @blacklist counter drop")

        return "\n".join(rules)
