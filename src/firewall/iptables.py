from typing_extensions import override
from firewall.fwtype import FWType

class Iptables(FWType):

    @override
    def getBanlist(self,ips) -> str:
        """
        Generate iptables ban rules from an array of IP addresses.

        Args:
            ips: List of IP addresses to ban

        Returns:
            String containing iptables commands, one per line
        """
        if not ips:
            return ""

        rules = []
        chain = "INPUT"
        target = "DROP"
        rules.append("#!/bin/bash")
        rules.append("# iptables ban rules")
        rules.append("")

        for ip in ips:

            ip = ip.strip()

            # Build the iptables command
            rule_parts = [
                "iptables",
                "-A", chain,
                "-s", ip
            ]

            # Add target
            rule_parts.extend(["-j", target])

            rules.append(" ".join(rule_parts))

        return "\n".join(rules)
