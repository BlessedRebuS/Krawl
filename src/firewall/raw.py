from typing_extensions import override
from firewall.fwtype import FWType


class Raw(FWType):

    @override
    def getBanlist(self, ips) -> str:
        """
        Generate raw list of bad IP addresses.

        Args:
            ips: List of IP addresses to ban

        Returns:
            String containing raw ips, one per line
        """
        if not ips:
            return ""

        return "\n".join(ips)
