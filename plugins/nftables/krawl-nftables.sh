#!/bin/bash
# This script fetches nftables-formatted firewall rules from Krawl and executes them.
# The Krawl API generates proper nftables rules, so we simply download and execute them.

# Configuration
KRAWL_URL="https://your-krawl-instance/your-dashboard-path"

# Fetch nftables-formatted rules from Krawl API
curl -s "${KRAWL_URL}/api/export-ips?categories=attacker&fwtype=nftables" > /tmp/krawl_nftables_rules.sh

# Verify the file was downloaded successfully
if [ ! -s /tmp/krawl_nftables_rules.sh ]; then
  echo "Error: Failed to fetch nftables rules from Krawl API"
  exit 1
fi

# Execute the nftables rules as root
sudo bash /tmp/krawl_nftables_rules.sh

# Cleanup
rm -f /tmp/krawl_nftables_rules.sh

echo "Krawl nftables rules updated successfully"