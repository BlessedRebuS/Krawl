#!/bin/bash
# This script fetches iptables-formatted firewall rules from Krawl and executes them.
# The Krawl API generates proper iptables rules, so we simply download and execute them.

# Configuration
KRAWL_URL="https://your-krawl-instance/your-dashboard-path"

# Fetch iptables-formatted rules from Krawl API
curl -s "${KRAWL_URL}/api/get_banlist?fwtype=iptables" > /tmp/krawl_iptables_rules.sh

# Verify the file was downloaded successfully
if [ ! -s /tmp/krawl_iptables_rules.sh ]; then
  echo "Error: Failed to fetch iptables rules from Krawl API"
  exit 1
fi

# Execute the iptables rules as root
sudo bash /tmp/krawl_iptables_rules.sh

# Cleanup
rm -f /tmp/krawl_iptables_rules.sh

echo "Krawl iptables rules updated successfully"