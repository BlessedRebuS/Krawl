# Nftables + Krawl Integration

Automatically block malicious IPs detected by Krawl using nftables firewall rules.

## Prerequisites

- Modern Linux system with nftables installed (Ubuntu 22+, Debian 12+, RHEL 9+)
- Krawl running with API accessible
- Root/sudo access
- Curl for HTTP requests
- Cron for scheduling

## Check if your system uses nftables

```bash
sudo nft list tables
```

If this returns tables, use nftables. Otherwise, use iptables.

## Quick Setup

### 1. Create the script

```bash
#!/bin/bash
KRAWL_URL="https://your-krawl-instance/your-dashboard-path"
curl -s "${KRAWL_URL}/api/export-ips?categories=attacker&fwtype=nftables" > /tmp/krawl_nftables_rules.sh
sudo bash /tmp/krawl_nftables_rules.sh
rm -f /tmp/krawl_nftables_rules.sh
echo "Krawl nftables rules updated"
```

Save as `krawl-nftables.sh` and make executable:
```bash
chmod +x krawl-nftables.sh
```

### 2. Test it

```bash
sudo ./krawl-nftables.sh
```

### 3. Schedule with Cron

```bash
sudo crontab -e
```

Add this line to update rules every hour:
```bash
0 * * * * /path/to/krawl-nftables.sh
```

## Commands

### View blocked IPs
```bash
sudo nft list set inet filter blacklist
```

### Count blocked IPs
```bash
sudo nft list set inet filter blacklist | grep "elements" | wc -w
```

### Manually block an IP
```bash
sudo nft add element inet filter blacklist { 192.0.2.100 }
```

### Manually unblock an IP
```bash
sudo nft delete element inet filter blacklist { 192.0.2.100 }
```

### View all rules
```bash
sudo nft list table inet filter
```

### Clear all blocked IPs
```bash
sudo nft flush set inet filter blacklist
```

## How It Works

1. Script fetches nftables-formatted rules from Krawl API (`/api/export-ips?categories=attacker&fwtype=nftables`)
2. Executes the downloaded bash script
3. Creates `inet filter` table and `blacklist` set
4. Drops all traffic from blacklisted IPs immediately
