# Iptables + Krawl Integration

Automatically block malicious IPs detected by Krawl using iptables firewall rules.

## Prerequisites

- Linux system with iptables installed
- Krawl running with API accessible
- Root/sudo access
- Curl for HTTP requests
- Cron for scheduling

## Quick Setup

### 1. Create the script

```bash
#!/bin/bash
KRAWL_URL="https://your-krawl-instance/your-dashboard-path"
curl -s "${KRAWL_URL}/api/get_banlist?fwtype=iptables" > /tmp/krawl_iptables_rules.sh
sudo bash /tmp/krawl_iptables_rules.sh
rm -f /tmp/krawl_iptables_rules.sh
echo "Krawl iptables rules updated"
```

Save as `krawl-iptables.sh` and make executable:
```bash
chmod +x krawl-iptables.sh
```

### 2. Test it

```bash
sudo ./krawl-iptables.sh
```

### 3. Schedule with Cron

```bash
sudo crontab -e
```

Add this line to update rules every hour:
```bash
0 * * * * /path/to/krawl-iptables.sh
```

## Commands

### View blocked IPs
```bash
sudo iptables -L INPUT -n | grep DROP
```

### Manually block an IP
```bash
sudo iptables -A INPUT -s 192.0.2.100 -j DROP
```

### Manually unblock an IP
```bash
sudo iptables -D INPUT -s 192.0.2.100 -j DROP
```

### List all rules with statistics
```bash
sudo iptables -L INPUT -n -v
```

### Save rules (survive reboot)
```bash
sudo iptables-save > /etc/iptables/rules.v4
```

### Load rules on boot
```bash
sudo apt-get install iptables-persistent
sudo iptables-save > /etc/iptables/rules.v4
```

## How It Works

1. Script fetches iptables-formatted rules from Krawl API (`/api/get_banlist?fwtype=iptables`)
2. Executes the downloaded bash script
3. Drops all traffic from blacklisted IPs immediately
