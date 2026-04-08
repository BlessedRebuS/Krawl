# Fail2Ban + Krawl Integration

## Overview

This guide explains how to integrate **[fail2ban](https://github.com/fail2ban/fail2ban)** with Krawl to automatically block detected malicious IPs at the firewall level using iptables. Fail2ban monitors Krawl's malicious IP export and applies real-time IP bans.

## Architecture

```
Krawl detects malicious IPs
         ↓
Writes to malicious_ips.txt
         ↓
Fail2ban monitors the file
         ↓
Filter matches IPs using regex
         ↓
Iptables firewall blocks the IP
         ↓
Auto-unban after bantime expires
```

## Prerequisites

- Linux system with iptables
- Fail2ban installed: `sudo apt-get install fail2ban`
- Krawl running and generating malicious IPs
- Root/sudo access

## Installation & Setup

### 1. Create the Filter Configuration [krawl-filter.conf](krawl-filter.conf)

Create `/etc/fail2ban/filter.d/krawl-filter.conf`:

```ini
[Definition]
failregex = ^<HOST>$
```

**Explanation:** The filter matches any line that contains only an IP address (`<HOST>` is fail2ban's placeholder for IP addresses). In this case, we use **one IP per row** as a result of the Krawl detection engine for attackers.

### 2. Create the Jail Configuration [krawl-jail.conf](krawl-jail.conf)
### 2.1 Krawl is on the same host
Create `/etc/fail2ban/jail.d/krawl-jail.conf` and replace the `logpath` with the path to the krawl `malicious_ips.txt`: 

```ini
[krawl]
enabled = true
filter = krawl
logpath = /path/to/malicious_ips.txt
backend = auto
maxretry = 1
findtime = 1
bantime = 2592000
action = iptables-allports[name=krawl-ban, port=all, protocol=all]
```
### 2.2 Krawl is on a different host

If Krawl is deployed on another instance, you can use the Krawl API to get malicious IPs via a **curl** command scheduled with **cron**.

```bash
curl http://your-krawl-instance/dashboard-path/api/export-ips?categories=attacker&fwtype=raw -o malicious_ips.txt
```

#### Cron Setup

Edit your crontab to refresh the malicious IPs list:

```bash
sudo crontab -e
```

Add this single cron job to fetch malicious IPs every hour:

```bash
0 * * * * curl http://your-krawl-instance/dashboard-path/api/export-ips?categories=attacker&fwtype=raw -o /tmp/malicious_ips.txt
```

Replace the `krawl-jail.conf` **logpath** with `/tmp/malicious_ips.txt`.

### 3. Reload Fail2Ban

```bash
sudo systemctl restart fail2ban
```

Verify the jail is active:

```bash
sudo fail2ban-client status krawl
```

## How It Works

### When an IP is Added to malicious_ips.txt

1. **Fail2ban detects the new line** in the log file (via inotify)
2. **Filter regex matches** the IP address pattern
3. **maxretry check:** Since maxretry=1, ban immediately
4. **Action triggered:** `iptables-allports` adds a firewall block rule
5. **IP is blocked** on all ports and protocols

### When the 30-Day Rotation Occurs

Your malicious IPs file is rotated every 30 days. With `bantime = 2592000` (30 days):

If you used `bantime = -1` (permanent), old IPs would remain banned forever even after removal from the file. This option is not recommended because external IPs can rotate and are unlikely to be static.

## Monitoring

### Check Currently Banned IPs

```bash
sudo fail2ban-client status krawl
```

### View Fail2Ban Logs

```bash
sudo tail -f /var/log/fail2ban.log | grep krawl
```

## Management Commands

### Manually Ban an IP

```bash
sudo fail2ban-client set krawl banip 192.168.1.100
```

### Manually Unban an IP

```bash
sudo fail2ban-client set krawl unbanip 192.168.1.100
```


### Clear All Bans in Krawl Jail

```bash
sudo fail2ban-client set krawl unbanall
```

### Restart the Krawl Jail Only

```bash
sudo fail2ban-client restart krawl
```

## References

- [Fail2Ban Documentation](https://www.fail2ban.org/wiki/index.php/Main_Page)
- [Fail2Ban Configuration Manual](https://www.fail2ban.org/wiki/index.php/Jail.conf)
- [Iptables Basics](https://www.digitalocean.com/community/tutorials/iptables-essentials-common-firewall-rules-and-commands)
