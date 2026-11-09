# CrowdSec + Krawl Integration

Feeds the IPs Krawl has already classified as attackers into CrowdSec as ban
decisions, so CrowdSec's own bouncers (nginx, firewall, Cloudflare) enforce them
without Krawl writing firewall rules itself.

## Why decisions rather than rules

CrowdSec already owns enforcement and knows which remediation component sits in
front of each service. A ruleset exported from Krawl would duplicate that and
would have to be kept in step with whatever bouncer is installed; a decisions
list lets CrowdSec decide how to apply the ban.

## Prerequisites

- CrowdSec installed with `cscli` on the host that runs the sync
- Krawl running with the API reachable
- `curl`
- Cron (or a systemd timer) for scheduling

## Setup

### 1. Create the script

```bash
#!/bin/bash
KRAWL_URL="https://your-krawl-instance/your-dashboard-path"
OUT="$(mktemp /tmp/krawl_crowdsec.XXXXXX.json)"
trap 'rm -f "${OUT}"' EXIT
curl -fsS "${KRAWL_URL}/api/export-ips?categories=attacker&fwtype=crowdsec" -o "${OUT}"
[ -s "${OUT}" ] || { echo "nothing to import"; exit 1; }
cscli decisions import -i "${OUT}" --format json
```

Save as `krawl-crowdsec.sh`, `chmod +x` it, and run it once by hand to confirm
the import works before scheduling it.

The export is JSON because `cscli decisions import` reads only csv, json or
values, and chooses the parser from the file extension; the `--format json`
flag makes that explicit when a temp file has an unexpected name.

### 2. Schedule it

```cron
*/30 * * * * /usr/local/bin/krawl-crowdsec.sh >> /var/log/krawl-crowdsec.log 2>&1
```

Decisions carry the duration Krawl emits (4h by default, `CROWDSEC_BAN_DURATION`
in `src/firewall/__init__.py`). Importing a decision that already exists
refreshes it, so a 30-minute sync keeps the bans alive without piling up
duplicates, and an attacker that stops appearing expires on its own.

## Notes

- Importing the same IP repeatedly is safe: CrowdSec treats it as the same
  decision rather than creating duplicates.
- If Krawl is unreachable the script exits non-zero and leaves CrowdSec's
  existing decisions alone, so a failed sync does not unban anyone.
- `categories` accepts the same values as the other exporters (`attacker`,
  `bad_crawler`, and so on); importing `regular_user` here would ban your
  legitimate traffic.
