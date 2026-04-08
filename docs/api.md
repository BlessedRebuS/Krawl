# External APIs

Krawl calls a set of external APIs to enrich IP data, resolve geolocation, and check reputation. All external calls happen in background tasks — they never block incoming requests.

## IP Geolocation

| Service | URL | Used for |
|---------|-----|----------|
| [ip-api.com](http://ip-api.com) | `http://ip-api.com/json/{ip}` | Country, city, ISP, ASN, proxy/hosting flags |

- **Called by**: `fetch_ip_rep` background task (runs every 5 minutes)
- **Timeout**: 5 seconds
- **Rate limits**: ip-api.com allows 45 requests/minute on the free tier. Krawl processes up to 50 unenriched IPs per task run.
- **Caching**: Results are persisted to the database after enrichment — the API is only called once per IP.
- **Fallback**: If the API is unreachable, the IP remains unenriched and is retried on the next task run.
- **Note**: Private/internal IPs are skipped automatically.

## IP Reputation

| Service | URL | Used for |
|---------|-----|----------|
| [iprep.lcrawl.com](https://iprep.lcrawl.com) | `https://iprep.lcrawl.com/api/iprep/?cidr={ip}` | Blocklist status and reputation data |

- **Called by**: `fetch_ip_rep` background task (same task as geolocation, every 5 minutes)
- **Timeout**: 10 seconds
- **Caching**: Results are persisted to the database alongside geolocation data.
- **Fallback**: If the API fails, geolocation enrichment still proceeds — the blocklist data is simply empty for that IP.

## Server IP Discovery

These services are used **once at startup** to determine the server's own public IP address. This IP is then excluded from traffic statistics.

| Service | URL |
|---------|-----|
| [api.ipify.org](https://api.ipify.org) | `https://api.ipify.org` |
| [ident.me](http://ident.me) | `http://ident.me` |
| [ifconfig.me](https://ifconfig.me) | `https://ifconfig.me` |

- **Timeout**: 5 seconds per service
- **Fallback**: Services are tried in sequence — if one fails, the next is attempted. If all fail, a warning is logged and Krawl continues without filtering its own IP.

## Reverse Geocoding

| Service | URL | Used for |
|---------|-----|----------|
| [nominatim.openstreetmap.org](https://nominatim.openstreetmap.org) | `https://nominatim.openstreetmap.org/reverse` | Reverse geocoding (latitude/longitude to address) |

- Listed for reference; usage depends on dashboard features.
