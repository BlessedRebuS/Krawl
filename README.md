<h1 align="center">Krawl</h1>

<h3 align="center">
  <a name="readme-top"></a>
  <img
    src="img/krawl-svg.svg"
    height="250"
  >
</h3>
<div align="center">

<p align="center">
  A modern, customizable web honeypot server designed to detect and track malicious activity from attackers and web crawlers through deceptive web pages, fake credentials, and canary tokens.
</p>

<div align="center">
  <a href="https://github.com/blessedrebus/krawl/blob/main/LICENSE">
    <img src="https://img.shields.io/github/license/blessedrebus/krawl" alt="License">
  </a>
  <a href="https://github.com/blessedrebus/krawl/releases">
    <img src="https://img.shields.io/github/v/release/blessedrebus/krawl" alt="Release">
  </a>
</div>

<div align="center">
  <a href="https://ghcr.io/blessedrebus/krawl">
    <img src="https://img.shields.io/badge/ghcr.io-krawl-blue" alt="GitHub Container Registry">
  </a>
  <a href="https://kubernetes.io/">
    <img src="https://img.shields.io/badge/kubernetes-ready-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes">
  </a>
  <a href="https://github.com/BlessedRebuS/Krawl/pkgs/container/krawl-chart">
    <img src="https://img.shields.io/badge/helm-chart-0F1689?logo=helm&logoColor=white" alt="Helm Chart">
  </a>
</div>

<br>

<p align="center">
  <a href="#what-is-krawl">What is Krawl?</a> •
  <a href="#-installation">Installation</a> •
  <a href="#honeypot-pages">Honeypot Pages</a> •
  <a href="#dashboard">Dashboard</a> •
  <a href="./ToDo.md">Todo</a> •
  <a href="#-contributing">Contributing</a>
</p>

<br>
</div>

## Demo
Tip: crawl the `robots.txt` paths for additional fun
### Krawl URL: [http://demo.krawlme.com](http://demo.krawlme.com)
### View the dashboard [http://demo.krawlme.com/das_dashboard](http://demo.krawlme.com/das_dashboard)

## What is Krawl?

**Krawl** is a cloud‑native deception server designed to detect, delay, and analyze malicious attackers, web crawlers and automated scanners.

It creates realistic fake web applications filled with low‑hanging fruit such as admin panels, configuration files, and exposed fake credentials to attract and identify suspicious activity.

By wasting attacker resources, Krawl helps clearly distinguish malicious behavior from legitimate crawlers.

It features:

- **Spider Trap Pages**: Infinite random links to waste crawler resources based on the [spidertrap project](https://github.com/adhdproject/spidertrap)
- **Fake Login Pages**: WordPress, phpMyAdmin, admin panels
- **Honeypot Paths**: Advertised in robots.txt to catch scanners
- **Fake Credentials**: Realistic-looking usernames, passwords, API keys
- **[Canary Token](#customizing-the-canary-token) Integration**: External alert triggering
- **Random server headers**: Confuse attacks based on server header and version
- **Real-time Dashboard**: Monitor suspicious activity
- **Customizable Wordlists**: Easy JSON-based configuration
- **Random Error Injection**: Mimic real server behavior

![dashboard](img/deception-page.png)

![geoip](img/geoip_dashboard.png)

## 🚀 Installation

### Docker Run

Run Krawl with the latest image:

```bash
docker run -d \
  -p 5000:5000 \
  -e KRAWL_PORT=5000 \
  -e KRAWL_DELAY=100 \
  -e KRAWL_DASHBOARD_SECRET_PATH="/my-secret-dashboard" \
  -e KRAWL_DATABASE_RETENTION_DAYS=30 \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

Access the server at `http://localhost:5000`

### Docker Compose

Create a `docker-compose.yaml` file:

```yaml
services:
  krawl:
    image: ghcr.io/blessedrebus/krawl:latest
    container_name: krawl-server
    ports:
      - "5000:5000"
    environment:
      - CONFIG_LOCATION=config.yaml
      - TZ="Europe/Rome"
    volumes:
      - ./config.yaml:/app/config.yaml:ro
      - krawl-data:/app/data
    restart: unless-stopped

volumes:
  krawl-data:
```

Run with:

```bash
docker-compose up -d
```

Stop with:

```bash
docker-compose down
```

### Kubernetes
**Krawl is also available natively on Kubernetes**. Installation can be done either [via manifest](kubernetes/README.md) or [using the helm chart](helm/README.md).

## Use Krawl to Ban Malicious IPs
Krawl uses a reputation-based system to classify attacker IP addresses. Every five minutes, Krawl exports the identified malicious IPs to a `malicious_ips.txt` file.

This file can either be mounted from the Docker container into another system or downloaded directly via `curl`:

```bash
curl https://your-krawl-instance/<DASHBOARD-PATH>/api/download/malicious_ips.txt
```

This file can be used to [update a set of firewall rules](https://www.allthingstech.ch/using-opnsense-and-ip-blocklists-to-block-malicious-traffic), for example on OPNsense and pfSense, enabling automatic blocking of malicious IPs or using IPtables

## IP Reputation
Krawl [uses tasks that analyze recent traffic to build and continuously update an IP reputation](src/tasks/analyze_ips.py) score. It runs periodically and evaluates each active IP address based on multiple behavioral indicators to classify it as an attacker, crawler, or regular user. Thresholds are fully customizable.

![ip reputation](img/ip-reputation.png)

The analysis includes:
- **Risky HTTP methods usage** (e.g. POST, PUT, DELETE ratios)
- **Robots.txt violations**
- **Request timing anomalies** (bursty or irregular patterns)
- **User-Agent consistency**
- **Attack URL detection** (e.g. SQL injection, XSS patterns)

Each signal contributes to a weighted scoring model that assigns a reputation category:
- `attacker`
- `bad_crawler`
- `good_crawler`
- `regular_user`
- `unknown` (for insufficient data)

The resulting scores and metrics are stored in the database and used by Krawl to drive dashboards, reputation tracking, and automated mitigation actions such as IP banning or firewall integration.

## Forward server header
If Krawl is deployed behind a proxy such as NGINX the **server header** should be forwarded using the following configuration in your proxy:

```bash
location / {
    proxy_pass https://your-krawl-instance;
    proxy_pass_header Server;
}
```

## API
Krawl uses the following APIs
- https://iprep.lcrawl.com (IP Reputation)
- https://nominatim.openstreetmap.org/reverse (Reverse IP Lookup)
- https://api.ipify.org (Public IP discovery)
- http://ident.me (Public IP discovery)
- https://ifconfig.me (Public IP discovery)

## Configuration
Krawl uses a **configuration hierarchy** in which **environment variables take precedence over the configuration file**. This approach is recommended for Docker deployments and quick out-of-the-box customization.

### Configuration via Enviromental Variables

| Environment Variable | Description | Default |
|----------------------|-------------|---------|
| `CONFIG_LOCATION` | Path to yaml config file | `config.yaml` |
| `KRAWL_PORT` | Server listening port | `5000` |
| `KRAWL_DELAY` | Response delay in milliseconds | `100` |
| `KRAWL_SERVER_HEADER` | HTTP Server header for deception | `""` |
| `KRAWL_LINKS_LENGTH_RANGE` | Link length range as `min,max` | `5,15` |
| `KRAWL_LINKS_PER_PAGE_RANGE` | Links per page as `min,max` | `10,15` |
| `KRAWL_CHAR_SPACE` | Characters used for link generation | `abcdefgh...` |
| `KRAWL_MAX_COUNTER` | Initial counter value | `10` |
| `KRAWL_CANARY_TOKEN_URL` | External canary token URL | None |
| `KRAWL_CANARY_TOKEN_TRIES` | Requests before showing canary token | `10` |
| `KRAWL_DASHBOARD_SECRET_PATH` | Custom dashboard path | Auto-generated |
| `KRAWL_PROBABILITY_ERROR_CODES` | Error response probability (0-100%) | `0` |
| `KRAWL_DATABASE_PATH` | Database file location | `data/krawl.db` |
| `KRAWL_DATABASE_RETENTION_DAYS` | Days to retain data in database | `30` |
| `KRAWL_HTTP_RISKY_METHODS_THRESHOLD` | Threshold for risky HTTP methods detection | `0.1` |
| `KRAWL_VIOLATED_ROBOTS_THRESHOLD` | Threshold for robots.txt violations | `0.1` |
| `KRAWL_UNEVEN_REQUEST_TIMING_THRESHOLD` | Coefficient of variation threshold for timing | `0.5` |
| `KRAWL_UNEVEN_REQUEST_TIMING_TIME_WINDOW_SECONDS` | Time window for request timing analysis in seconds | `300` |
| `KRAWL_USER_AGENTS_USED_THRESHOLD` | Threshold for detecting multiple user agents | `2` |
| `KRAWL_ATTACK_URLS_THRESHOLD` | Threshold for attack URL detection | `1` |
| `KRAWL_INFINITE_PAGES_FOR_MALICIOUS` | Serve infinite pages to malicious IPs | `true` |
| `KRAWL_MAX_PAGES_LIMIT` | Maximum page limit for crawlers | `250` |
| `KRAWL_BAN_DURATION_SECONDS` | Ban duration in seconds for rate-limited IPs | `600` |

For example

```bash
# Set canary token
export CONFIG_LOCATION="config.yaml" 
export KRAWL_CANARY_TOKEN_URL="http://your-canary-token-url"

# Set number of pages range (min,max format)
export KRAWL_LINKS_PER_PAGE_RANGE="5,25"

# Set analyzer thresholds
export KRAWL_HTTP_RISKY_METHODS_THRESHOLD="0.2"
export KRAWL_VIOLATED_ROBOTS_THRESHOLD="0.15"

# Set custom dashboard path
export KRAWL_DASHBOARD_SECRET_PATH="/my-secret-dashboard"
```

Example of a Docker run with env variables:

```bash
docker run -d \
  -p 5000:5000 \
  -e KRAWL_PORT=5000 \
  -e KRAWL_DELAY=100 \
  -e KRAWL_CANARY_TOKEN_URL="http://your-canary-token-url" \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

### Configuration via config.yaml
You can use the [config.yaml](config.yaml) file for more advanced configurations, such as Docker Compose or Helm chart deployments.

# Honeypot
Below is a complete overview of the Krawl honeypot’s capabilities

## robots.txt
The actual (juicy) robots.txt configuration [is the following](src/templates/html/robots.txt). 

## Honeypot pages
Requests to common admin endpoints (`/admin/`, `/wp-admin/`, `/phpMyAdmin/`) return a fake login page. Any login attempt triggers a 1-second delay to simulate real processing and is fully logged in the dashboard (credentials, IP, headers, timing).

![admin page](img/admin-page.png)


Requests to paths like `/backup/`, `/config/`, `/database/`, `/private/`, or `/uploads/` return a fake directory listing populated with “interesting” files, each assigned a random file size to look realistic.

![directory-page](img/directory-page.png)

The `.env` endpoint exposes fake database connection strings, **AWS API keys**, and **Stripe secrets**. It intentionally returns an error due to the `Content-Type` being `application/json` instead of plain text, mimicking a “juicy” misconfiguration that crawlers and scanners often flag as information leakage.

The `/server` page displays randomly generated fake error information for each known server.

![server and env page](img/server-and-env-page.png)

The pages `/api/v1/users` and `/api/v2/secrets` show fake users and random secrets in JSON format

![users and secrets](img/users-and-secrets.png)

The pages `/credentials.txt` and `/passwords.txt` show fake users and random secrets 

![credentials and passwords](img/credentials-and-passwords.png)

Pages such as `/users`, `/search`, `/contact`, `/info`, `/input`, and `/feedback`, along with APIs like `/api/sql` and `/api/database`, are designed to lure attackers into performing attacks such as **SQL injection** or **XSS**. 

![sql injection](img/sql_injection.png)

Automated tools like **SQLMap** will receive a different randomized database error on each request, increasing scan noise and confusing the attacker. All detected attacks are logged and displayed in the dashboard.

## Customizing the Canary Token
To create a custom canary token, visit https://canarytokens.org

and generate a “Web bug” canary token.

This optional token is triggered when a crawler fully traverses the webpage until it reaches 0. At that point, a URL is returned. When this URL is requested, it sends an alert to the user via email, including the visitor’s IP address and user agent.


To enable this feature, set the canary token URL [using the environment variable](#configuration-via-environment-variables) `CANARY_TOKEN_URL`.

## Customizing the wordlist 

Edit `wordlists.json` to customize fake data for your use case

```json
{
  "usernames": {
    "prefixes": ["admin", "root", "user"],
    "suffixes": ["_prod", "_dev", "123"]
  },
  "passwords": {
    "prefixes": ["P@ssw0rd", "Admin"],
    "simple": ["test", "password"]
  },
  "directory_listing": {
    "files": ["credentials.txt", "backup.sql"],
    "directories": ["admin/", "backup/"]
  }
}
```

or **values.yaml** in the case of helm chart installation

## Dashboard

Access the dashboard at `http://<server-ip>:<port>/<dashboard-path>`

The dashboard shows:
- Total and unique accesses
- Suspicious activity and attack detection
- Top IPs, paths, user-agents and GeoIP localization
- Real-time monitoring

The attackers’ access to the honeypot endpoint and related suspicious activities (such as failed login attempts) are logged. 

Krawl also implements a scoring system designed to distinguish between malicious and legitimate behavior on the website.

![dashboard-1](img/dashboard-1.png)

The top IP Addresses is shown along with top paths and User Agents

![dashboard-2](img/dashboard-2.png)

![dashboard-3](img/dashboard-3.png)

## 🤝 Contributing

Contributions welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Make your changes
4. Submit a pull request (explain the changes!)


<div align="center">

## ⚠️ Disclaimer

**This is a deception/honeypot system.**  
Deploy in isolated environments and monitor carefully for security events.  
Use responsibly and in compliance with applicable laws and regulations.

## Star History
<img src="https://api.star-history.com/svg?repos=BlessedRebuS/Krawl&type=Date" width="600" alt="Star History Chart" />
