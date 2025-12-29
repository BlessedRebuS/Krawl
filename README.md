<h1 align="center">🕷️ Krawl</h1>

<h3 align="center">
  <a name="readme-top"></a>
  <img
    src="img/krawl-logo.jpg"
    height="200"
  >
</h3>
<div align="center">

<p align="center">
  A modern, customizable zero-dependencies honeypot server designed to detect and track malicious activity through deceptive web pages, fake credentials, and canary tokens.
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
  <a href="#-quick-start">Quick Start</a> •
  <a href="#honeypot-pages">Honeypot Pages</a> •
  <a href="#dashboard">Dashboard</a> •
  <a href="./ToDo.md">Todo</a> •
  <a href="#-contributing">Contributing</a>
</p>

<br>
</div>

## Star History
<img src="https://api.star-history.com/svg?repos=BlessedRebuS/Krawl&type=Date" width="600" alt="Star History Chart" />

## Try Krawl
Tip: crawl the `robots.txt` paths for additional fun
###  http://demo.krawlme.com
## View the dashboard 
### http://demo.krawlme.com/das_dashboard

## What is Krawl?

**Krawl** is a cloud‑native deception server designed to detect, delay, and analyze malicious web crawlers and automated scanners.

It creates realistic fake web applications filled with low‑hanging fruit such as admin panels, configuration files, and exposed fake credentials to attract and identify suspicious activity.

By wasting attacker resources, Krawl helps clearly distinguish malicious behavior from legitimate crawlers.

It features:

- **Spider Trap Pages**: Infinite random links to waste crawler resources based on the [spidertrap project](https://github.com/adhdproject/spidertrap)
- **Fake Login Pages**: WordPress, phpMyAdmin, admin panels
- **Honeypot Paths**: Advertised in robots.txt to catch scanners
- **Fake Credentials**: Realistic-looking usernames, passwords, API keys
- **[Canary Token](#customizing-the-canary-token) Integration**: External alert triggering
- **Real-time Dashboard**: Monitor suspicious activity
- **Customizable Wordlists**: Easy JSON-based configuration
- **Random Error Injection**: Mimic real server behavior

![asd](img/deception-page.png)

## 🚀 Quick Start
## Helm Chart

Install with default values

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart \
  --namespace krawl-system \
  --create-namespace
```

Install with custom [canary token](#customizing-the-canary-token) 

```bash
helm install krawl oci://ghcr.io/blessedrebus/krawl-chart \
  --namespace krawl-system \
  --create-namespace \
  --set config.canaryTokenUrl="http://your-canary-token-url"
```

To access the deception server

```bash
kubectl get svc krawl -n krawl-system
```

Once the EXTERNAL-IP is assigned, access your deception server at:

```
http://<EXTERNAL-IP>:5000
```

## Kubernetes / Kustomize
Apply all manifests with

```bash
kubectl apply -f https://raw.githubusercontent.com/BlessedRebuS/Krawl/refs/heads/main/manifests/krawl-all-in-one-deploy.yaml
```

Retrieve dashboard path with
```bash
kubectl get secret krawl-server -n krawl-system -o jsonpath='{.data.dashboard-path}' | base64 -d
```

Or clone the repo and apply the `manifest` folder with

```bash
kubectl apply -k manifests
```

## Docker
Run Krawl as a docker container with

```bash
docker run -d \
  -p 5000:5000 \
  -e CANARY_TOKEN_URL="http://your-canary-token-url" \
  --name krawl \
  ghcr.io/blessedrebus/krawl:latest
```

## Docker Compose
Run Krawl with docker-compose in the project folder with

```bash
docker-compose up -d
```

Stop it with

```bash
docker-compose down
```

## Python 3.11+

Clone the repository

```bash
git clone https://github.com/blessedrebus/krawl.git
cd krawl/src
```
Run the server
```bash
python3 server.py
```

Visit

`http://localhost:5000`

To access the dashboard

`http://localhost:5000/<dashboard-secret-path>`

## Configuration via Environment Variables

To customize the deception server installation several **environment variables** can be specified.

| Variable | Description | Default |
|----------|-------------|---------|
| `PORT` | Server listening port | `5000` |
| `DELAY` | Response delay in milliseconds | `100` |
| `LINKS_MIN_LENGTH` | Minimum random link length | `5` |
| `LINKS_MAX_LENGTH` | Maximum random link length | `15` |
| `LINKS_MIN_PER_PAGE` | Minimum links per page | `10` |
| `LINKS_MAX_PER_PAGE` | Maximum links per page | `15` |
| `MAX_COUNTER` | Initial counter value | `10` |
| `CANARY_TOKEN_TRIES` | Requests before showing canary token | `10` |
| `CANARY_TOKEN_URL` | External canary token URL | None |
| `DASHBOARD_SECRET_PATH` | Custom dashboard path | Auto-generated |
| `PROBABILITY_ERROR_CODES` | Error response probability (0-100%) | `0` |
| `SERVER_HEADER` | HTTP Server header for deception | `Apache/2.2.22 (Ubuntu)` |

## robots.txt
The actual (juicy) robots.txt configuration is the following

```txt
Disallow: /admin/
Disallow: /api/
Disallow: /backup/
Disallow: /config/
Disallow: /database/
Disallow: /private/
Disallow: /uploads/
Disallow: /wp-admin/
Disallow: /phpMyAdmin/
Disallow: /admin/login.php
Disallow: /api/v1/users
Disallow: /api/v2/secrets
Disallow: /.env
Disallow: /credentials.txt
Disallow: /passwords.txt
Disallow: /.git/
Disallow: /backup.sql
Disallow: /db_backup.sql
```

## Honeypot pages
Requests to common admin endpoints (`/admin/`, `/wp-admin/`, `/phpMyAdmin/`) return a fake login page. Any login attempt triggers a 1-second delay to simulate real processing and is fully logged in the dashboard (credentials, IP, headers, timing).

<div align="center">
  <img src="img/admin-page.png" width="60%" />
</div>

Requests to paths like `/backup/`, `/config/`, `/database/`, `/private/`, or `/uploads/` return a fake directory listing populated with “interesting” files, each assigned a random file size to look realistic.

![directory-page](img/directory-page.png)

The `.env` endpoint exposes fake database connection strings, **AWS API keys**, and **Stripe secrets**. It intentionally returns an error due to the `Content-Type` being `application/json` instead of plain text, mimicking a “juicy” misconfiguration that crawlers and scanners often flag as information leakage.

![env-page](img/env-page.png)

The pages `/api/v1/users` and `/api/v2/secrets` show fake users and random secrets in JSON format

<div align="center">
  <img src="img/api-users-page.png" width="45%" style="vertical-align: middle; margin: 0 10px;" />
  <img src="img/api-secrets-page.png" width="45%" style="vertical-align: middle; margin: 0 10px;" />
</div>

The pages `/credentials.txt` and `/passwords.txt` show fake users and random secrets 

<div align="center">
  <img src="img/credentials-page.png" width="35%" style="vertical-align: middle; margin: 0 10px;" />
  <img src="img/passwords-page.png" width="45%" style="vertical-align: middle; margin: 0 10px;" />
</div>

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
- Suspicious activity detection
- Top IPs, paths, and user-agents
- Real-time monitoring

The attackers' triggered honeypot path and the suspicious activity (such as failed login attempts) are logged

![dashboard-1](img/dashboard-1.png)

The top IP Addresses is shown along with top paths and User Agents

![dashboard-2](img/dashboard-2.png)

### Retrieving Dashboard Path

Check server startup logs or get the secret with 

```bash
kubectl get secret krawl-server -n krawl-system \
  -o jsonpath='{.data.dashboard-path}' | base64 -d && echo
```

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
