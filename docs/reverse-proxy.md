# Deploying Behind a Reverse Proxy or CDN

You can configure a reverse proxy or CDN so all web requests land on Krawl by default, and hide your real content behind a secret URL.

## How Krawl Detects the Real Client IP

Krawl reads proxy headers in priority order to determine the real client IP:

| Priority | Header | Set by |
|----------|--------|--------|
| 1 | `CF-Connecting-IP` | Cloudflare |
| 2 | `X-Forwarded-For` | Standard proxy header (nginx, Traefik, HAProxy, etc.) |
| 3 | `X-Real-IP` | nginx convention |

The first header present wins. This means **Cloudflare and similar CDNs work out of the box**, they set `CF-Connecting-IP` which Krawl picks up immediately.

## Customizing the Header Priority

The checked headers and their order are configurable. If your proxy uses a non-standard header, or you want to change the priority, update the `proxy_headers` list.

### wordlists.json

Edit the top-level `proxy_headers` array in `wordlists.json`:

```json
{
  "proxy_headers": [
    "CF-Connecting-IP",
    "X-Forwarded-For",
    "X-Real-IP"
  ]
}
```

Headers are checked in array order — put the one your proxy sets first. For example, if you're behind AWS ALB (which sets `X-Forwarded-For`), move it to the top:

```json
{
  "proxy_headers": [
    "X-Forwarded-For",
    "X-Real-IP"
  ]
}
```

### Helm Values

Set `wordlists.proxy_headers` in your values file:

```yaml
wordlists:
  proxy_headers:
    - CF-Connecting-IP
    - X-Forwarded-For
    - X-Real-IP
```

## NGINX Configuration

```nginx
location / {
    proxy_pass http://your-krawl-instance:5000;
    proxy_pass_header Server;

    # Required for Krawl to see the real client IP
    proxy_set_header Host $host;
    proxy_set_header X-Real-IP $remote_addr;
    proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    proxy_set_header X-Forwarded-Proto $scheme;
}

location /my-hidden-service {
    proxy_pass https://my-hidden-service;
}
```

> **Important**: The `X-Real-IP` and `X-Forwarded-For` headers are essential. Without them, Krawl sees the proxy's IP instead of the attacker's IP, which breaks IP tracking, reputation scoring, and geolocation.

## Decoy Subdomains

You can create multiple "interesting" looking subdomains that all point to Krawl:

- `admin.example.com`
- `portal.example.com`
- `sso.example.com`
- `login.example.com`
- `vpn.example.com`

Additionally, you may configure your reverse proxy to forward all non-existing subdomains (e.g. `nonexistent.example.com`) to Krawl, so any crawlers guessing subdomains at random will automatically end up at your honeypot.

### Wildcard Subdomain Deception

Pointing a wildcard DNS record (`*.example.com`) at Krawl means any subdomain an attacker guesses, whether it exists or not, lands on your honeypot. This is useful for:

- **Subdomain enumeration scanners**: bots that brute-force thousands of subdomains (`admin.`, `staging.`, `dev.`, `test.`, `vpn.`) hunting for services you haven't registered. With a wildcard DNS record, every guess resolves to Krawl instead of NXDOMAIN, giving early visibility into who's mapping your attack surface. Note that any subdomain you *do* register with its own SSL certificate gets logged publicly regardless (see [crt.sh](https://crt.sh)). Requesting a **wildcard SSL certificate** for `*.rebus.ninja` avoids that leak: one CT log entry instead of one per real subdomain.
- **Abandoned or leaked subdomains**: subdomains referenced in old commits, DNS records, or leaked configs that no longer point at real services. A wildcard catches anyone still probing them.
- **Multi-tenant or multi-brand setups**: if you operate multiple domains or brands, a single Krawl instance can serve as the catch-all for all of them by adding a wildcard Ingress or nginx `server_name` per domain.

### NGINX Wildcard Example

```nginx
server {
    listen 80;
    server_name *.example.com;

    location / {
        proxy_pass http://your-krawl-instance:5000;
        proxy_pass_header Server;
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
```

### Traefik Wildcard Ingress Example

```yaml
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: krawl
  namespace: krawl-system
spec:
  ingressClassName: traefik
  rules:
    - host: '*.your-krawl-instance.com'
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: krawl
                port:
                  number: 5000
    - host: your-krawl-instance.com
      http:
        paths:
          - path: /
            pathType: Prefix
            backend:
              service:
                name: krawl
                port:
                  number: 5000
```