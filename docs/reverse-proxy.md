# Deploying Behind a Reverse Proxy

You can configure a reverse proxy so all web requests land on Krawl by default, and hide your real content behind a secret URL.

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
