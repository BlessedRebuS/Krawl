# Canary Token Integration

Krawl can embed a [canary token](https://canarytokens.org) link into honeypot pages. When a crawler clicks it, you receive an email alert with the visitor's IP address and user agent.

## How It Works

Krawl maintains a **page counter** that starts at the value of `KRAWL_CANARY_TOKEN_TRIES` (default: 10). Every time a honeypot page is served, the counter decrements by 1. When the counter reaches 0, the canary token URL is injected as a clickable link in the generated page.

After triggering, the counter resets back to `KRAWL_CANARY_TOKEN_TRIES` and the cycle repeats.

This means:
- With the default value of `10`, the canary token link appears on every 10th page view.
- The counter is **global** (shared across all visitors), not per-IP.
- Automated crawlers that follow all links on a page will eventually hit the canary token URL, triggering the alert.

## Setup

1. Visit [canarytokens.org](https://canarytokens.org) and generate a **"Web bug / URL token"**.
2. Enter your email address to receive alerts.
3. Copy the generated URL.

## Configuration

Set the canary token URL via environment variable:

```bash
export KRAWL_CANARY_TOKEN_URL="http://canarytokens.com/your-token-id/submit.aspx"
export KRAWL_CANARY_TOKEN_TRIES=10  # Optional: number of pages before token appears
```

Or via `config.yaml`:

```yaml
canary:
  token_url: "http://canarytokens.com/your-token-id/submit.aspx"
  token_tries: 10
```

See the full [environment variables reference](../README.md#configuration-via-environmental-variables) for more configuration options.
