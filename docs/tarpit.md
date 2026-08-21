# Tarpit

The tarpit makes Krawl a deliberately expensive place to crawl. When enabled, every
honeypot response is delayed and padded with meaningless generated text, so automated
crawlers — in particular the ones harvesting pages to train models — burn time and
collect noise.

It is **opt-in** and off by default.

## What it does

Two things, applied to honeypot traffic only:

1. **Delay** — an extra `delay_seconds` on top of the normal `server.delay`, applied to
   every honeypot response. A crawler that would have fetched a hundred pages a minute
   gets a handful.
2. **Word salad** — each generated page carries a block of randomly chosen words with no
   meaning or grammar, styled as ordinary muted page text. It costs a scraper storage and
   tokens and contributes nothing usable to a dataset.

Combined with `crawl.infinite_pages_for_malicious`, a crawler that keeps following links
never reaches an end, and every step costs it `delay_seconds`.

## Configuration

```yaml
tarpit:
  enabled: true       # off by default
  delay_seconds: 5    # added to every honeypot response
```

| Env var | Description | Default |
|---|---|---|
| `KRAWL_TARPIT_ENABLED` | Enable the tarpit | `false` |
| `KRAWL_TARPIT_DELAY_SECONDS` | Extra delay per honeypot response | `5` |

Helm:

```yaml
config:
  tarpit:
    enabled: true
    delay_seconds: 5
```

## Choosing a delay

`delay_seconds` trades effectiveness against your own resources: each waiting request
holds a connection for the whole delay. Krawl waits asynchronously, so a slow response
costs a connection rather than a worker, but the connections are still real.

- **1–5 s** — noticeable drag on crawlers, negligible cost. Good starting point.
- **10–30 s** — genuinely painful for a crawler, but expect a large number of concurrent
  open connections under sustained scanning. Confirm your reverse proxy and Krawl's
  connection limits can absorb it.
- Above that, most clients time out and disconnect, which ends the tarpit early and
  achieves less than a delay they will sit through.

Watch `krawl_accesses_total` and your connection counts after enabling it: the intended
result is fewer requests per crawler, not more.

## Caveats

- **The tarpit applies to every honeypot visitor**, not only to IPs already classified as
  malicious — including search engine crawlers that respect your `robots.txt` and any
  human who lands on the honeypot. This is fine for a dedicated honeypot host and a poor
  fit for a decoy path on a site you want indexed.
- The dashboard is not affected, only honeypot pages.
- Behind a reverse proxy, make sure its own read/response timeout is longer than
  `delay_seconds`, or the proxy will cut the connection and return its own error page
  instead of the tarpit. See [Reverse Proxy](reverse-proxy.md).
