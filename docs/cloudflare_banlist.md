# Cloudflare Banlist Sync

When a site sits behind Cloudflare's proxy, the origin server never sees the real client IP every request arrives from Cloudflare's edge IP ranges, and the actual attacker IP is only available in the **CF-Connecting-IP header**. This means IP bans applied at the origin, such as iptables, fail2ban, or application-level blocklists, are largely ineffective, since you'd be blocking Cloudflare's own infrastructure instead of the attacker, while the malicious traffic keeps flowing through the proxy to your app.

To solve this, we implemented banning at the edge instead of the origin. Krawl pushes banned IPs directly into a Cloudflare Account IP List via the API, and that list is referenced in a Cloudflare WAF rule. This means the block happens before the request ever reaches your infrastructure, at Cloudflare's network layer, using the real client IP that Cloudflare itself observed rather than a spoofable header.

The integration works on Cloudflare's free plan, which supports one IP List with up to **10,000 entries**. A background task performs the sync on a configurable interval, using full list replacement rather than incremental updates. Everything is configured from the Webhooks tab in the Krawl dashboard, with no manual API token setup or curl commands required. Once active, the list is visible under the Cloudflare account's Lists configuration and can be attached to any WAF custom rule.

## Prerequisites

A Cloudflare API token with two permissions:

- Account Rule Lists Read
- Account Rule Lists Write

Create one at https://dash.cloudflare.com/profile/api-tokens. Use the "Edit Cloudflare IP Lists" template or manually select Account > Rule Lists > Read + Write under the account you want to target.

You also need your Account ID (32 hex characters). Find it at https://dash.cloudflare.com/ in the right sidebar under "Account ID", or via the guide at https://developers.cloudflare.com/fundamentals/account/find-account-and-zone-ids/.

## Setup

1. Go to the Webhooks tab in the Krawl dashboard
2. Enter your Account ID and API Token
3. Set a list name (default: `krawl_banlist`)
4. Select which IP categories to include (attacker, bad_crawler, regular_user, good_crawler, timed_out)
5. Set the sync interval in minutes
6. Click Save

The server tests the connection, creates the list if it doesn't exist, and starts the background sync loop. The list appears at https://dash.cloudflare.com/YOUR_ACCOUNT_ID/configurations/lists.

Once the configuration is set up, the CloudFlare list page should appear like this:

![Cloudflare IP List in dashboard](../img/cloudflare-banlist.png)

## How it works

The background task (`src/tasks/sync_cloudflare.py`) runs every 60 seconds. On each tick it checks whether the webhook is enabled and, if so, reads the current banlist from the database, filters for public IPs only, and does a full PUT replace of all items in the Cloudflare list.

If the list ID saved in config no longer exists (deleted from the Cloudflare dashboard), the task searches existing lists by name. If a match is found it uses that list ID; otherwise it creates a new list.
