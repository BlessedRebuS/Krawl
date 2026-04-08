# Customizing the Wordlist

Krawl uses a `wordlists.json` file to generate realistic fake data for honeypot pages. You can customize this file to tailor the deception content to your environment.

## File Location

- **Default path**: `wordlists.json` in the project root (next to `config.yaml`)
- **Docker**: Mount as a volume: `-v ./wordlists.json:/app/wordlists.json:ro`
- **Helm**: Configure via `values.yaml` under the wordlists ConfigMap (see [Helm chart documentation](../helm/README.md))

If the file is missing or contains invalid JSON, Krawl falls back to built-in defaults.

## Reload Behavior

Wordlists are loaded **once at startup**. Changes to `wordlists.json` require restarting Krawl to take effect.

## Structure

The file supports the following top-level fields:

```json
{
  "usernames": {
    "prefixes": ["admin", "root", "user", "deploy"],
    "suffixes": ["_prod", "_dev", "_backup", "123"]
  },
  "passwords": {
    "prefixes": ["P@ssw0rd", "Admin", "Welcome"],
    "simple": ["test", "password", "changeme"]
  },
  "emails": {
    "domains": ["company.com", "internal.corp"]
  },
  "api_keys": {
    "prefixes": ["sk-", "ak-", "AKIA"]
  },
  "databases": {
    "names": ["production", "users_db", "main"],
    "hosts": ["db-prod.internal", "10.0.1.50"]
  },
  "applications": {
    "names": ["wordpress", "jira", "confluence"]
  },
  "users": {
    "roles": ["admin", "operator", "readonly"]
  },
  "directory_listing": {
    "files": ["credentials.txt", "backup.sql", ".env", "wp-config.php"],
    "directories": ["admin/", "backup/", ".git/", "config/"]
  },
  "server_headers": ["Apache/2.4.41", "nginx/1.18.0", "Microsoft-IIS/10.0"],
  "error_codes": [400, 403, 404, 500, 502, 503]
}
```

### Field Descriptions

| Field | Description |
|-------|-------------|
| `usernames` | Prefixes and suffixes combined to generate fake usernames in credential pages |
| `passwords` | Used to generate realistic-looking passwords shown in fake credential files |
| `emails` | Domains used to generate fake email addresses |
| `api_keys` | Prefixes for generating fake API keys (e.g., AWS-style `AKIA...`) |
| `databases` | Database names and hosts shown in fake configuration files |
| `applications` | Application names used in fake admin panels and configs |
| `users` | Roles displayed in fake user management pages |
| `directory_listing` | Files and directories shown in fake directory listing pages |
| `server_headers` | Server header values randomly rotated in HTTP responses |
| `error_codes` | HTTP status codes used when random error injection is enabled |

Additional fields (`fake_passwd`, `fake_shadow`, `xxe_responses`, `command_outputs`, `sql_errors`, `attack_patterns`, `suspicious_patterns`, `credential_fields`) are also supported — see the default `wordlists.json` for the full schema.
