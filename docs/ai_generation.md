# AI-Generated Deception Pages

Krawl can automatically generate realistic deception pages using AI models from OpenRouter or OpenAI APIs. This feature creates unique, plausible honeypot pages on-the-fly to attract and deceive attackers.

## Features

- **Dynamic Page Generation**: Creates unique HTML pages for any request path
- **AI Provider Support**: OpenRouter and OpenAI
- **Smart Caching**: Caches generated pages to avoid redundant API calls
- **Daily Rate Limiting**: Control API costs with configurable daily request limits
- **Fallback Behavior**: Gracefully falls back to standard honeypot when disabled or limit reached
- **Cached Page Serving**: Serve previously cached pages even when AI generation is disabled

## Configuration

### Enable AI Generation

Set in `config.yaml`:
```yaml
ai:
  enabled: true
  provider: "openrouter"  # or "openai"
  api_key: "your-api-key-here"
  model: "nvidia/nemotron-3-super-120b-a12b:free"
  timeout: 60
  max_daily_requests: 10
  prompt: |
    Path: {path}{query_part}
    Generate a realistic deception page...
```

Or use environment variables:
```bash
export KRAWL_AI_ENABLED=true
export KRAWL_AI_PROVIDER=openrouter
export KRAWL_AI_API_KEY=your-api-key
export KRAWL_AI_MODEL=nvidia/nemotron-3-super-120b-a12b:free
export KRAWL_AI_TIMEOUT=60
export KRAWL_AI_MAX_DAILY_REQUESTS=10
```

## Supported Providers

### OpenRouter
Free and paid models available. Recommended for cost-effective generation.

To use AI Generation without charges, use **Free Models** like `nvidia/nemotron-3-super-120b-a12b:free`
- No cost for API calls
- Rate limited (per day)

**Register**: https://openrouter.ai

### OpenAI
Commercial API with various models. It is more than fine a small model like `gpt-5.1-mini` for this use case.

**Register**: https://openai.com/api

## How It Works

1. **Request arrives** for an unknown path
2. **Check database cache**: Serve cached page if available (always returned regardless of AI status)
3. **Check if AI enabled**: If disabled and no cache, fall back to standard honeypot
4. **Check daily limit**: If limit reached, fall back to standard honeypot
5. **Generate page**: Call AI API with customizable prompt
6. **Cache result**: Store generated HTML in database for future requests
7. **Serve page**: Return generated HTML to attacker

## Logging

Generated pages are logged with provider and model information:

```
[AI GENERATED] 127.0.0.1 - /admin/login - openrouter/nvidia/nemotron-3-super-120b-a12b:free
[AI GENERATED] [CACHED] 192.168.1.1 - /config.php - openrouter/nvidia/nemotron-3-super-120b-a12b:free
```

The `[CACHED]` flag indicates the page was served from database cache without calling the AI API.

## Cost Control

### Daily Request Limit

Prevent unexpected API costs:

```yaml
ai:
  max_daily_requests: 5  # Max 5 new pages per day
```

When limit is reached:
- New requests fall back to standard honeypot behavior
- Previously cached pages continue to be served
- Warning logged: "Daily AI generation limit reached"

### Cost Estimation

**Pricing Modelfor gpt-5.1-mini**: [$0.25 input / $2 output per million tokens](https://developers.openai.com/api/docs/models/gpt-5-mini)

**Standard Response**: ~500 tokens per HTML page + ~100 tokens for prompt input

**Cost per deception page**: ~$0.001

**Monthly Costs:**
- 100 pages/month: ~$0.10
- 500 pages/month: ~$0.50
- 1,000 pages/month: ~$1.00

**Using OpenRouter Free Model**: $0 (rate limited, no charge)

## Customization

### Custom Prompt Template

Define how pages should look:

```yaml
ai:
  prompt: |
    Path: {path}{query_part}
    
    Generate a realistic fake webpage that:
    1. Appears to be a legitimate admin interface
    2. Contains realistic-looking forms and fields
    3. Has no obvious honeypot indicators
    4. Includes plausible error messages if applicable
    5. Returns only HTML, no markdown or explanations
    
    Return the complete HTML only:
```

Variables available:
- `{path}` — Request path (e.g., "/admin/login")
- `{query_part}` — Query string if present (e.g., "?id=1")

## Dashboard Integration

Access generated pages tab in the Krawl dashboard:

1. Authenticate with dashboard password
2. Click **Deception** tab
3. View all generated pages
4. See generation timestamps and access counts
5. Manage and delete cached pages

### Set the Daily Quota

Option 1: Increase limit
```yaml
ai:
  max_daily_requests: 20
```

If you want to disable AI, it is possible to keep serving cached pages
```yaml
ai:
  enabled: false  # Cached pages still served
```

### Cached Page Serving Issues

Cached pages are managed in the dashboard **Deception** tab:
- View all cached pages
- See access statistics
- Delete individual pages or by date range
- Bulk operations available