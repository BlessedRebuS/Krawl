# AI-Generated Deception Pages
Krawl AI Deception generation is used to trick attackers into generating useful deception pages. In this way **attackers help generate your fake vulnerable attack surface**.

Krawl can automatically generate realistic deception pages using AI models from OpenRouter, OpenAI APIs or self-hosted LLMs. This feature creates unique, plausible honeypot pages on-the-fly to attract and deceive attackers.

## Configuration

### Enable AI Generation with external services (OpenRouter / OpenAI)

Set in `config.yaml`:
```yaml
ai:
  enabled: true
  provider: "openrouter"  # or "openai"
  # openai_base_url: "your-custom-base-url" #optional for custom API endpoints
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
export KRAWL_AI_OPENAI_BASE_URL=your-custom-base-url
export KRAWL_AI_MODEL=nvidia/nemotron-3-super-120b-a12b:free
export KRAWL_AI_TIMEOUT=60
export KRAWL_AI_MAX_DAILY_REQUESTS=10
```

### Enable AI Generation with self-hosted LLMs

Krawl can be configured to use a self-hosted LLM to generate deception pages using [llama.cpp](https://github.com/ggml-org/llama.cpp) or [ollama](https://ollama.com/).

The [docker-compose setup](../docker-compose.yaml) includes both **llama.cpp** and **Ollama** as optional services.

The LLM endpoint can be configured via `openai_base_url` environment variable pointing to the local service because it is OpenAI compatible. For docker deployments it can be used `http://krawl-llm:8080/v1` as endpoint because it is the service name of the llm.

For detailed configuration options, see [Self-Hosted LLM](#self-hosted-llm-recommended-for-privacy) section below.

## Supported Providers

### OpenRouter
Free and paid models available. Recommended for cost-effective generation.

To use AI Generation without charges, use **Free Models** like `nvidia/nemotron-3-super-120b-a12b:free`
- No cost for API calls
- Rate limited (per day)

**Register**: https://openrouter.ai

### OpenAI
Commercial API with various models. A small model like `gpt-5.1-mini` is more than enough for this use case.

**Register**: https://openai.com/api

### Self-Hosted LLM
For maximum privacy and cost efficiency, Krawl can run with self-hosted LLMs using **llama.cpp** or **Ollama**, either through Docker Compose deployments or on external CPU / GPU-backed instances.

**llama.cpp** is a lightweight C++ inference engine that runs GGUF models directly with minimal overhead, offering maximum raw performance and low memory usage. It provides a simple HTTP server and is ideal when you need full control over a single model.

**Ollama** builds on top of llama.cpp and adds a convenient model management layer, making deployment and model switching easier. The tradeoff is a small performance overhead compared to running llama.cpp directly.

See both [llama.cpp](https://github.com/ggml-org/llama.cpp) and [Ollama](https://docs.ollama.com/) documentation to choose the best engine for your setup.

In our tests, we used models like [Qwen 1.5-1.8B](https://huggingface.co/Qwen/Qwen1.5-1.8B) and [Qwen3.5-4B](https://huggingface.co/Qwen/Qwen3.5-4B) to perform basic **JSON, TXT, and fake vulnerable static HTML page** generation. In order to modify the result on your scenario, modify the  [prompt section](../config.yaml)  in the config.yaml file

In general, the larger the model parameter count, the more polished, realistic, and complex the generated HTML pages tend to be.

> [!NOTE]
> If you do want to use external LLMs (not hosted on docker) just change the `openai_base_url` pointing to your LLMs APIs endpoint

#### Option 1: llama.cpp with Docker Compose

- Deploy the [docker-compose.yaml](../docker-compose.yaml) uncommenting the preferred LLM
- Specify the model from HuggingFace on first run with **repo/model** standard and specify the GGUF file name. [See GGUF documentation for more information](https://huggingface.co/docs/hub/gguf-llamacpp).
```yaml
command: >
  --hf-repo Qwen/Qwen1.5-1.8B-Chat-GGUF
  --hf-file qwen1_5-1_8b-chat-q4_k_m.gguf
  --port 8080
  --host 0.0.0.0
  -n -1
```
- Exposes LLM API on your chosen port. Default is `8080`.

**Configuration**:
```yaml
ai:
  enabled: true
  provider: "openai"  # OpenAI compatible engine 
  api_key: "krawl"    # Keep this for compatibility
  timeout: 60
  max_daily_requests: 1000  # No API cost, can be higher
```

You can specify the **HuggingFace Token** with the env variable
```bash
HF_TOKEN=your_hf_token
```

#### Option 2: Ollama with Docker Compose

- Set up the alternative service in [docker-compose.yaml](../docker-compose.yaml) uncommenting ollama
- Modify the entrypoint with your desired model [from the ollama library](https://ollama.com/library)
```yaml
entrypoint: >
  sh -c "
    /bin/ollama serve &
    until /bin/ollama list > /dev/null 2>&1; do
      sleep 2;
    done;
    /bin/ollama pull qwen:1.8b;
    wait
```
- Exposes LLM API on your chosen port. Default is `8080`.

**Configuration**:
```yaml
ai:
  enabled: true
  provider: "openai"  # OpenAI compatible engine 
  api_key: "krawl"    # Keep this for compatibility
  model: "qwen:1.8b-chat"  # Model name on Ollama. This is required to build the request
  timeout: 60
  max_daily_requests: 1000  # No API cost, can be higher
```

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
- **Previously cached pages continue to be served**

### Cost Estimation

**Pricing Model for gpt-5.1-mini**: [$0.25 input / $2 output per million tokens](https://developers.openai.com/api/docs/models/gpt-5-mini)

**Standard Response**: ~500 tokens per HTML page + ~100 tokens for prompt input

**Cost per deception page**: ~$0.001

**Monthly Costs:**
- 100 pages/month: ~$0.10
- 500 pages/month: ~$0.50
- 1,000 pages/month: ~$1.00

**Using OpenRouter Free Model**: $0 (rate limited, no charge)

**Using self-hosted LLMs**: $0 (unlimited, no charge)

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