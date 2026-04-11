# RedPill Provider

RedPill is an OpenAI-compatible inference provider that runs open-weight models inside **hardware TEE (Trusted Execution Environment) enclaves** using Intel TDX and NVIDIA H100/H200 Confidential Computing.

## What Makes RedPill Different

### TEE Protection Guarantees

Unlike standard API providers where the operator can theoretically access your prompts and outputs:

- **Hardware-level encryption**: Data is encrypted in use, not just in transit/at rest
- **Blind execution**: Neither RedPill nor the cloud operator can observe prompts/outputs in plaintext
- **Attestation**: You can cryptographically verify the enclave is running the expected code

This matters for:
- Sensitive business logic or proprietary prompts
- Personal data (PII, financial, health)
- Credential handling or API key processing
- Confidential research or unreleased work

### Comparison to Policy-Only Providers

| Provider | Encryption | Operator Access | Attestation |
|----------|-----------|-----------------|-------------|
| RedPill (TEE) | Hardware enclave | No | Yes |
| OpenRouter/Nous | TLS + zero-retention policy | Technically possible | No |
| Self-hosted | Full control | N/A | N/A |

RedPill is the middle ground: cloud convenience with near self-hosted privacy.

## Configuration

```bash
# Set your API key
echo "REDPILL_API_KEY=*** >> ~/.hermes/.env

# Select RedPill
hermes model  # Choose "RedPill (TEE-protected aggregator API)"
```

### Environment Variables

| Variable | Required | Default |
|----------|----------|---------|
| `REDPILL_API_KEY` | Yes | - |
| `REDPILL_BASE_URL` | No | `https://api.redpill.ai/v1` |

## Available Models

RedPill exposes 17+ open-weight models. Key options:

### Recommended for Agent Work (Tool Calling)

| Model | Context | Speed | Cost | Notes |
|-------|---------|-------|------|-------|
| `qwen/qwen3.5-27b` | 128K | Fast | $ | Best price/performance for most tasks |
| `qwen/qwen3.5-397b-a17b` | 256K | Medium | $$ | MoE, strongest Qwen variant |
| `z-ai/glm-4.7` | 128K | Fast | $ | Strong reasoning, good tool use |
| `deepseek/deepseek-v3.2` | 256K | Medium | $$ | Excellent coding/reasoning |

### Specialized Models

| Model | Use Case |
|-------|----------|
| `moonshotai/kimi-k2-thinking` | Extended reasoning chains |
| `qwen/qwen3-coder-480b-a35b-instruct` | Code generation |
| `qwen/qwen3-vl-30b-a3b-instruct` | Vision + language |
| `deepseek/deepseek-r1-0528` | Research/math |

### Budget Options

- `qwen/qwen-2.5-7b-instruct` - Fastest, cheapest, weaker reasoning
- `openai/gpt-oss-20b` - OpenAI's open weights, decent baseline

## Pricing

RedPill uses pay-per-token pricing. Check current rates at [redpill.ai/pricing](https://redpill.ai/pricing).

**Typical ranges** (verify before heavy use):
- 7B-27B models: $0.10-0.50 / 1M input tokens
- 70B-400B models: $0.80-3.00 / 1M input tokens
- Output tokens: 2-4x input pricing

## Rate Limits

- Default: 60 RPM, 100K TPM (varies by model)
- Higher limits available on request
- No daily quota on standard plans

## Known Limitations

1. **Model availability**: Models may be added/removed by RedPill without notice
2. **Latency**: TEE overhead adds ~10-50ms vs. non-TEE inference
3. **No fine-tuning**: API-only, no custom model training
4. **Vision support**: Limited to specific models (check docs)

## Troubleshooting

### Connection Errors

```bash
# Test connectivity
curl -H "Authorization: Bearer *** \
  https://api.redpill.ai/v1/models
```

### Model Not Found

RedPill's model list changes. Verify available models:

```bash
hermes model list --provider redpill
```

### TEE Attestation

To verify enclave attestation (advanced):

```python
import requests

response = requests.get(
    "https://api.redpill.ai/v1/attestation",
    headers={"Authorization": f"Bearer {REDPILL_API_KEY}"}
)
print(response.json())
```

## When to Use RedPill

**Good fit:**
- Handling sensitive data or credentials
- Proprietary prompts you don't want exposed
- Compliance requirements (HIPAA, SOC2 adjacent)
- You want cloud convenience without trusting the operator

**Consider alternatives:**
- Maximum performance (self-hosted on Spark)
- Maximum model variety (OpenRouter)
- Lowest cost at scale (self-hosted or Nous subscription)

## Related

- [RedPill Documentation](https://docs.redpill.ai/)
- [TEE Explainer](https://www.intel.com/content/www/us/en/developer/tools/trust-domain-extensions/documentation.html)
- [Hermes Provider Guide](../providers.md)
