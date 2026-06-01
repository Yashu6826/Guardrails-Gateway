# Design Notes - SentraGuard Lite

## Architecture

The gateway is a stateless FastAPI service with exactly 2 endpoints. All detection runs in-process using regex-based pattern matching — no external API keys, no ML models, fully deterministic and offline.

## Design Decisions

### Pattern Matching vs ML Models
Chose regex pattern matching for the MVP. Trade-off: deterministic, fast (<5ms), works offline, but can be evaded by sophisticated attacks. ML-based detection (e.g. deberta-v3-base-prompt-injection) can be added as a second layer.

### Risk Score: 0-100 Integer
Weighted sum of detector scores (prompt_injection 45%, RAG injection 40%, PII 15%), multiplied by 100 and rounded. Integer scale avoids floating-point ambiguity and matches the `/policy` thresholds directly.

### Block Decision = Fail-Safe
On `decision=block`, the response returns `sanitized_prompt=[BLOCKED]` and `sanitized_context_docs=[]`. This prevents any downstream consumer from accidentally forwarding attack content to an LLM. The raw prompt is never echoed back.

### RAG Doc Blanking
Flagged RAG documents get their text replaced with `[BLOCKED_DOC]` (on transform) or omitted entirely (on block). The caller never receives malicious document content in sanitized fields.

### Exactly 2 Endpoints
The spec requires exactly `POST /analyze` and `GET /policy`. OpenAPI surface (`/docs`, `/redoc`, `/openapi.json`) is disabled via `openapi_url=None`. No `/health` endpoint — the docker-compose healthcheck hits `GET /policy` instead.

### CORS
Default `allow_origins` restricted to `localhost:8501` and `localhost:3000`. Configurable via `CORS_ALLOWED_ORIGINS` env var. Not `allow_origins=*`.

### Error Handling
500 responses return a generic `detail: "internal error"`. The real exception is logged server-side with the `request_id` for debugging, but never echoed to the caller.

## Production Hardening (what I would add)

1. **Rate limiting** — Redis-backed per-user/per-app rate limits.
2. **API authentication** — `X-API-Key` header validation.
3. **Response scanning** — Scan LLM outputs for PII leakage (new endpoint).
4. **ML detection layer** — Fine-tuned classifier as second pass after regex.
5. **Structured logging** — JSON logs with `request_id` correlation, ship to ELK/Datadog.
6. **Async workers** — Multiple uvicorn workers behind a load balancer.
7. **Input length limits** — Already enforced via Pydantic (10K prompt, 50K per doc).
8. **Multi-language support** — Current patterns are English-only.
9. **Caching** — LRU cache for identical prompts (with TTL).
10. **Metrics** — Prometheus counters for decision distribution, latency histograms.

## Limitations

- English-only detection patterns.
- No semantic understanding (can miss context-dependent attacks).
- `aws_secret` regex is intentionally broad — would need tuning for production to reduce false positives.
- No persistent audit log (stateless design).
- Single-process by default (add workers for throughput).

## Testing Strategy

Tests cover all 10 required cases plus additional coverage for:
- OpenAPI surface disabled (404 on `/docs`, `/redoc`, `/openapi.json`, `/health`)
- `context_docs` max-3 enforcement
- Block decision returns sentinel values (not raw attack content)
- RAG doc blanking on flagged documents
- `risk_score` is integer 0-100
