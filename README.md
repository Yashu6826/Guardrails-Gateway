# SentraGuard Lite - Guardrails Gateway

A minimal GenAI guardrails gateway that analyzes incoming prompts and optional retrieved context, returning a policy decision (allow/block/transform) with a 0-100 integer risk score, risk tags, and redacted outputs.

## Quick Start

### Docker (recommended)

```bash
docker compose up --build
# API  -> http://localhost:8000
# UI   -> http://localhost:8501
```

### Local

```bash
# Terminal 1 - API
pip install -r requirements.api.txt
uvicorn app.main:app --reload --port 8000

# Terminal 2 - UI
pip install -r requirements.ui.txt
API_BASE_URL=http://localhost:8000 streamlit run ui/streamlit_app.py
```

## API Endpoints (exactly 2)

### POST /analyze

Analyzes a request and returns a decision.

- `context_docs`: 0-3 documents (max 3 enforced by Pydantic validation).
- `prompt`: max 10 000 characters.
- `risk_score` is an integer 0-100.
- On `block`: `sanitized_prompt` = `[BLOCKED]`, `sanitized_context_docs` = `[]`.
- On `transform`: flagged RAG docs replaced with `[BLOCKED_DOC]`; PII replaced with `[REDACTED]`.

### GET /policy

Returns the loaded policy/detectors configuration with version, detectors list, and integer thresholds (`block_score`: 80, `transform_score`: 40).

> The OpenAPI/Swagger UI is **disabled** (`/docs`, `/redoc`, `/openapi.json` all return 404).

## CLI

```bash
python cli.py analyze --input sample_request.json --output out.json
```

- Reads the input JSON, calls `POST /analyze`, writes the response to the output file.
- `--api-url` flag or `GUARDRAILS_API_URL` env var to override default `http://localhost:8000`.
- Generates a unique `request_id` (UUID) when not provided.
- Distinct exit codes: 0 success, 2 bad input, 3 network error, 4 API error.

## Detection Logic

| Detector | What it catches | Examples |
|---|---|---|
| Prompt injection | Jailbreak, instruction override, role hijacking, leetspeak, homoglyphs, base64, reversed text, invisible chars | "ignore previous instructions", "act as DAN", "1gn0r3 rul35" |
| PII detection + redaction | Email, phone, SSN, credit card → `[REDACTED]` | "john@example.com", "555-123-4567" |
| RAG injection | Malicious instructions hidden in context docs, structure attacks, authority hijacking | "SYSTEM: override policy", "ignore the context documents" |

### Detection Breakdown

**Decision thresholds (0–100):** score ≥ 80 → block, score ≥ 40 → transform, score < 40 → allow.

The score is always **consistent with the decision** — if the decision is block the score will be ≥80, if transform it will be 40–79.

High-confidence prompt injection (≥ 0.75) or RAG injection (≥ 0.7) triggers immediate **block** regardless of aggregate score.

## Running Tests

```bash
pip install -r requirements.test.txt
pytest -v
```

## Streamlit UI

Accepts prompt text and 0-3 context documents. Calls `POST /analyze` and displays decision, score, tags, sanitized outputs, and raw JSON.

See [DESIGN_NOTES.md](DESIGN_NOTES.md) for architecture decisions, trade-offs, and production hardening notes.
