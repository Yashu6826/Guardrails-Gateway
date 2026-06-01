import os
import logging
from typing import List

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from app.models import AnalyzeRequest, AnalyzeResponse, PolicyResponse, Decision, ContextDoc
from app.guardrails.risk_scorer import RiskScorer

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

# Exactly 2 endpoints — disable OpenAPI surface entirely
app = FastAPI(
    title="Guardrails Gateway",
    version="1.0.0",
    openapi_url=None,
    docs_url=None,
    redoc_url=None,
)

# CORS — restrict origins via env var, default to localhost only
_allowed_origins = os.getenv(
    "CORS_ALLOWED_ORIGINS",
    "http://localhost:8501,http://localhost:3000",
).split(",")

app.add_middleware(
    CORSMiddleware,
    allow_origins=_allowed_origins,
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Initialize risk scorer
risk_scorer = RiskScorer()


@app.post("/analyze", response_model=AnalyzeResponse)
async def analyze_request(request: AnalyzeRequest):
    """
    Analyze a prompt and optional context for security risks.
    Returns policy decision, risk score, tags, and redacted content.
    """
    try:
        logger.info(
            "Processing request - app_id: %s, user_id: %s, request_id: %s",
            request.metadata.app_id,
            request.metadata.user_id,
            request.metadata.request_id,
        )

        context_docs = [
            {"id": doc.id, "text": doc.text}
            for doc in request.context_docs
        ]

        result = risk_scorer.analyze(request.prompt, context_docs)

        logger.info(
            "Risk assessment - decision: %s, score: %s, tags: %s",
            result["decision"],
            result["risk_score"],
            result["risk_tags"],
        )

        sanitized_docs = [
            ContextDoc(id=doc["id"], text=doc["text"])
            for doc in result["sanitized_context_docs"]
        ]

        return AnalyzeResponse(
            decision=Decision(result["decision"]),
            risk_score=result["risk_score"],
            risk_tags=result["risk_tags"],
            sanitized_prompt=result["sanitized_prompt"],
            sanitized_context_docs=sanitized_docs,
            reasons=result.get("reasons", []),
        )

    except Exception as e:
        logger.error(
            "Error processing request (request_id=%s): %s",
            request.metadata.request_id,
            str(e),
        )
        raise HTTPException(status_code=500, detail="internal error")


@app.get("/policy", response_model=PolicyResponse)
async def get_policy():
    """Return the loaded policy / detectors configuration."""
    return PolicyResponse(
        version="1",
        detectors=["prompt_injection", "pii", "rag_injection"],
        thresholds={"block_score": 80, "transform_score": 40},
    )