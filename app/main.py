from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
import logging
from typing import List

from app.models import AnalyzeRequest, AnalyzeResponse, PolicyResponse, Decision
from app.guardrails.risk_scorer import RiskScorer
from app.guardrails.prompt_injection import PromptInjectionDetector
from app.guardrails.pii_detector import PIIDetector
from app.guardrails.rag_injection import RAGInjectionDetector

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Guardrails Gateway", version="1.0.0")

# Enable CORS for UI
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
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
        # Log minimal information (no prompt/response content)
        logger.info(f"Processing request - app_id: {request.metadata.app_id}, "
                   f"user_id: {request.metadata.user_id}, "
                   f"request_id: {request.metadata.request_id}")
        
        # Convert context docs to dict format
        context_docs = [
            {"id": doc.id, "text": doc.text} 
            for doc in request.context_docs
        ]
        
        # Analyze risks
        result = risk_scorer.analyze(request.prompt, context_docs)
        
        # Log risk assessment (no content)
        logger.info(f"Risk assessment - decision: {result['decision']}, "
                   f"score: {result['risk_score']}, "
                   f"tags: {result['risk_tags']}")
        
        # Convert sanitized docs back to ContextDoc objects
        sanitized_docs = [
            {"id": doc['id'], "text": doc['text']}
            for doc in result['sanitized_context_docs']
        ]
        
        return AnalyzeResponse(
            decision=Decision(result['decision']),
            risk_score=result['risk_score'],
            risk_tags=result['risk_tags'],
            sanitized_prompt=result['sanitized_prompt'],
            sanitized_context_docs=sanitized_docs,
            raw_response=result.get('details')
        )
        
    except Exception as e:
        logger.error(f"Error processing request: {str(e)}")
        raise HTTPException(status_code=500, detail=str(e))

@app.get("/policy")
async def get_policy():
    """
    Get the current policy configuration.
    """
    return PolicyResponse(
        policies={
            "prompt_injection": {
                "enabled": True,
                "threshold": 0.5,
                "action": "block"
            },
            "pii": {
                "enabled": True,
                "redaction": True,
                "detection_types": ["email", "phone", "ssn", "credit_card"]
            },
            "rag_injection": {
                "enabled": True,
                "threshold": 0.6,
                "action": "block"
            }
        },
        version="1.0.0"
    )

@app.get("/health")
async def health_check():
    """
    Health check endpoint.
    """
    return {"status": "healthy"}