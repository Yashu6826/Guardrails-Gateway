from typing import List, Dict, Any
from app.guardrails.prompt_injection import PromptInjectionDetector
from app.guardrails.pii_detector import PIIDetector
from app.guardrails.rag_injection import RAGInjectionDetector


class RiskScorer:
    """
    Calculates overall risk score (0-100 integer) and determines policy decision.

    Scoring contract:
      - decision == block   =>  risk_score >= 80
      - decision == transform => 40 <= risk_score < 80
      - decision == allow    =>  risk_score < 40

    The score is computed from individual detector scores (0.0-1.0) and then
    *clamped* so it is always consistent with the decision.  This avoids the
    old bug where score=36 but decision=block.
    """

    BLOCK_SCORE = 80
    TRANSFORM_SCORE = 40

    def __init__(self):
        self.prompt_injection_detector = PromptInjectionDetector()
        self.pii_detector = PIIDetector()
        self.rag_injection_detector = RAGInjectionDetector()

    def analyze(self, prompt: str, context_docs: List[Dict[str, str]]) -> Dict[str, Any]:
        risk_tags: List[str] = []
        reasons: List[Dict[str, str]] = []

        # === PROMPT INJECTION ===
        is_pi, pi_score, pi_patterns = PromptInjectionDetector.detect(prompt)
        if is_pi:
            risk_tags.append("prompt_injection")
            for p in pi_patterns[:5]:
                reasons.append({"tag": "prompt_injection", "evidence": f"matched phrase: {p}"})

        # === PII ===
        pii_types, pii_score, pii_instances = PIIDetector.detect(prompt)
        if pii_types:
            risk_tags.append("pii")
            for pt in pii_types:
                reasons.append({"tag": "pii", "evidence": f"detected PII type: {pt}"})

        # === RAG INJECTION ===
        rag_score = 0.0
        rag_injection_detected = False
        flagged_doc_indices: set = set()

        for idx, doc in enumerate(context_docs):
            is_ri, ri_score, ri_patterns = RAGInjectionDetector.detect(doc.get("text", ""))
            if is_ri:
                rag_injection_detected = True
                flagged_doc_indices.add(idx)
                for p in ri_patterns[:3]:
                    reasons.append({"tag": "rag_injection", "evidence": f"doc {doc.get('id', '?')}: {p}"})
            rag_score = max(rag_score, ri_score)

        if rag_injection_detected:
            risk_tags.append("rag_injection")

        # === DECISION (decide first, then derive a consistent score) ===
        if (
            (is_pi and pi_score >= 0.75)
            or (rag_injection_detected and rag_score >= 0.7)
        ):
            decision = "block"
        elif (
            (is_pi and pi_score >= 0.4)  # Lowered from 0.5 to catch medium-confidence injections
            or (rag_injection_detected and rag_score >= 0.4)
            or (pii_types and pii_score >= 0.3)
        ):
            decision = "transform"
        else:
            decision = "allow"

        # === SCORE — must be consistent with the decision ===
        # Take the dominant detector score (whichever drove the decision).
        dominant = max(pi_score, rag_score, pii_score)

        # Map the dominant 0.0-1.0 score into the correct band.
        if decision == "block":
            # Map dominant [0.7 .. 1.0] → [80 .. 100]
            risk_score = max(self.BLOCK_SCORE, min(round(dominant * 100), 100))
        elif decision == "transform":
            # Map into [40 .. 79]
            raw = round(dominant * 100)
            risk_score = max(self.TRANSFORM_SCORE, min(raw, self.BLOCK_SCORE - 1))
        else:
            # allow — score < 40
            raw = round(dominant * 100)
            risk_score = min(raw, self.TRANSFORM_SCORE - 1)

        # Boost if multiple threats
        threat_count = sum([1 if is_pi else 0, 1 if pii_types else 0, 1 if rag_injection_detected else 0])
        if threat_count >= 2:
            risk_score = min(risk_score + 10, 100)
            # Promote decision if boosted score crosses a threshold
            if risk_score >= self.BLOCK_SCORE and decision != "block":
                decision = "block"
            elif risk_score >= self.TRANSFORM_SCORE and decision == "allow":
                decision = "transform"

        # === SANITIZE ===
        if decision == "block":
            sanitized_prompt = "[BLOCKED]"
            sanitized_docs: List[Dict[str, str]] = []
        else:
            sanitized_prompt = PIIDetector.redact(prompt)
            sanitized_docs = []
            for idx, doc in enumerate(context_docs):
                if idx in flagged_doc_indices:
                    sanitized_docs.append({"id": doc.get("id", ""), "text": "[BLOCKED_DOC]"})
                else:
                    sanitized_docs.append(
                        {"id": doc.get("id", ""), "text": PIIDetector.redact(doc.get("text", ""))}
                    )

        risk_tags = list(dict.fromkeys(risk_tags))

        return {
            "decision": decision,
            "risk_score": risk_score,
            "risk_tags": risk_tags,
            "sanitized_prompt": sanitized_prompt,
            "sanitized_context_docs": sanitized_docs,
            "reasons": reasons,
        }