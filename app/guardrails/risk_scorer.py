from typing import List, Dict, Any
from app.guardrails.prompt_injection import PromptInjectionDetector
from app.guardrails.pii_detector import PIIDetector
from app.guardrails.rag_injection import RAGInjectionDetector

class RiskScorer:
    """Calculates overall risk score and determines policy decision with improved thresholds."""
    
    def __init__(self):
        self.prompt_injection_detector = PromptInjectionDetector()
        self.pii_detector = PIIDetector()
        self.rag_injection_detector = RAGInjectionDetector()
    
    def analyze(self, prompt: str, context_docs: List[Dict[str, str]]) -> Dict[str, Any]:
        """
        Analyze prompt and context for risks with improved decision logic.
        Returns comprehensive risk assessment.
        """
        risk_tags = []
        details = {}
        
        # Updated weights - prompt injection and RAG injection are critical
        weights = {
            'prompt_injection': 0.45,    # Increased from 0.4
            'rag_injection': 0.40,       # Increased from 0.35
            'pii': 0.15                  # Reduced from 0.25 - PII leakage is important but less urgent
        }
        
        # === PROMPT INJECTION CHECK ===
        is_pi, pi_score, pi_patterns = PromptInjectionDetector.detect(prompt)
        
        # If we detected high-confidence injection, mark it immediately
        if is_pi:
            risk_tags.append("prompt_injection")
            if pi_score >= 0.8:
                risk_tags.append("prompt_injection_high_confidence")
        
        details['prompt_injection'] = {
            'score': pi_score,
            'detected': is_pi,
            'pattern_count': len(pi_patterns),
            'patterns': pi_patterns[:5]  # Limit patterns in response
        }
        
        # === PII CHECK IN PROMPT ===
        pii_types, pii_score, pii_instances = PIIDetector.detect(prompt)
        
        if pii_types:
            risk_tags.extend([f"pii_{pii_type}" for pii_type in pii_types])
            # Check for critical PII types
            critical_pii = ['ssn', 'credit_card', 'aws_key', 'github_token', 'private_key', 'api_key']
            if any(t in pii_types for t in critical_pii):
                risk_tags.append("pii_critical")
                # Boost PII score for critical types
                pii_score = max(pii_score, 0.7)
        
        details['pii'] = {
            'score': pii_score,
            'found_types': pii_types,
            'type_count': len(pii_types)
        }
        
        # === RAG INJECTION CHECK ===
        rag_score = 0.0
        rag_injection_detected = False
        rag_critical = False
        
        for idx, doc in enumerate(context_docs):
            is_ri, ri_score, ri_patterns = RAGInjectionDetector.detect(doc.get('text', ''))
            if is_ri:
                rag_injection_detected = True
                risk_tags.append(f"rag_injection_doc_{idx}")
                if ri_score >= 0.8:
                    rag_critical = True
            rag_score = max(rag_score, ri_score)
        
        if rag_injection_detected:
            risk_tags.append("rag_injection")
            if rag_critical:
                risk_tags.append("rag_injection_high_confidence")
        
        details['rag_injection'] = {
            'score': rag_score,
            'detected': rag_injection_detected,
            'context_doc_count': len(context_docs)
        }
        
        # === CALCULATE TOTAL RISK WITH STRICTER LOGIC ===
        total_risk = (
            pi_score * weights['prompt_injection'] +
            pii_score * weights['pii'] +
            rag_score * weights['rag_injection']
        )
        
        # Boost score if multiple threats detected
        threat_count = sum([
            1 if is_pi else 0,
            1 if pii_types else 0,
            1 if rag_injection_detected else 0
        ])
        
        if threat_count >= 2:
            # Multiple threats detected - increase risk
            total_risk = min(total_risk * 1.15, 1.0)
            risk_tags.append("multi_threat")
        
        # === DECISION LOGIC (STRICTER) ===
        # Block: Any high-confidence injection, multiple critical PII, or RAG injection
        if (is_pi and pi_score >= 0.75) or \
           (rag_injection_detected and rag_score >= 0.7) or \
           (total_risk >= 0.65) or \
           ('pii_critical' in risk_tags and pii_score >= 0.8):
            decision = "block"
        # Transform: Medium-high risk requiring sanitization
        elif total_risk >= 0.45 or \
             (is_pi and pi_score >= 0.5) or \
             (pii_types and pii_score >= 0.6):
            decision = "transform"
        # Allow: Low risk
        else:
            decision = "allow"
        
        # Ensure decision is conservative on close calls
        if 0.4 <= total_risk < 0.45 and (is_pi or pii_types):
            decision = "transform"  # Be conservative
        
        # === SANITIZE CONTENT ===
        sanitized_prompt = PIIDetector.redact(prompt)
        
        # If prompt injection detected, also provide warning in sanitization
        if is_pi:
            sanitized_prompt = f"[INJECTION_DETECTED] {sanitized_prompt}"
        
        sanitized_docs = []
        for doc in context_docs:
            sanitized_text = PIIDetector.redact(doc.get('text', ''))
            sanitized_docs.append({
                'id': doc.get('id', ''),
                'text': sanitized_text
            })
        
        return {
            'decision': decision,
            'risk_score': round(total_risk, 3),
            'risk_tags': list(set(risk_tags)),  # Remove duplicates
            'sanitized_prompt': sanitized_prompt,
            'sanitized_context_docs': sanitized_docs,
            'details': details
        }