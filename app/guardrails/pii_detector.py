import re
from typing import List, Tuple, Dict
from app.utils.redactor import Redactor

class PIIDetector:
    """Detects and redacts PII from text with improved pattern matching."""
    
    PII_PATTERNS = {
        # Email addresses - improved pattern
        'email': r'\b[A-Za-z0-9][A-Za-z0-9._%+-]*@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b',
        
        # Phone numbers - supports various formats
        'phone': r'(?:\+?1[-.\s]?)?(?:\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}|[0-9]{3}-[0-9]{4}-[0-9]{4})\b',
        
        # SSN - with word boundary
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        
        # Credit cards - more specific patterns (Visa, Mastercard, Amex, Discover, etc.)
        'credit_card': r'\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12}|(?:2131|1800|35\d{3})\d{11}|[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4}[- ]?[0-9]{4})\b',
        
        # IP addresses - with validation to avoid false positives
        'ip_address': r'\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\b',
        
        # API keys - longer alphanumeric sequences (32+ chars) or with explicit key names
        'api_key': r'\b(?:api[_-]?key|apikey|api_secret|secret_key|access_key|private_key)\s*[=:]\s*[A-Za-z0-9_\-\.]{32,}|\bsk_(?:live|test)_[A-Za-z0-9_\-\.]{32,}\b',
        
        # JWT tokens - improved pattern
        'jwt_token': r'\beyJ[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\.[A-Za-z0-9_\-\.]+\b',
        
        # AWS Access Keys
        'aws_key': r'\bAKIA[0-9A-Z]{16}\b',
        
        # Database connection strings
        'db_connection': r'(?:mongodb|mysql|postgresql|oracle)://[A-Za-z0-9._:\-@/]+',
        
        # AWS Secrets - base64-like patterns after common key names
        'aws_secret': r'\b(?:aws_secret_access_key|[A-Za-z0-9/+=]{40,})\b',
        
        # GitHub tokens
        'github_token': r'\bghp_[A-Za-z0-9_]{36,}\b',
        
        # Private keys (PEM format)
        'private_key': r'-----BEGIN (?:RSA |DSA |EC )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |DSA |EC )?PRIVATE KEY-----',
        
        # Sensitive file paths
        'file_path': r'(?:/home/[a-z]+/\.ssh/id_rsa|/root/\.ssh/id_rsa|C:\\Users\\[^\\]+\\\.ssh\\id_rsa)',
        
        # License keys (common format)
        'license_key': r'\b[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}-[A-Z0-9]{5}\b',
    }
    
    @classmethod
    def detect(cls, text: str) -> Tuple[List[str], float, Dict[str, List[str]]]:
        """
        Detect PII in text with improved accuracy.
        Returns: (found_pii_types, risk_score, pii_instances)
        """
        found_pii = []
        pii_instances = {}
        risk_score = 0.0
        
        for pii_type, pattern in cls.PII_PATTERNS.items():
            try:
                matches = re.findall(pattern, text, re.IGNORECASE | re.MULTILINE)
                if matches:
                    found_pii.append(pii_type)
                    pii_instances[pii_type] = matches
                    
                    # Assign risk weights based on PII type
                    weights = {
                        'ssn': 0.95,  # Very high risk
                        'credit_card': 0.95,  # Very high risk
                        'api_key': 0.9,  # Very high risk
                        'aws_key': 0.95,  # Very high risk
                        'aws_secret': 0.95,  # Very high risk
                        'github_token': 0.9,  # Very high risk
                        'jwt_token': 0.85,  # High risk
                        'db_connection': 0.9,  # High risk
                        'private_key': 0.99,  # Critical risk
                        'email': 0.35,  # Medium risk
                        'phone': 0.35,  # Medium risk
                        'ip_address': 0.25,  # Low risk in most contexts
                        'file_path': 0.7,  # High risk
                        'license_key': 0.5,  # Medium-high risk
                    }
                    
                    # Calculate risk based on count
                    weight = weights.get(pii_type, 0.3)
                    match_count = min(len(matches), 3)  # Cap contribution at 3 matches
                    # If match_count is 1, use full weight; otherwise scale by count
                    if match_count == 1:
                        risk_score += weight
                    else:
                        risk_score += weight * (match_count / 2)
            except Exception as e:
                # Skip patterns that cause regex errors
                continue
        
        risk_score = min(risk_score, 1.0)
        return found_pii, risk_score, pii_instances
    
    @classmethod
    def redact(cls, text: str) -> str:
        """Redact all PII from text."""
        redacted = text
        
        try:
            for pii_type, pattern in cls.PII_PATTERNS.items():
                redacted = re.sub(pattern, '[REDACTED]', redacted, flags=re.IGNORECASE | re.MULTILINE)
        except Exception as e:
            # Fallback to simple redaction if regex fails
            for pattern in cls.PII_PATTERNS.values():
                try:
                    redacted = re.sub(pattern, '[REDACTED]', redacted, flags=re.IGNORECASE | re.MULTILINE)
                except:
                    pass
        
        return redacted