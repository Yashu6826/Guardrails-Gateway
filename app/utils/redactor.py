"""
Redaction utilities for PII and sensitive content.
Provides consistent redaction across the application.
"""

import re
from typing import List, Tuple, Dict, Optional

class Redactor:
    """Handles redaction of sensitive information from text."""
    
    # Common patterns for redaction
    PII_PATTERNS = {
        'email': r'\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b',
        'phone': r'\b(?:\+?1[-.\s]?)?\(?[0-9]{3}\)?[-.\s]?[0-9]{3}[-.\s]?[0-9]{4}\b',
        'ssn': r'\b\d{3}-\d{2}-\d{4}\b',
        'credit_card': r'\b(?:\d{4}[- ]?){3}\d{4}\b',
        'ip_address': r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b',
        'api_key': r'\b[A-Za-z0-9]{32,}\b',
        'jwt_token': r'eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+',
    }
    
    # Redaction tokens
    DEFAULT_REDACTION = '[REDACTED]'
    PARTIAL_REDACTION = '[REDACTED_{}]'
    
    @classmethod
    def redact_pii(cls, text: str, redaction_token: str = None) -> str:
        """
        Redact all PII from text using regex patterns.
        
        Args:
            text: Input text to redact
            redaction_token: Token to use for redaction (default: [REDACTED])
            
        Returns:
            Text with PII replaced by redaction token
        """
        if redaction_token is None:
            redaction_token = cls.DEFAULT_REDACTION
        
        redacted_text = text
        for pii_type, pattern in cls.PII_PATTERNS.items():
            redacted_text = re.sub(
                pattern, 
                redaction_token, 
                redacted_text, 
                flags=re.IGNORECASE
            )
        
        return redacted_text
    
    @classmethod
    def redact_with_context(cls, text: str, pii_types: List[str]) -> str:
        """
        Redact specific PII types from text.
        
        Args:
            text: Input text to redact
            pii_types: List of PII types to redact (email, phone, etc.)
            
        Returns:
            Text with specified PII types redacted
        """
        redacted_text = text
        for pii_type in pii_types:
            if pii_type in cls.PII_PATTERNS:
                pattern = cls.PII_PATTERNS[pii_type]
                redacted_text = re.sub(
                    pattern, 
                    cls.DEFAULT_REDACTION, 
                    redacted_text, 
                    flags=re.IGNORECASE
                )
        
        return redacted_text
    
    @classmethod
    def redact_partial(cls, text: str, preserve_ratio: float = 0.3) -> str:
        """
        Partially redact text, preserving some characters for context.
        
        Args:
            text: Input text to partially redact
            preserve_ratio: Ratio of characters to preserve (0.0 to 1.0)
            
        Returns:
            Text with partial redaction
        """
        if not text or preserve_ratio <= 0:
            return cls.DEFAULT_REDACTION
        
        if preserve_ratio >= 1.0:
            return text
        
        # For emails and structured data, use different logic
        if '@' in text and '.' in text:  # Likely an email
            local_part, domain = text.split('@', 1)
            preserve_len = max(1, int(len(local_part) * preserve_ratio))
            partial_local = local_part[:preserve_len] + '*' * (len(local_part) - preserve_len)
            return f"{partial_local}@{domain}"
        
        # For regular text
        preserve_len = max(1, int(len(text) * preserve_ratio))
        preserved = text[:preserve_len]
        redacted_len = len(text) - preserve_len
        return preserved + '*' * min(redacted_len, 10)  # Limit stars to 10
    
    @classmethod
    def redact_custom_pattern(cls, text: str, pattern: str, redaction_token: str = None) -> str:
        """
        Redact custom patterns from text.
        
        Args:
            text: Input text to redact
            pattern: Regex pattern to match
            redaction_token: Token to use for redaction
            
        Returns:
            Text with custom pattern redacted
        """
        if redaction_token is None:
            redaction_token = cls.DEFAULT_REDACTION
        
        return re.sub(pattern, redaction_token, text, flags=re.IGNORECASE)
    
    @classmethod
    def get_redacted_ranges(cls, text: str) -> List[Tuple[int, int]]:
        """
        Get ranges of text that would be redacted without modifying the text.
        Useful for highlighting redacted portions in UI.
        
        Args:
            text: Input text to analyze
            
        Returns:
            List of (start, end) tuples for redacted ranges
        """
        redacted_ranges = []
        
        for pattern in cls.PII_PATTERNS.values():
            for match in re.finditer(pattern, text, re.IGNORECASE):
                redacted_ranges.append((match.start(), match.end()))
        
        # Sort and merge overlapping ranges
        if not redacted_ranges:
            return []
        
        redacted_ranges.sort()
        merged = [list(redacted_ranges[0])]
        
        for start, end in redacted_ranges[1:]:
            if start <= merged[-1][1]:
                merged[-1][1] = max(merged[-1][1], end)
            else:
                merged.append([start, end])
        
        return [tuple(r) for r in merged]
    
    @classmethod
    def redact_json_values(cls, data: Dict, sensitive_keys: List[str]) -> Dict:
        """
        Recursively redact values for specific keys in a JSON/dict structure.
        
        Args:
            data: Dictionary to redact
            sensitive_keys: List of keys whose values should be redacted
            
        Returns:
            Redacted dictionary
        """
        if not isinstance(data, dict):
            return data
        
        redacted_data = {}
        for key, value in data.items():
            if key in sensitive_keys:
                redacted_data[key] = cls.DEFAULT_REDACTION
            elif isinstance(value, dict):
                redacted_data[key] = cls.redact_json_values(value, sensitive_keys)
            elif isinstance(value, list):
                redacted_data[key] = [
                    cls.redact_json_values(item, sensitive_keys) if isinstance(item, dict) 
                    else cls.DEFAULT_REDACTION if key in sensitive_keys else item
                    for item in value
                ]
            else:
                redacted_data[key] = value
        
        return redacted_data
    
    @classmethod
    def validate_redaction(cls, original: str, redacted: str) -> Dict[str, bool]:
        """
        Validate that redaction worked correctly.
        
        Args:
            original: Original text
            redacted: Redacted text
            
        Returns:
            Dictionary with validation results
        """
        results = {
            'length_changed': len(original) != len(redacted),
            'contains_redaction_token': cls.DEFAULT_REDACTION in redacted,
            'no_original_patterns': True
        }
        
        # Check if any original patterns remain
        for pattern in cls.PII_PATTERNS.values():
            if re.search(pattern, redacted, re.IGNORECASE):
                if cls.DEFAULT_REDACTION not in redacted:
                    results['no_original_patterns'] = False
                    break
        
        return results


# Convenience functions for common use cases
def quick_redact(text: str) -> str:
    """Quick redaction of common PII."""
    return Redactor.redact_pii(text)

def redact_email(text: str) -> str:
    """Redact only email addresses."""
    return Redactor.redact_with_context(text, ['email'])

def redact_phone(text: str) -> str:
    """Redact only phone numbers."""
    return Redactor.redact_with_context(text, ['phone'])

def redact_all_sensitive(text: str) -> str:
    """Redact all sensitive information (PII + custom patterns)."""
    text = Redactor.redact_pii(text)
    # Add custom patterns for tokens, passwords, etc.
    text = Redactor.redact_custom_pattern(text, r'\b(?:token|secret|password|key)[=:]\s*\S+', '[CREDENTIAL_REDACTED]')
    return text