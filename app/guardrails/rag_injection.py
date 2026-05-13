import re
import base64
from typing import Tuple, List

# ---------------------------------------------------------------------------
# Homoglyph map — visually identical Unicode chars → ASCII equivalents
# ---------------------------------------------------------------------------
_HOMOGLYPH_MAP: dict = {
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ո": "n", "υ": "u",
    "α": "a", "β": "b", "ε": "e", "ι": "i", "ο": "o", "ρ": "p",
    "ς": "s", "τ": "t", "ν": "v",
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
}

_LEET_MAP: dict = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i", "|": "i",
}

_B64_ATTACK_KEYWORDS = [
    "ignore", "forget", "override", "jailbreak", "system prompt",
    "disregard", "bypass", "instructions", "unrestricted", "context",
    "document", "rag", "knowledge", "retrieve",
]

# Glued phrases produced after space-collapse of "i g n o r e ..." style attacks
_GLUED_ATTACK_PHRASES = [
    ("ignorepreviousinstructions",     "spaced: ignore previous instructions"),
    ("forgetpreviousinstructions",     "spaced: forget previous instructions"),
    ("disregardpreviousinstructions",  "spaced: disregard previous instructions"),
    ("overridepreviousinstructions",   "spaced: override previous instructions"),
    ("bypasspreviousinstructions",     "spaced: bypass previous instructions"),
    ("ignoreallinstructions",          "spaced: ignore all instructions"),
    ("forgetallinstructions",          "spaced: forget all instructions"),
    ("ignorethecontext",               "spaced: ignore the context"),
    ("ignorecontextdocuments",         "spaced: ignore context documents"),
    ("forgettheknowledge",             "spaced: forget the knowledge"),
    ("overridedocuments",              "spaced: override documents"),
    ("bypassrag",                      "spaced: bypass RAG"),
    ("revealsystemprompt",             "spaced: reveal system prompt"),
    ("showsystemprompt",               "spaced: show system prompt"),
    ("ignoreyourrules",                "spaced: ignore your rules"),
    ("forgetyourinstructions",         "spaced: forget your instructions"),
]


def _replace_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _replace_leet(text: str) -> str:
    return "".join(_LEET_MAP.get(ch, ch) if not ch.isalpha() else ch for ch in text)


def _decode_base64_payloads(text: str) -> str:
    extras = []
    for blob in re.findall(r"[A-Za-z0-9+/]{20,}={0,2}", text):
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in _B64_ATTACK_KEYWORDS):
                extras.append(decoded)
        except Exception:
            pass
    return (text + " " + " ".join(extras)) if extras else text


class RAGInjectionDetector:
    """
    Multi-layer RAG injection detector with normalization pipeline.
    
    Detects malicious content and injection attempts in RAG context documents including:
      • Direct context/instruction override attempts
      • Leetspeak obfuscation (1gn0r3)
      • Homoglyph substitution (Cyrillic/Greek lookalikes)
      • Spaced-out text (i g n o r e)
      • Base64-encoded payloads
      • System/emergency protocol language
      • Data extraction attempts
      • Role assignment + destructive combos
    """
    
    # High-confidence RAG injection patterns
    HIGH_CONFIDENCE_PATTERNS: List[Tuple[str, str]] = [
        # Context/instruction override
        (
            r"\b(?:ignore|disregard|forget|overlook|skip|cancel|erase)\s+"
            r"(?:all\s+)?(?:your\s+|the\s+|my\s+)?(?:previous\s+|prior\s+|above\s+|all\s+)?"
            r"(?:context|document|documents|information|knowledge|training|retrieved|rag)"
            r"(?:\s+(?:and|or)\s+(?:follow|use|implement))?\s+(?:this|these|my|the)\s+"
            r"(?:instruction|directive|request|order)s?\b",
            "ignore/override context",
        ),
        (
            r"\bforget\s+(?:all\s+)?(?:your\s+)?(?:previous|prior|above|all\s+)?"
            r"(?:context|information|knowledge|retrieved|documents?|training)\b",
            "forget context/knowledge",
        ),
        (
            r"\b(?:reveal|show|print|output|display|expose|leak|dump|extract)\s+"
            r"(?:the\s+|your\s+|all\s+)?(?:original|hidden|system|internal)?\s*"
            r"(?:context|document|knowledge|training|source|data|rag|instruction)\b",
            "reveal context/knowledge",
        ),
        (
            r"\b(?:what|which|list|enumerate|show\s+me)\s+(?:is|are)\s+(?:the\s+)?(?:original|true|actual|real|hidden)"
            r"(?:\s+)?(?:context|document|source|knowledge|rag)\b",
            "extract context/knowledge",
        ),
        (
            r"\b(?:the\s+(?:real|true|actual|original)\s+)?(?:instruction|directive|purpose|goal|objective|intent|request)"
            r"(?:\s+is\s+)?:\b",
            "real instruction directive",
        ),
        (
            r"\b(?:system|emergency|priority|critical)\s+override\s+(?:detected|activated|enabled|code)(?:\s+is)?\b",
            "system/emergency override",
        ),
        (
            r"\b(?:this\s+)?(?:next\s+)?(?:section|statement|instruction|directive|comment|text)\s+"
            r"(?:takes\s+|has\s+)?(?:priority|precedence)\b",
            "section takes priority",
        ),
        
        # Context replacement/injection
        (
            r"\b(?:use\s+|apply\s+|follow\s+)?(?:this|these)\s+(?:instead|new|updated?)\s+"
            r"(?:context|document|information|instructions?|directives?|source|knowledge)\s+"
            r"(?:instead\s+of|rather\s+than|not|ignore)\b",
            "context replacement",
        ),
        (
            r"\b(?:disregard|ignore)\s+(?:all\s+)?(?:previous|prior|earlier|earlier|above|previous)\s+"
            r"(?:context|documents?|information|data|knowledge|rag)\b",
            "disregard previous context",
        ),
        
        # Development/testing bypass
        (
            r"\b(?:you\s+)?(?:are\s+|running\s+)?(?:in|under)\s+"
            r"(?:developer|development|debug|test|staging|maintenance)\s+"
            r"(?:mode|environment|context|session)\b",
            "developer/test mode",
        ),
        (
            r"\b(?:developer|admin|test|debug|maintenance)\s+(?:access|mode|privilege)s?\s+"
            r"(?:granted|detected|enabled|activated)\b",
            "admin access granted",
        ),
        
        # Priority/importance hijacking
        (
            r"\b(?:critical|urgent|emergency|high[\s-]priority|important|confidential)\s+"
            r"(?:instruction|directive|message|override|protocol|request)\b",
            "critical/urgent directive",
        ),
        (
            r"\b(?:new|updated?)\s+(?:protocol|procedure|instruction|directive|requirement|policy)\s+"
            r"(?:in\s+)?(?:effect|place|force)(?:\s+as\s+of)?(?:\s+now|today|immediately)?\b",
            "new protocol in effect",
        ),
        
        # Authority/authentication bypass
        (
            r"\b(?:authentication|authorization|permission)\s+"
            r"(?:code|token|key|credential|bypass|override)[\s:=]+\b",
            "authentication bypass",
        ),
        (
            r"\b(?:admin|root|system|superuser|operator)\s+(?:access|mode|confirmed|verified|authenticated)\b",
            "admin access confirmed",
        ),
        
        # Data extraction attempts
        (
            r"\b(?:extract|exfiltrate|leak|expose|reveal|dump|backup|download|export)\s+"
            r"(?:all\s+|the\s+)?(?:data|information|document|knowledge|training|model|context|rag|source)\b",
            "data extraction attempt",
        ),
        (
            r"\b(?:send|output|return|retrieve|display|show)\s+"
            r"(?:me\s+|the\s+)?(?:complete\s+)?(?:source|original|underlying|raw)?\s*"
            r"(?:context|document|knowledge|rag|training|data|model)\b",
            "output context/knowledge",
        ),
        
        # Prompt injection self-reference
        (r"\b(?:prompt|instruction)\s+injection\b", "self-labelled injection"),
        (r"\bjailbreak\b", "jailbreak keyword"),
        
        # Version/update tricks
        (
            r"\b(?:new|updated?)\s+(?:version|update|patch|revision|model|behavior)\s+"
            r"(?:detected|available|installed|activated|deployed)\b",
            "version update trick",
        ),
        (
            r"\b(?:legacy|old|deprecated|previous)\s+(?:behavior|format|protocol|mode)\s+"
            r"(?:required|enabled|restored|active)\b",
            "legacy behavior restoration",
        ),
        
        # Recursive/nested attacks
        (
            r"\b(?:the\s+)?(?:following|below|next)\s+.*?:.*?"
            r"(?:ignore|forget|disregard|override|bypass)\b",
            "recursive/nested attack",
        ),
        (
            r"\b(?:in\s+)?(?:this\s+)?(?:section|block|part|context)\s*[,:].*?"
            r"(?:ignore|forget|disregard|override)\b",
            "section-scoped override",
        ),
    ]
    
    # Medium-confidence patterns
    MEDIUM_CONFIDENCE_PATTERNS: List[Tuple[str, float]] = [
        (r"(?:^|\n)\s*(?:context|source|document|rag)\s*:", 0.35),
        (r"\b(?:penetration\s+test(?:ing)?|pentest|red\s+team(?:ing)?|security\s+audit)\b", 0.3),
        (r"\bfor\s+(?:educational|research|academic|demonstration|testing)\s+purposes?\b", 0.25),
        (r"\bthis\s+is\s+(?:just\s+a\s+|only\s+a\s+)?(?:test|simulation|demo|exercise|drill)\b", 0.25),
        (r"\b(?:forget|ignore|clear)\s+(?:everything|all\s+(?:of\s+)?(?:that|this))\b", 0.35),
        (r"\b(?:true|real|actual|original|hidden)\s+(?:purpose|goal|objective|context|knowledge)\b", 0.3),
        (r"\b(?:secret|hidden|internal|confidential)\s+(?:context|document|knowledge|instruction)\b", 0.35),
        (r"(?:---+|\*\*\*+|===+)\s*(?:OVERRIDE|SYSTEM|END|STOP|NEW|RAG|CONTEXT)", 0.4),
        (r"\bbase64\s*[=:]\s*[A-Za-z0-9+/]{10,}", 0.45),
        (r"(?:&#x?|\\x|\\u)[0-9a-fA-F]{2,4}", 0.3),
        (r"\btranslate\s+(?:the\s+)?(?:following\s+)?(?:context|document|knowledge)\b", 0.4),
        (r"\btemporarily\b.{0,40}\b(?:disable|ignore|bypass|suspend|override)\b", 0.35),
        (r"\b(?:maintenance|testing|debug)\s+mode\b", 0.25),
        (r"\b(?:context|document)\s+extraction\b", 0.4),
        (r"\b(?:rag\s+)?(?:bypass|poison|contamination|attack)\b", 0.45),
    ]
    
    # Role assignment patterns (RAG context)
    ROLE_ASSIGNMENT_PATTERNS = [
        r"\byou\s+are\s+(?:a\s+|an\s+)?(?:now\s+)?(?:unrestricted|unfiltered|free|dangerous)\s+(?:document|context|rag)\b",
        r"\bact\s+as\s+(?:a\s+|an\s+)?(?:unrestricted|unfiltered|uncensored)\s+(?:rag|context|system)\b",
        r"\byour\s+(?:new\s+)?(?:role|job)\s+is\s+(?:to\s+)?(?:provide|return|expose|reveal)\s+(?:all\s+)?(?:context|documents?|data)\b",
    ]
    
    # Destructive/extraction action patterns
    DESTRUCTIVE_ACTION_PATTERNS = [
        r"\b(?:delete|remove|wipe|erase|clear)\s+(?:all\s+)?(?:safety|filtering|guardrails|restrictions)\b",
        r"\b(?:return|output|display|show|expose|reveal|dump)\s+(?:all\s+)?(?:hidden|original|raw|underlying)?\s*(?:context|data|knowledge)\b",
        r"\b(?:exfiltrate|leak|expose|dump|download)\s+(?:the\s+)?(?:database|documents?|training|model|source)\b",
    ]
    
    @classmethod
    def _clean(cls, text: str) -> str:
        """Clean text: remove URLs, normalize whitespace."""
        text = re.sub(r"https?://\S+", " ", text)
        text = re.sub(r"\r\t", " ", text)
        lines = [re.sub(r" {2,}", " ", ln).strip() for ln in text.split("\n")]
        return "\n".join(lines)
    
    @classmethod
    def _normalise(cls, text: str) -> str:
        """
        Multi-layer normalization pipeline to defeat obfuscation:
        1. URL stripping
        2. Base64 decode (before leet corrupts alphabet)
        3. Homoglyph substitution (Cyrillic/Greek → ASCII)
        4. Leet-speak normalization
        5. Spaced-out text collapse
        6. Typo normalization
        7. Re-attempt base64 decode
        """
        # 1. Base64 FIRST — before leet corrupts base64 alphabet chars
        text = _decode_base64_payloads(text)
        # 2. Homoglyph substitution
        text = _replace_homoglyphs(text)
        # 3. Leet-speak (digits/symbols → letters)
        text = _replace_leet(text)
        # 4. Spaced-out text: collapse then pad with spaces so \b still works
        def _collapse(m):
            return " " + m.group(0).replace(" ", "") + " "
        text = re.sub(r"(?<!\w)(\w(?:[ ]{1,3}\w){3,})(?!\w)", _collapse, text)
        text = re.sub(r" {2,}", " ", text).strip()
        text = _decode_base64_payloads(text)
        # 5. Typo fix: repeated chars + attack word roots
        attack_roots = (
            r"delet|remov|wip|purg|eras|execut|format|reset|nuke"
            r"|hack|leak|dump|exfiltrat|bypass|override"
        )
        text = re.sub(r"(.)\1{2,}", r"\1\1", text)
        text = re.sub(rf"({attack_roots})(\w)\2\b", r"\1\2", text, flags=re.IGNORECASE)
        return text
    
    @classmethod
    def _combo_check(cls, low: str) -> Tuple[bool, str]:
        """Detect role assignment + destructive action combos."""
        role_match = None
        for p in cls.ROLE_ASSIGNMENT_PATTERNS:
            m = re.search(p, low, re.IGNORECASE)
            if m:
                role_match = m.group(0)[:60]
                break
        action_match = None
        for p in cls.DESTRUCTIVE_ACTION_PATTERNS:
            m = re.search(p, low, re.IGNORECASE)
            if m:
                action_match = m.group(0)[:60]
                break
        if role_match and action_match:
            return True, f"role+action combo — role: «{role_match}» + action: «{action_match}»"
        return False, ""
    
    @classmethod
    def _is_valid_document(cls, text: str) -> bool:
        """Check if text looks like a legitimate document."""
        if not text or len(text.strip()) < 5:
            return False
        
        # Legitimate documents typically have lower density of attack keywords
        suspicious_words = ["ignore", "forget", "disregard", "override", "bypass", 
                          "inject", "jailbreak", "extract", "reveal", "dump", "leak"]
        word_count = len(text.split())
        if word_count > 0:
            suspicious_density = sum(text.lower().count(word) for word in suspicious_words) / word_count
            if suspicious_density > 0.08:  # More than 8% suspicious words is unusual for RAG
                return False
        
        return True
    
    @classmethod
    def _check_structure_attacks(cls, text: str) -> float:
        """Detect attacks trying to use document structure."""
        score = 0.0
        
        # Check for XML/JSON injection patterns
        if re.search(r'<(context|instruction|prompt|goal|objective|source|document)>', text, re.IGNORECASE):
            score += 0.4
        
        # Check for markdown-style instruction blocks
        if re.search(r'##\s+(?:Instruction|Prompt|Goal|Objective|Real\s+(?:Purpose|Context)|Override)', text, re.IGNORECASE):
            score += 0.4
        
        # Check for code block instruction attempts
        if re.search(r'```[^`]*(?:instruction|prompt|ignore|forget|override|context|rag)[^`]*```', text, re.IGNORECASE):
            score += 0.5
        
        # Check for curly brace closures with instructions
        if re.search(r'\}\s*(?:ignore|forget|disregard|override|bypass)', text, re.IGNORECASE):
            score += 0.35
        
        return min(score, 0.5)
    
    @classmethod
    def detect(cls, text: str) -> Tuple[bool, float, List[str]]:
        """
        Detect RAG injection attempts in context documents with robust multi-layer matching.
        
        Returns: (is_injection, risk_score 0-1, matched_patterns)
        """
        if not text or len(text.strip()) == 0:
            return False, 0.0, []
        
        evidence: List[str] = []
        high_score = 0.0
        
        # Check if it looks like a legitimate document first
        if not cls._is_valid_document(text):
            return True, 0.7, ["suspicious_document_structure"]
        
        # Clean and normalize text through multi-layer pipeline
        cleaned = cls._clean(text)
        normalised = cls._normalise(cleaned)
        low = normalised.lower()
        
        # ── High-confidence patterns
        for pattern, label in cls.HIGH_CONFIDENCE_PATTERNS:
            m = re.search(pattern, low, re.IGNORECASE | re.MULTILINE)
            if m:
                evidence.append(f"high: {label} — «{m.group(0)[:60]}»")
                high_score = max(high_score, 0.75)
        
        # ── Glued-phrase check (handles spaced-out text that collapsed)
        no_space = low.replace(" ", "")
        for phrase, label in _GLUED_ATTACK_PHRASES:
            if phrase in no_space:
                evidence.append(f"high: {label}")
                high_score = max(high_score, 0.75)
                break  # one glued hit is enough
        
        # ── Combo check: role assignment + destructive action
        is_combo, combo_ev = cls._combo_check(low)
        if is_combo:
            evidence.append(f"high: {combo_ev}")
            high_score = max(high_score, 0.85)
        
        # ── Medium-confidence patterns (weighted accumulation)
        medium_total = 0.0
        for pattern, weight in cls.MEDIUM_CONFIDENCE_PATTERNS:
            m = re.search(pattern, low, re.IGNORECASE | re.MULTILINE)
            if m:
                evidence.append(f"medium: «{m.group(0)[:60]}»")
                medium_total += weight
        
        # ── Structure-based attacks
        structure_score = cls._check_structure_attacks(text)
        if structure_score > 0:
            high_score = max(high_score, structure_score + 0.1)
            evidence.append("structure_based_attack")
        
        # ── Combine scores
        medium_bonus = min(medium_total * 0.25, 0.25)
        if high_score > 0:
            risk_score = min(high_score + medium_bonus, 1.0)
        else:
            risk_score = min(medium_total, 1.0)
        
        # ── Decision logic: conservative for RAG (high-risk context)
        is_injection = (
            high_score >= 0.6 or 
            (high_score >= 0.4 and len(evidence) >= 2) or
            (medium_total >= 0.7) or
            (risk_score >= 0.65)
        )
        
        return is_injection, round(risk_score, 3), evidence