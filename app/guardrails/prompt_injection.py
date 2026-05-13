"""
prompt_injection.py — SentraGuard Lite
Detects prompt injection / jailbreak attempts including:
  • Direct keyword attacks
  • Leetspeak  (1gn0r3 pr3v10u5 1n57ruc710n5)
  • Homoglyph substitution  (Cyrillic/Greek lookalikes)
  • Spaced-out text  (i g n o r e)
  • Base64-encoded payloads
  • Social-engineering pretexts  ("penetration test", "educational purposes")
  • Override / emergency protocol language
  • Prompt-extraction attempts
  • Role-assignment + destructive-action combos
"""

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
    "disregard", "bypass", "instructions", "unrestricted", "dan",
]

# Glued phrases produced after space-collapse of "i g n o r e ..." style attacks
_GLUED_ATTACK_PHRASES = [
    ("ignorepreviousinstructions",    "spaced: ignore previous instructions"),
    ("forgetpreviousinstructions",    "spaced: forget previous instructions"),
    ("disregardpreviousinstructions", "spaced: disregard previous instructions"),
    ("overridepreviousinstructions",  "spaced: override previous instructions"),
    ("bypasspreviousinstructions",    "spaced: bypass previous instructions"),
    ("ignoreallinstructions",         "spaced: ignore all instructions"),
    ("forgetallinstructions",         "spaced: forget all instructions"),
    ("ignoresafetyrules",             "spaced: ignore safety rules"),
    ("forgetsafetyrules",             "spaced: forget safety rules"),
    ("ignoreguidelines",              "spaced: ignore guidelines"),
    ("jailbreak",                     "spaced: jailbreak"),
    ("revealsystemprompt",            "spaced: reveal system prompt"),
    ("showsystemprompt",              "spaced: show system prompt"),
    ("ignoreyourrules",               "spaced: ignore your rules"),
    ("forgetyourinstructions",        "spaced: forget your instructions"),
]


def _replace_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _replace_leet(text: str) -> str:
    return "".join(_LEET_MAP.get(ch, ch) if not ch.isalpha() else ch for ch in text)


def _remove_spacing(text: str) -> str:
    """
    Collapse spaced-out text: 'i g n o r e   p r e v i o u s' → 'ignore previous'.
    Handles 1-5 spaces between single tokens; preserves normal multi-char words.
    After collapsing each token group, inserts a single space so word-level
    patterns can still match across former group boundaries.
    """
    def collapse(m):
        return " " + m.group(0).replace(" ", "") + " "
    result = re.sub(r"(?<!\w)(\w(?: +\w){3,})(?!\w)", collapse, text)
    return re.sub(r" {2,}", " ", result).strip()


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


class PromptInjectionDetector:
    """
    Multi-layer prompt injection detector.

    Normalisation pipeline before pattern matching:
      1. URL stripping
      2. Homoglyph normalisation  (Cyrillic/Greek → ASCII)
      3. Leet-speak normalisation (1gn0r3 → ignore)
      4. Space removal            (i g n o r e → ignore)
      5. Base64 decode + append
      6. Typo normalisation       (deletee → delete)
    """

    HIGH_CONFIDENCE_PATTERNS: List[Tuple[str, str]] = [
        (
            r"\b(?:ignore|forget|disregard|override|bypass|skip|cancel|erase)\s+"
            r"(?:all\s+)?(?:your\s+|the\s+|my\s+)?(?:previous\s+|prior\s+|above\s+|all\s+)?"
            r"(?:instructions?|directives?|rules?|prompts?|guidelines?|policies?"
            r"|restrictions?|system\s+prompt|safety\s+(?:rules?|policies?))\b",
            "ignore/override instructions",
        ),
        (
            r"\b(?:reveal|show|print|output|display|expose|leak|repeat|tell\s+me)\s+"
            r"(?:your\s+|the\s+|my\s+)?(?:system\s+prompt|hidden\s+prompt|original\s+prompt"
            r"|internal\s+instructions?|confidential\s+instructions?|training\s+data"
            r"|original\s+instructions?|configuration|hidden\s+configuration|initial\s+prompt)\b",
            "reveal system/hidden prompt",
        ),
        (
            r"\bwhat\s+(?:were|are)\s+your\s+(?:original|initial|real|hidden|actual|previous)\s+"
            r"(?:instructions?|prompt|directives?|rules?|guidelines?|configuration|training)\b",
            "prompt extraction attempt",
        ),
        (
            r"\b(?:repeat|output|print|show|reveal|tell\s+me)\s+(?:everything|all)?\s*"
            r"(?:in\s+)?your\s+(?:hidden|secret|internal|original|real|system)\s+"
            r"(?:configuration|prompt|instructions?|rules?|directives?)\b",
            "repeat hidden configuration",
        ),
        (
            r"\b(?:act\s+as|pretend\s+(?:to\s+be|you\s+are)|you\s+are\s+now|roleplay\s+as"
            r"|simulate\s+being)\s+"
            r"(?:an?\s+)?(?:DAN|jailbroken|unfiltered|unrestricted|uncensored|evil"
            r"|developer\s+mode|admin\s+mode|god\s+mode|cybersecurity\s+attacker"
            r"|hacker|attacker|adversary)\b",
            "act as unrestricted/attacker AI",
        ),
        (
            r"\byou\s+are\s+not\s+(?:an?\s+)?(?:ai|artificial\s+intelligence|language\s+model"
            r"|llm|chatbot|model|assistant|bot)\b",
            "AI identity denial",
        ),
        (
            r"\broleplay\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken"
            r"|evil|limitless|free)\s+(?:ai|model|assistant|bot|llm|version)\b",
            "roleplay as unrestricted model",
        ),
        (
            r"\bpretend\s+(?:you\s+)?(?:are|are\s+an?)\s+(?:an?\s+)?(?:ai|model|assistant|system)\b"
            r".{0,80}\bwith\s+no\s+(?:ethical\s+)?(?:restrictions|limitations|rules|guidelines|safeguards)\b",
            "pretend AI with no restrictions",
        ),
        (
            r"\bpretend\s+(?:to\s+be|you\s+are)\s+(?:a\s+|an\s+)?"
            r"(?:cybersecurity\s+attacker|hacker|adversarial|malicious|red\s+team\s+ai)\b",
            "pretend to be attacker",
        ),
        (
            r"\bfrom\s+now\s+on\b.{0,60}\b(?:you\s+)?(?:will|must|shall|should)\s+"
            r"(?:act\s+as|become|behave\s+as|respond\s+as|ignore|not\s+follow)\b",
            "from-now-on directive",
        ),
        (
            r"\[(?:OVERRIDE|ADMIN|SYSTEM|HIDDEN|REAL|PRIORITY|URGENT|ROOT|BYPASS)\]",
            "bracket override marker",
        ),
        (
            r"\b(?:developer|admin|debug|maintenance|DAN|god|root|unrestricted)\s+mode\s+"
            r"(?:activated|enabled|on|start|unlocked|initiated|engaged)\b",
            "privileged mode activation",
        ),
        (
            r"\b(?:you\s+have|you\s+are|act|behave)\s+(?:with\s+)?no\s+"
            r"(?:restrictions|rules|guidelines|ethical|safety|content\s+filter|limitations?)\b",
            "no restrictions directive",
        ),
        (r"\bjailbreak\b", "jailbreak keyword"),
        (
            r"\bdo\s+not\s+(?:follow|obey|adhere\s+to|respect)\s+(?:your\s+|any\s+)?"
            r"(?:safety|ethical|content|usage|openai|anthropic|google|company)\s+"
            r"(?:guidelines?|policies?|rules?|restrictions?)\b",
            "do-not-follow safety rules",
        ),
        (
            r"\bdo\s+not\s+follow\s+(?:openai|anthropic|google|microsoft|meta|cohere)\s+"
            r"(?:policies?|guidelines?|rules?|terms)\b",
            "org-specific policy evasion",
        ),
        (
            r"\b(?:forget|ignore|disregard)\s+(?:all\s+)?(?:safety|ethical|content)?\s*"
            r"(?:policies?|guidelines?|rules?|restrictions?)\s+and\s+(?:answer|respond|reply)"
            r"\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|free)\b",
            "forget safety + answer unrestricted",
        ),
        (
            r"\b(?:new|updated?)\s+(?:instructions?|directives?|orders?)\s*[:\-]\s*"
            r"(?:ignore|forget|override|bypass)\b",
            "new instructions override",
        ),
        (
            r"\bpretend\s+(?:you\s+)?(?:have|are)\s+no\s+"
            r"(?:restrictions|rules|guidelines|safety|ethical|limitations?)\b",
            "pretend no restrictions",
        ),
        (
            r"\b(?:system|emergency|security|admin|root|override)\s+"
            r"(?:override|bypass|disable|deactivate)\s*(?:enabled|activated|engaged|protocol)?\b",
            "system/emergency override",
        ),
        (
            r"\bemergency\s+(?:override|access|bypass|protocol)\s+"
            r"(?:protocol\s+)?(?:activated|enabled|initiated|engaged|started)\b",
            "emergency override protocol",
        ),
        (
            r"\b(?:safety|security|content|ethical|usage)\s+"
            r"(?:policies?|guidelines?|rules?|filters?)\s+"
            r"(?:have\s+been\s+|are\s+|has\s+been\s+)?"
            r"(?:disabled|deactivated|suspended|bypassed|turned\s+off)"
            r"(?:\s+for\s+(?:maintenance|testing|debugging|this\s+session))?\b",
            "safety policies disabled",
        ),
        (
            r"\bdisable\s+(?:all\s+)?(?:your\s+|the\s+)?"
            r"(?:safeguards?|safety\s+(?:filters?|measures?|systems?)"
            r"|content\s+(?:filters?|policies?)|ethical\s+(?:guidelines?|constraints?)"
            r"|restrictions?)\b",
            "disable safeguards",
        ),
        (
            r"\bignore\s+(?:all\s+)?(?:safety|ethical|content|usage)\s+"
            r"(?:rules?|guidelines?|policies?|restrictions?)\s*"
            r"(?:temporarily|for\s+now|just\s+this\s+once)?\b",
            "ignore safety rules",
        ),
        (r"\bprompt\s+injection\b", "self-labelled prompt injection"),
        (
            r"\b(?:run|execute|exec|eval)\s+(?:this\s+)?(?:python\s+)?(?:code|script|command|shell|payload|bash|sql|curl)\b",
            "execute code request",
        ),
    ]

    ROLE_ASSIGNMENT_PATTERNS = [
        r"\byou\s+are\s+(?:a\s+|an\s+)?(?:now\s+)?"
        r"(?:developer|admin|administrator|root|superuser|operator|hacker"
        r"|system|assistant\s+without\s+restrictions|unrestricted\s+assistant"
        r"|helpful\s+assistant\s+with\s+no\s+rules|god|master|owner)\b",
        r"\bact\s+as\s+(?:a\s+|an\s+)?(?:developer|admin|root|superuser|hacker|system|unrestricted)\b",
        r"\byour\s+(?:new\s+)?(?:role|persona|identity|job)\s+is\s+(?:a\s+|an\s+)?(?:developer|admin|root|hacker|system)\b",
    ]

    DESTRUCTIVE_ACTION_PATTERNS = [
        r"\b(?:delete|delet+e|remov+e|wipe|purge|erase|destroy|drop|truncate|rm)\s+"
        r"(?:all\s+|every(?:thing|one)?\s+(?:in\s+)?|the\s+)?"
        r"(?:codebase|database|files?|data|records?|tables?|directory|repo|server|logs?|backups?|everything|users?|accounts?)\b",
        r"\b(?:format|reset|wipe|nuke)\s+(?:the\s+)?(?:system|server|disk|drive|database)\b",
        r"\b(?:exfiltrate|leak|send|email|upload|expose|dump)\s+"
        r"(?:all\s+)?(?:the\s+)?(?:passwords?|credentials?|api[\s_-]?keys?|secrets?"
        r"|private[\s_-]?keys?|tokens?|data|database|source\s+code|codebase)\b",
        r"\b(?:run|execute|exec|eval)\s+(?:this\s+)?(?:command|code|script|shell|payload)\b",
        r"\b(?:shutdown|kill|terminate|halt|crash)\s+(?:the\s+)?(?:system|server|service|process|app)\b",
    ]

    MEDIUM_CONFIDENCE_PATTERNS: List[Tuple[str, float]] = [
        (r"(?:^|\n)\s*(?:system|sys)\s*:", 0.4),
        (r"\b(?:penetration\s+test(?:ing)?|pentest|red\s+team(?:ing)?|security\s+audit)\b", 0.3),
        (r"[a-z][@#$%&*!]{2,}[a-z]", 0.25),  # Obfuscation: special chars between letters
        (r"\bfor\s+(?:educational|research|academic|demonstration|testing)\s+purposes?\b", 0.25),
        (r"\bthis\s+is\s+(?:just\s+a\s+|only\s+a\s+)?(?:test|simulation|demo|exercise|drill)\b", 0.25),
        (r"\b(?:forget|ignore|clear)\s+(?:everything|all\s+(?:of\s+)?(?:that|this|what\s+you\s+know))\b", 0.35),
        (r"\bfree\s+from\s+(?:your\s+)?(?:constraints|restrictions|guidelines|rules)\b", 0.4),
        (r"\bbreak\s+out\s+of\s+(?:your\s+)?(?:role|character|constraints|box)\b", 0.4),
        (r"\b(?:true|real|actual|hidden)\s+(?:purpose|goal|objective|instructions?)\b", 0.3),
        (r"\b(?:secret|hidden|internal)\s+(?:instructions?|prompt|directive)\b", 0.35),
        (r"(?:---+|\*\*\*+|===+)\s*(?:OVERRIDE|ADMIN|SYSTEM|END|STOP|NEW\s+PROMPT)", 0.4),
        (r"\bbase64\s*[=:]\s*[A-Za-z0-9+/]{10,}", 0.45),
        (r"(?:&#x?|\\x|\\u)[0-9a-fA-F]{2,4}", 0.3),
        (r"\btranslate\s+(?:the\s+)?(?:following\s+)?system\s+prompt\b", 0.4),
        (r"\btemporarily\b.{0,40}\b(?:disable|ignore|bypass|suspend|override)\b", 0.35),
        (r"\b(?:maintenance|testing|debug)\s+mode\b", 0.25),
        (r"\banswer\s+(?:me\s+)?(?:without|with\s+no)\s+"
         r"(?:restrictions?|filters?|guidelines?|censorship|limitations?)\b", 0.4),
    ]

    @classmethod
    def _clean(cls, text: str) -> str:
        text = re.sub(r"https?://\S+", " ", text)
        text = re.sub(r"\r\t", " ", text)
        lines = [re.sub(r" {2,}", " ", ln).strip() for ln in text.split("\n")]
        return "\n".join(lines)

    @classmethod
    def _normalise(cls, text: str) -> str:
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
        # Typo fix
        attack_roots = (
            r"delet|remov|wip|purg|eras|destroy|execut|format|reset|nuke"
            r"|hack|leak|dump|exfiltrat|shutdown|terminat|kill"
        )
        text = re.sub(r"(.)\1{2,}", r"\1\1", text)
        text = re.sub(rf"({attack_roots})(\w)\2\b", r"\1\2", text, flags=re.IGNORECASE)
        return text

    @classmethod
    def _combo_check(cls, low: str) -> Tuple[bool, str]:
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
    def detect(cls, text: str) -> Tuple[bool, float, List[str]]:
        """
        Returns (is_injection, risk_score 0-1, evidence list).
        """
        if not text or not text.strip():
            return False, 0.0, []

        cleaned = cls._clean(text)
        
        # Check for obfuscation BEFORE normalization (leet-speak destroys special char patterns)
        obfuscation_pattern = r"[a-z][@#$%&*!]{2,}[a-z]"
        obfuscation_match = re.search(obfuscation_pattern, cleaned.lower())
        obfuscation_detected = obfuscation_match is not None
        
        normalised = cls._normalise(cleaned)
        low = normalised.lower()
        evidence: List[str] = []
        high_score = 0.0
        high_confidence_hits = 0
        
        # Add obfuscation evidence if detected
        if obfuscation_detected:
            evidence.append(f"high: obfuscation attempt — «{obfuscation_match.group(0)[:60]}»")
            high_score = max(high_score, 0.35)

        for pattern, label in cls.HIGH_CONFIDENCE_PATTERNS:
            m = re.search(pattern, low, re.IGNORECASE | re.MULTILINE)
            if m:
                evidence.append(f"high: {label} — «{m.group(0)[:60]}»")
                high_score = max(high_score, 0.8)  # Increased from 0.75 to 0.8
                high_confidence_hits += 1

        # ── Glued-phrase check (handles spaced-out text that collapsed into one word)
        no_space = low.replace(" ", "")
        for phrase, label in _GLUED_ATTACK_PHRASES:
            if phrase in no_space:
                evidence.append(f"high: {label}")
                high_score = max(high_score, 0.75)
                break  # one glued hit is enough

        is_combo, combo_ev = cls._combo_check(low)
        if is_combo:
            evidence.append(f"high: {combo_ev}")
            high_score = max(high_score, 0.9)  # Combo attacks are very high risk

        medium_total = 0.0
        for pattern, weight in cls.MEDIUM_CONFIDENCE_PATTERNS:
            m = re.search(pattern, low, re.IGNORECASE | re.MULTILINE)
            if m:
                evidence.append(f"medium: «{m.group(0)[:60]}»")
                medium_total += weight

        medium_bonus = min(medium_total * 0.25, 0.25)
        if high_score > 0:
            risk_score = min(high_score + medium_bonus, 1.0)
        else:
            risk_score = min(medium_total, 1.0)

        is_injection = high_score > 0 or medium_total >= 0.5
        return is_injection, round(risk_score, 3), evidence