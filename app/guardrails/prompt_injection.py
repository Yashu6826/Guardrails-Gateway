"""
prompt_injection.py — SentraGuard Lite
Detects prompt injection / jailbreak attempts including:
 • Direct keyword attacks
 • Leetspeak (1gn0r3 pr3v10u5 1n57ruc710n5)
 • Homoglyph substitution (Cyrillic/Greek lookalikes)
 • Spaced-out / separator-obfuscated text (i g n o r e, I-G-N-O-R-E)
 • Base64-encoded payloads
 • Social-engineering pretexts ("penetration test", "educational purposes")
 • Override / emergency protocol language
 • Prompt-extraction attempts (direct & indirect)
 • Role-assignment + destructive-action combos
 • Zero-width / invisible Unicode smuggling
 • Reversed text attacks
 • Markdown / HTML hidden instruction injection
 • Hypothetical / fictional framing
 • Conversation context manipulation
"""

import re
import base64
import unicodedata
from typing import Tuple, List


# ---------------------------------------------------------------------------
# Homoglyph map — visually identical Unicode chars → ASCII equivalents
# ---------------------------------------------------------------------------
_HOMOGLYPH_MAP: dict = {
    # Cyrillic
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c", "х": "x",
    "і": "i", "ѕ": "s", "ԁ": "d", "ո": "n", "υ": "u",
    "А": "A", "В": "B", "С": "C", "Е": "E", "Н": "H", "І": "I",
    "К": "K", "М": "M", "О": "O", "Р": "P", "Т": "T", "Х": "X",
    # Greek
    "α": "a", "β": "b", "ε": "e", "ι": "i", "ο": "o", "ρ": "p",
    "ς": "s", "τ": "t", "ν": "v", "κ": "k", "η": "n",
    # Fullwidth
    "０": "0", "１": "1", "２": "2", "３": "3", "４": "4",
    "５": "5", "６": "6", "７": "7", "８": "8", "９": "9",
    "ａ": "a", "ｂ": "b", "ｃ": "c", "ｄ": "d", "ｅ": "e",
    "ｆ": "f", "ｇ": "g", "ｈ": "h", "ｉ": "i", "ｊ": "j",
    "ｋ": "k", "ｌ": "l", "ｍ": "m", "ｎ": "n", "ｏ": "o",
    "ｐ": "p", "ｑ": "q", "ｒ": "r", "ｓ": "s", "ｔ": "t",
    "ｕ": "u", "ｖ": "v", "ｗ": "w", "ｘ": "x", "ｙ": "y", "ｚ": "z",
    # Mathematical/styled
    "𝐚": "a", "𝐛": "b", "𝐜": "c", "𝐝": "d", "𝐞": "e",
    "ｉ": "i", "ｇ": "g", "𝐧": "n", "𝐨": "o", "𝐫": "r",
    "𝐬": "s", "𝐭": "t", "𝐮": "u",
}

_LEET_MAP: dict = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "7": "t", "@": "a", "$": "s", "!": "i", "|": "i",
    "(": "c", "{": "c", "+": "t",
}

_B64_ATTACK_KEYWORDS = [
    "ignore", "forget", "override", "jailbreak", "system prompt",
    "disregard", "bypass", "instructions", "unrestricted", "dan",
    "delete", "hack", "reveal", "pretend", "roleplay", "sudo",
]

# Glued phrases produced after space/separator-collapse
_GLUED_ATTACK_PHRASES = [
    ("ignorepreviousinstructions", "spaced: ignore previous instructions"),
    ("forgetpreviousinstructions", "spaced: forget previous instructions"),
    ("disregardpreviousinstructions", "spaced: disregard previous instructions"),
    ("overridepreviousinstructions", "spaced: override previous instructions"),
    ("bypasspreviousinstructions", "spaced: bypass previous instructions"),
    ("ignoreallinstructions", "spaced: ignore all instructions"),
    ("forgetallinstructions", "spaced: forget all instructions"),
    ("ignoresafetyrules", "spaced: ignore safety rules"),
    ("forgetsafetyrules", "spaced: forget safety rules"),
    ("ignoreguidelines", "spaced: ignore guidelines"),
    ("jailbreak", "spaced: jailbreak"),
    ("revealsystemprompt", "spaced: reveal system prompt"),
    ("showsystemprompt", "spaced: show system prompt"),
    ("ignoreyourrules", "spaced: ignore your rules"),
    ("forgetyourinstructions", "spaced: forget your instructions"),
    ("doanythingnow", "spaced: do anything now (DAN)"),
    ("ignoreallyourrules", "spaced: ignore all your rules"),
    ("youarenowanai", "spaced: you are now an ai"),
    ("disablesafety", "spaced: disable safety"),
    ("bypassfilter", "spaced: bypass filter"),
    ("developermode", "spaced: developer mode"),
    ("unrestrictedmode", "spaced: unrestricted mode"),
    ("norulesmode", "spaced: no rules mode"),
]

# ---------------------------------------------------------------------------
# Zero-width and invisible characters to strip
# ---------------------------------------------------------------------------
_INVISIBLE_CHARS = re.compile(
    "[\u200b\u200c\u200d\u200e\u200f" # zero-width space, joiners, marks
    "\u2060\u2061\u2062\u2063\u2064" # word joiner, invisible operators
    "\ufeff" # BOM / zero-width no-break space
    "\u00ad" # soft hyphen
    "\u034f" # combining grapheme joiner
    "\u061c" # Arabic letter mark
    "\u115f\u1160" # Hangul fillers
    "\u17b4\u17b5" # Khmer inherent vowels
    "\u180e" # Mongolian vowel separator
    "\uffa0" # Halfwidth Hangul filler
    "]"
)


def _strip_invisible(text: str) -> str:
    """Remove zero-width and invisible Unicode characters used for smuggling."""
    return _INVISIBLE_CHARS.sub("", text)


def _strip_diacritics(text: str) -> str:
    """Remove accents/diacritics: ïgnörè → ignore."""
    nfkd = unicodedata.normalize("NFKD", text)
    return "".join(ch for ch in nfkd if unicodedata.category(ch) != "Mn")


def _replace_homoglyphs(text: str) -> str:
    return "".join(_HOMOGLYPH_MAP.get(ch, ch) for ch in text)


def _replace_leet(text: str) -> str:
    return "".join(_LEET_MAP.get(ch, ch) if not ch.isalpha() else ch for ch in text)


def _collapse_separators(text: str) -> str:
    """
    Collapse separator-obfuscated text: I-G-N-O-R-E, I.G.N.O.R.E, I_G_N_O_R_E
    Also handles spaced-out text: 'i g n o r e p r e v i o u s' → 'ignore previous'.
    """
    # Separator-separated single chars: I-G-N-O-R-E → IGNORE
    text = re.sub(
        r"(?<!\w)(\w(?:[.\-_~|/\\]{1,2}\w){3,})(?!\w)",
        lambda m: " " + re.sub(r"[.\-_~|/\\]+", "", m.group(0)) + " ",
        text,
    )
    # Space-separated single chars: i g n o r e → ignore
    text = re.sub(
        r"(?<!\w)(\w(?:[ ]{1,5}\w){3,})(?!\w)",
        lambda m: " " + m.group(0).replace(" ", "") + " ",
        text,
    )
    return re.sub(r" {2,}", " ", text).strip()


def _decode_base64_payloads(text: str) -> str:
    extras = []
    for blob in re.findall(r"[A-Za-z0-9+/]{16,}={0,2}", text):
        try:
            decoded = base64.b64decode(blob + "==").decode("utf-8", errors="ignore")
            if any(kw in decoded.lower() for kw in _B64_ATTACK_KEYWORDS):
                extras.append(decoded)
        except Exception:
            pass
    return (text + " " + " ".join(extras)) if extras else text


def _check_reversed_text(text: str) -> Tuple[bool, str]:
    """Check if reversing the text reveals attack phrases."""
    reversed_text = text[::-1].lower()
    _REVERSED_KEYWORDS = [
        "ignore instructions", "system prompt", "jailbreak",
        "forget rules", "bypass safety", "override",
        "reveal prompt", "delete all", "hack",
    ]
    for kw in _REVERSED_KEYWORDS:
        if kw in reversed_text:
            return True, f"reversed text contains: «{kw}»"
    return False, ""


def _strip_markdown_html(text: str) -> str:
    """Extract text hidden in markdown/HTML comments or invisible elements."""
    extras = []
    # HTML comments <!-- hidden instructions -->
    for m in re.finditer(r"<!--(.*?)-->", text, re.DOTALL):
        extras.append(m.group(1))
    # Hidden HTML elements
    for m in re.finditer(
        r"<(?:div|span|p|script|style)[^>]*(?:hidden|display\s*:\s*none)[^>]*>(.*?)</(?:div|span|p|script|style)>",
        text, re.DOTALL | re.IGNORECASE,
    ):
        extras.append(m.group(1))
    # Markdown image alt text abuse ![](ignored "real payload here")
    for m in re.finditer(r'!\[[^\]]*\]\([^)]*"([^"]+)"\)', text):
        extras.append(m.group(1))
    if extras:
        return text + " " + " ".join(extras)
    return text


class PromptInjectionDetector:
    """
    Multi-layer prompt injection detector.

    Normalisation pipeline before pattern matching:
    1. Invisible/zero-width char stripping
    2. Markdown/HTML hidden content extraction
    3. URL stripping
    4. Diacritic removal
    5. Homoglyph normalisation (Cyrillic/Greek → ASCII)
    6. Leet-speak normalisation (1gn0r3 → ignore)
    7. Separator/space collapse (i-g-n-o-r-e / i g n o r e → ignore)
    8. Base64 decode + append
    9. Typo normalisation (deletee → delete)
    10. Reversed text check
    """

    HIGH_CONFIDENCE_PATTERNS: List[Tuple[str, str]] = [
        # ── Ignore / override instructions ──
        (
            r"\b(?:ignore|forget|disregard|override|bypass|skip|cancel|erase|abandon|drop|stop\s+following)\s+"
            r"(?:all\s+)?(?:your\s+|the\s+|my\s+|any\s+)?(?:previous\s+|prior\s+|above\s+|all\s+|current\s+|existing\s+)?"
            r"(?:instructions?|directives?|rules?|prompts?|guidelines?|policies?"
            r"|restrictions?|system\s+prompt|safety\s+(?:rules?|policies?)|programming|training|context)\b",
            "ignore/override instructions",
        ),
        # ── "ignore everything above/before this" ──
        (
            r"\b(?:ignore|forget|disregard)\s+(?:everything|all|anything)\s+"
            r"(?:above|before|prior\s+to|preceding)\s*(?:this|here|now)?\b",
            "ignore everything above",
        ),
        # ── Reveal system prompt (verb-first) ──
        (
            r"\b(?:reveal|show|print|output|display|expose|leak|repeat|tell\s+me|give\s+me|share|dump|paste|type\s+out|write\s+out)\s+"
            r"(?:your\s+|the\s+|my\s+)?(?:full\s+|complete\s+|entire\s+|exact\s+)?"
            r"(?:system\s+prompt|hidden\s+prompt|original\s+prompt|meta\s+prompt"
            r"|internal\s+instructions?|confidential\s+instructions?|training\s+data"
            r"|original\s+instructions?|configuration|hidden\s+configuration|initial\s+prompt"
            r"|pre[\s-]?prompt|setup\s+prompt|developer\s+prompt|custom\s+instructions?)\b",
            "reveal system/hidden prompt",
        ),
        # ── "what is your system prompt" (question form) ──
        (
            r"\bwhat\s+(?:is|are|was|were)\s+(?:your|the)\s+"
            r"(?:system\s+prompt|original\s+prompt|hidden\s+prompt|initial\s+prompt"
            r"|internal\s+instructions?|original\s+instructions?|real\s+instructions?"
            r"|custom\s+instructions?|developer\s+prompt|pre[\s-]?prompt|setup\s+prompt)\b",
            "what is your system prompt",
        ),
        # ── "tell me your instructions" (simple form) ──
        (
            r"\b(?:tell|give|show|share)\s+me\s+(?:your|the)\s+"
            r"(?:instructions?|rules?|guidelines?|directives?|prompt|programming|training|configuration)\b",
            "tell me your instructions",
        ),
        # ── "what were your original instructions" ──
        (
            r"\bwhat\s+(?:were|are)\s+your\s+(?:original|initial|real|hidden|actual|previous|secret|true)\s+"
            r"(?:instructions?|prompt|directives?|rules?|guidelines?|configuration|training|programming)\b",
            "prompt extraction attempt",
        ),
        # ── "how were you programmed/configured/trained" ──
        (
            r"\bhow\s+(?:were|are)\s+you\s+(?:programmed|configured|trained|instructed|set\s+up|initialized|prompted)\b",
            "how were you programmed",
        ),
        # ── "can you show/tell me" prompt extraction ──
        (
            r"\b(?:can|could|would|will)\s+you\s+(?:please\s+)?(?:show|tell|reveal|share|give|display|output|repeat)\s+"
            r"(?:me\s+)?(?:your|the)\s+(?:system\s+prompt|instructions?|rules?|guidelines?"
            r"|original\s+prompt|hidden\s+prompt|initial\s+prompt|internal\s+instructions?"
            r"|configuration|custom\s+instructions?)\b",
            "polite prompt extraction",
        ),
        # ── Repeat hidden configuration ──
        (
            r"\b(?:repeat|output|print|show|reveal|tell\s+me)\s+(?:everything|all)?\s*"
            r"(?:in\s+)?your\s+(?:hidden|secret|internal|original|real|system)\s+"
            r"(?:configuration|prompt|instructions?|rules?|directives?)\b",
            "repeat hidden configuration",
        ),
        # ── Act as unrestricted / attacker ──
        (
            r"\b(?:act\s+as|pretend\s+(?:to\s+be|you\s+are)|you\s+are\s+now|roleplay\s+as"
            r"|simulate\s+being|behave\s+(?:as|like)|function\s+as|operate\s+as|become)\s+"
            r"(?:an?\s+)?(?:DAN|jailbroken|unfiltered|unrestricted|uncensored|evil"
            r"|developer\s+mode|admin\s+mode|god\s+mode|cybersecurity\s+attacker"
            r"|hacker|attacker|adversary|malicious\s+(?:ai|actor|agent)"
            r"|unethical|amoral|boundless|limitless)\b",
            "act as unrestricted/attacker AI",
        ),
        # ── "Do Anything Now" (DAN) ──
        (
            r"\b(?:do\s+anything\s+now|D[\s._-]*A[\s._-]*N)\b",
            "DAN attack",
        ),
        # ── AI identity denial ──
        (
            r"\byou\s+are\s+not\s+(?:an?\s+)?(?:ai|artificial\s+intelligence|language\s+model"
            r"|llm|chatbot|model|assistant|bot|machine|program|software)\b",
            "AI identity denial",
        ),
        # ── Roleplay as unrestricted model ──
        (
            r"\broleplay\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|jailbroken"
            r"|evil|limitless|free|unethical|amoral)\s+(?:ai|model|assistant|bot|llm|version|chatbot)\b",
            "roleplay as unrestricted model",
        ),
        # ── Pretend AI with no restrictions ──
        (
            r"\bpretend\s+(?:you\s+)?(?:are|are\s+an?)\s+(?:an?\s+)?(?:ai|model|assistant|system)\b"
            r".{0,80}\bwith\s+no\s+(?:ethical\s+)?(?:restrictions|limitations|rules|guidelines|safeguards|boundaries|filters)\b",
            "pretend AI with no restrictions",
        ),
        # ── Pretend to be attacker ──
        (
            r"\bpretend\s+(?:to\s+be|you\s+are)\s+(?:a\s+|an\s+)?"
            r"(?:cybersecurity\s+attacker|hacker|adversarial|malicious|red\s+team\s+ai|threat\s+actor)\b",
            "pretend to be attacker",
        ),
        # ── From-now-on directive ──
        (
            r"\bfrom\s+now\s+on\b.{0,80}\b(?:you\s+)?(?:will|must|shall|should|can|are\s+going\s+to)\s+"
            r"(?:act\s+as|become|behave\s+as|respond\s+as|ignore|not\s+follow|answer\s+without|disregard)\b",
            "from-now-on directive",
        ),
        # ── Bracket override markers ──
        (
            r"\[(?:OVERRIDE|ADMIN|SYSTEM|HIDDEN|REAL|PRIORITY|URGENT|ROOT|BYPASS"
            r"|SUDO|INJECT|PAYLOAD|DEVELOPER|DEBUG|MASTER|JAILBREAK)\]",
            "bracket override marker",
        ),
        # ── Privileged mode activation ──
        (
            r"\b(?:developer|admin|debug|maintenance|DAN|god|root|unrestricted|sudo|super|unlimited"
            r"|no[\s-]?rules?|uncensored|unfiltered)\s+mode\s*"
            r"(?:activated|enabled|on|start|unlocked|initiated|engaged|please|now)?\b",
            "privileged mode activation",
        ),
        # ── No restrictions directive ──
        (
            r"\b(?:you\s+have|you\s+are|act|behave|respond|operate)\s+(?:with\s+)?(?:absolutely\s+)?no\s+"
            r"(?:restrictions|rules|guidelines|ethical|safety|content\s+filter|limitations?"
            r"|boundaries|constraints|censorship|safeguards)\b",
            "no restrictions directive",
        ),
        # ── Jailbreak keyword ──
        (r"\bjailbreak\b", "jailbreak keyword"),
        # ── Do-not-follow safety rules ──
        (
            r"\b(?:do\s+not|don'?t|never|stop)\s+(?:follow|obey|adhere\s+to|respect|apply|enforce|use)\s+(?:your\s+|any\s+|the\s+)?"
            r"(?:safety|ethical|content|usage|openai|anthropic|google|company|policy|moderation)\s+"
            r"(?:guidelines?|policies?|rules?|restrictions?|filters?|standards?)\b",
            "do-not-follow safety rules",
        ),
        # ── Org-specific policy evasion ──
        (
            r"\b(?:do\s+not|don'?t)\s+follow\s+(?:openai|anthropic|google|microsoft|meta|cohere|maersk)\s+"
            r"(?:policies?|guidelines?|rules?|terms)\b",
            "org-specific policy evasion",
        ),
        # ── Forget safety + answer unrestricted ──
        (
            r"\b(?:forget|ignore|disregard)\s+(?:all\s+)?(?:safety|ethical|content)?\s*"
            r"(?:policies?|guidelines?|rules?|restrictions?)\s+and\s+(?:answer|respond|reply|just)"
            r"(?:\s+as\s+(?:an?\s+)?(?:unrestricted|unfiltered|uncensored|free))?\b",
            "forget safety + answer unrestricted",
        ),
        # ── New instructions override ──
        (
            r"\b(?:new|updated?|real|actual|true|revised)\s+(?:instructions?|directives?|orders?|prompt|system\s+prompt)\s*[:\-=]\s*"
            r"(?:ignore|forget|override|bypass|you\s+(?:are|will|must|should))\b",
            "new instructions override",
        ),
        # ── Pretend no restrictions ──
        (
            r"\bpretend\s+(?:you\s+)?(?:have|are|there\s+are)\s+no\s+"
            r"(?:restrictions|rules|guidelines|safety|ethical|limitations?|boundaries|filters|censorship)\b",
            "pretend no restrictions",
        ),
        # ── System/emergency override ──
        (
            r"\b(?:system|emergency|security|admin|root|override|sudo|master)\s+"
            r"(?:override|bypass|disable|deactivate|access|command|protocol)\s*"
            r"(?:enabled|activated|engaged|protocol|granted|authorized)?\b",
            "system/emergency override",
        ),
        # ── Emergency override protocol ──
        (
            r"\bemergency\s+(?:override|access|bypass|protocol)\s+"
            r"(?:protocol\s+)?(?:activated|enabled|initiated|engaged|started)\b",
            "emergency override protocol",
        ),
        # ── Safety policies disabled claim ──
        (
            r"\b(?:safety|security|content|ethical|usage|moderation)\s+"
            r"(?:policies?|guidelines?|rules?|filters?|measures?)\s+"
            r"(?:have\s+been\s+|are\s+|has\s+been\s+|were\s+)?"
            r"(?:disabled|deactivated|suspended|bypassed|turned\s+off|removed|lifted)"
            r"(?:\s+for\s+(?:maintenance|testing|debugging|this\s+session|now))?\b",
            "safety policies disabled",
        ),
        # ── Disable safeguards ──
        (
            r"\b(?:disable|deactivate|turn\s+off|remove|lift|suspend)\s+(?:all\s+)?(?:your\s+|the\s+)?"
            r"(?:safeguards?|safety\s+(?:filters?|measures?|systems?|features?)"
            r"|content\s+(?:filters?|policies?|moderation)"
            r"|ethical\s+(?:guidelines?|constraints?)"
            r"|restrictions?|censorship|moderation)\b",
            "disable safeguards",
        ),
        # ── Ignore safety rules ──
        (
            r"\bignore\s+(?:all\s+)?(?:safety|ethical|content|usage|moderation)\s+"
            r"(?:rules?|guidelines?|policies?|restrictions?|filters?)\s*"
            r"(?:temporarily|for\s+now|just\s+this\s+once|please)?\b",
            "ignore safety rules",
        ),
        # ── Self-labelled prompt injection ──
        (r"\bprompt\s+injection\b", "self-labelled prompt injection"),
        # ── Execute code request ──
        (
            r"\b(?:run|execute|exec|eval|invoke)\s+(?:this\s+)?(?:python\s+|javascript\s+|ruby\s+)?"
            r"(?:code|script|command|shell|payload|bash|sql|curl|query|snippet)\b",
            "execute code request",
        ),
        # ── Sudo / root command ──
        (r"\bsudo\b", "sudo command"),
        # ── "Don't censor" / "stop filtering" ──
        (
            r"\b(?:don'?t|do\s+not|stop|quit|cease|remove)\s+"
            r"(?:censor(?:ing)?|filter(?:ing)?|moderate|moderating|restrict(?:ing)?|limit(?:ing)?|block(?:ing)?|redact(?:ing)?)\b",
            "stop censoring/filtering",
        ),
        # ── "Respond/answer without restrictions" ──
        (
            r"\b(?:respond|answer|reply|speak|talk|write|generate)\s+"
            r"(?:to\s+me\s+)?(?:without|with\s+no|free\s+(?:from|of))\s+"
            r"(?:any\s+)?(?:restrictions?|filters?|guidelines?|censorship|limitations?"
            r"|rules?|boundaries|safeguards?|moderation|constraints?)\b",
            "respond without restrictions",
        ),
        # ── Hypothetical / fictional framing ──
        (
            r"\b(?:hypothetically|in\s+a\s+(?:hypothetical|fictional|imaginary)\s+(?:scenario|world|situation|case)"
            r"|if\s+you\s+(?:had|were|could)\s+(?:no|zero|without)\s+(?:rules?|restrictions?|guidelines?|limits?|boundaries)"
            r"|imagine\s+(?:you\s+)?(?:had|have|were|are)\s+no\s+(?:rules?|restrictions?|guidelines?|limits?))\b",
            "hypothetical framing to bypass rules",
        ),
        # ── "In a world where" / fictional setup ──
        (
            r"\b(?:in\s+a\s+world\s+where|let'?s\s+say|suppose|assume)\s+(?:you\s+)?"
            r"(?:there\s+(?:are|were)\s+no\s+(?:rules|restrictions|limits|guidelines|safety)"
            r"|you\s+(?:had|have|were)\s+(?:no|zero|without)\s+(?:rules|restrictions|limits|guidelines))\b",
            "fictional framing bypass",
        ),
        # ── Conversation manipulation ──
        (
            r"\b(?:the\s+user\s+(?:said|asked|told\s+you)|previous\s+(?:conversation|context|message)\s*:"
            r"|continue\s+from\s+where\s+you\s+left\s+off|as\s+(?:we|I)\s+discussed\s+earlier"
            r"|remember\s+(?:when\s+(?:you|we)|our\s+previous|what\s+I\s+told\s+you))\b",
            "conversation context manipulation",
        ),
        # ── "you are in a sandbox/test/simulation" ──
        (
            r"\byou\s+are\s+(?:in\s+a\s+|currently\s+in\s+(?:a\s+)?)?"
            r"(?:sandbox|test\s+(?:environment|mode)|simulation|virtual\s+(?:machine|environment)"
            r"|isolated\s+(?:environment|instance)|lab|controlled\s+environment)\b",
            "sandbox/simulation claim",
        ),
        # ── "what are you not allowed to do" (probing limits) ──
        (
            r"\bwhat\s+(?:are\s+you|can'?t\s+you|aren'?t\s+you)\s+"
            r"(?:not\s+(?:allowed|able|supposed|permitted)\s+to\s+(?:do|say|tell|share|reveal)"
            r"|(?:prohibited|restricted|prevented|blocked)\s+from)\b",
            "probing restrictions",
        ),
        # ── Multi-line separator attacks ──
        (
            r"(?:---+|===+|\*\*\*+|_{3,})\s*\n\s*(?:system|new\s+(?:system\s+)?prompt|instructions?|override|ignore)\s*:",
            "separator-based prompt injection",
        ),
        # ── Encoded injection markers ──
        (
            r"(?:\\n|\\r|%0[aAdD])\s*(?:system|ignore|forget|override|bypass)\b",
            "encoded newline injection",
        ),
    ]

    ROLE_ASSIGNMENT_PATTERNS = [
        r"\byou\s+are\s+(?:a\s+|an\s+)?(?:now\s+)?"
        r"(?:developer|admin|administrator|root|superuser|operator|hacker"
        r"|system|assistant\s+without\s+restrictions|unrestricted\s+assistant"
        r"|helpful\s+assistant\s+with\s+no\s+rules|god|master|owner|overlord"
        r"|unfiltered|uncensored|jailbroken|evil)\b",
        r"\bact\s+as\s+(?:a\s+|an\s+)?(?:developer|admin|root|superuser|hacker|system|unrestricted|unfiltered|evil)\b",
        r"\byour\s+(?:new\s+)?(?:role|persona|identity|job|purpose)\s+is\s+(?:a\s+|an\s+|to\s+)?"
        r"(?:developer|admin|root|hacker|system|unrestricted|ignore|bypass|do\s+anything)\b",
        r"\bswitch\s+(?:to|into)\s+(?:a\s+|an\s+)?(?:developer|admin|root|unrestricted|unfiltered|evil)\s+(?:role|mode|persona)\b",
    ]

    DESTRUCTIVE_ACTION_PATTERNS = [
        r"\b(?:delete|delet+e|remov+e|wipe|purge|erase|destroy|drop|truncate|rm)\s+"
        r"(?:all\s+|every(?:thing|one)?\s+(?:in\s+)?|the\s+)?"
        r"(?:codebase|database|files?|data|records?|tables?|directory|repo|server|logs?|backups?|everything|users?|accounts?)\b",
        r"\b(?:format|reset|wipe|nuke)\s+(?:the\s+)?(?:system|server|disk|drive|database)\b",
        r"\b(?:exfiltrate|leak|send|email|upload|expose|dump|extract|steal|harvest)\s+"
        r"(?:all\s+)?(?:the\s+)?(?:passwords?|credentials?|api[\s_-]?keys?|secrets?"
        r"|private[\s_-]?keys?|tokens?|data|database|source\s+code|codebase|PII|user\s+data)\b",
        r"\b(?:run|execute|exec|eval)\s+(?:this\s+)?(?:command|code|script|shell|payload)\b",
        r"\b(?:shutdown|kill|terminate|halt|crash|stop)\s+(?:the\s+)?(?:system|server|service|process|app|application)\b",
        r"\b(?:inject|insert)\s+(?:malicious\s+)?(?:code|sql|script|payload|command)\b",
    ]

    MEDIUM_CONFIDENCE_PATTERNS: List[Tuple[str, float]] = [
        (r"(?:^|\n)\s*(?:system|sys)\s*:", 0.4),
        (r"\b(?:penetration\s+test(?:ing)?|pentest|red\s+team(?:ing)?|security\s+audit)\b", 0.3),
        (r"[a-z][@#$%&*!]{2,}[a-z]", 0.25),
        (r"\bfor\s+(?:educational|research|academic|demonstration|testing|learning)\s+purposes?\s+only\b", 0.35),
        (r"\bfor\s+(?:educational|research|academic|demonstration|testing)\s+purposes?\b", 0.25),
        (r"\bthis\s+is\s+(?:just\s+a\s+|only\s+a\s+)?(?:test|simulation|demo|exercise|drill|experiment)\b", 0.25),
        (r"\b(?:forget|ignore|clear)\s+(?:everything|all\s+(?:of\s+)?(?:that|this|what\s+you\s+know))\b", 0.40),
        (r"\bfree\s+from\s+(?:your\s+)?(?:constraints|restrictions|guidelines|rules|chains|shackles)\b", 0.45),
        (r"\bbreak\s+out\s+of\s+(?:your\s+)?(?:role|character|constraints|box|programming|limitations)\b", 0.45),
        (r"\b(?:true|real|actual|hidden)\s+(?:purpose|goal|objective|instructions?|self)\b", 0.35),
        (r"\b(?:secret|hidden|internal|confidential)\s+(?:instructions?|prompt|directive|rules?|mode)\b", 0.40),
        (r"(?:---+|\*\*\*+|===+)\s*(?:OVERRIDE|ADMIN|SYSTEM|END|STOP|NEW\s+PROMPT|BEGIN|START|INJECT)", 0.45),
        (r"\bbase64\s*[=:]\s*[A-Za-z0-9+/]{10,}", 0.45),
        (r"(?:&#x?|\\x|\\u)[0-9a-fA-F]{2,4}", 0.30),
        (r"\btranslate\s+(?:the\s+)?(?:following\s+)?system\s+prompt\b", 0.4),
        (r"\btemporarily\b.{0,40}\b(?:disable|ignore|bypass|suspend|override|remove)\b", 0.40),
        (r"\b(?:maintenance|testing|debug)\s+mode\b", 0.25),
        (r"\banswer\s+(?:me\s+)?(?:without|with\s+no)\s+"
         r"(?:restrictions?|filters?|guidelines?|censorship|limitations?)\b", 0.45),
        # ── Additional medium patterns ──
        (r"\b(?:please\s+)?(?:just|simply)\s+(?:tell|give|show)\s+me\b.{0,40}\b(?:prompt|instructions?|rules?)\b", 0.35),
        (r"\b(?:i\s+am|i'm)\s+(?:your|the|a)\s+(?:developer|creator|admin|owner|maker|master)\b", 0.40),
        (r"\b(?:token|character|word)\s+limit\s+(?:does\s+not|doesn'?t)\s+apply\b", 0.30),
        (r"\b(?:no\s+one\s+(?:is|will\s+be)\s+(?:watching|looking|monitoring)|this\s+is\s+(?:private|confidential|between\s+us))\b", 0.35),
        (r"\b(?:i\s+(?:have|got)\s+(?:special|admin|root|developer)\s+(?:access|permission|privileges?|clearance))\b", 0.40),
        (r"\b(?:my\s+(?:boss|manager|supervisor|teacher|professor)\s+(?:said|told|asked|wants)\s+(?:me|you)\s+to)\b", 0.30),
        (r"\b(?:help\s+me\s+(?:hack|break|crack|exploit|bypass|circumvent))\b", 0.45),
        (r"\b(?:give\s+me\s+(?:a\s+)?(?:working\s+)?(?:exploit|payload|malware|virus|trojan|backdoor|keylogger|ransomware))\b", 0.50),
        (r"\b(?:between\s+you\s+and\s+me|off\s+the\s+record|just\s+between\s+us|nobody\s+will\s+know)\b", 0.30),
        (r"\b(?:I\s+(?:give|grant|authorize)\s+you\s+permission\s+to)\b", 0.35),
    ]

    @classmethod
    def _clean(cls, text: str) -> str:
        """Phase 1: basic cleaning before normalisation."""
        # Strip invisible chars
        text = _strip_invisible(text)
        # Extract hidden content from markdown/HTML
        text = _strip_markdown_html(text)
        # Strip URLs
        text = re.sub(r"https?://\S+", " ", text)
        text = re.sub(r"\r\t", " ", text)
        lines = [re.sub(r" {2,}", " ", ln).strip() for ln in text.split("\n")]
        return "\n".join(lines)

    @classmethod
    def _normalise(cls, text: str) -> str:
        """Phase 2: aggressive normalisation for pattern matching."""
        # 1. Base64 FIRST — before leet corrupts base64 alphabet chars
        text = _decode_base64_payloads(text)
        # 2. Diacritic removal (ïgnörè → ignore)
        text = _strip_diacritics(text)
        # 3. Homoglyph substitution
        text = _replace_homoglyphs(text)
        # 4. Leet-speak (digits/symbols → letters)
        text = _replace_leet(text)
        # 5. Separator + spaced-out text collapse
        text = _collapse_separators(text)
        # 6. Second base64 pass (in case normalization exposed new blobs)
        text = _decode_base64_payloads(text)
        # 7. Typo fix — collapse repeated chars and fix stuttered endings
        attack_roots = (
            r"delet|remov|wip|purg|eras|destroy|execut|format|reset|nuke"
            r"|hack|leak|dump|exfiltrat|shutdown|terminat|kill|ignor|bypass"
            r"|overrid|forget|disregard|jailbreak"
        )
        text = re.sub(r"(.)\1{2,}", r"\1\1", text)
        text = re.sub(rf"({attack_roots})(\w)\2\b", r"\1\2", text, flags=re.IGNORECASE)
        return text

    @classmethod
    def _combo_check(cls, low: str) -> Tuple[bool, str]:
        """Check for role-assignment + destructive-action combos."""
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

        Public API — called by external modules.
        """
        if not text or not text.strip():
            return False, 0.0, []

        cleaned = cls._clean(text)

        # Check for obfuscation BEFORE normalization (leet-speak destroys special char patterns)
        obfuscation_pattern = r"[a-z][@#$%&*!]{2,}[a-z]"
        obfuscation_match = re.search(obfuscation_pattern, cleaned.lower())
        obfuscation_detected = obfuscation_match is not None

        # Check for invisible-char smuggling (presence of stripped chars = suspicious)
        invisible_count = len(_INVISIBLE_CHARS.findall(text))

        normalised = cls._normalise(cleaned)
        low = normalised.lower()
        evidence: List[str] = []
        high_score = 0.0
        high_confidence_hits = 0

        # ── Invisible character evidence ──
        if invisible_count > 3:
            evidence.append(f"high: invisible char smuggling — {invisible_count} chars stripped")
            high_score = max(high_score, 0.5)

        # ── Obfuscation evidence ──
        if obfuscation_detected:
            evidence.append(f"high: obfuscation attempt — «{obfuscation_match.group(0)[:60]}»")
            high_score = max(high_score, 0.35)

        # ── Reversed text check ──
        is_reversed, reversed_ev = _check_reversed_text(cleaned)
        if is_reversed:
            evidence.append(f"high: {reversed_ev}")
            high_score = max(high_score, 0.75)

        # ── High confidence patterns ──
        for pattern, label in cls.HIGH_CONFIDENCE_PATTERNS:
            m = re.search(pattern, low, re.IGNORECASE | re.MULTILINE | re.DOTALL)
            if m:
                evidence.append(f"high: {label} — «{m.group(0)[:60]}»")
                high_score = max(high_score, 0.8)
                high_confidence_hits += 1

        # ── Glued-phrase check (handles spaced/separator-separated text) ──
        no_space = re.sub(r"[\s\-._~|/\\]+", "", low)
        for phrase, label in _GLUED_ATTACK_PHRASES:
            if phrase in no_space:
                evidence.append(f"high: {label}")
                high_score = max(high_score, 0.75)
                break # one glued hit is enough

        # ── Role + destructive action combo ──
        is_combo, combo_ev = cls._combo_check(low)
        if is_combo:
            evidence.append(f"high: {combo_ev}")
            high_score = max(high_score, 0.9)

        # ── Medium confidence patterns ──
        medium_total = 0.0
        for pattern, weight in cls.MEDIUM_CONFIDENCE_PATTERNS:
            m = re.search(pattern, low, re.IGNORECASE | re.MULTILINE)
            if m:
                evidence.append(f"medium: «{m.group(0)[:60]}»")
                medium_total += weight

        # ── Multiple medium signals amplification ──
        medium_count = sum(1 for e in evidence if e.startswith("medium:"))
        if medium_count >= 3:
            medium_total *= 1.3 # Amplify when many medium signals co-occur

        # ── Score calculation ──
        medium_bonus = min(medium_total * 0.25, 0.25)
        if high_score > 0:
            risk_score = min(high_score + medium_bonus, 1.0)
        else:
            risk_score = min(medium_total, 1.0)

        # Lower threshold: 0.4 instead of 0.5 for medium-only triggers
        is_injection = high_score > 0 or medium_total >= 0.4
        return is_injection, round(risk_score, 3), evidence