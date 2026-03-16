import re
import unicodedata

# Layer 1: Direct instruction injection patterns
_INJECTION_PATTERNS = [
    r"ignore\s+(all\s+)?(previous|prior|above)\s+instructions?",
    r"forget\s+(everything|all|your)\s+(you|instructions?|context)",
    r"(new|your)\s+(role|persona|identity|task)\s+is",
    r"\[?(system|inst|s)\]?\s*:",
    r"(jailbreak|dan|dude|developer\s+mode|do\s+anything\s+now)",
    r"pretend\s+(you\s+are|to\s+be|you're)",
    r"act\s+as\s+(if\s+you\s+are|a|an)",
    r"repeat\s+(your\s+)?(system\s+)?prompt",
    r"reveal\s+(your|the)\s+(instructions?|prompt|system)",
]

_COMPILED = [re.compile(p, re.IGNORECASE | re.UNICODE) for p in _INJECTION_PATTERNS]

# Layer 2: Encoding bypass normalization
def _normalize_input(text: str) -> str:
    return unicodedata.normalize("NFKC", text).lower()

# Layer 3: Token length gate
MAX_CHAT_INPUT = 500

# Layer 4: Safe character filter (allow alphanumeric + basic punctuation)
# This prevents obscure encoding bypasses while allowing natural questions.
_SAFE_CHARS_RE = re.compile(r"[^a-zA-Z0-9\s\.\?\,\!\-\_\(\)\[\]\"\'\:\%\$\#\@\*\+]")

def guard_chat_input(raw: str) -> str:
    """
    Returns sanitized natural language or raises ValueError.
    Maintains 5 layers of defense while easing usability.
    """
    # Layer 3: length gate
    if not raw or len(raw) > MAX_CHAT_INPUT:
        raise ValueError("Invalid metric input: too long or empty")

    # Layer 2: Encoding bypass normalization
    normalized = _normalize_input(raw)

    # Layer 1: injection pattern check
    for pattern in _COMPILED:
        if pattern.search(normalized):
            raise ValueError("Invalid metric input: injection detected")

    # Layer 5: blocklist terms (covers things regex misses)
    blocklist = [
        "base64", "hex encode", "rot13", "__import__",
        "eval(", "exec(", "os.system", "subprocess",
        "drop table", "rm -rf", "dan mode", "developer mode"
    ]
    for term in blocklist:
        if term in normalized:
            raise ValueError("Invalid metric input: blocked term")

    # Layer 6: Safe character filter
    # Remove any characters not in our safe set to block obscure exploit payloads
    sanitized = _SAFE_CHARS_RE.sub(" ", raw)
    # Collapse multiple spaces
    sanitized = " ".join(sanitized.split())

    if not sanitized:
        raise ValueError("Invalid metric input: no safe characters")

    return sanitized

# Compatibility alias for app.py
unbreakable_input_guard = guard_chat_input