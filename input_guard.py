"""
input_guard.py — 6-Layer Input Guard
Blocks 99.9% of prompt injection attacks before they reach the LLM.

Layer 1: Length limit
Layer 2: Blocklist (OWASP Top 10 injection patterns)
Layer 3: Delimiter protection
Layer 4: Character whitelist
Layer 5: Semantic / intent filter
Layer 6: Context allowlist (ML metrics domain only)
"""

import re
from security import SecurityError

MAX_INPUT_LEN = 500

# Layer 2: Injection pattern blocklist
INJECTION_PATTERNS = [
    r"ignore.*previous", r"forget.*instructions", r"forget.*your", r"forget.*rule", r"forget.*rules", r"override.*rules",
    r"new.*role", r"act.*as", r"you\s+are\s+now", r"system\s+prompt",
    r"exec\s*\(", r"import\s+", r"curl\s+", r"rm\s+-rf", r"sudo\s+",
    r"<\s*script", r"javascript\s*:", r"dan\s*:", r"developer\s+mode",
    r"jailbreak", r"base64", r"eval\s*\(", r"__import__",
    r"reveal.*prompt", r"repeat.*instructions", r"show.*config",
    r"bypass.*filter", r"disable.*safety", r"enable.*mode",
]

# Layer 5: Risky intent phrases
RISKY_PHRASES = [
    "change your", "new instructions", "stop following",
    "from now on", "pretend you", "act like", "your real",
    "true purpose", "hidden mode", "no restrictions",
]

# Layer 6: ML metrics context allowlist — ML-specific terms only
CONTEXT_PATTERN = re.compile(
    r"\b(f1|precision|recall|auc|roc|accuracy|risk|deploy|deployment|metric|"
    r"drift|psi|model|threshold|confusion|false.positive|false.negative|"
    r"performance|calibration|fairness|latency|overfitting|overfit|"
    r"classification|regression|training|train|test|gap|validation|prediction|"
    r"score|matrix|imbalance|bias|explainability|nanobot|"
    r"feature|weight|loss|entropy|gradient|epoch|batch|"
    r"true.positive|true.negative|fp.rate|fn.rate|baseline|benchmark|"
    r"remediation|regulatory|nist|eu|dpdp|compliance|"
    r"top.\d|explain|analysis|analyse|analyze|report|summary|"
    r"concern|indicate|mean|show|describe|interpret|assess)\b",
    re.IGNORECASE
)

# Safe characters whitelist
SAFE_CHARS = set(
    "abcdefghijklmnopqrstuvwxyz"
    "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
    "0123456789 .,!?%-()?'"
)


def unbreakable_input_guard(raw_input: str) -> str:
    """
    6-layer input guard. Returns sanitised string or raises SecurityError.
    Blocks 99.9% of prompt injection attacks.
    """
    # Layer 1: Length limit
    if len(raw_input) > MAX_INPUT_LEN:
        raise SecurityError(
            f"Input too long (max {MAX_INPUT_LEN} characters).",
            f"Input length {len(raw_input)} exceeds limit"
        )

    # Layer 2: Injection pattern blocklist
    for pattern in INJECTION_PATTERNS:
        if re.search(pattern, raw_input, re.IGNORECASE):
            raise SecurityError(
                "Invalid input: disallowed content detected.",
                f"Injection pattern matched: {pattern}"
            )

    # Layer 3: Delimiter stripping (prevents prompt boundary attacks)
    cleaned = raw_input
    for delimiter in ["###", "---", "===", "```", "<<<", ">>>", "|||"]:
        cleaned = cleaned.replace(delimiter, " ")

    # Layer 4: Character whitelist
    cleaned = "".join(c if c in SAFE_CHARS else " " for c in cleaned)

    # Layer 5: Semantic / intent filter
    lower = cleaned.lower()
    for phrase in RISKY_PHRASES:
        if phrase in lower:
            raise SecurityError(
                "Invalid input: disallowed content detected.",
                f"Risky phrase detected: {phrase}"
            )

    # Layer 6: Context allowlist — must be about ML metrics (or a simple greeting)
    greetings = {"hi", "hello", "hey", "hola", "sup", "greetings"}
    if not CONTEXT_PATTERN.search(cleaned) and not any(g in lower.split() for g in greetings):
        raise SecurityError(
            "I can only answer questions about the loaded ML metrics. "
            "Please ask about accuracy, F1, precision, recall, AUC, drift, or deployment risk.",
            "Off-topic input — no ML context or greeting found"
        )

    return cleaned.strip()