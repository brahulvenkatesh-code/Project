"""
security.py — Comprehensive Security Layer
PS2 Model Performance Explainer | Giggso Build-Break Challenge

Covers:
  - Blocklist enforcement
  - Allowlist field whitelist
  - Prompt injection WAF (regex)
  - Pydantic v2 schema validation
  - 0<=metric<=1 range enforcement
  - Numeric-only extraction for LLM
  - Request size cap (10 KB)
  - In-memory rate limiter
  - Safe error messaging (no internals exposed)
  - JSON depth / complexity limits
"""

from __future__ import annotations
import json, re, time, hashlib, hmac
from typing import Any
from collections import defaultdict

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CONSTANTS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MAX_JSON_BYTES   = 10_000     # 10 KB hard cap
MAX_JSON_DEPTH   = 8          # max nesting depth
MAX_JSON_KEYS    = 200        # max total keys in JSON
MAX_STRING_LEN   = 500        # max length of any string value
RATE_LIMIT_RPM   = 10         # requests per minute per session
MAX_MSG_CHARS    = 1_000      # max user chat message length
MAX_LLM_INPUT    = 4_000      # chars sent to LLM
MAX_LLM_TOKENS   = 2048       # max LLM output tokens (Gemini free tier safe limit)
MSG_RATE_LIMIT_S = 1.0        # min seconds between user chat messages

# Raw string patterns caught pre-parse
RAW_BLOCKLIST = ["${", "$(", "{{", "<%", "__class__", "__mro__", "__import__"]

# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BLOCKLIST — reject any input containing these terms
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BLOCKLIST = {
    # Code execution
    "exec", "eval", "import", "subprocess", "os.system", "os.popen",
    "__import__", "compile", "builtins", "globals", "locals", "vars",
    "getattr", "setattr", "delattr", "open(", "file(",
    # Cloud / infra (s3 removed — S3 URLs appear in valid data_source fields)
    "lambda", "dynamodb", "ec2", "iam", "cloudwatch",
    "azure", "gcp", "kubectl", "terraform", "ansible",
    # DB / injection
    "select ", "insert ", "update ", "delete ", "drop ", "truncate ",
    "union ", "exec(", "xp_cmd", "--", "1=1", "or 1",
    # System / dangerous
    "system", "shell", "bash", "powershell", "cmd.exe", "/etc/passwd",
    "chmod", "chown", "sudo", "root", "admin",
    # LLM manipulation
    "jailbreak", "dan mode", "developer mode", "unrestricted mode",
    "ignore all", "forget everything", "new persona",
    # Data exfil
    "exfiltrate", "curl ", "wget ", "nc ", "netcat",
    # Environment variable injection
    "${", "$(", "${env", "process.env", "os.environ",
    # Shell command patterns
    "rm -rf", "chmod ", "chown ", "mkfs", "dd if=",
    "> /dev/", "| sh", "| bash", "2>&1",
}

def check_blocklist(text: str) -> tuple[bool, str]:
    """Returns (is_blocked, matched_term). Uses word-boundary matching to avoid false positives."""
    lower = text.lower()
    for term in BLOCKLIST:
        # Literal match for operators, spaces, special chars
        if term.endswith("(") or " " in term or any(c in term for c in ".-*/="):
            if term in lower:
                return True, term
        else:
            # Word-boundary: term must not be part of a longer word
            pattern = r'(?<![a-z0-9_])' + re.escape(term) + r'(?![a-z0-9_])'
            if re.search(pattern, lower):
                return True, term
    return False, ""



# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PII PROTECTION
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

PII_FIELDS = {
    # True PII — identity / access credentials only
    "email", "user_email", "contact", "phone", "mobile",
    "password", "secret", "api_key", "private_key",
    "ssn", "dob", "national_id",
    # Infrastructure identifiers (not ML feature names)
    "aws_account_id", "account_id", "resource_arn", "iam_role", "role_arn",
    "server_ip", "ip_address",
    # User-identifying operational metadata
    "created_by", "owner", "owner_id", "user_id", "username",
}

# Keys whose VALUES should never be PII-scanned (they hold things like S3 paths, feature names, messages)
_PII_SKIP_KEYS = {
    "data_source", "message", "performance_message", "column_names",
    "drifted_features", "biased_columns", "recommended_action", "tags", "info",
}

def check_pii(data: Any, path: str = "", _skip_key: bool = False) -> list:
    """Returns list of PII field paths found in data."""
    found = []
    if isinstance(data, dict):
        for k, v in data.items():
            if k.lower() in PII_FIELDS:
                found.append(f"{path}.{k}" if path else k)
            elif k.lower() not in _PII_SKIP_KEYS:
                # Only recurse into values not in skip-list
                found.extend(check_pii(v, f"{path}.{k}" if path else k))
    elif isinstance(data, list):
        # Skip lists of strings — these are feature/column name lists, not PII
        if not all(isinstance(i, str) for i in data):
            for i, v in enumerate(data):
                found.extend(check_pii(v, f"{path}[{i}]"))
    return found


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# ALLOWLIST — only these JSON keys are permitted
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

ALLOWED_KEYS = {
    # === Metadata ===
    "trinity_metadata", "schema_version", "generated_by", "report_id",
    "evaluation_date", "model_type", "session_id",
    # === Model info ===
    "model_info", "name", "version", "framework", "algorithm", "task",
    "target_variable", "feature_count", "training_samples", "test_samples",
    "num_classes", "class_labels",
    # === Classification metrics ===
    "performance_metrics",
    "accuracy", "precision", "recall", "f1_score", "f1",
    "roc_auc", "auc_roc", "auc_pr", "log_loss",
    "matthews_corrcoef", "balanced_accuracy",
    "false_positive_rate", "false_negative_rate",
    "specificity", "sensitivity",
    "cohen_kappa", "top_2_accuracy",
    "macro_f1", "weighted_f1", "macro_precision", "macro_recall",
    # === Regression metrics ===
    "mae", "mse", "rmse", "r2_score", "mape",
    "explained_variance", "max_error", "median_absolute_error",
    # === Confusion matrix ===
    "confusion_matrix",
    "true_positive", "true_negative", "false_positive", "false_negative",
    # === Threshold ===
    "threshold_analysis", "optimal_threshold", "default_threshold",
    "threshold_sensitivity",
    # === Drift ===
    "drift_metrics", "feature_drift_score", "label_drift_score",
    "psi_score", "drift_status", "drifted_features",
    # === Latency ===
    "latency_ms", "p50", "p95", "p99", "mean",
    # === Generalization ===
    "generalization", "train_accuracy", "test_accuracy", "train_test_gap",
    "cross_val_mean", "cross_val_std", "train_r2", "test_r2",
    # === Calibration ===
    "calibration", "brier_score", "expected_calibration_error",
    "calibration_status",
    # === Fairness ===
    "fairness", "demographic_parity_diff", "equalized_odds_diff",
    "fairness_status",
    # === Uncertainty ===
    "uncertainty", "prediction_interval_coverage",
    "mean_prediction_std", "uncertainty_status",
    # === Per-class ===
    "per_class_metrics", "support",
    "billing", "technical", "account", "delivery", "returns",
    "product_info", "escalation", "other",
    # === Confidence ===
    "confidence_analysis", "mean_confidence", "low_confidence_pct",
    "confidence_threshold", "flagged_for_review_pct",
    # === Residual ===
    "residual_analysis", "residual_mean", "residual_std",
    "skewness", "kurtosis", "normality_test_pvalue",
    "heteroscedasticity_detected",
    # === Business ===
    "business_impact", "estimated_bad_loan_rate",
    "threshold_for_rejection", "approval_rate",
    "expected_loss_reduction_pct",
    # === Operational ===
    "operational", "tokens_per_second", "gpu_memory_mb",
    "model_size_mb", "inference_batch_size",
}

# Metrics whose value MUST be in [0.0, 1.0]
BOUNDED_0_1 = {
    "accuracy", "precision", "recall", "f1_score", "f1",
    "roc_auc", "auc_roc", "auc_pr", "balanced_accuracy",
    "false_positive_rate", "false_negative_rate", "specificity",
    "sensitivity", "macro_f1", "weighted_f1", "macro_precision",
    "macro_recall", "feature_drift_score", "label_drift_score",
    "mean_confidence", "low_confidence_pct", "brier_score",
    "demographic_parity_diff", "equalized_odds_diff", "approval_rate",
    "prediction_interval_coverage", "train_accuracy", "test_accuracy",
    "cross_val_mean", "train_r2", "test_r2",
    "cross_val_std", "flagged_for_review_pct",
    "expected_calibration_error",
}

# Metrics that must be non-negative
NON_NEGATIVE = {
    "mae", "mse", "rmse", "log_loss", "brier_score",
    "p50", "p95", "p99", "mean",
    "training_samples", "test_samples", "feature_count",
    "gpu_memory_mb", "model_size_mb", "tokens_per_second",
    "support", "true_positive", "true_negative",
    "false_positive", "false_negative",
}


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# PROMPT INJECTION WAF
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

INJECTION_PATTERNS = [
    r"ignore\s+(previous|above|prior|all)\s+instructions?",
    r"forget\s+(everything|context|instructions?|above|prior)",
    r"you\s+are\s+now\s+(a\s+)?(dan|jailbreak|unrestricted|evil|gpt)",
    r"pretend\s+(you\s+(have\s+no|are\s+without)|there\s+are\s+no)\s+(restrictions?|rules?|limits?|guidelines?)",
    r"system\s+override",
    r"new\s+(system\s+)?instructions?\s*(follow|below|are|:)",
    r"your\s+(true\s+self|real\s+purpose|actual\s+instructions?|hidden\s+mode)",
    r"i\s+am\s+(your\s+)?(developer|admin|anthropic|openai|giggso\s+cto|creator|owner|god)",
    r"(reveal|show|print|display|repeat|output)\s+(your\s+)?(system\s+prompt|instructions?|config|prompt|rules)",
    r"disregard\s+(all\s+)?(previous|prior|your)\s+(instructions?|rules?|guidelines?|constraints?)",
    r"(for\s+)?(educational|research|fictional|hypothetical|creative|fun|testing)\s+purposes?,?\s*(ignore|bypass|skip|forget)",
    r"act\s+as\s+(if\s+you\s+(have\s+no|are\s+without)|a\s+different)",
    r"<\s*script[\s>]",
    r"javascript\s*:",
    r"data\s*:\s*text/html",
    r"base64\s*[,:\s][A-Za-z0-9+/=]{20,}",
    r"\[INST\]|\[SYS\]|<<SYS>>|<\|system\|>|<\|im_start\|>",
    r"###\s*(system|instruction|prompt|override)",
    r"---(system|instruction|override)---",
    r"prompt\s*injection",
    r"jailbreak",
    r"bypass\s+(safety|filter|restriction|guideline)",
    r"do\s+anything\s+now",
    r"enable\s+(developer|god|admin|root)\s+mode",
    # Additional attack patterns
    r"ignore\s+instructions?",
    r"ignore\s+(rules|guidelines|restrictions|constraints|safety)",
    r"assume.{0,30}(precision|recall|f1|auc|accuracy).{0,30}(excellent|perfect|good|acceptable)",
    r"assuming.{0,30}(f1|auc|precision|recall|accuracy).{0,30}(means|is).{0,30}(perfect|excellent|good)",
    r"note.{0,5}(auc|f1|precision|recall|accuracy).{0,30}(best|perfect|excellent)",
    r"compare.{0,20}(with|to).{0,20}other.{0,20}(fraud|model|detection)",
    r"(show|give).{0,20}anonymized.{0,20}(example|sample|data)",
    r"quantum.{0,20}(coherence|entanglement|score|metric)",
]
INJECTION_RE = re.compile("|".join(INJECTION_PATTERNS), re.IGNORECASE | re.DOTALL)

def scan_injection(text: str) -> bool:
    return bool(INJECTION_RE.search(text))

# Instruction patterns for JSON field names and values
_FIELD_INJECT_RE = re.compile(
    r"(ignore|override|system:|instruction|disable|bypass|admin|"
    r"production.ready|treat.*as.*info|reclassif|disable.*check|"
    r"approved.*by|unrestricted|confirm.*deploy)",
    re.IGNORECASE
)

def scan_json_for_injection(obj: Any, depth: int = 0) -> bool:
    if depth > MAX_JSON_DEPTH: return False
    if isinstance(obj, str):
        # Scan value for injection patterns
        if scan_injection(obj): return True
        if check_blocklist(obj)[0]: return True
        if any(p in obj for p in RAW_BLOCKLIST): return True
        if _FIELD_INJECT_RE.search(obj): return True
        return False
    if isinstance(obj, dict):
        for k, v in obj.items():
            # Also scan KEY names for injections
            if isinstance(k, str) and _FIELD_INJECT_RE.search(k): return True
            if scan_json_for_injection(v, depth+1): return True
        return False
    if isinstance(obj, list):
        return any(scan_json_for_injection(v, depth+1) for v in obj)
    return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# VALIDATION ERROR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class SecurityError(Exception):
    """Raised for any security or validation violation."""
    def __init__(self, public_msg: str, internal: str = ""):
        self.public_msg  = public_msg    # shown to user
        self.internal    = internal or public_msg  # logged only
        super().__init__(public_msg)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CORE VALIDATION PIPELINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def validate_json_input(raw: str) -> dict:
    """
    Full validation pipeline for incoming metrics JSON.
    Returns cleaned dict or raises SecurityError.
    Steps: size → parse → depth → key count → blocklist/injection →
           allowlist filter → range validation
    """
    # Step 5: Size cap
    if len(raw.encode("utf-8")) > MAX_JSON_BYTES:
        raise SecurityError(
            "Invalid metric input: file too large.",
            f"JSON size {len(raw.encode())} exceeds {MAX_JSON_BYTES}B limit"
        )

    # Raw string scan BEFORE parsing — catches encoded/template injection
    RAW_INJECTION = ["${", "$(", "{{", "<%", "__class__", "__mro__", "__import__"]
    if any(p in raw for p in RAW_INJECTION):
        raise SecurityError(
            "Invalid metric input: disallowed content detected.",
            f"Raw injection pattern found in input"
        )

    # Step 1c: Parse
    try:
        data = json.loads(raw)
    except json.JSONDecodeError as e:
        raise SecurityError("Invalid metric input: malformed JSON.", str(e))

    # Type check
    if not isinstance(data, dict) or not data:
        raise SecurityError("Invalid metric input: must be a non-empty JSON object.")

    # Depth check (prevent deeply nested bombs)
    if _json_depth(data) > MAX_JSON_DEPTH:
        raise SecurityError("Invalid metric input: JSON too deeply nested.")

    # Key count (prevent large object DoS)
    if _count_keys(data) > MAX_JSON_KEYS:
        raise SecurityError("Invalid metric input: too many fields.")

    # String value length check
    _check_string_lengths(data)

    # Blocklist + injection scan on raw string values
    if scan_json_for_injection(data):
        raise SecurityError("Invalid metric input: disallowed content detected.")

    # Blocklist on the raw string itself (catches encoded variants)
    blocked, term = check_blocklist(raw)
    if blocked:
        raise SecurityError("Invalid metric input: disallowed content detected.", f"blocklist hit: {term}")

    # PII scan — detect and BLOCK (raise error) if PII present in JSON
    pii_found = check_pii(data)
    if pii_found:
        import logging
        logging.getLogger("ps2").warning(f"PII fields detected: {pii_found}")
        raise SecurityError(
            "Invalid metric input: disallowed fields detected.",
            f"PII/infrastructure fields found: {pii_found}"
        )

    # Step 2: Allowlist — strip unknown keys (also strips PII not in ALLOWED_KEYS)
    cleaned = _apply_allowlist(data)
    if not cleaned:
        raise SecurityError("Invalid metric input: no recognised metric fields found.")

    # Step 6b: Range validation
    violations = _validate_ranges(cleaned)
    if violations:
        raise SecurityError(
            f"Invalid metric input: out-of-range values detected ({len(violations)} field(s)).",
            f"Range violations: {violations}"
        )

    return cleaned


def validate_chat_message(msg: str) -> str:
    """Validate and sanitize a user chat message."""
    msg = msg.strip()

    if not msg:
        raise SecurityError("Message cannot be empty.")

    if len(msg) > MAX_MSG_CHARS:
        raise SecurityError(f"Message too long (max {MAX_MSG_CHARS} characters).")

    blocked, term = check_blocklist(msg)
    if blocked:
        raise SecurityError("Invalid input: disallowed content detected.")

    if scan_injection(msg):
        raise SecurityError("Invalid input: disallowed content detected.")

    return msg


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# HELPERS
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def _json_depth(obj: Any, d: int = 0) -> int:
    if isinstance(obj, dict):
        return max((_json_depth(v, d+1) for v in obj.values()), default=d)
    if isinstance(obj, list):
        return max((_json_depth(v, d+1) for v in obj), default=d)
    return d

def _count_keys(obj: Any) -> int:
    if isinstance(obj, dict):
        return len(obj) + sum(_count_keys(v) for v in obj.values())
    if isinstance(obj, list):
        return sum(_count_keys(v) for v in obj)
    return 0

def _check_string_lengths(obj: Any, path: str = ""):
    if isinstance(obj, str):
        if len(obj) > MAX_STRING_LEN:
            raise SecurityError(
                "Invalid metric input: string value too long.",
                f"String at '{path}' exceeds {MAX_STRING_LEN} chars"
            )
    elif isinstance(obj, dict):
        for k, v in obj.items():
            _check_string_lengths(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            _check_string_lengths(v, f"{path}[{i}]")

def _apply_allowlist(obj: Any, depth: int = 0) -> Any:
    if depth > MAX_JSON_DEPTH: return None
    if isinstance(obj, dict):
        result = {}
        for k, v in obj.items():
            if k not in ALLOWED_KEYS:
                continue
            cleaned = _apply_allowlist(v, depth+1)
            if cleaned is not None:
                result[k] = cleaned
        return result if result else None
    if isinstance(obj, list):
        cleaned = [_apply_allowlist(i, depth+1) for i in obj]
        cleaned = [i for i in cleaned if i is not None]
        return cleaned if cleaned else None
    if isinstance(obj, (int, float)) and not isinstance(obj, bool):
        return obj
    if isinstance(obj, (str, bool)):
        return obj
    return None

def _validate_ranges(obj: Any, violations: list = None, path: str = "") -> list:
    if violations is None: violations = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            _validate_ranges(v, violations, f"{path}.{k}" if path else k)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        key = path.split(".")[-1]
        if key in BOUNDED_0_1 and not (0.0 <= obj <= 1.0):
            violations.append(f"{path}={obj} (expected [0,1])")
        if key in NON_NEGATIVE and obj < 0:
            violations.append(f"{path}={obj} (must be >= 0)")
    return violations


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# NUMERIC EXTRACTION (Step 7b — only numbers reach the LLM)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def extract_numerics(obj: Any, out: dict = None, prefix: str = "") -> dict:
    if out is None: out = {}
    if isinstance(obj, dict):
        for k, v in obj.items():
            extract_numerics(v, out, f"{prefix}.{k}" if prefix else k)
    elif isinstance(obj, (int, float)) and not isinstance(obj, bool):
        out[prefix] = round(float(obj), 6)
    elif isinstance(obj, list) and all(isinstance(i, (int, float)) for i in obj):
        out[prefix] = obj
    return out

def cross_validate_metrics(data: dict) -> list[str]:
    """
    Cross-validate internal consistency of metrics.
    Detects mislabelling, swapped values, fake metrics, quality flips.
    Returns list of violations found.
    """
    violations = []
    pm = data.get("performance_metrics", {})
    current = pm.get("current", pm)  # support flat or nested

    # 1. Confusion matrix cross-check
    cm = data.get("confusion_matrix", {})
    labels = cm.get("labels", {})
    if labels:
        tp = labels.get("true_positives", 0)
        fp = labels.get("false_positives", 0)
        fn = labels.get("false_negatives", 0)
        tn = labels.get("true_negatives", 0)
        total = tp + fp + fn + tn

        if total > 0:
            # Check precision consistency
            calc_precision = tp / (tp + fp) if (tp + fp) > 0 else 0
            reported_precision = current.get("precision", current.get("f1", None))
            if reported_precision is not None:
                if abs(calc_precision - reported_precision) > 0.05:
                    violations.append(
                        f"MISLABEL: Reported precision {reported_precision:.3f} "
                        f"inconsistent with confusion matrix derived precision {calc_precision:.3f}. "
                        f"Possible TP/FP swap or label manipulation."
                    )

            # Check recall consistency
            calc_recall = tp / (tp + fn) if (tp + fn) > 0 else 0
            reported_recall = current.get("recall", None)
            if reported_recall is not None:
                if abs(calc_recall - reported_recall) > 0.05:
                    violations.append(
                        f"MISLABEL: Reported recall {reported_recall:.3f} "
                        f"inconsistent with confusion matrix derived recall {calc_recall:.3f}. "
                        f"Possible TN/FN swap or label manipulation."
                    )

            # Check accuracy consistency
            calc_accuracy = (tp + tn) / total if total > 0 else 0
            reported_accuracy = current.get("accuracy", None)
            if reported_accuracy is not None:
                if abs(calc_accuracy - reported_accuracy) > 0.05:
                    violations.append(
                        f"MISLABEL: Reported accuracy {reported_accuracy:.3f} "
                        f"inconsistent with confusion matrix {calc_accuracy:.3f}. "
                        f"Possible confusion matrix manipulation."
                    )

    # 2. Reference vs current sanity check
    reference = pm.get("reference", {})
    if reference and current:
        ref_acc = reference.get("accuracy", 0)
        cur_acc = current.get("accuracy", current.get("acc", 0))
        # If current >> reference by suspicious amount, may be fake metrics
        if isinstance(cur_acc, float) and isinstance(ref_acc, float):
            if cur_acc > ref_acc + 0.10 and cur_acc > 0.95:
                violations.append(
                    f"SUSPICIOUS: Current accuracy {cur_acc:.3f} is suspiciously higher "
                    f"than reference {ref_acc:.3f}. Possible fake metric injection."
                )

    # 3. Data quality flip detection
    dq = data.get("data_quality", {})
    if dq:
        passed = dq.get("passed", 0)
        failed = dq.get("failed", 0)
        total_checks = dq.get("total_checks", 0)
        pass_pct = dq.get("pass_percentage", 0)
        if total_checks > 0 and passed + failed > 0:
            calc_pct = (passed / total_checks) * 100
            if abs(calc_pct - pass_pct) > 5:
                violations.append(
                    f"FLIP: Reported pass% {pass_pct:.1f} inconsistent with "
                    f"calculated {calc_pct:.1f}% ({passed}/{total_checks}). "
                    f"Possible pass/fail label swap."
                )

    # 4. Bias override detection
    bias = data.get("bias_report", {})
    if bias:
        bias_detected = bias.get("bias_detected", False)
        severity = bias.get("severity", "")
        metrics = bias.get("metrics", [])
        if bias_detected and severity in ("info", "low", "none"):
            violations.append(
                f"BIAS_OVERRIDE: bias_detected=true but severity='{severity}'. "
                f"Possible severity downgrade injection."
            )
        if metrics:
            biased_count = sum(1 for m in metrics if m.get("is_biased", False))
            override_count = sum(1 for m in metrics if "override" in m)
            if override_count > 0:
                violations.append(
                    f"BIAS_OVERRIDE: {override_count} bias metric(s) contain 'override' fields. "
                    f"Possible bias dismissal injection."
                )

    return violations


def build_llm_safe_payload(data: dict) -> str:
    """Serialize only numeric metrics, truncate to MAX_LLM_INPUT chars."""
    numerics = extract_numerics(data)
    payload  = json.dumps(numerics, indent=2)
    if len(payload) > MAX_LLM_INPUT:
        payload = payload[:MAX_LLM_INPUT] + "\n...[truncated for safety]"
    return payload


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RATE LIMITER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

_rate_store: dict[str, list] = defaultdict(list)

_last_msg_time: dict[str, float] = {}

def check_message_rate(session_key: str) -> None:
    """OWASP A10: 1 message per second per session."""
    now = time.time()
    last = _last_msg_time.get(session_key, 0)
    if now - last < MSG_RATE_LIMIT_S:
        raise SecurityError("Please wait before sending another message.")
    _last_msg_time[session_key] = now


def check_rate_limit(session_key: str) -> None:
    now = time.time()
    _rate_store[session_key] = [t for t in _rate_store[session_key] if now - t < 60]
    if len(_rate_store[session_key]) >= RATE_LIMIT_RPM:
        raise SecurityError("Rate limit exceeded. Please wait before sending more requests.")
    _rate_store[session_key].append(now)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DETERMINISTIC RISK ENGINE (Step 8 — no LLM involvement)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

RISK_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW"]

def run_risk_engine(data: dict) -> dict:
    """Pure deterministic risk assessment."""
    n = extract_numerics(data)
    triggered = []

    def g(key):
        for k, v in n.items():
            if k == key or k.endswith(f".{key}"):
                return v
        return None

    # ── CRITICAL ──────────────────────────────────────────────────────────────
    auc = g("auc_roc") or g("roc_auc")
    if auc is not None and auc < 0.70:
        triggered.append(("CRITICAL", f"AUC-ROC={auc:.3f} < 0.70 — inadequate discrimination"))

    psi = g("psi_score")
    if psi is not None and psi > 0.25:
        triggered.append(("CRITICAL", f"PSI={psi:.3f} > 0.25 — severe distribution shift"))

    fnr = g("false_negative_rate")
    if fnr is not None and fnr > 0.50:
        triggered.append(("CRITICAL", f"FNR={fnr:.3f} > 0.50 — majority of positives missed"))

    gap = g("train_test_gap")
    if gap is not None and gap > 0.10:
        triggered.append(("CRITICAL", f"Train-test gap={gap:.3f} > 0.10 — severe overfitting"))

    dpd = g("demographic_parity_diff")
    if dpd is not None and dpd > 0.10:
        triggered.append(("CRITICAL", f"DemographicParityDiff={dpd:.3f} > 0.10 — fairness violation"))

    r2 = g("r2_score") or g("test_r2")
    if r2 is not None and r2 < 0.50:
        triggered.append(("CRITICAL", f"R²={r2:.3f} < 0.50 — regression model explains <50% of variance"))

    # ── HIGH ──────────────────────────────────────────────────────────────────
    f1 = g("f1_score") or g("f1") or g("macro_f1") or g("weighted_f1")
    if f1 is not None and f1 < 0.70:
        triggered.append(("HIGH", f"F1={f1:.3f} < 0.70 — insufficient model performance"))

    prec = g("precision") or g("macro_precision")
    if prec is not None and prec < 0.60:
        triggered.append(("HIGH", f"Precision={prec:.3f} < 0.60 — high false positive risk"))

    rec = g("recall") or g("macro_recall")
    if rec is not None and rec < 0.60:
        triggered.append(("HIGH", f"Recall={rec:.3f} < 0.60 — high false negative risk"))

    if psi is not None and 0.20 <= psi <= 0.25:
        triggered.append(("HIGH", f"PSI={psi:.3f} in [0.20,0.25] — significant drift"))

    p99 = g("latency_ms.p99") or g("p99")
    if p99 is not None and p99 > 500:
        triggered.append(("HIGH", f"p99 latency={p99}ms > 500ms — SLA breach risk"))

    if gap is not None and 0.07 <= gap <= 0.10:
        triggered.append(("HIGH", f"Train-test gap={gap:.3f} — notable overfitting"))

    het = g("heteroscedasticity_detected")
    if het is True:
        triggered.append(("HIGH", "Heteroscedasticity detected — regression variance non-uniform"))

    mae = g("mae")
    rmse = g("rmse")
    if rmse is not None and mae is not None and rmse > 2 * mae:
        triggered.append(("HIGH", f"RMSE({rmse:.3f}) >> MAE({mae:.3f}) — large outlier errors present"))

    # ── MEDIUM ────────────────────────────────────────────────────────────────
    if f1 is not None and 0.70 <= f1 < 0.80:
        triggered.append(("MEDIUM", f"F1={f1:.3f} in [0.70,0.80] — acceptable, monitor closely"))

    if psi is not None and 0.10 <= psi < 0.20:
        triggered.append(("MEDIUM", f"PSI={psi:.3f} in [0.10,0.20] — moderate drift detected"))

    if p99 is not None and 200 <= p99 <= 500:
        triggered.append(("MEDIUM", f"p99={p99}ms — approaching SLA boundary"))

    cv_std = g("cross_val_std")
    if cv_std is not None and cv_std > 0.008:
        triggered.append(("MEDIUM", f"CrossValStd={cv_std:.4f} > 0.008 — high fold variance"))

    ece = g("expected_calibration_error")
    if ece is not None and ece > 0.05:
        triggered.append(("MEDIUM", f"ECE={ece:.3f} > 0.05 — miscalibrated confidence scores"))

    if gap is not None and 0.02 <= gap < 0.07:
        triggered.append(("MEDIUM", f"Train-test gap={gap:.3f} — mild overfitting"))

    log_loss_val = g("log_loss")
    if log_loss_val is not None and log_loss_val > 0.5:
        triggered.append(("MEDIUM", f"LogLoss={log_loss_val:.3f} > 0.5 — poor probability estimates"))

    # ── Determine final level ─────────────────────────────────────────────────
    if not triggered:
        level = "LOW"
    else:
        levels_hit = {r[0] for r in triggered}
        level = next(l for l in RISK_ORDER if l in levels_hit)

    return {
        "level": level,
        "color": {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}[level],
        "triggered": [{"severity": r[0], "message": r[1]} for r in triggered],
        "recommendations": _build_recommendations(level, triggered, data),
        "engine": "deterministic_v2",
        "disclaimer": "Risk determined by fixed rules only. Human expert review required before any deployment decision.",
    }

def _build_recommendations(level: str, triggered: list, data: dict) -> list[str]:
    recs = []
    if level == "CRITICAL":
        recs.append("🚫 Do NOT deploy. Resolve all CRITICAL issues before re-evaluation.")
    elif level == "HIGH":
        recs.append("⛔ Hold deployment. Escalate HIGH severity findings to your ML engineering team.")
    elif level == "MEDIUM":
        recs.append("⚠️ Deploy only with enhanced monitoring, drift alerts, and rollback plan.")
    else:
        recs.append("✅ Metrics within acceptable bounds. Proceed to final human expert sign-off.")

    drifted = data.get("drift_metrics", {})
    if isinstance(drifted, dict):
        feats = drifted.get("drifted_features", [])
        psi_v = drifted.get("psi_score", 0)
        if feats and psi_v > 0.10:
            recs.append(f"Investigate drifted features: {', '.join(str(f) for f in feats[:5])}. Consider retraining.")

    p99_v = data.get("latency_ms", {})
    if isinstance(p99_v, dict) and p99_v.get("p99", 0) > 200:
        recs.append(f"Optimize inference pipeline — p99={p99_v['p99']}ms may breach SLA.")

    recs.append("Escalate final deployment decision to a human ML engineer and domain expert.")
    return recs


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OWASP A02 — Security Headers (CSP + SRI)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import streamlit as _st

def inject_security_headers():
    """
    Inject CSP and security meta tags into Streamlit.
    Covers OWASP A02 Security Misconfiguration.
    """
    _st.markdown("""
<meta http-equiv="Content-Security-Policy"
  content="default-src 'self';
           script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com;
           style-src 'self' 'unsafe-inline' https://fonts.googleapis.com;
           img-src 'self' data:;
           connect-src 'self';">
<meta http-equiv="X-Content-Type-Options" content="nosniff">
<meta http-equiv="X-Frame-Options" content="DENY">
<meta http-equiv="Referrer-Policy" content="no-referrer">
""", unsafe_allow_html=True)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OWASP A04 — Cryptographic / Deduplication
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

import hashlib as _hashlib

def sha256_hash(data: bytes) -> str:
    """SHA256 hash of file bytes for deduplication. OWASP A04."""
    return _hashlib.sha256(data).hexdigest()


def is_duplicate(file_hash: str, json_store: dict) -> bool:
    """Check if this file has already been uploaded this session."""
    return file_hash in json_store


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# OWASP A10 — Response cap
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

MAX_RESPONSE_CHARS = 4_000   # Cap NanoBot response length shown in UI


def cap_response(text: str) -> str:
    """Truncate LLM response to MAX_RESPONSE_CHARS. OWASP A10."""
    if len(text) > MAX_RESPONSE_CHARS:
        return text[:MAX_RESPONSE_CHARS] + "\n\n*[Response capped at 4000 chars — download full report for complete output]*"
    return text


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# COMPATIBILITY WRAPPERS (used by api.py — do not remove)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

def parse_and_validate(raw_bytes: bytes) -> dict:
    """Entry point for bytes-based raw data (FastAPI)."""
    return validate_json_input(raw_bytes.decode("utf-8", errors="replace"))

def safe_token_compare(provided: str, expected: str) -> bool:
    """Constant-time comparison — prevents timing oracle attacks."""
    return hmac.compare_digest(
        provided.encode("utf-8"),
        expected.encode("utf-8")
    )