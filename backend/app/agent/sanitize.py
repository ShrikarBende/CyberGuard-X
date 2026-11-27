"""Redact credential-like values before errors are stored or logged."""
import re


_SECRET_PATTERNS = (
    (re.compile(r"(?i)\bBearer\s+\S+"), "Bearer [redacted]"),
    (re.compile(r"\b(?:sk[-_]|gsk_)[A-Za-z0-9_-]+"), "[redacted-key]"),
    (re.compile(r"(?i)https?://[^\s/@:]+:[^\s/@]+@"), "https://[redacted]@"),
)


def sanitize_error(value) -> str:
    text = str(value)
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    return text


def redact_exception_for_logging(exc) -> str:
    safe = sanitize_error(exc)
    try:
        exc.args = (safe,)
        exc.__cause__ = None
    except Exception:
        pass
    return safe
