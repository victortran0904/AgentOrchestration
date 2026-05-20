"""Shared redaction helpers for logs and public records."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


REDACTED = "[REDACTED]"

SENSITIVE_KEY_PARTS = {
    "authorization",
    "cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "api_key",
    "apikey",
    "signature",
    "credential",
}

_KEY_PATTERN = (
    r"authorization|cookie|password|passwd|secret|token|"
    r"api[_-]?key|signature|credentials?"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)\b(authorization\s*[:=]\s*bearer\s+)([^\s,;]+)"
)
_ASSIGNMENT_RE = re.compile(
    rf"(?i)\b({_KEY_PATTERN})\b(\s*[:=]\s*)(\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_BEARER_RE = re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/\-=]+")
_OPENAI_KEY_RE = re.compile(r"\bsk-[A-Za-z0-9_-]{8,}\b")
_URL_RE = re.compile(r"(?i)\bhttps?://[^\s<>'\"]+")
_TRAILING_URL_PUNCTUATION = ".,;:)]}"


def _normalize_key(key: Any) -> str:
    return re.sub(r"[^a-z0-9]", "", str(key).lower())


def is_sensitive_key(key: Any) -> bool:
    normalized = _normalize_key(key)
    return any(
        _normalize_key(part) in normalized
        for part in SENSITIVE_KEY_PARTS
    )


def _sanitize_url(raw_url: str) -> str:
    suffix = ""
    while raw_url and raw_url[-1] in _TRAILING_URL_PUNCTUATION:
        suffix = raw_url[-1] + suffix
        raw_url = raw_url[:-1]

    try:
        parsed = urlsplit(raw_url)
    except ValueError:
        return raw_url + suffix

    netloc = parsed.netloc
    if "@" in netloc:
        netloc = netloc.rsplit("@", 1)[1]

    query = urlencode(
        [
            (key, REDACTED if is_sensitive_key(key) else value)
            for key, value in parse_qsl(parsed.query, keep_blank_values=True)
        ],
        safe="[]",
    )
    return urlunsplit((parsed.scheme, netloc, parsed.path, query, "")) + suffix


def sanitize_text(value: str) -> str:
    """Redact common secret shapes embedded in free-form text."""
    value = _URL_RE.sub(lambda match: _sanitize_url(match.group(0)), value)
    value = _AUTH_HEADER_RE.sub(
        lambda match: f"{match.group(1)}{REDACTED}",
        value,
    )
    value = _BEARER_RE.sub(f"Bearer {REDACTED}", value)
    value = _ASSIGNMENT_RE.sub(
        lambda match: f"{match.group(1)}{match.group(2)}{REDACTED}",
        value,
    )
    return _OPENAI_KEY_RE.sub(REDACTED, value)


def sanitize_value(value: Any) -> Any:
    """Recursively sanitize dictionaries, sequences, and strings."""
    if isinstance(value, Mapping):
        sanitized = {}
        for key, item in value.items():
            if is_sensitive_key(key):
                sanitized[key] = REDACTED
            else:
                sanitized[key] = sanitize_value(item)
        return sanitized

    if isinstance(value, list):
        return [sanitize_value(item) for item in value]

    if isinstance(value, tuple):
        return tuple(sanitize_value(item) for item in value)

    if isinstance(value, set):
        return {sanitize_value(item) for item in value}

    if isinstance(value, str):
        return sanitize_text(value)

    return value


sanitize = sanitize_value
redact = sanitize_value
