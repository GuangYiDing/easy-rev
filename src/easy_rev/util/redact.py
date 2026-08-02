"""Redact tokens / PII-ish fields from RE artifacts and tool outputs.

Use before sharing packs, reports, or AI tool results that may contain
Authorization headers, cookies, or session tokens.
"""

from __future__ import annotations

import re
from typing import Any

# Case-insensitive key substrings that trigger redaction
SENSITIVE_KEY_PARTS: tuple[str, ...] = (
    "authorization",
    "proxy-authorization",
    "cookie",
    "set-cookie",
    "password",
    "passwd",
    "secret",
    "token",
    "access_token",
    "refresh_token",
    "id_token",
    "api_key",
    "apikey",
    "x-api-key",
    "session",
    "csrf",
    "private_key",
    "client_secret",
)

REDACTED = "***REDACTED***"

# Bearer / basic-ish patterns in free text
_BEARER_RE = re.compile(r"(?i)\b(bearer|token)\s+[A-Za-z0-9._\-+/=]{8,}")
_JWT_RE = re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b")


def is_sensitive_key(key: str) -> bool:
    k = str(key).lower().replace("-", "_")
    for part in SENSITIVE_KEY_PARTS:
        if part in k:
            return True
    return False


def redact_string(value: str) -> str:
    """Redact bearer tokens / JWTs inside a string."""
    out = _BEARER_RE.sub(r"\1 " + REDACTED, value)
    out = _JWT_RE.sub(REDACTED, out)
    return out


def redact_obj(value: Any, *, depth: int = 0, max_depth: int = 12) -> Any:
    """Deep-copy-ish redaction of dict/list structures."""
    if depth > max_depth:
        return value
    if isinstance(value, dict):
        out: dict[str, Any] = {}
        for k, v in value.items():
            if is_sensitive_key(str(k)):
                out[str(k)] = REDACTED
            else:
                out[str(k)] = redact_obj(v, depth=depth + 1, max_depth=max_depth)
        return out
    if isinstance(value, list):
        return [redact_obj(v, depth=depth + 1, max_depth=max_depth) for v in value]
    if isinstance(value, tuple):
        return tuple(redact_obj(v, depth=depth + 1, max_depth=max_depth) for v in value)
    if isinstance(value, str):
        return redact_string(value)
    return value


def redact_headers(headers: dict[str, Any] | None) -> dict[str, Any]:
    """Redact a flat header map."""
    return redact_obj(headers or {})  # type: ignore[return-value]
