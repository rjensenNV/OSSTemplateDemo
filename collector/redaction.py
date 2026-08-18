"""Central secret and request-URL redaction for persisted diagnostics."""

from __future__ import annotations

import re
import urllib.parse
from collections.abc import Iterable


_QUERY_URL = re.compile(r"https?://[^\s\"'<>]*\?[^\s\"'<>]*", re.IGNORECASE)
_CREDENTIAL_FIELD = re.compile(
    r"(?i)\b(api[_-]?key|access[_-]?token|auth(?:orization)?|token)"
    r"(\s*(?:=|:|%3[dD])\s*)"
    r"([^&\s,;\"'<>]+)"
)
_BEARER = re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._~+/=-]+")


def redact_sensitive(value: object, *, secrets: Iterable[str] = ()) -> str:
    """Return a bounded diagnostic with credentials and query URLs removed."""
    text = str(value)
    for secret in secrets:
        if not isinstance(secret, str) or not secret:
            continue
        text = text.replace(secret, "[REDACTED]")
        text = text.replace(
            urllib.parse.quote(secret, safe=""),
            "[REDACTED]",
        )
        text = text.replace(
            urllib.parse.quote_plus(secret, safe=""),
            "[REDACTED]",
        )
    text = _QUERY_URL.sub("[REDACTED URL]", text)
    text = _CREDENTIAL_FIELD.sub(
        lambda match: match.group(1) + match.group(2) + "[REDACTED]",
        text,
    )
    text = _BEARER.sub("Bearer [REDACTED]", text)
    return text[:500]
