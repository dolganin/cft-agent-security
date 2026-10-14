from __future__ import annotations

import re

REDACTION_MARKER = "<redacted>"
DEFAULT_MAX_ERROR_LENGTH = 400
_TRACEBACK_MARKER = "Traceback (most recent call last):"

_SECRET_NAME = (
    r"(?:api[_-]?key|access[_-]?token|token|password|passwd|secret|"
    r"[a-z][a-z0-9_]*(?:_api_key|_token|_secret|_password))"
)
_BEARER_RE = re.compile(
    r"(?i)(?P<header>\bauthorization\s*:\s*)?\bbearer\s+[^\s,;]+"
)
_JSON_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>[\"']{_SECRET_NAME}[\"']\s*:\s*)"
    r"(?P<quote>[\"'])(?P<value>.*?)(?P=quote)"
)
_KEY_VALUE_SECRET_RE = re.compile(
    rf"(?i)(?P<prefix>\b{_SECRET_NAME}\b\s*=\s*)"
    r"(?P<value>\"[^\"]*\"|'[^']*'|[^\s,;&]+)"
)
_BASIC_AUTH_URL_RE = re.compile(
    r"(?i)(?P<scheme>\bhttps?://)(?P<username>[^/\s:@]+):(?P<password>[^@\s/]+)@"
)
_POSIX_HOME_RE = re.compile(r"(?<![\w.])/(?:Users|home)/[^/\s]+")
_WINDOWS_HOME_RE = re.compile(r"(?i)\b[a-z]:\\Users\\[^\\\s]+")


def redact_error_message(
    message: object,
    *,
    max_length: int = DEFAULT_MAX_ERROR_LENGTH,
) -> str:
    """Возвращаем детерминированное ограниченное сообщение для внешнего error contract"""

    if max_length < 1:
        raise ValueError("max_length must be at least 1")

    raw_message = str(message)
    if _TRACEBACK_MARKER in raw_message:
        prefix = raw_message.split(_TRACEBACK_MARKER, 1)[0].strip()
        raw_message = prefix or "Internal error"

    redacted = " ".join(raw_message.split())
    redacted = _BASIC_AUTH_URL_RE.sub(
        rf"\g<scheme>\g<username>:{REDACTION_MARKER}@",
        redacted,
    )
    redacted = _BEARER_RE.sub(_redact_bearer, redacted)
    redacted = _JSON_SECRET_RE.sub(
        rf"\g<prefix>\g<quote>{REDACTION_MARKER}\g<quote>",
        redacted,
    )
    redacted = _KEY_VALUE_SECRET_RE.sub(
        rf"\g<prefix>{REDACTION_MARKER}",
        redacted,
    )
    redacted = _POSIX_HOME_RE.sub("<home>", redacted)
    redacted = _WINDOWS_HOME_RE.sub("<home>", redacted)

    if len(redacted) <= max_length:
        return redacted
    if max_length <= 3:
        return redacted[:max_length]
    return f"{redacted[: max_length - 3]}..."


def _redact_bearer(match: re.Match[str]) -> str:
    header = match.group("header") or ""
    return f"{header}Bearer {REDACTION_MARKER}"


def redact_observation(value: object, *, field: str = "") -> object:
    """Redact parsed observations leaf-by-leaf without corrupting their JSON envelope.

    The public error formatter deliberately drops tracebacks/collapses whitespace;
    applying it to an encoded JSON object destroys source and failure observations.
    """
    if isinstance(value, dict):
        return {key: (REDACTION_MARKER if re.fullmatch(_SECRET_NAME, key, re.IGNORECASE) else
                      redact_observation(item, field=key)) for key, item in value.items()}
    if isinstance(value, list):
        return [redact_observation(item, field=field) for item in value]
    if not isinstance(value, str):
        return value
    if field == "stderr" and value.lstrip().startswith(_TRACEBACK_MARKER):
        value = next((line for line in reversed(value.splitlines()) if line.strip()), "Internal error")
    value = _BASIC_AUTH_URL_RE.sub(rf"\g<scheme>\g<username>:{REDACTION_MARKER}@", value)
    value = _BEARER_RE.sub(_redact_bearer, value)
    value = _JSON_SECRET_RE.sub(rf"\g<prefix>\g<quote>{REDACTION_MARKER}\g<quote>", value)
    value = _KEY_VALUE_SECRET_RE.sub(rf"\g<prefix>{REDACTION_MARKER}", value)
    value = re.sub(r"\bsk-[a-zA-Z0-9_-]{16,}|\beyJ[\w-]+\.[\w-]+\.[\w-]+", REDACTION_MARKER, value)
    return _WINDOWS_HOME_RE.sub("<home>", _POSIX_HOME_RE.sub("<home>", value))
