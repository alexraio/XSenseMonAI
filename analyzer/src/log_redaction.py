"""Logging setup with automatic redaction of secrets (Telegram bot tokens, API keys).

Third-party HTTP clients (``httpx``/``httpcore``) log full request URLs at INFO level.
The Telegram Bot API embeds the bot token in the URL path (``/bot<TOKEN>/sendMessage``),
so without redaction the token would leak into ``docker logs`` output.
"""

from __future__ import annotations

import logging
import re
from collections.abc import Iterable

REDACTED = "<REDACTED>"

# Telegram bot tokens have the shape "<numeric bot id>:<35-char secret>"
TELEGRAM_TOKEN_PATTERN = re.compile(r"(?<!\d)\d{6,}:[A-Za-z0-9_-]{30,}(?![A-Za-z0-9_-])")

# Minimum length for an explicitly configured secret to be redacted verbatim.
# Prevents short placeholder values (e.g. "lm-studio", "ollama") from mangling log lines.
MIN_SECRET_LENGTH = 12

NOISY_HTTP_LOGGERS = ("httpx", "httpcore")

LOG_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
LOG_DATEFMT = "%Y-%m-%dT%H:%M:%SZ"


def mask_identifier(value: str | int | None, visible: int = 3) -> str:
    """Mask an identifier (e.g. a Telegram chat ID), keeping only the last `visible` characters."""
    text = str(value or "")
    if len(text) <= visible:
        return "*" * len(text)
    return "*" * (len(text) - visible) + text[-visible:]


def redact_text(text: str, secrets: Iterable[str] = ()) -> str:
    """Replace Telegram bot tokens and any explicitly provided secrets with a placeholder."""
    redacted = TELEGRAM_TOKEN_PATTERN.sub(REDACTED, text)
    for secret in secrets:
        if secret and len(secret) >= MIN_SECRET_LENGTH and secret in redacted:
            redacted = redacted.replace(secret, REDACTED)
    return redacted


class SecretRedactingFilter(logging.Filter):
    """Handler-level filter that scrubs secrets from every record (including tracebacks)."""

    def __init__(self, secrets: Iterable[str] = ()) -> None:
        super().__init__()
        self.secrets: set[str] = set()
        self.update_secrets(secrets)

    def update_secrets(self, secrets: Iterable[str]) -> None:
        self.secrets |= {s.strip() for s in secrets if s and len(s.strip()) >= MIN_SECRET_LENGTH}

    def filter(self, record: logging.LogRecord) -> bool:
        try:
            message = record.getMessage()
        except (TypeError, ValueError):
            message = str(record.msg)
        record.msg = redact_text(message, self.secrets)
        record.args = None

        if record.exc_info and not record.exc_text:
            record.exc_text = logging.Formatter().formatException(record.exc_info)
        if record.exc_text:
            record.exc_text = redact_text(record.exc_text, self.secrets)
        return True


def configure_logging(secrets: Iterable[str] = (), level: int = logging.INFO) -> SecretRedactingFilter:
    """Configure root logging once and attach (or update) the redaction filter on all handlers.

    Safe to call multiple times: subsequent calls only register additional secrets.
    """
    logging.basicConfig(level=level, format=LOG_FORMAT, datefmt=LOG_DATEFMT)
    root = logging.getLogger()
    secrets = list(secrets)

    active_filter: SecretRedactingFilter | None = None
    for handler in root.handlers:
        existing = next(
            (f for f in handler.filters if isinstance(f, SecretRedactingFilter)), None
        )
        if existing is None:
            existing = active_filter or SecretRedactingFilter(secrets)
            handler.addFilter(existing)
        existing.update_secrets(secrets)
        active_filter = active_filter or existing

    # Request-level URL logging is not needed in production and is the main leak vector
    for name in NOISY_HTTP_LOGGERS:
        logging.getLogger(name).setLevel(logging.WARNING)

    return active_filter or SecretRedactingFilter(secrets)
