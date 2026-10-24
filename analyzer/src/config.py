"""Configuration management for the PfsenseMon AI Analyzer."""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path

from dotenv import load_dotenv


def _parse_csv_set(value: str | None) -> set[str]:
    """Parse a comma-separated environment variable into a normalized set of strings."""
    if not value:
        return set()
    return {item.strip() for item in value.split(",") if item.strip()}


def normalize_anthropic_base_url(url: str | None) -> str:
    """Normalize an Anthropic-compatible base URL (strips trailing /v1/messages or /v1)."""
    cleaned = (url or "").strip().rstrip("/")
    if not cleaned:
        return "https://api.anthropic.com"
    if cleaned.endswith("/v1/messages"):
        cleaned = cleaned[: -len("/v1/messages")].rstrip("/")
    elif cleaned.endswith("/v1"):
        cleaned = cleaned[: -len("/v1")].rstrip("/")
    return cleaned


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Immutable application settings loaded from environment variables."""

    # Anthropic / MiniMax API settings
    anthropic_api_key: str
    anthropic_base_url: str = "https://api.minimax.io/anthropic"
    anthropic_model: str = "MiniMax-M2.5"
    ai_report_language: str = "Italian"

    # Telegram Bot settings
    telegram_bot_token: str = ""
    telegram_chat_id: str = ""
    telegram_enable_raw_fallback: bool = True

    # Loki connection
    loki_url: str = "http://loki:3100"

    # Scheduling & Zero-Token filter thresholds
    analysis_interval_minutes: int = 15
    wan_block_hit_threshold: int = 50
    wan_port_scan_threshold: int = 8
    outbound_suspicious_threshold: int = 1
    auth_event_threshold: int = 1
    alert_dedup_ttl_minutes: int = 120
    max_prompt_items_per_tier: int = 25

    # Whitelists
    whitelist_internal_ips: set[str] = field(default_factory=set)
    whitelist_external_ips: set[str] = field(default_factory=set)
    whitelist_outbound_ports: set[str] = field(
        default_factory=lambda: {
            "53",
            "80",
            "123",
            "443",
            "465",
            "587",
            "853",
            "993",
            "51820",
            "1194",
        }
    )

    # State persistence path for deduplication cache
    state_file_path: Path = Path("/app/state/dedup_cache.json")

    @classmethod
    def from_env(cls, env_path: str | Path | None = None) -> AppConfig:
        """Load configuration from .env file and OS environment variables."""
        if env_path:
            load_dotenv(dotenv_path=env_path)
        else:
            load_dotenv()

        default_ports = "53,80,123,443,465,587,853,993,51820,1194"
        raw_fallback = os.getenv("TELEGRAM_ENABLE_RAW_FALLBACK", "true").lower() in {
            "1",
            "true",
            "yes",
        }

        return cls(
            anthropic_api_key=os.getenv("ANTHROPIC_API_KEY", "").strip(),
            anthropic_base_url=normalize_anthropic_base_url(
                os.getenv("ANTHROPIC_BASE_URL", "https://api.minimax.io/anthropic")
            ),
            anthropic_model=os.getenv("ANTHROPIC_MODEL", "MiniMax-M2.5").strip(),
            ai_report_language=os.getenv("AI_REPORT_LANGUAGE", "Italian").strip(),
            telegram_bot_token=os.getenv("TELEGRAM_BOT_TOKEN", "").strip(),
            telegram_chat_id=os.getenv("TELEGRAM_CHAT_ID", "").strip(),
            telegram_enable_raw_fallback=raw_fallback,
            loki_url=os.getenv(
                "LOKI_INTERNAL_URL", os.getenv("LOKI_URL", "http://localhost:3100")
            ).rstrip("/"),
            analysis_interval_minutes=max(1, int(os.getenv("ANALYSIS_INTERVAL_MINUTES", "15"))),
            wan_block_hit_threshold=max(1, int(os.getenv("WAN_BLOCK_HIT_THRESHOLD", "50"))),
            wan_port_scan_threshold=max(1, int(os.getenv("WAN_PORT_SCAN_THRESHOLD", "8"))),
            outbound_suspicious_threshold=max(
                1, int(os.getenv("OUTBOUND_SUSPICIOUS_THRESHOLD", "1"))
            ),
            auth_event_threshold=max(1, int(os.getenv("AUTH_EVENT_THRESHOLD", "1"))),
            alert_dedup_ttl_minutes=max(0, int(os.getenv("ALERT_DEDUP_TTL_MINUTES", "120"))),
            max_prompt_items_per_tier=max(5, int(os.getenv("MAX_PROMPT_ITEMS_PER_TIER", "25"))),
            whitelist_internal_ips=_parse_csv_set(os.getenv("WHITELIST_INTERNAL_IPS")),
            whitelist_external_ips=_parse_csv_set(os.getenv("WHITELIST_EXTERNAL_IPS")),
            whitelist_outbound_ports=_parse_csv_set(
                os.getenv("WHITELIST_OUTBOUND_PORTS", default_ports)
            ),
            state_file_path=Path(
                os.getenv("STATE_FILE_PATH", "/tmp/pfsensemon_dedup_cache.json")
            ),
        )
