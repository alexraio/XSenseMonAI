"""Configuration management for the PfsenseMon AI Analyzer."""

from __future__ import annotations

import ipaddress
import os
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlparse

from dotenv import load_dotenv

SUPPORTED_LLM_PROVIDERS = {"anthropic", "ollama", "openai", "openrouter"}


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


def normalize_openai_base_url(url: str | None, provider: str = "openai") -> str:
    """Normalize an OpenAI-compatible base URL for Ollama, OpenAI, LM Studio, or OpenRouter."""
    cleaned = (url or "").strip().rstrip("/")
    if cleaned.endswith("/chat/completions"):
        cleaned = cleaned[: -len("/chat/completions")].rstrip("/")

    if not cleaned:
        if provider == "ollama":
            return "http://host.docker.internal:11434/v1"
        if provider == "openrouter":
            return "https://openrouter.ai/api/v1"
        return "https://api.openai.com/v1"

    if provider == "ollama" and not cleaned.endswith("/v1"):
        cleaned = f"{cleaned}/v1"
    return cleaned


def is_local_endpoint(url: str) -> bool:
    """Return True if the base URL points to localhost, Docker host, or a private RFC1918 IP."""
    try:
        parsed = urlparse(url)
        host = (parsed.hostname or "").strip().lower()
    except ValueError:
        return False

    if not host:
        return False
    if host in {"localhost", "127.0.0.1", "::1", "0.0.0.0", "host.docker.internal"}:
        return True
    if host.endswith((".local", ".internal", ".lan")):
        return True
    try:
        addr = ipaddress.ip_address(host)
        return addr.is_private or addr.is_loopback or addr.is_link_local
    except ValueError:
        return False


@dataclass(frozen=True, slots=True)
class AppConfig:
    """Immutable application settings loaded from environment variables."""

    # Anthropic / MiniMax API settings (retained for full backward compatibility)
    anthropic_api_key: str = ""
    anthropic_base_url: str = "https://api.minimax.io/anthropic"
    anthropic_model: str = "MiniMax-M2.5"
    ai_report_language: str = "Italian"

    # Multi-Provider & Local LLM settings ('anthropic' | 'ollama' | 'openai' | 'openrouter')
    llm_provider: str = "anthropic"
    llm_api_key: str = ""
    llm_base_url: str = ""
    llm_model: str = ""
    llm_timeout_seconds: float = 90.0
    llm_max_tokens: int = 1500
    llm_structured_output: bool = True
    openrouter_site_url: str = "https://github.com/alexraio/XSenseMonAI"
    openrouter_app_name: str = "PfsenseMon"

    # Post-filter GeoIP & ASN enrichment toggle
    enable_geoip: bool = True

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

    def __post_init__(self) -> None:
        provider = (self.llm_provider or "anthropic").strip().lower()
        if provider not in SUPPORTED_LLM_PROVIDERS:
            raise ValueError(
                f"Unsupported LLM_PROVIDER '{provider}'. Must be one of: {sorted(SUPPORTED_LLM_PROVIDERS)}"
            )
        object.__setattr__(self, "llm_provider", provider)

        effective_key = (self.llm_api_key or self.anthropic_api_key).strip()
        object.__setattr__(self, "llm_api_key", effective_key)

        if provider == "anthropic":
            base_url = normalize_anthropic_base_url(self.llm_base_url or self.anthropic_base_url)
            default_model = self.anthropic_model.strip() or "MiniMax-M2.5"
        else:
            base_url = normalize_openai_base_url(self.llm_base_url, provider=provider)
            default_models = {
                "ollama": "qwen2.5:14b",
                "openai": "gpt-4o-mini",
                "openrouter": "google/gemini-2.5-flash",
            }
            default_model = default_models.get(provider, "gpt-4o-mini")

        object.__setattr__(self, "llm_base_url", base_url)
        object.__setattr__(self, "llm_model", (self.llm_model or default_model).strip())

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
        enable_geoip = os.getenv("ENABLE_GEOIP", "true").lower() in {
            "1",
            "true",
            "yes",
        }
        structured_output = os.getenv("LLM_STRUCTURED_OUTPUT", "true").lower() in {
            "1",
            "true",
            "yes",
        }

        provider = os.getenv("LLM_PROVIDER", "anthropic").strip().lower() or "anthropic"
        anthropic_key = os.getenv("ANTHROPIC_API_KEY", "").strip()
        anthropic_base = normalize_anthropic_base_url(
            os.getenv("ANTHROPIC_BASE_URL", "https://api.minimax.io/anthropic")
        )
        anthropic_model = os.getenv("ANTHROPIC_MODEL", "MiniMax-M2.5").strip()

        # Resolve provider-aware API key, base URL, and model with backward compatibility
        llm_api_key = (
            os.getenv("LLM_API_KEY")
            or os.getenv("OPENROUTER_API_KEY")
            or os.getenv("OPENAI_API_KEY")
            or anthropic_key
            or ""
        ).strip()

        raw_llm_base = os.getenv("LLM_BASE_URL", "").strip()
        if not raw_llm_base:
            if provider == "ollama":
                raw_llm_base = os.getenv("OLLAMA_BASE_URL", "").strip()
            elif provider == "openrouter":
                raw_llm_base = os.getenv("OPENROUTER_BASE_URL", "").strip()
            elif provider == "openai":
                raw_llm_base = os.getenv("OPENAI_BASE_URL", "").strip()
            else:
                raw_llm_base = anthropic_base

        raw_llm_model = os.getenv("LLM_MODEL", "").strip()
        if not raw_llm_model:
            if provider == "ollama":
                raw_llm_model = os.getenv("OLLAMA_MODEL", "").strip()
            elif provider == "openrouter":
                raw_llm_model = os.getenv("OPENROUTER_MODEL", "").strip()
            elif provider == "openai":
                raw_llm_model = os.getenv("OPENAI_MODEL", "").strip()
            else:
                raw_llm_model = anthropic_model

        return cls(
            anthropic_api_key=anthropic_key,
            anthropic_base_url=anthropic_base,
            anthropic_model=anthropic_model,
            ai_report_language=os.getenv("AI_REPORT_LANGUAGE", "Italian").strip(),
            llm_provider=provider,
            llm_api_key=llm_api_key,
            llm_base_url=raw_llm_base,
            llm_model=raw_llm_model,
            llm_timeout_seconds=max(5.0, float(os.getenv("LLM_TIMEOUT_SECONDS", "90.0"))),
            llm_max_tokens=max(256, int(os.getenv("LLM_MAX_TOKENS", "1500"))),
            llm_structured_output=structured_output,
            openrouter_site_url=os.getenv(
                "OPENROUTER_SITE_URL", "https://github.com/alexraio/XSenseMonAI"
            ).strip(),
            openrouter_app_name=os.getenv("OPENROUTER_APP_NAME", "PfsenseMon").strip(),
            enable_geoip=enable_geoip,
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
