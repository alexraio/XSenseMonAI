"""Regression tests for sleep-resilient scheduling and secret redaction in logs.

Covers issues found while analyzing live Docker logs (2026-10-25):
1. Analysis windows were silently skipped after the Docker host suspended (monotonic sleep
   counting + fixed look-back). `plan_analysis_windows` / `run_scheduled_windows` must backfill.
2. httpx INFO logs leaked the Telegram bot token embedded in the Bot API URL.
3. Zero-Token skip log line mentioned "Anthropic" regardless of the configured provider.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from src.ai_analyst import AnthropicSOCAnalyst
from src.config import AppConfig
from src.filter_engine import ZeroTokenFilterEngine
from src.log_redaction import (
    REDACTED,
    SecretRedactingFilter,
    configure_logging,
    mask_identifier,
    redact_text,
)
from src.loki_client import LokiClient
from src.main import CycleOutcome, run_scheduled_windows
from src.models import NormalizedLogEvent
from src.notifier import TelegramNotifier
from src.scheduler import SchedulerState, plan_analysis_windows

# Synthetic token with the real Telegram shape (numeric id + 35-char secret); not a live secret
FAKE_BOT_TOKEN = "1234567890:AAFakeTokenForUnitTests_abcdefghijk"
NOW = datetime(2026, 10, 25, 9, 0, 0, tzinfo=UTC)
HOUR = timedelta(minutes=60)


def _config(tmp_path: Path, **overrides: object) -> AppConfig:
    params: dict[str, object] = {
        "llm_provider": "openai",
        "llm_base_url": "http://host.docker.internal:1234/v1",
        "telegram_bot_token": FAKE_BOT_TOKEN,
        "telegram_chat_id": "123456789",
        "analysis_interval_minutes": 60,
        "max_catchup_minutes": 1440,
        "enable_geoip": False,
        "state_file_path": tmp_path / "dedup_cache.json",
    }
    params.update(overrides)
    return AppConfig(**params)  # type: ignore[arg-type]


def _assert_contiguous(windows: list[tuple[datetime, datetime]]) -> None:
    for (_, prev_end), (next_start, _) in zip(windows, windows[1:], strict=False):
        assert prev_end == next_start


# ==============================================================================
# 1. Window planning
# ==============================================================================
def test_plan_first_run_uses_single_interval_window() -> None:
    assert plan_analysis_windows(NOW, None, HOUR, 24 * HOUR) == [(NOW - HOUR, NOW)]


def test_plan_normal_cadence_with_jitter_yields_single_contiguous_window() -> None:
    last_end = NOW - HOUR - timedelta(seconds=75)  # cycle duration jitter
    windows = plan_analysis_windows(NOW, last_end, HOUR, 24 * HOUR)
    assert windows == [(last_end, NOW)]


def test_plan_restart_shortly_after_cycle_keeps_full_interval_window() -> None:
    windows = plan_analysis_windows(NOW, NOW - timedelta(minutes=5), HOUR, 24 * HOUR)
    assert windows == [(NOW - HOUR, NOW)]


def test_plan_backfills_overnight_suspension_without_gaps() -> None:
    """Reproduces the live incident: cycles at 20:18 then 04:24 UTC (~8h unanalyzed)."""
    last_end = datetime(2026, 10, 24, 20, 18, 3, tzinfo=UTC)
    now = datetime(2026, 10, 25, 4, 24, 0, tzinfo=UTC)
    windows = plan_analysis_windows(now, last_end, HOUR, 24 * HOUR)

    assert windows[0][0] == last_end
    assert windows[-1][1] == now
    _assert_contiguous(windows)
    assert len(windows) == 8
    assert all(end - start >= HOUR for start, end in windows)
    assert all(end - start <= HOUR * 1.1 for start, end in windows)


def test_plan_caps_backfill_at_max_catchup() -> None:
    last_end = NOW - timedelta(days=3)
    windows = plan_analysis_windows(NOW, last_end, HOUR, 6 * HOUR)
    assert windows[0][0] == NOW - 6 * HOUR
    assert len(windows) == 6
    _assert_contiguous(windows)


def test_plan_ignores_cursor_in_the_future() -> None:
    assert plan_analysis_windows(NOW, NOW + HOUR, HOUR, 24 * HOUR) == [(NOW - HOUR, NOW)]


def test_scheduler_state_roundtrip_and_corrupt_file(tmp_path: Path) -> None:
    state = SchedulerState(tmp_path / "scheduler_state.json")
    assert state.load_last_window_end() is None
    state.save_last_window_end(NOW)
    assert state.load_last_window_end() == NOW

    state.path.write_text("{not-json", encoding="utf-8")
    assert state.load_last_window_end() is None


# ==============================================================================
# 2. Daemon backfill orchestration
# ==============================================================================
def _mocks(tmp_path: Path) -> tuple[AppConfig, MagicMock, ZeroTokenFilterEngine, MagicMock, MagicMock]:
    cfg = _config(tmp_path)
    loki = MagicMock(spec=LokiClient)
    loki.fetch_pfsense_events.return_value = []
    return (
        cfg,
        loki,
        ZeroTokenFilterEngine(cfg),
        MagicMock(spec=AnthropicSOCAnalyst),
        MagicMock(spec=TelegramNotifier),
    )


def test_run_scheduled_windows_backfills_and_persists_cursor(tmp_path: Path) -> None:
    cfg, loki, engine, analyst, notifier = _mocks(tmp_path)
    state = SchedulerState(cfg.scheduler_state_path)
    state.save_last_window_end(NOW - 3 * HOUR)

    outcomes = run_scheduled_windows(cfg, loki, engine, analyst, notifier, state, now=NOW)

    assert outcomes == [CycleOutcome.COMPLETED] * 3
    queried = [
        (c.kwargs["start_time"], c.kwargs["end_time"]) for c in loki.fetch_pfsense_events.call_args_list
    ]
    assert queried[0][0] == NOW - 3 * HOUR and queried[-1][1] == NOW
    _assert_contiguous(queried)
    assert state.load_last_window_end() == NOW


def test_run_scheduled_windows_stops_and_keeps_cursor_on_loki_outage(tmp_path: Path) -> None:
    cfg, loki, engine, analyst, notifier = _mocks(tmp_path)
    state = SchedulerState(cfg.scheduler_state_path)
    state.save_last_window_end(NOW - 3 * HOUR)
    loki.fetch_pfsense_events.side_effect = [[], ConnectionError("loki down"), []]

    outcomes = run_scheduled_windows(cfg, loki, engine, analyst, notifier, state, now=NOW)

    assert outcomes == [CycleOutcome.COMPLETED, CycleOutcome.LOKI_UNAVAILABLE]
    # Only the first window was analyzed; the failed one must be retried next cycle
    assert state.load_last_window_end() == NOW - 2 * HOUR


def test_run_scheduled_windows_advances_cursor_after_ai_failure(tmp_path: Path) -> None:
    """LLM outages must not cause the same windows to be re-alerted forever."""
    cfg, loki, engine, analyst, notifier = _mocks(tmp_path)
    state = SchedulerState(cfg.scheduler_state_path)
    state.save_last_window_end(NOW - HOUR)
    loki.fetch_pfsense_events.return_value = [
        NormalizedLogEvent(
            timestamp=NOW - timedelta(minutes=10),
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_blocked",
            src_ip="192.168.1.145",
            dst_ip="198.51.100.77",
            dst_port="4444",
            proto="tcp",
            action="block",
            hit_count=3,
        )
    ]
    analyst.analyze.side_effect = RuntimeError("LM Studio unreachable")

    outcomes = run_scheduled_windows(cfg, loki, engine, analyst, notifier, state, now=NOW)

    assert outcomes == [CycleOutcome.AI_FAILED]
    notifier.send_raw_fallback_alert.assert_called_once()
    assert state.load_last_window_end() == NOW


def test_run_scheduled_windows_dry_run_does_not_move_cursor(tmp_path: Path) -> None:
    cfg, loki, engine, analyst, notifier = _mocks(tmp_path)
    state = SchedulerState(cfg.scheduler_state_path)
    state.save_last_window_end(NOW - 2 * HOUR)

    run_scheduled_windows(cfg, loki, engine, analyst, notifier, state, dry_run=True, now=NOW)

    assert state.load_last_window_end() == NOW - 2 * HOUR


def test_zero_token_skip_log_reports_configured_provider(
    tmp_path: Path, caplog: pytest.LogCaptureFixture
) -> None:
    cfg, loki, engine, analyst, notifier = _mocks(tmp_path)
    state = SchedulerState(cfg.scheduler_state_path)

    with caplog.at_level(logging.INFO, logger="pfsensemon.main"):
        run_scheduled_windows(cfg, loki, engine, analyst, notifier, state, now=NOW)

    skip_lines = [r.getMessage() for r in caplog.records if "Zero-Token Filter" in r.getMessage()]
    assert skip_lines and all("provider=openai" in line for line in skip_lines)
    assert not any("Anthropic" in line for line in skip_lines)


# ==============================================================================
# 3. Secret redaction
# ==============================================================================
def test_redact_text_scrubs_telegram_token_in_bot_api_url() -> None:
    line = f'HTTP Request: POST https://api.telegram.org/bot{FAKE_BOT_TOKEN}/sendMessage "200 OK"'
    redacted = redact_text(line)
    assert FAKE_BOT_TOKEN not in redacted
    assert f"/bot{REDACTED}/sendMessage" in redacted


def test_redact_text_scrubs_explicit_secrets_but_ignores_short_placeholders() -> None:
    api_key = "test-secret-key-for-redaction-0123456789"
    assert api_key not in redact_text(f"auth failed for {api_key}", [api_key])
    assert redact_text("api_key=lm-studio", ["lm-studio"]) == "api_key=lm-studio"


def test_mask_identifier_keeps_only_last_digits() -> None:
    assert mask_identifier("123456789") == "******789"
    assert mask_identifier("-1001234567890").endswith("890")
    assert "1001234567" not in mask_identifier("-1001234567890")


def test_secret_filter_redacts_args_and_tracebacks() -> None:
    filt = SecretRedactingFilter()
    record = logging.LogRecord(
        "httpx", logging.INFO, __file__, 1, "HTTP Request: POST %s", (
            f"https://api.telegram.org/bot{FAKE_BOT_TOKEN}/sendMessage",
        ), None,
    )
    assert filt.filter(record)
    assert FAKE_BOT_TOKEN not in record.getMessage()

    try:
        raise RuntimeError(f"Client error for url https://api.telegram.org/bot{FAKE_BOT_TOKEN}/x")
    except RuntimeError:
        import sys

        exc_record = logging.LogRecord(
            "src.notifier", logging.ERROR, __file__, 1, "boom", None, sys.exc_info()
        )
    filt.filter(exc_record)
    assert exc_record.exc_text and FAKE_BOT_TOKEN not in exc_record.exc_text


def test_configure_logging_silences_httpx_request_logs() -> None:
    configure_logging(secrets=[FAKE_BOT_TOKEN])
    assert logging.getLogger("httpx").getEffectiveLevel() >= logging.WARNING
    assert logging.getLogger("httpcore").getEffectiveLevel() >= logging.WARNING
