"""Main entrypoint and periodic scheduler for the PfsenseMon AI Analyzer."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from collections.abc import Callable
from datetime import UTC, datetime, timedelta
from enum import Enum
from types import FrameType

from .ai_analyst import AnthropicSOCAnalyst
from .config import AppConfig
from .filter_engine import ZeroTokenFilterEngine
from .geoip import enrich_evaluation_with_geoip
from .log_redaction import configure_logging
from .loki_client import LokiClient
from .notifier import TelegramNotifier
from .scheduler import SchedulerState, plan_analysis_windows

configure_logging()
logger = logging.getLogger("pfsensemon.main")

WINDOW_TIME_FORMAT = "%Y-%m-%d %H:%M:%S"


class CycleOutcome(Enum):
    """Result of analyzing a single time window."""

    COMPLETED = "completed"  # Includes Zero-Token skips and dry-runs
    LOKI_UNAVAILABLE = "loki_unavailable"  # Window was NOT analyzed; must be retried
    AI_FAILED = "ai_failed"  # Window was analyzed; raw fallback alert was attempted


class GracefulKiller:
    """Handles SIGINT/SIGTERM for clean container shutdown."""

    def __init__(self) -> None:
        self.stop_requested = False
        signal.signal(signal.SIGINT, self._handle)
        signal.signal(signal.SIGTERM, self._handle)

    def _handle(self, signum: int, _frame: FrameType | None) -> None:
        logger.info("Received signal %d, initiating graceful shutdown...", signum)
        self.stop_requested = True


def run_analysis_cycle(
    config: AppConfig,
    loki: LokiClient,
    filter_engine: ZeroTokenFilterEngine,
    analyst: AnthropicSOCAnalyst,
    notifier: TelegramNotifier,
    lookback_minutes: int | None = None,
    dry_run: bool = False,
) -> bool:
    """Execute one complete log retrieval, Zero-Token filtering, AI analysis, and alerting cycle."""
    window_minutes = lookback_minutes or config.analysis_interval_minutes
    window_end = datetime.now(tz=UTC)
    window_start = window_end - timedelta(minutes=window_minutes)
    outcome = run_analysis_window(
        config=config,
        loki=loki,
        filter_engine=filter_engine,
        analyst=analyst,
        notifier=notifier,
        window_start=window_start,
        window_end=window_end,
        dry_run=dry_run,
    )
    return outcome is CycleOutcome.COMPLETED


def run_analysis_window(
    config: AppConfig,
    loki: LokiClient,
    filter_engine: ZeroTokenFilterEngine,
    analyst: AnthropicSOCAnalyst,
    notifier: TelegramNotifier,
    window_start: datetime,
    window_end: datetime,
    dry_run: bool = False,
) -> CycleOutcome:
    """Analyze an explicit [window_start, window_end] time range."""
    window_minutes = round((window_end - window_start).total_seconds() / 60)

    logger.info(
        "Starting analysis cycle for window %s -> %s UTC (%d min)",
        window_start.astimezone(UTC).strftime(WINDOW_TIME_FORMAT),
        window_end.astimezone(UTC).strftime(WINDOW_TIME_FORMAT),
        window_minutes,
    )

    try:
        events = loki.fetch_pfsense_events(start_time=window_start, end_time=window_end)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to fetch events from Loki (%s): %s", config.loki_url, exc)
        return CycleOutcome.LOKI_UNAVAILABLE

    evaluation = filter_engine.evaluate(
        events=events,
        window_start=window_start,
        window_end=window_end,
    )

    if not evaluation.should_invoke_ai:
        logger.info(
            "Zero-Token Filter: No anomalies exceeded thresholds (raw_wan_blocks=%d, dedup_suppressed=%d). "
            "Skipping LLM call (provider=%s, 0 tokens spent).",
            evaluation.total_raw_wan_blocks,
            evaluation.suppressed_by_dedup_count,
            config.llm_provider,
        )
        return CycleOutcome.COMPLETED

    logger.info(
        "Anomalies detected! Trigger reasons: %s",
        "; ".join(evaluation.trigger_reasons),
    )

    if config.enable_geoip:
        enrich_evaluation_with_geoip(evaluation)

    if dry_run:
        logger.info(
            "[DRY-RUN] Would call LLM (%s/%s) with %d Tier-1, %d Tier-2, %d Tier-3 items.",
            config.llm_provider,
            config.llm_model,
            len(evaluation.tier1_anomalies),
            len(evaluation.tier2_events),
            len(evaluation.tier3_offenders),
        )
        return CycleOutcome.COMPLETED

    try:
        report = analyst.analyze(evaluation)
        loki.push_ai_report(report)
        notifier.send_ai_report(report, evaluation)
        return CycleOutcome.COMPLETED
    except Exception as exc:  # noqa: BLE001
        logger.error("AI analysis failed: %s. Attempting raw fallback alert...", exc)
        notifier.send_raw_fallback_alert(evaluation, str(exc))
        return CycleOutcome.AI_FAILED


def run_scheduled_windows(
    config: AppConfig,
    loki: LokiClient,
    filter_engine: ZeroTokenFilterEngine,
    analyst: AnthropicSOCAnalyst,
    notifier: TelegramNotifier,
    state: SchedulerState,
    should_stop: Callable[[], bool] = lambda: False,
    dry_run: bool = False,
    now: datetime | None = None,
) -> list[CycleOutcome]:
    """Analyze every window since the last persisted cursor, backfilling gaps after suspension.

    The cursor is advanced after each analyzed window (also when the LLM fails, since the raw
    fallback alert already covered it). A Loki outage stops the backfill so that the
    remaining windows are retried on the next cycle. Dry-runs never move the cursor.
    """
    now = now or datetime.now(tz=UTC)
    interval = timedelta(minutes=config.analysis_interval_minutes)
    max_catchup = timedelta(minutes=config.max_catchup_minutes)
    last_window_end = state.load_last_window_end()

    windows = plan_analysis_windows(now, last_window_end, interval, max_catchup)
    if last_window_end is not None and len(windows) > 1:
        logger.warning(
            "Detected analysis gap since %s UTC (host suspended or analyzer offline); "
            "backfilling %d window(s).",
            last_window_end.astimezone(UTC).strftime(WINDOW_TIME_FORMAT),
            len(windows),
        )
    if last_window_end is not None and windows[0][0] > last_window_end:
        logger.warning(
            "Gap exceeds MAX_CATCHUP_MINUTES=%d; events between %s and %s UTC will not be analyzed.",
            config.max_catchup_minutes,
            last_window_end.astimezone(UTC).strftime(WINDOW_TIME_FORMAT),
            windows[0][0].astimezone(UTC).strftime(WINDOW_TIME_FORMAT),
        )

    outcomes: list[CycleOutcome] = []
    for window_start, window_end in windows:
        if should_stop():
            break
        outcome = run_analysis_window(
            config=config,
            loki=loki,
            filter_engine=filter_engine,
            analyst=analyst,
            notifier=notifier,
            window_start=window_start,
            window_end=window_end,
            dry_run=dry_run,
        )
        outcomes.append(outcome)
        if outcome is CycleOutcome.LOKI_UNAVAILABLE:
            logger.warning("Loki unavailable; remaining window(s) will be retried on the next cycle.")
            break
        if not dry_run:
            state.save_last_window_end(window_end)
    return outcomes


def main() -> int:
    parser = argparse.ArgumentParser(description="PfsenseMon AI Security Analyzer")
    parser.add_argument(
        "--once",
        action="store_true",
        help="Run a single analysis cycle and exit immediately.",
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Query Loki and run the Zero-Token filter without calling the LLM or Telegram.",
    )
    parser.add_argument(
        "--lookback-minutes",
        type=int,
        default=None,
        help="Override the time window (in minutes) to inspect in Loki.",
    )
    parser.add_argument(
        "--reset-dedup",
        action="store_true",
        help="Clear the deduplication cache before running the cycle.",
    )
    args = parser.parse_args()

    config = AppConfig.from_env()
    configure_logging(
        secrets=[config.telegram_bot_token, config.llm_api_key, config.anthropic_api_key]
    )
    if args.reset_dedup and config.state_file_path.exists():
        config.state_file_path.unlink(missing_ok=True)
        logger.info("Cleared deduplication cache at %s", config.state_file_path)
    loki = LokiClient(base_url=config.loki_url)
    filter_engine = ZeroTokenFilterEngine(config=config)
    analyst = AnthropicSOCAnalyst(config=config)
    notifier = TelegramNotifier(config=config)

    if args.once:
        success = run_analysis_cycle(
            config=config,
            loki=loki,
            filter_engine=filter_engine,
            analyst=analyst,
            notifier=notifier,
            lookback_minutes=args.lookback_minutes,
            dry_run=args.dry_run,
        )
        return 0 if success else 1

    killer = GracefulKiller()
    interval_sec = config.analysis_interval_minutes * 60
    scheduler_state = SchedulerState(config.scheduler_state_path)
    logger.info(
        "PfsenseMon Analyzer daemon started (interval=%dm, max_catchup=%dm, provider=%s, model=%s, api_base=%s, geoip=%s, loki=%s)",
        config.analysis_interval_minutes,
        config.max_catchup_minutes,
        config.llm_provider,
        config.llm_model,
        config.llm_base_url,
        config.enable_geoip,
        config.loki_url,
    )

    # Wait briefly for Loki readiness on startup
    for _ in range(10):
        if loki.is_ready() or killer.stop_requested:
            break
        logger.info("Waiting for Loki at %s to become ready...", config.loki_url)
        time.sleep(3)

    while not killer.stop_requested:
        # Wall-clock deadline: after a host suspension the next cycle starts immediately
        # on wake-up instead of waiting for the full interval of monotonic sleep seconds.
        next_run_at = time.time() + interval_sec
        if args.lookback_minutes:
            # Explicit look-back override keeps the legacy fixed-window behaviour
            run_analysis_cycle(
                config=config,
                loki=loki,
                filter_engine=filter_engine,
                analyst=analyst,
                notifier=notifier,
                lookback_minutes=args.lookback_minutes,
                dry_run=args.dry_run,
            )
        else:
            run_scheduled_windows(
                config=config,
                loki=loki,
                filter_engine=filter_engine,
                analyst=analyst,
                notifier=notifier,
                state=scheduler_state,
                should_stop=lambda: killer.stop_requested,
                dry_run=args.dry_run,
            )
        # Sleep in 1-second increments to remain responsive to SIGTERM
        while not killer.stop_requested and time.time() < next_run_at:
            time.sleep(1)

    logger.info("PfsenseMon Analyzer stopped cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
