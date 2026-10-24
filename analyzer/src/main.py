"""Main entrypoint and periodic scheduler for the PfsenseMon AI Analyzer."""

from __future__ import annotations

import argparse
import logging
import signal
import sys
import time
from datetime import UTC, datetime, timedelta
from types import FrameType

from .ai_analyst import AnthropicSOCAnalyst
from .config import AppConfig
from .filter_engine import ZeroTokenFilterEngine
from .loki_client import LokiClient
from .notifier import TelegramNotifier

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    datefmt="%Y-%m-%dT%H:%M:%SZ",
)
logger = logging.getLogger("pfsensemon.main")


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

    logger.info(
        "Starting analysis cycle for window %s -> %s (%d min)",
        window_start.strftime("%H:%M:%S"),
        window_end.strftime("%H:%M:%S"),
        window_minutes,
    )

    try:
        events = loki.fetch_pfsense_events(start_time=window_start, end_time=window_end)
    except Exception as exc:  # noqa: BLE001
        logger.error("Failed to fetch events from Loki (%s): %s", config.loki_url, exc)
        return False

    evaluation = filter_engine.evaluate(
        events=events,
        window_start=window_start,
        window_end=window_end,
    )

    if not evaluation.should_invoke_ai:
        logger.info(
            "Zero-Token Filter: No anomalies exceeded thresholds (raw_wan_blocks=%d, dedup_suppressed=%d). "
            "Skipping Anthropic API call (0 tokens spent).",
            evaluation.total_raw_wan_blocks,
            evaluation.suppressed_by_dedup_count,
        )
        return True

    logger.info(
        "Anomalies detected! Trigger reasons: %s",
        "; ".join(evaluation.trigger_reasons),
    )

    if dry_run:
        logger.info(
            "[DRY-RUN] Would call Anthropic API with %d Tier-1, %d Tier-2, %d Tier-3 items.",
            len(evaluation.tier1_anomalies),
            len(evaluation.tier2_events),
            len(evaluation.tier3_offenders),
        )
        return True

    try:
        report = analyst.analyze(evaluation)
        loki.push_ai_report(report)
        notifier.send_ai_report(report, evaluation)
        return True
    except Exception as exc:  # noqa: BLE001
        logger.error("AI analysis failed: %s. Attempting raw fallback alert...", exc)
        notifier.send_raw_fallback_alert(evaluation, str(exc))
        return False


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
        help="Query Loki and run the Zero-Token filter without calling Anthropic or Telegram.",
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
    logger.info(
        "PfsenseMon Analyzer daemon started (interval=%dm, model=%s, api_base=%s, loki=%s)",
        config.analysis_interval_minutes,
        config.anthropic_model,
        config.anthropic_base_url,
        config.loki_url,
    )

    # Wait briefly for Loki readiness on startup
    for _ in range(10):
        if loki.is_ready() or killer.stop_requested:
            break
        logger.info("Waiting for Loki at %s to become ready...", config.loki_url)
        time.sleep(3)

    while not killer.stop_requested:
        run_analysis_cycle(
            config=config,
            loki=loki,
            filter_engine=filter_engine,
            analyst=analyst,
            notifier=notifier,
            lookback_minutes=args.lookback_minutes,
            dry_run=args.dry_run,
        )
        # Sleep in 1-second increments to remain responsive to SIGTERM
        for _ in range(interval_sec):
            if killer.stop_requested:
                break
            time.sleep(1)

    logger.info("PfsenseMon Analyzer stopped cleanly.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
