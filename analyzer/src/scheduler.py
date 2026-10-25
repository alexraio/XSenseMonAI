"""Wall-clock based scheduling helpers with persistent cursor and gap backfilling.

The analyzer usually runs inside Docker Desktop on a laptop/desktop host. When the host
sleeps, the Docker VM is suspended and monotonic timers (``time.sleep``) stop advancing.
Counting sleep seconds therefore delays cycles by the full suspension time, and since each
cycle only inspected the last ``interval`` minutes, every minute in between was never
analyzed. This module plans analysis windows from the persisted end of the last
successfully analyzed window, so no time range is silently skipped.
"""

from __future__ import annotations

import json
import logging
from datetime import UTC, datetime, timedelta
from pathlib import Path

logger = logging.getLogger(__name__)

# A trailing gap shorter than this fraction of the interval is merged into the oldest
# window instead of producing a tiny extra window (absorbs normal scheduling jitter).
JITTER_TOLERANCE_RATIO = 0.1


def plan_analysis_windows(
    now: datetime,
    last_window_end: datetime | None,
    interval: timedelta,
    max_catchup: timedelta,
) -> list[tuple[datetime, datetime]]:
    """Return chronologically ordered, contiguous (start, end) windows covering the gap.

    - First run / unknown cursor / cursor in the future: a single `interval` window ending now.
    - Normal cadence (gap ~ interval): a single window from the cursor to now.
    - After a suspension: consecutive `interval`-sized windows back to the cursor, bounded by
      `max_catchup` (older data is intentionally not backfilled).
    Every window is at least `interval` long so per-interval thresholds keep their meaning.
    """
    if interval <= timedelta(0):
        raise ValueError("interval must be positive")

    if last_window_end is None or last_window_end >= now:
        return [(now - interval, now)]

    catchup_floor = now - max(max_catchup, interval)
    gap_start = max(last_window_end, catchup_floor)
    tolerance = interval * JITTER_TOLERANCE_RATIO

    windows: list[tuple[datetime, datetime]] = []
    end = now
    while end - gap_start > interval + tolerance:
        windows.append((end - interval, end))
        end -= interval
    windows.append((min(gap_start, end - interval), end))
    windows.reverse()
    return windows


class SchedulerState:
    """Persists the end timestamp of the last successfully analyzed window."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def load_last_window_end(self) -> datetime | None:
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            value = datetime.fromisoformat(raw["last_window_end"])
        except (OSError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            logger.warning("Could not load scheduler state file %s: %s", self.path, exc)
            return None
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    def save_last_window_end(self, value: datetime) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps({"last_window_end": value.astimezone(UTC).isoformat()}),
                encoding="utf-8",
            )
            tmp_path.replace(self.path)
        except OSError as exc:
            logger.warning("Could not persist scheduler state file %s: %s", self.path, exc)
