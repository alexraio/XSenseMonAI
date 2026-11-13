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
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any

from .models import ActiveMonitoringMode

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


@dataclass(frozen=True, slots=True)
class ModeResolution:
    """Resolved monitoring mode (`onboarding` or `steady`) for an analysis cycle."""

    active_mode: ActiveMonitoringMode
    should_notify_graduation: bool = False
    remaining_hours: float = 0.0


class SchedulerState:
    """Persists the end timestamp of the last analyzed window and onboarding lifecycle state."""

    def __init__(self, path: Path) -> None:
        self.path = path

    def _load_dict(self, warn_on_error: bool = True) -> dict[str, Any] | None:
        if not self.path.exists():
            return None
        try:
            raw = json.loads(self.path.read_text(encoding="utf-8"))
            if isinstance(raw, dict):
                return raw
            if warn_on_error:
                logger.warning("Scheduler state file %s does not contain a JSON object", self.path)
            return None
        except (OSError, json.JSONDecodeError, TypeError, ValueError) as exc:
            if warn_on_error:
                logger.warning("Could not load scheduler state file %s: %s", self.path, exc)
            return None

    def _save_dict(self, data: dict[str, Any]) -> None:
        try:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            tmp_path = self.path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps(data, indent=2),
                encoding="utf-8",
            )
            tmp_path.replace(self.path)
        except OSError as exc:
            logger.warning("Could not persist scheduler state file %s: %s", self.path, exc)

    def load_last_window_end(self) -> datetime | None:
        raw = self._load_dict(warn_on_error=True)
        if not raw or "last_window_end" not in raw:
            return None
        try:
            value = datetime.fromisoformat(str(raw["last_window_end"]))
        except (TypeError, ValueError) as exc:
            logger.warning("Could not load scheduler state file %s: %s", self.path, exc)
            return None
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    def save_last_window_end(self, value: datetime) -> None:
        data = self._load_dict(warn_on_error=False) or {}
        data["last_window_end"] = value.astimezone(UTC).isoformat()
        self._save_dict(data)

    def load_onboarding_started_at(self) -> datetime | None:
        raw = self._load_dict(warn_on_error=False)
        if not raw or "onboarding_started_at" not in raw:
            return None
        try:
            value = datetime.fromisoformat(str(raw["onboarding_started_at"]))
        except (TypeError, ValueError):
            return None
        return value if value.tzinfo else value.replace(tzinfo=UTC)

    def save_onboarding_started_at(
        self,
        value: datetime,
        graduation_notified: bool | None = None,
    ) -> None:
        data = self._load_dict(warn_on_error=False) or {}
        data["onboarding_started_at"] = value.astimezone(UTC).isoformat()
        if graduation_notified is not None:
            data["graduation_notified"] = bool(graduation_notified)
        self._save_dict(data)

    def is_graduation_notified(self) -> bool:
        raw = self._load_dict(warn_on_error=False) or {}
        return bool(raw.get("graduation_notified", False))

    def mark_graduation_notified(self) -> None:
        data = self._load_dict(warn_on_error=False) or {}
        data["graduation_notified"] = True
        self._save_dict(data)

    def resolve_active_mode(
        self,
        configured_mode: str = "auto",
        duration_hours: int = 48,
        now: datetime | None = None,
        dedup_state_path: Path | None = None,
        persist: bool = True,
    ) -> ModeResolution:
        """Resolve whether the current cycle should run in `onboarding` or `steady` mode."""
        mode = (configured_mode or "auto").strip().lower()
        if mode == "onboarding":
            return ModeResolution(
                active_mode="onboarding",
                should_notify_graduation=False,
                remaining_hours=float(max(0, duration_hours)),
            )
        if mode in {"steady", "standard", "quiet", "production"}:
            return ModeResolution(
                active_mode="steady",
                should_notify_graduation=False,
                remaining_hours=0.0,
            )

        current_now = (now or datetime.now(tz=UTC)).astimezone(UTC)
        if duration_hours <= 0:
            return ModeResolution(
                active_mode="steady",
                should_notify_graduation=False,
                remaining_hours=0.0,
            )

        started_at = self.load_onboarding_started_at()
        if started_at is None:
            has_existing_cursor = self.load_last_window_end() is not None
            has_existing_dedup = bool(
                dedup_state_path
                and dedup_state_path.exists()
                and dedup_state_path.stat().st_size > 2
            )
            if has_existing_cursor or has_existing_dedup:
                migrated_start = current_now - timedelta(hours=duration_hours + 1)
                if persist:
                    self.save_onboarding_started_at(migrated_start, graduation_notified=True)
                logger.info(
                    "Existing deployment state detected; migrating directly to 'steady' monitoring mode."
                )
                return ModeResolution(
                    active_mode="steady",
                    should_notify_graduation=False,
                    remaining_hours=0.0,
                )

            started_at = current_now
            if persist:
                self.save_onboarding_started_at(started_at, graduation_notified=False)

        elapsed_hours = (current_now - started_at).total_seconds() / 3600.0
        if elapsed_hours < duration_hours:
            remaining = max(0.0, duration_hours - elapsed_hours)
            return ModeResolution(
                active_mode="onboarding",
                should_notify_graduation=False,
                remaining_hours=remaining,
            )

        should_notify = not self.is_graduation_notified()
        return ModeResolution(
            active_mode="steady",
            should_notify_graduation=should_notify,
            remaining_hours=0.0,
        )
