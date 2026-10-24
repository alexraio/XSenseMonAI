"""Zero-Token Pre-Filter Engine and Anti-Spam Deduplication Cache."""

from __future__ import annotations

import json
import logging
import time
from collections import defaultdict
from datetime import datetime
from pathlib import Path

from .config import AppConfig
from .models import (
    AuthOrAccessSummary,
    FilterEvaluationResult,
    NormalizedLogEvent,
    OutboundAnomalySummary,
    WanOffenderSummary,
)

logger = logging.getLogger(__name__)


class DeduplicationCache:
    """TTL-based cache to prevent repeated Telegram/AI alerts for the same ongoing offender."""

    def __init__(self, ttl_minutes: int, state_path: Path | None = None) -> None:
        self.ttl_seconds = max(0, ttl_minutes * 60)
        self.state_path = state_path
        self._store: dict[str, float] = {}
        self._load()

    def _load(self) -> None:
        if not self.state_path or not self.state_path.exists():
            return
        try:
            raw = json.loads(self.state_path.read_text(encoding="utf-8"))
            now = time.time()
            if isinstance(raw, dict):
                self._store = {
                    str(k): float(v)
                    for k, v in raw.items()
                    if isinstance(v, (int, float)) and (now - float(v)) < self.ttl_seconds
                }
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("Could not load deduplication state file %s: %s", self.state_path, exc)

    def save(self) -> None:
        if not self.state_path:
            return
        try:
            self.state_path.parent.mkdir(parents=True, exist_ok=True)
            self.state_path.write_text(json.dumps(self._store, indent=2), encoding="utf-8")
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("Could not persist deduplication state file %s: %s", self.state_path, exc)

    def is_suppressed(self, key: str, now: float | None = None) -> bool:
        """Return True if key was already alerted within the TTL cooldown window."""
        if self.ttl_seconds <= 0:
            return False
        current = now if now is not None else time.time()
        last_seen = self._store.get(key)
        return last_seen is not None and (current - last_seen) < self.ttl_seconds

    def mark_alerted(self, keys: list[str], now: float | None = None) -> None:
        """Record keys as alerted at the current timestamp and prune expired entries."""
        if self.ttl_seconds <= 0:
            return
        current = now if now is not None else time.time()
        # Prune expired
        expired = [k for k, ts in self._store.items() if (current - ts) >= self.ttl_seconds]
        for k in expired:
            del self._store[k]
        for key in keys:
            self._store[key] = current
        self.save()


class ZeroTokenFilterEngine:
    """Evaluates normalized Loki events locally and decides whether Anthropic API is needed."""

    def __init__(self, config: AppConfig, dedup_cache: DeduplicationCache | None = None) -> None:
        self.config = config
        self.dedup = dedup_cache or DeduplicationCache(
            ttl_minutes=config.alert_dedup_ttl_minutes,
            state_path=config.state_file_path,
        )

    def evaluate(
        self,
        events: list[NormalizedLogEvent],
        window_start: datetime,
        window_end: datetime,
    ) -> FilterEvaluationResult:
        """Aggregate events into the 3 security tiers and check detection thresholds."""
        tier1_groups: dict[tuple[str, str, str, str, str, str], int] = defaultdict(int)
        tier1_flags: dict[tuple[str, str, str, str, str, str], str] = {}

        tier2_groups: dict[tuple[str, str, str, str, str], int] = defaultdict(int)
        tier2_samples: dict[tuple[str, str, str, str, str], list[str]] = defaultdict(list)

        tier3_hits_by_ip: dict[str, int] = defaultdict(int)
        tier3_ports_by_ip: dict[str, set[str]] = defaultdict(set)
        tier3_protos_by_ip: dict[str, set[str]] = defaultdict(set)
        total_raw_wan_blocks = 0

        for ev in events:
            # Defense-in-depth: ignore out-of-state TCP teardown/keepalive blocks (FA, FPA, A, R without SYN)
            if (
                ev.proto.lower() == "tcp"
                and ev.action.lower() == "block"
                and ev.tcp_flags
                and "S" not in ev.tcp_flags.upper()
            ):
                continue

            # ------------------------------------------------------------------
            # Tier 1: Suspicious Outbound / Internal Lateral Blocked
            # ------------------------------------------------------------------
            if ev.security_tier == "tier_1_outbound_suspicious":
                if ev.src_ip in self.config.whitelist_internal_ips:
                    continue
                if ev.dst_ip in self.config.whitelist_external_ips:
                    continue
                if (
                    ev.sub_type == "outbound_uncommon_port"
                    and ev.dst_port in self.config.whitelist_outbound_ports
                ):
                    continue

                t1_key = (ev.src_ip, ev.dst_ip, ev.dst_port, ev.proto, ev.action, ev.sub_type)
                tier1_groups[t1_key] += ev.hit_count
                if ev.tcp_flags and not tier1_flags.get(t1_key):
                    tier1_flags[t1_key] = ev.tcp_flags

            # ------------------------------------------------------------------
            # Tier 2: Allowed Inbound WAN & pfSense Authentication Logs
            # ------------------------------------------------------------------
            elif ev.security_tier == "tier_2_access_and_auth":
                if ev.src_ip in self.config.whitelist_external_ips:
                    continue
                t2_key = (ev.src_ip, ev.sub_type, ev.action, ev.dst_port, ev.proto)
                tier2_groups[t2_key] += ev.hit_count
                if ev.raw_log and len(tier2_samples[t2_key]) < 3:
                    tier2_samples[t2_key].append(ev.raw_log[:220])

            # ------------------------------------------------------------------
            # Tier 3: Blocked Inbound WAN Traffic (Pre-aggregated by Vector)
            # ------------------------------------------------------------------
            elif ev.security_tier == "tier_3_wan_blocked":
                if ev.src_ip in self.config.whitelist_external_ips or ev.src_ip == "unknown":
                    continue
                total_raw_wan_blocks += ev.hit_count
                tier3_hits_by_ip[ev.src_ip] += ev.hit_count
                if ev.dst_port and ev.dst_port != "0":
                    tier3_ports_by_ip[ev.src_ip].add(ev.dst_port)
                if ev.proto and ev.proto != "unknown":
                    tier3_protos_by_ip[ev.src_ip].add(ev.proto)

        # Build Tier 1 summaries (filtered by deduplication cache)
        suppressed_count = 0
        new_dedup_keys: list[str] = []

        tier1_list: list[OutboundAnomalySummary] = []
        for (src_ip, dst_ip, dst_port, proto, action, sub_type), hits in sorted(
            tier1_groups.items(), key=lambda x: x[1], reverse=True
        ):
            dedup_key = f"tier1:{src_ip}:{dst_ip}:{dst_port}:{sub_type}"
            if self.dedup.is_suppressed(dedup_key):
                suppressed_count += 1
                continue
            new_dedup_keys.append(dedup_key)
            tier1_list.append(
                OutboundAnomalySummary(
                    src_ip=src_ip,
                    dst_ip=dst_ip,
                    dst_port=dst_port,
                    proto=proto,
                    action=action,
                    sub_type=sub_type,
                    total_hits=hits,
                    sample_tcp_flags=tier1_flags.get(
                        (src_ip, dst_ip, dst_port, proto, action, sub_type), ""
                    ),
                )
            )

        # Build Tier 2 summaries
        tier2_list: list[AuthOrAccessSummary] = []
        for (src_ip, sub_type, action, dst_port, proto), hits in sorted(
            tier2_groups.items(), key=lambda x: x[1], reverse=True
        ):
            dedup_key = f"tier2:{src_ip}:{sub_type}:{dst_port}"
            if self.dedup.is_suppressed(dedup_key):
                suppressed_count += 1
                continue
            new_dedup_keys.append(dedup_key)
            tier2_list.append(
                AuthOrAccessSummary(
                    src_ip=src_ip,
                    sub_type=sub_type,
                    action=action,
                    dst_port=dst_port,
                    proto=proto,
                    total_hits=hits,
                    sample_raw_logs=tier2_samples[(src_ip, sub_type, action, dst_port, proto)],
                )
            )

        # Build Tier 3 summaries (only offenders exceeding hit threshold or port-scan threshold)
        tier3_list: list[WanOffenderSummary] = []
        for src_ip, total_hits in sorted(
            tier3_hits_by_ip.items(), key=lambda x: x[1], reverse=True
        ):
            ports = sorted(tier3_ports_by_ip[src_ip])
            distinct_ports = len(ports)
            is_high_vol = total_hits >= self.config.wan_block_hit_threshold
            is_scanner = distinct_ports >= self.config.wan_port_scan_threshold

            if not (is_high_vol or is_scanner):
                continue

            dedup_key = f"tier3:{src_ip}:{'scan' if is_scanner else 'flood'}"
            if self.dedup.is_suppressed(dedup_key):
                suppressed_count += 1
                continue
            new_dedup_keys.append(dedup_key)

            tier3_list.append(
                WanOffenderSummary(
                    src_ip=src_ip,
                    total_blocked_hits=total_hits,
                    distinct_ports_count=distinct_ports,
                    targeted_ports=ports[:20],
                    protocols=sorted(tier3_protos_by_ip[src_ip]),
                    is_port_scanner=is_scanner,
                    is_high_volume=is_high_vol,
                )
            )

        # Cap items per tier to protect the Anthropic context window
        cap = self.config.max_prompt_items_per_tier
        tier1_list = tier1_list[:cap]
        tier2_list = tier2_list[:cap]
        tier3_list = tier3_list[:cap]

        trigger_reasons: list[str] = []
        if len(tier1_list) >= self.config.outbound_suspicious_threshold:
            trigger_reasons.append(
                f"Detected {len(tier1_list)} suspicious outbound/internal traffic flow(s) (Tier 1)"
            )
        if len(tier2_list) >= self.config.auth_event_threshold:
            trigger_reasons.append(
                f"Detected {len(tier2_list)} authentication or allowed WAN access event group(s) (Tier 2)"
            )
        if tier3_list:
            trigger_reasons.append(
                f"Detected {len(tier3_list)} aggressive external WAN offender(s) exceeding thresholds (Tier 3)"
            )

        should_invoke = len(trigger_reasons) > 0
        if should_invoke and new_dedup_keys:
            self.dedup.mark_alerted(new_dedup_keys)

        return FilterEvaluationResult(
            window_start=window_start,
            window_end=window_end,
            should_invoke_ai=should_invoke,
            trigger_reasons=trigger_reasons,
            tier1_anomalies=tier1_list,
            tier2_events=tier2_list,
            tier3_offenders=tier3_list,
            total_raw_wan_blocks=total_raw_wan_blocks,
            suppressed_by_dedup_count=suppressed_count,
        )
