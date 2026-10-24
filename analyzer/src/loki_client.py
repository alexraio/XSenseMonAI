"""Client for querying pfSense logs from Grafana Loki and pushing AI reports back."""

from __future__ import annotations

import json
import logging
import time
from datetime import UTC, datetime
from typing import Any

import httpx

from .models import AISecurityReport, NormalizedLogEvent

logger = logging.getLogger(__name__)


class LokiClient:
    """HTTP client for interacting with Grafana Loki's query_range and push APIs."""

    def __init__(self, base_url: str, timeout_seconds: float = 20.0) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout_seconds

    def is_ready(self) -> bool:
        """Check whether the Loki instance is ready to accept requests."""
        try:
            with httpx.Client(timeout=5.0) as client:
                response = client.get(f"{self.base_url}/ready")
                return response.status_code == 200
        except httpx.HTTPError as exc:
            logger.warning("Loki readiness check failed: %s", exc)
            return False

    def fetch_pfsense_events(
        self,
        start_time: datetime,
        end_time: datetime,
        limit: int = 5000,
    ) -> list[NormalizedLogEvent]:
        """Fetch all normalized pfSense log entries across the 3 security tiers."""
        query = '{app="pfsense", security_tier=~"tier_1_outbound_suspicious|tier_2_access_and_auth|tier_3_wan_blocked"}'
        params: dict[str, Any] = {
            "query": query,
            "start": str(int(start_time.timestamp() * 1e9)),
            "end": str(int(end_time.timestamp() * 1e9)),
            "limit": limit,
            "direction": "backward",
        }

        url = f"{self.base_url}/loki/api/v1/query_range"
        events: list[NormalizedLogEvent] = []

        with httpx.Client(timeout=self.timeout) as client:
            response = client.get(url, params=params)
            response.raise_for_status()
            payload = response.json()

        streams = payload.get("data", {}).get("result", [])
        for stream in streams:
            stream_labels = stream.get("stream", {})
            default_tier = stream_labels.get("security_tier", "unknown")
            default_sub_type = stream_labels.get("sub_type", "unknown")
            default_action = stream_labels.get("action", "unknown")
            default_direction = stream_labels.get("direction", "unknown")

            for ts_ns_str, raw_line in stream.get("values", []):
                try:
                    ts_dt = datetime.fromtimestamp(int(ts_ns_str) / 1e9, tz=UTC)
                except (ValueError, TypeError):
                    ts_dt = datetime.now(tz=UTC)

                try:
                    parsed = json.loads(raw_line)
                    if not isinstance(parsed, dict):
                        parsed = {"raw_log": str(raw_line)}
                except json.JSONDecodeError:
                    parsed = {"raw_log": raw_line}

                events.append(
                    NormalizedLogEvent(
                        timestamp=ts_dt,
                        security_tier=str(parsed.get("security_tier") or default_tier),
                        sub_type=str(parsed.get("sub_type") or default_sub_type),
                        src_ip=str(parsed.get("src_ip") or "unknown"),
                        dst_ip=str(parsed.get("dst_ip") or "unknown"),
                        src_port=str(parsed.get("src_port") or "0"),
                        dst_port=str(parsed.get("dst_port") or "0"),
                        proto=str(parsed.get("proto") or "unknown"),
                        action=str(parsed.get("action") or default_action),
                        direction=str(parsed.get("direction") or default_direction),
                        interface=str(parsed.get("interface") or "unknown"),
                        hit_count=int(parsed.get("hit_count") or 1),
                        tcp_flags=str(parsed.get("tcp_flags") or ""),
                        raw_log=str(parsed.get("raw_log") or ""),
                    )
                )

        logger.info(
            "Fetched %d normalized pfSense events from Loki between %s and %s",
            len(events),
            start_time.isoformat(),
            end_time.isoformat(),
        )
        return events

    def push_ai_report(self, report: AISecurityReport) -> bool:
        """Push the structured AI security report back into Loki for Grafana visualization."""
        url = f"{self.base_url}/loki/api/v1/push"
        now_ns = str(int(time.time() * 1e9))
        log_payload = json.dumps(
            {
                "event_type": "ai_security_report",
                "severity": report.severity,
                "title": report.title,
                "executive_summary": report.executive_summary,
                "key_findings": report.key_findings,
                "recommended_actions": report.recommended_actions,
                "suspicious_ips": report.suspicious_ips,
                "model_used": report.model_used,
                "input_tokens": report.input_tokens,
                "output_tokens": report.output_tokens,
            },
            ensure_ascii=False,
        )

        body = {
            "streams": [
                {
                    "stream": {
                        "app": "pfsense",
                        "security_tier": "ai_report",
                        "severity": report.severity,
                    },
                    "values": [[now_ns, log_payload]],
                }
            ]
        }

        try:
            with httpx.Client(timeout=10.0) as client:
                response = client.post(url, json=body)
                response.raise_for_status()
            logger.info("Successfully stored AI security report in Loki (severity=%s)", report.severity)
            return True
        except httpx.HTTPError as exc:
            logger.error("Failed to push AI report to Loki: %s", exc)
            return False
