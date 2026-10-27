"""Data models for normalized pfSense log events, aggregated summaries, and AI reports."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field

SecurityTier = Literal[
    "tier_1_outbound_suspicious",
    "tier_2_access_and_auth",
    "tier_3_wan_blocked",
]

SeverityLevel = Literal["INFO", "WARNING", "CRITICAL"]


class NormalizedLogEvent(BaseModel):
    """Represents a single structured log entry retrieved from Grafana Loki."""

    timestamp: datetime
    security_tier: str
    sub_type: str = "unknown"
    src_ip: str = "unknown"
    dst_ip: str = "unknown"
    src_port: str = "0"
    dst_port: str = "0"
    proto: str = "unknown"
    action: str = "unknown"
    direction: str = "unknown"
    interface: str = "unknown"
    hit_count: int = 1
    tcp_flags: str = ""
    raw_log: str = ""


class GeoIPInfo(BaseModel):
    """Geographical and ASN attribution metadata for an IP address."""

    country: str = "Unknown"
    country_code: str = ""
    city: str = ""
    isp: str = ""
    asn: str = ""

    def short_label(self) -> str:
        """Return a compact human-readable label (e.g., 'DE · Hetzner · AS24940')."""
        if self.country_code == "LAN":
            return "LAN"
        parts: list[str] = []
        if self.country_code:
            parts.append(self.country_code)
        elif self.country and self.country != "Unknown":
            parts.append(self.country)
        if self.isp:
            parts.append(self.isp)
        if self.asn:
            asn_token = self.asn.split()[0] if self.asn else ""
            if asn_token and asn_token not in self.isp:
                parts.append(asn_token)
        return " · ".join(parts)


class OutboundAnomalySummary(BaseModel):
    """Aggregated Tier 1 suspicious outbound or lateral traffic per internal source IP."""

    src_ip: str
    dst_ip: str
    dst_port: str
    proto: str
    action: str
    sub_type: str
    total_hits: int
    sample_tcp_flags: str = ""
    dst_geoip: GeoIPInfo | None = None


class AuthOrAccessSummary(BaseModel):
    """Aggregated Tier 2 authentication daemon events or allowed inbound WAN traffic."""

    src_ip: str
    sub_type: str
    action: str
    dst_port: str
    proto: str
    total_hits: int
    sample_raw_logs: list[str] = Field(default_factory=list)
    src_geoip: GeoIPInfo | None = None


class WanOffenderSummary(BaseModel):
    """Aggregated Tier 3 inbound WAN blocked traffic per external attacker IP."""

    src_ip: str
    total_blocked_hits: int
    distinct_ports_count: int
    targeted_ports: list[str] = Field(default_factory=list)
    protocols: list[str] = Field(default_factory=list)
    is_port_scanner: bool = False
    is_high_volume: bool = False
    src_geoip: GeoIPInfo | None = None


class FilterEvaluationResult(BaseModel):
    """Output of the Zero-Token Pre-Filter evaluation for a time window."""

    window_start: datetime
    window_end: datetime
    should_invoke_ai: bool = False
    trigger_reasons: list[str] = Field(default_factory=list)
    tier1_anomalies: list[OutboundAnomalySummary] = Field(default_factory=list)
    tier2_events: list[AuthOrAccessSummary] = Field(default_factory=list)
    tier3_offenders: list[WanOffenderSummary] = Field(default_factory=list)
    total_raw_wan_blocks: int = 0
    suppressed_by_dedup_count: int = 0
    suppressed_by_known_flows_count: int = 0
    known_flows_context: list[dict[str, Any]] = Field(default_factory=list)
    ip_geoip_map: dict[str, GeoIPInfo] = Field(default_factory=dict)


class AISecurityReport(BaseModel):
    """Structured security assessment returned by Claude (Anthropic API)."""

    severity: SeverityLevel = "INFO"
    title: str
    executive_summary: str
    key_findings: list[str] = Field(default_factory=list)
    recommended_actions: list[str] = Field(default_factory=list)
    suspicious_ips: list[str] = Field(default_factory=list)
    model_used: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
