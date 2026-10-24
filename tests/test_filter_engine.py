"""Unit tests for PfsenseMon Zero-Token Filter Engine, Deduplication Cache, and AI JSON parser."""

from __future__ import annotations

from datetime import UTC, datetime, timedelta
from pathlib import Path

from src.ai_analyst import AnthropicSOCAnalyst
from src.config import AppConfig, normalize_anthropic_base_url
from src.filter_engine import DeduplicationCache, ZeroTokenFilterEngine
from src.models import NormalizedLogEvent


def _make_config(tmp_path: Path) -> AppConfig:
    return AppConfig(
        anthropic_api_key="sk-ant-test",
        wan_block_hit_threshold=50,
        wan_port_scan_threshold=5,
        outbound_suspicious_threshold=1,
        auth_event_threshold=1,
        alert_dedup_ttl_minutes=60,
        whitelist_internal_ips={"192.168.1.10"},
        whitelist_external_ips={"8.8.8.8"},
        whitelist_outbound_ports={"80", "443", "53"},
        state_file_path=tmp_path / "dedup.json",
    )


def test_zero_token_filter_stays_silent_on_low_volume_wan_noise(tmp_path: Path) -> None:
    """Ensure harmless background WAN blocks below threshold do NOT trigger Anthropic API calls."""
    cfg = _make_config(tmp_path)
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_3_wan_blocked",
            sub_type="wan_inbound_block",
            src_ip="93.184.216.34",
            dst_ip="203.0.113.2",
            dst_port="22",
            proto="tcp",
            action="block",
            direction="in",
            hit_count=12,
        )
    ]

    result = engine.evaluate(events, now - timedelta(minutes=15), now)
    assert result.should_invoke_ai is False
    assert result.trigger_reasons == []
    assert result.total_raw_wan_blocks == 12


def test_tier1_suspicious_outbound_triggers_ai_and_respects_whitelist(tmp_path: Path) -> None:
    """Verify Tier 1 outbound anomalies trigger AI while whitelisted internal IPs are ignored."""
    cfg = _make_config(tmp_path)
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    events = [
        # Whitelisted internal IP -> should be ignored
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_uncommon_port",
            src_ip="192.168.1.10",
            dst_ip="198.51.100.1",
            dst_port="4444",
            proto="tcp",
            action="pass",
            hit_count=5,
        ),
        # Non-whitelisted compromised host -> should trigger AI
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_blocked",
            src_ip="192.168.1.145",
            dst_ip="198.51.100.77",
            dst_port="4444",
            proto="tcp",
            action="block",
            hit_count=4,
            tcp_flags="S",
        ),
    ]

    result = engine.evaluate(events, now - timedelta(minutes=15), now)
    assert result.should_invoke_ai is True
    assert len(result.tier1_anomalies) == 1
    assert result.tier1_anomalies[0].src_ip == "192.168.1.145"
    assert result.tier1_anomalies[0].total_hits == 4


def test_tier3_port_scan_detection_and_deduplication(tmp_path: Path) -> None:
    """Verify an external IP scanning >= 5 distinct ports triggers AI once and is suppressed on repeat."""
    cfg = _make_config(tmp_path)
    dedup = DeduplicationCache(ttl_minutes=60, state_path=cfg.state_file_path)
    engine = ZeroTokenFilterEngine(cfg, dedup_cache=dedup)
    now = datetime.now(tz=UTC)

    scan_events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_3_wan_blocked",
            sub_type="wan_inbound_block",
            src_ip="185.220.101.42",
            dst_ip="203.0.113.2",
            dst_port=str(port),
            proto="tcp",
            action="block",
            direction="in",
            hit_count=3,
        )
        for port in (21, 22, 23, 3389, 8080, 8443)
    ]

    # First evaluation: should trigger AI
    first_eval = engine.evaluate(scan_events, now - timedelta(minutes=15), now)
    assert first_eval.should_invoke_ai is True
    assert len(first_eval.tier3_offenders) == 1
    assert first_eval.tier3_offenders[0].is_port_scanner is True
    assert first_eval.tier3_offenders[0].distinct_ports_count == 6

    # Second evaluation within TTL cooldown: should be suppressed by deduplication cache
    second_eval = engine.evaluate(scan_events, now - timedelta(minutes=15), now)
    assert second_eval.should_invoke_ai is False
    assert second_eval.suppressed_by_dedup_count == 1


def test_parse_claude_json_response_with_code_fences() -> None:
    """Ensure AnthropicSOCAnalyst._parse_json_response extracts JSON even inside markdown fences."""
    raw = """```json
    {
      "severity": "CRITICAL",
      "title": "Suspicious Outbound C2 Activity",
      "executive_summary": "Internal host 192.168.1.145 attempted multiple connections to port 4444.",
      "key_findings": ["4 blocked SYN packets to 198.51.100.77:4444"],
      "recommended_actions": ["Isolate host 192.168.1.145"],
      "suspicious_ips": ["192.168.1.145", "198.51.100.77"]
    }
    ```"""
    report = AnthropicSOCAnalyst._parse_json_response(raw)
    assert report.severity == "CRITICAL"
    assert report.title == "Suspicious Outbound C2 Activity"
    assert "192.168.1.145" in report.suspicious_ips


def test_minimax_anthropic_base_url_normalization() -> None:
    """Verify ANTHROPIC_BASE_URL normalization handles MiniMax URLs with or without /v1/messages."""
    assert (
        normalize_anthropic_base_url("https://api.minimax.io/anthropic")
        == "https://api.minimax.io/anthropic"
    )
    assert (
        normalize_anthropic_base_url("https://api.minimax.io/anthropic/")
        == "https://api.minimax.io/anthropic"
    )
    assert (
        normalize_anthropic_base_url("https://api.minimax.io/anthropic/v1")
        == "https://api.minimax.io/anthropic"
    )
    assert (
        normalize_anthropic_base_url("https://api.minimax.io/anthropic/v1/messages")
        == "https://api.minimax.io/anthropic"
    )
    assert normalize_anthropic_base_url("") == "https://api.anthropic.com"


if __name__ == "__main__":
    import tempfile

    with tempfile.TemporaryDirectory() as tmpdir:
        base = Path(tmpdir)
        test_zero_token_filter_stays_silent_on_low_volume_wan_noise(base / "t1")
        test_tier1_suspicious_outbound_triggers_ai_and_respects_whitelist(base / "t2")
        test_tier3_port_scan_detection_and_deduplication(base / "t3")
        test_parse_claude_json_response_with_code_fences()
        test_minimax_anthropic_base_url_normalization()
    print("All 5 unit tests passed successfully!")

