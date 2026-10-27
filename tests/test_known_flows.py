"""Unit and integration tests for KnownFlowsStore, granular flow suppression, and LLM context."""

from __future__ import annotations

import json
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

from src.ai_analyst import AnthropicSOCAnalyst
from src.config import AppConfig
from src.filter_engine import ZeroTokenFilterEngine
from src.known_flows import (
    KnownFlowRule,
    KnownFlowsStore,
    build_flow_suggestions,
    parse_compact_flow_rule,
)
from src.models import NormalizedLogEvent
from src.notifier import TelegramNotifier


def test_known_flow_rule_aliases_cidr_and_port_ranges() -> None:
    """Ensure KnownFlowRule supports human-friendly aliases, CIDR subnets, and port ranges."""
    rule = KnownFlowRule.model_validate(
        {
            "src": "172.16.0.0/24",
            "dst": "192.168.1.50",
            "ports": "443, 8000-8090",
            "proto": "TCP",
            "reason": "IoT VLAN to Media Server",
        }
    )
    assert rule.id.startswith("flow-")
    assert rule.src_ip == "172.16.0.0/24"
    assert rule.dst_ip == "192.168.1.50"
    assert rule.ports == ["443", "8000-8090"]
    assert rule.proto == "tcp"
    assert rule.description == "IoT VLAN to Media Server"

    now = datetime.now(tz=UTC)
    ev_match_443 = NormalizedLogEvent(
        timestamp=now,
        security_tier="tier_1_outbound_suspicious",
        sub_type="internal_lateral_blocked",
        src_ip="172.16.0.10",
        dst_ip="192.168.1.50",
        dst_port="443",
        proto="tcp",
        action="block",
        tcp_flags="S",
    )
    ev_match_range = ev_match_443.model_copy(update={"dst_port": "8080"})
    ev_unlisted_port = ev_match_443.model_copy(update={"dst_port": "22"})
    ev_other_dst = ev_match_443.model_copy(update={"dst_ip": "192.168.1.1"})

    assert rule.matches_event(ev_match_443) is True
    assert rule.matches_event(ev_match_range) is True
    assert rule.matches_event(ev_unlisted_port) is False
    assert rule.matches_event(ev_other_dst) is False


def test_known_flows_store_crud_and_hot_reload(tmp_path: Path) -> None:
    """Verify CRUD operations, port merging, enable/disable toggle, and disk hot-reload."""
    flows_file = tmp_path / "known_flows.json"
    store = KnownFlowsStore(file_path=flows_file)
    assert store.list_rules() == []

    # Add first rule via compact expression
    r1 = parse_compact_flow_rule(
        "172.16.0.10>192.168.1.50:443/tcp",
        description="Smart Display to Speaker",
    )
    saved1 = store.add_rule(r1)
    assert flows_file.exists()
    assert saved1.ports == ["443"]

    # Add second rule with same src/dst/proto -> should merge ports cleanly
    r2 = parse_compact_flow_rule(
        "172.16.0.10>192.168.1.50:8080/tcp",
        description="Smart Display to Speaker",
    )
    saved2 = store.add_rule(r2)
    assert len(store.list_rules()) == 1
    assert saved2.ports == ["443", "8080"]

    # Toggle enabled False (for future Web UI switch support)
    toggled = store.set_rule_enabled(saved2.id, enabled=False)
    assert toggled is not None
    assert toggled.enabled is False
    assert store.list_rules(include_disabled=False) == []

    # Re-enable and test external hot-reload when user edits JSON file directly
    external_payload = [
        {
            "src_ip": "172.16.0.10",
            "dst_ip": "192.168.1.50",
            "ports": ["443", "8080", "8443"],
            "description": "Edited by hand on host",
        }
    ]
    flows_file.write_text(json.dumps(external_payload, indent=2), encoding="utf-8")
    assert store.reload_if_changed() is True
    rules = store.list_rules()
    assert len(rules) == 1
    assert rules[0].ports == ["443", "8080", "8443"]
    assert rules[0].description == "Edited by hand on host"

    # Remove rule by ID
    assert store.remove_rule(rules[0].id) is True
    assert store.list_rules() == []


def test_filter_engine_suppresses_known_flow_but_alerts_on_other_ports_with_context(
    tmp_path: Path,
) -> None:
    """Verify known flows silence specific benign traffic (0 tokens) while keeping other ports monitored."""
    flows_file = tmp_path / "known_flows.json"
    flows_file.write_text(
        json.dumps(
            [
                {
                    "src_ip": "172.16.0.10",
                    "dst_ip": "192.168.1.50",
                    "ports": ["443", "8080"],
                    "description": "Smart Display to Music Player",
                }
            ]
        ),
        encoding="utf-8",
    )

    cfg = AppConfig(
        anthropic_api_key="sk-ant-test",
        known_flows_path=flows_file,
        state_file_path=tmp_path / "dedup.json",
    )
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    # Window 1: Only the known benign traffic on ports 443 and 8080 -> 0 tokens spent!
    benign_events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="172.16.0.10",
            dst_ip="192.168.1.50",
            dst_port="443",
            proto="tcp",
            action="block",
            hit_count=5,
            tcp_flags="S",
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="172.16.0.10",
            dst_ip="192.168.1.50",
            dst_port="8080",
            proto="tcp",
            action="block",
            hit_count=4,
            tcp_flags="S",
        ),
    ]
    res1 = engine.evaluate(benign_events, now, now)
    assert res1.should_invoke_ai is False
    assert res1.suppressed_by_known_flows_count == 2
    assert res1.tier1_anomalies == []

    # Window 2: Same device suddenly attempts SSH (port 22) -> MUST trigger AI with context!
    suspicious_events = [
        *benign_events,
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="172.16.0.10",
            dst_ip="192.168.1.50",
            dst_port="22",
            proto="tcp",
            action="block",
            hit_count=3,
            tcp_flags="S",
        ),
    ]
    res2 = engine.evaluate(suspicious_events, now, now)
    assert res2.should_invoke_ai is True
    assert res2.suppressed_by_known_flows_count == 2
    assert len(res2.tier1_anomalies) == 1
    assert res2.tier1_anomalies[0].dst_port == "22"
    assert len(res2.known_flows_context) == 1
    assert res2.known_flows_context[0]["description"] == "Smart Display to Music Player"


def test_whitelist_internal_ips_does_not_hide_blocked_lateral_or_outbound_drops(
    tmp_path: Path,
) -> None:
    """Ensure coarse WHITELIST_INTERNAL_IPS only ignores allowed uncommon-port traffic, never blocks."""
    cfg = AppConfig(
        anthropic_api_key="sk-ant-test",
        whitelist_internal_ips={"172.16.0.10"},
        state_file_path=tmp_path / "dedup.json",
    )
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    blocked_lateral = NormalizedLogEvent(
        timestamp=now,
        security_tier="tier_1_outbound_suspicious",
        sub_type="internal_lateral_blocked",
        src_ip="172.16.0.10",
        dst_ip="192.168.1.1",
        dst_port="443",
        proto="tcp",
        action="block",
        hit_count=3,
        tcp_flags="S",
    )
    res = engine.evaluate([blocked_lateral], now, now)
    assert res.should_invoke_ai is True
    assert len(res.tier1_anomalies) == 1


def test_telegram_and_llm_include_known_flow_suggestions_and_context(
    tmp_path: Path,
) -> None:
    """Verify Telegram alert includes consolidated JSON snippet and LLM payload includes known_authorized_flows."""
    flows_file = tmp_path / "known_flows.json"
    flows_file.write_text(
        json.dumps(
            [
                {
                    "src_ip": "172.16.0.10",
                    "dst_ip": "192.168.1.50",
                    "ports": ["443"],
                    "description": "Smart Display HTTPS",
                }
            ]
        ),
        encoding="utf-8",
    )
    cfg = AppConfig(
        llm_provider="ollama",
        llm_base_url="http://localhost:11434/v1",
        llm_model="qwen2.5:14b",
        telegram_bot_token="123456:ABC-DEF",
        telegram_chat_id="123456789",
        known_flows_path=flows_file,
        state_file_path=tmp_path / "dedup.json",
    )
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="172.16.0.10",
            dst_ip="192.168.1.50",
            dst_port="8080",
            proto="tcp",
            action="block",
            hit_count=6,
            tcp_flags="S",
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="172.16.0.10",
            dst_ip="192.168.1.50",
            dst_port="8443",
            proto="tcp",
            action="block",
            hit_count=3,
            tcp_flags="S",
        ),
    ]
    evaluation = engine.evaluate(events, now, now)
    suggestions = build_flow_suggestions(evaluation.tier1_anomalies)
    assert len(suggestions) == 1
    assert suggestions[0].ports == ["8080", "8443"]

    # Check LLM prompt payload contains known_authorized_flows
    analyst = AnthropicSOCAnalyst(cfg)
    captured_body: dict[str, Any] = {}

    def fake_post(url: str, headers: dict[str, str], json: dict[str, Any]) -> Any:
        captured_body.update(json)
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.json.return_value = {
            "choices": [
                {
                    "message": {
                        "content": '{"severity":"WARNING","title":"Lateral Block","executive_summary":"Test","key_findings":[],"recommended_actions":[],"suspicious_ips":["172.16.0.10"]}'
                    }
                }
            ],
            "usage": {"prompt_tokens": 100, "completion_tokens": 50},
        }
        return mock_resp

    with patch("src.ai_analyst.httpx.Client.post", side_effect=fake_post):
        report = analyst.analyze(evaluation)

    user_msg_content = captured_body["messages"][1]["content"]
    assert "known_authorized_flows" in user_msg_content
    assert "Smart Display HTTPS" in user_msg_content

    # Check Telegram notification includes copy-pasteable JSON snippet
    notifier = TelegramNotifier(cfg)
    sent_messages: list[str] = []

    def fake_tg_post(url: str, json: dict[str, Any]) -> Any:
        sent_messages.append(json["text"])
        mock_resp = MagicMock()
        mock_resp.status_code = 200
        return mock_resp

    with patch("src.notifier.httpx.Client.post", side_effect=fake_tg_post):
        assert notifier.send_ai_report(report, evaluation) is True

    assert len(sent_messages) == 1
    assert "Known Flow Suppression" in sent_messages[0]
    assert "&quot;ports&quot;: [&quot;8080&quot;, &quot;8443&quot;]" in sent_messages[0]


def test_tier1_src_ports_enrichment_and_p2p_dht_flow_suggestion(tmp_path: Path) -> None:
    """Verify Tier 1 anomalies include `src_ports` (e.g. 6881/UDP BitTorrent DHT) and generate `src_ports` rule suggestions."""
    cfg = AppConfig(
        anthropic_api_key="sk-ant-test",
        state_file_path=tmp_path / "dedup.json",
    )
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    dht_events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_blocked",
            src_ip="10.0.0.25",
            src_port="6881",
            dst_ip="198.51.100.10",
            dst_port="27879",
            proto="udp",
            action="block",
            hit_count=1,
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_blocked",
            src_ip="10.0.0.25",
            src_port="6881",
            dst_ip="203.0.113.20",
            dst_port="64650",
            proto="udp",
            action="block",
            hit_count=1,
        ),
    ]
    res = engine.evaluate(dht_events, now, now)
    assert res.should_invoke_ai is True
    assert len(res.tier1_anomalies) == 2
    assert res.tier1_anomalies[0].src_ports == ["6881"]
    assert res.tier1_anomalies[1].src_ports == ["6881"]

    # Smart suggestion should consolidate by fixed src_port 6881 across multiple random external IPs
    suggestions = build_flow_suggestions(res.tier1_anomalies)
    assert len(suggestions) == 1
    assert suggestions[0].src_ip == "10.0.0.25"
    assert suggestions[0].src_ports == ["6881"]
    assert suggestions[0].dst_ip == "*"
    assert suggestions[0].ports == [] or suggestions[0].ports == ["*"]
    assert suggestions[0].proto == "udp"

    # Verify adding that suggested rule suppresses 6881/udp while keeping other UDP source ports monitored
    rule = KnownFlowRule.model_validate(json.loads(suggestions[0].to_json_snippet()))
    assert rule.matches_event(dht_events[0]) is True
    assert rule.matches_event(dht_events[1]) is True

    other_udp = dht_events[0].model_copy(update={"src_port": "55555"})
    assert rule.matches_event(other_udp) is False

