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


def test_identity_aware_known_flow_persists_across_dhcp_ip_rotation_and_prevents_inheritance(
    tmp_path: Path,
) -> None:
    """Verify a Known Flow by `src_host` survives DHCP IP rotation and is never inherited when another MAC takes the old IP."""
    flows_file = tmp_path / "known_flows.json"
    store = KnownFlowsStore(file_path=flows_file)
    rule = parse_compact_flow_rule(
        "apple-tv-salotto>192.168.1.50:8008,8009/tcp",
        description="Apple TV Cast to Media Server",
    )
    assert rule.src_host == "apple-tv-salotto"
    assert rule.src_ip == "*"
    store.add_rule(rule)

    cfg = AppConfig(
        anthropic_api_key="sk-ant-test",
        known_flows_path=flows_file,
        state_file_path=tmp_path / "dedup.json",
        enable_ptr_fallback=False,
    )
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    # Step 1: DHCP assigns 192.168.1.117 to apple-tv-salotto (00:00:5e:00:53:10)
    window1_events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_0_dhcp_identity",
            sub_type="dhcp_lease",
            src_ip="192.168.1.117",
            src_mac="00:00:5e:00:53:10",
            src_host="apple-tv-salotto.lan",
            action="lease_ack",
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="192.168.1.117",
            dst_ip="192.168.1.50",
            dst_port="8008",
            proto="tcp",
            action="block",
            tcp_flags="S",
        ),
    ]
    res1 = engine.evaluate(window1_events, now, now)
    assert res1.should_invoke_ai is False
    assert res1.suppressed_by_known_flows_count == 1

    # Step 2: DHCP rotates apple-tv-salotto to a NEW IP (192.168.1.140)
    window2_events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_0_dhcp_identity",
            sub_type="dhcp_lease",
            src_ip="192.168.1.140",
            src_mac="00:00:5e:00:53:10",
            src_host="apple-tv-salotto",
            action="lease_ack",
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="192.168.1.140",
            dst_ip="192.168.1.50",
            dst_port="8009",
            proto="tcp",
            action="block",
            tcp_flags="S",
        ),
    ]
    res2 = engine.evaluate(window2_events, now, now)
    assert res2.should_invoke_ai is False
    assert res2.suppressed_by_known_flows_count == 1

    # Step 3: A different device (guest-phone, 00:00:5e:00:53:99) gets the old IP 192.168.1.117
    # It MUST NOT inherit apple-tv-salotto's whitelist!
    window3_events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_0_dhcp_identity",
            sub_type="dhcp_lease",
            src_ip="192.168.1.117",
            src_mac="00:00:5e:00:53:99",
            src_host="guest-phone",
            action="lease_ack",
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="192.168.1.117",
            dst_ip="192.168.1.50",
            dst_port="8008",
            proto="tcp",
            action="block",
            tcp_flags="S",
        ),
    ]
    res3 = engine.evaluate(window3_events, now, now)
    assert res3.should_invoke_ai is True
    assert res3.suppressed_by_known_flows_count == 0
    assert len(res3.tier1_anomalies) == 1
    assert res3.tier1_anomalies[0].src_host == "guest-phone"
    assert res3.tier1_anomalies[0].src_mac == "00:00:5e:00:53:99"


def test_hostname_first_and_mac_fallback_in_telegram_flow_suggestions(
    tmp_path: Path,
) -> None:
    """Verify Telegram suggestions prioritize `src_host` first, then `src_mac` (when hostname is empty), then `src_ip`."""
    cfg = AppConfig(
        anthropic_api_key="sk-ant-test",
        state_file_path=tmp_path / "dedup.json",
        enable_ptr_fallback=False,
    )
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    events = [
        # Host 1: Has both hostname and MAC -> Suggestion MUST use `src_host`
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_0_dhcp_identity",
            sub_type="dhcp_lease",
            src_ip="192.168.1.10",
            src_mac="00:00:5e:00:53:10",
            src_host="macbook-pro.home.arpa",
            action="lease_ack",
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="192.168.1.10",
            dst_ip="192.168.1.50",
            dst_port="9000",
            proto="tcp",
            action="block",
            hit_count=5,
            tcp_flags="S",
        ),
        # Host 2: IoT device with Kea DHCP lease (MAC only, no hostname) -> Suggestion MUST use `src_mac`
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_0_dhcp_identity",
            sub_type="dhcp_lease",
            src_ip="172.16.0.55",
            action="lease_ack",
            raw_log="kea-dhcp4[123]: INFO DHCP4_LEASE_ALLOC [hwtype=1 00:00:5e:00:53:20]: lease 172.16.0.55 has been allocated",
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_uncommon_port",
            src_ip="172.16.0.55",
            dst_ip="198.51.100.40",
            dst_port="8883",
            proto="tcp",
            action="pass",
            hit_count=3,
            tcp_flags="S",
        ),
    ]
    evaluation = engine.evaluate(events, now, now)
    suggestions = build_flow_suggestions(evaluation.tier1_anomalies)
    assert len(suggestions) == 2

    # Suggestion 1 (highest hits = 5): Hostname-first
    s1_json = json.loads(suggestions[0].to_json_snippet())
    assert s1_json["src_host"] == "macbook-pro"
    assert "src_ip" not in s1_json
    assert "src_mac" not in s1_json

    # Suggestion 2 (hits = 3): MAC fallback when hostname is missing
    s2_json = json.loads(suggestions[1].to_json_snippet())
    assert s2_json["src_mac"] == "00:00:5e:00:53:20"
    assert "src_ip" not in s2_json
    assert "src_host" not in s2_json

    # Verify MAC-based rule matches future events from that MAC on any dynamic IP
    mac_rule = KnownFlowRule.model_validate(s2_json)
    moved_iot_event = events[3].model_copy(
        update={"src_ip": "172.16.0.99", "src_mac": "00:00:5e:00:53:20"}
    )
    assert mac_rule.matches_event(moved_iot_event) is True


def test_ptr_reverse_dns_fallback_on_cold_start(tmp_path: Path) -> None:
    """Verify Reverse DNS (`PTR`) resolves internal hostname on Cold Start when no DHCP log has arrived yet."""
    flows_file = tmp_path / "known_flows.json"
    store = KnownFlowsStore(file_path=flows_file)
    store.add_rule(
        KnownFlowRule.model_validate(
            {
                "src_host": "synology-nas",
                "dst_ip": "198.51.100.90",
                "ports": ["6281"],
                "proto": "tcp",
                "description": "Synology Cloud Sync",
            }
        )
    )

    cfg = AppConfig(
        anthropic_api_key="sk-ant-test",
        known_flows_path=flows_file,
        state_file_path=tmp_path / "dedup.json",
        enable_ptr_fallback=True,
    )
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    ev = NormalizedLogEvent(
        timestamp=now,
        security_tier="tier_1_outbound_suspicious",
        sub_type="outbound_uncommon_port",
        src_ip="192.168.1.200",
        dst_ip="198.51.100.90",
        dst_port="6281",
        proto="tcp",
        action="pass",
    )

    with patch(
        "src.device_identity.socket.gethostbyaddr",
        return_value=("synology-nas.localdomain.", [], ["192.168.1.200"]),
    ) as mock_ptr:
        res = engine.evaluate([ev], now, now)

    assert mock_ptr.call_count == 1
    assert res.should_invoke_ai is False
    assert res.suppressed_by_known_flows_count == 1


