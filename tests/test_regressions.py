"""Regression test suite for PfsenseMon.

Covers production bugs and edge cases discovered during live verification:
1. MiniMax-M3 / Anthropic SDK compatibility (no `temperature` kwarg, `thinking` block filtering).
2. Telegram Bot non-numeric `TELEGRAM_CHAT_ID` auto-discovery via `getUpdates` & HTML escaping.
3. Zero-Token filter strict 0-call guarantee and raw fallback alerting on LLM failure.
4. LokiClient stream parsing & AI report persistence.
5. Hermes Agent zero-dependency CLI (`query_pfsense_loki.py`) output verification.
6. Vector VRL configuration static regression check & OKF Wiki link/frontmatter lint check.
"""

from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock, patch

import httpx
from src.ai_analyst import AnthropicSOCAnalyst
from src.config import AppConfig
from src.filter_engine import ZeroTokenFilterEngine
from src.geoip import enrich_evaluation_with_geoip
from src.loki_client import LokiClient
from src.main import run_analysis_cycle
from src.models import (
    AISecurityReport,
    FilterEvaluationResult,
    NormalizedLogEvent,
    OutboundAnomalySummary,
    WanOffenderSummary,
)
from src.notifier import TelegramNotifier

REPO_ROOT = Path(__file__).resolve().parent.parent


def _base_config(tmp_path: Path, chat_id: str = "123456789") -> AppConfig:
    return AppConfig(
        anthropic_api_key="test-minimax-key",
        anthropic_base_url="https://api.minimax.io/anthropic",
        anthropic_model="MiniMax-M3",
        telegram_bot_token="123456:ABC-DEF",
        telegram_chat_id=chat_id,
        telegram_enable_raw_fallback=True,
        loki_url="http://loki:3100",
        state_file_path=tmp_path / "dedup_cache.json",
    )


# ==============================================================================
# 1. Regression: MiniMax-M3 SDK Call Kwargs & Thinking Block Filtering
# ==============================================================================
def test_regression_minimax_sdk_no_temperature_and_ignores_thinking_blocks(
    tmp_path: Path,
) -> None:
    """Ensure `messages.create` never passes `temperature` and skips `thinking` blocks."""
    cfg = _base_config(tmp_path)
    analyst = AnthropicSOCAnalyst(cfg)

    fake_response = SimpleNamespace(
        content=[
            SimpleNamespace(
                type="thinking",
                thinking="Internal reasoning that is not valid JSON: {broken",
                text="Internal reasoning that is not valid JSON: {broken",
            ),
            SimpleNamespace(
                type="text",
                text=json.dumps(
                    {
                        "severity": "CRITICAL",
                        "title": "Outbound C2 Detected",
                        "executive_summary": "Host 192.168.1.145 contacted 198.51.100.77:4444.",
                        "key_findings": ["6 blocked TCP SYN packets"],
                        "recommended_actions": ["Isolate 192.168.1.145"],
                        "suspicious_ips": ["192.168.1.145"],
                    }
                ),
            ),
        ],
        usage=SimpleNamespace(input_tokens=512, output_tokens=256),
    )

    mock_client = MagicMock()
    mock_client.messages.create.return_value = fake_response
    analyst.client = mock_client

    now = datetime.now(tz=UTC)
    evaluation = FilterEvaluationResult(
        window_start=now,
        window_end=now,
        should_invoke_ai=True,
        trigger_reasons=["Tier 1 anomaly"],
    )

    report = analyst.analyze(evaluation)

    # Verify temperature was NOT passed to messages.create
    _, called_kwargs = mock_client.messages.create.call_args
    assert "temperature" not in called_kwargs
    assert called_kwargs["model"] == "MiniMax-M3"

    # Verify thinking block was ignored and JSON text block was parsed
    assert report.severity == "CRITICAL"
    assert report.title == "Outbound C2 Detected"
    assert report.input_tokens == 512
    assert report.output_tokens == 256


# ==============================================================================
# 2. Regression: Telegram Non-Numeric chat_id Auto-Discovery & HTML Escaping
# ==============================================================================
def test_regression_telegram_bot_username_autodiscovery_via_getupdates(
    tmp_path: Path,
) -> None:
    """When TELEGRAM_CHAT_ID is a bot username (`demo_pfsense_bot`), resolve numeric ID via getUpdates."""
    cfg = _base_config(tmp_path, chat_id="demo_pfsense_bot")
    notifier = TelegramNotifier(cfg)

    now = datetime.now(tz=UTC)
    evaluation = FilterEvaluationResult(window_start=now, window_end=now, should_invoke_ai=True)
    report = AISecurityReport(
        severity="CRITICAL",
        title="Test <Alert> & 'Quotes'",
        executive_summary="Detected scan from <185.220.101.42> & ports",
        key_findings=["Port 22 <ssh>"],
        recommended_actions=["Block IP & check logs"],
        suspicious_ips=["185.220.101.42"],
        model_used="MiniMax-M3",
    )

    calls: list[tuple[str, str, dict[str, Any] | None]] = []

    def mock_get(url: str, **_kwargs: Any) -> httpx.Response:
        calls.append(("GET", url, None))
        return httpx.Response(
            200,
            json={
                "ok": True,
                "result": [
                    {
                        "update_id": 1001,
                        "message": {"chat": {"id": 123456789, "type": "private"}, "text": "/start"},
                    }
                ],
            },
            request=httpx.Request("GET", url),
        )

    def mock_post(url: str, json: dict[str, Any] | None = None, **_kwargs: Any) -> httpx.Response:
        calls.append(("POST", url, json))
        return httpx.Response(
            200,
            json={"ok": True},
            request=httpx.Request("POST", url),
        )

    with patch.object(httpx.Client, "get", side_effect=mock_get), patch.object(
        httpx.Client, "post", side_effect=mock_post
    ):
        ok = notifier.send_ai_report(report, evaluation)

    assert ok is True
    assert len(calls) == 2
    assert calls[0][0] == "GET" and calls[0][1].endswith("/getUpdates")
    assert calls[1][0] == "POST" and calls[1][1].endswith("/sendMessage")
    sent_payload = calls[1][2]
    assert sent_payload is not None
    assert sent_payload["chat_id"] == "123456789"
    # Verify dangerous HTML characters were escaped
    assert "&lt;Alert&gt;" in sent_payload["text"]
    assert "&lt;185.220.101.42&gt;" in sent_payload["text"]


# ==============================================================================
# 3. Regression: End-to-End Cycle Zero-Token Guarantee & Raw Fallback Alerting
# ==============================================================================
def test_regression_run_cycle_zero_token_and_raw_fallback_on_ai_failure(
    tmp_path: Path,
) -> None:
    """Verify 0 AI calls on quiet traffic, and raw fallback alert when AI throws an error."""
    cfg = _base_config(tmp_path)
    loki = MagicMock(spec=LokiClient)
    filter_engine = ZeroTokenFilterEngine(cfg)
    analyst = MagicMock(spec=AnthropicSOCAnalyst)
    notifier = MagicMock(spec=TelegramNotifier)

    # Case A: Quiet traffic (only 3 blocked WAN packets) -> 0 AI calls
    now = datetime.now(tz=UTC)
    loki.fetch_pfsense_events.return_value = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_3_wan_blocked",
            src_ip="93.184.216.34",
            dst_port="80",
            proto="tcp",
            action="block",
            hit_count=3,
        )
    ]

    ok_quiet = run_analysis_cycle(cfg, loki, filter_engine, analyst, notifier)
    assert ok_quiet is True
    analyst.analyze.assert_not_called()
    notifier.send_ai_report.assert_not_called()

    # Case B: Tier 1 suspicious outbound occurs, but AI API fails -> Raw Fallback MUST fire
    loki.fetch_pfsense_events.return_value = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_blocked",
            src_ip="192.168.1.145",
            dst_ip="198.51.100.77",
            dst_port="4444",
            proto="tcp",
            action="block",
            hit_count=6,
        )
    ]
    analyst.analyze.side_effect = RuntimeError("MiniMax gateway 503 Unavailable")

    ok_fail = run_analysis_cycle(cfg, loki, filter_engine, analyst, notifier)
    assert ok_fail is False
    analyst.analyze.assert_called_once()
    notifier.send_raw_fallback_alert.assert_called_once()


# ==============================================================================
# 4. Regression: LokiClient Stream Parsing & AI Report Push
# ==============================================================================
def test_regression_loki_client_parses_streams_and_pushes_report() -> None:
    """Verify LokiClient parses both JSON and plain-text log lines from Loki streams."""
    client = LokiClient("http://loki:3100")
    now = datetime.now(tz=UTC)

    fake_loki_payload = {
        "status": "success",
        "data": {
            "resultType": "streams",
            "result": [
                {
                    "stream": {
                        "app": "pfsense",
                        "security_tier": "tier_3_wan_blocked",
                        "sub_type": "wan_inbound_block",
                        "action": "block",
                        "direction": "in",
                    },
                    "values": [
                        [
                            "1792777849000000000",
                            json.dumps(
                                {
                                    "src_ip": "185.220.101.42",
                                    "dst_port": "22",
                                    "proto": "tcp",
                                    "hit_count": 15,
                                }
                            ),
                        ],
                        ["1792777850000000000", "non-json raw syslog fallback line"],
                    ],
                }
            ],
        },
    }

    with patch.object(
        httpx.Client,
        "get",
        return_value=httpx.Response(
            200,
            json=fake_loki_payload,
            request=httpx.Request("GET", "http://loki:3100/loki/api/v1/query_range"),
        ),
    ):
        events = client.fetch_pfsense_events(now, now)

    assert len(events) == 2
    assert events[0].src_ip == "185.220.101.42"
    assert events[0].hit_count == 15
    assert events[1].raw_log == "non-json raw syslog fallback line"


# ==============================================================================
# 5. Regression: Vector Config Static Checks & OKF Wiki Integrity Linter
# ==============================================================================
def test_regression_vector_yaml_has_no_fallible_vrl_antipatterns() -> None:
    """Ensure config/vector/vector.yaml never reintroduces E651 or E104 VRL errors and filters non-SYN TCP blocks."""
    vector_yaml = (REPO_ROOT / "config" / "vector" / "vector.yaml").read_text(encoding="utf-8")
    assert "to_string(matched.csv) ??" not in vector_yaml
    assert "to_string(parts[" not in vector_yaml or ") ??" not in vector_yaml.split("parts[")[1]
    assert "src_v4, _ = is_ipv4(" not in vector_yaml
    assert "dst_v4, _ = is_ipv4(" not in vector_yaml
    assert 'if proto == "tcp" && action == "block" && !contains(tcp_flags, "S")' in vector_yaml

    compose_yaml = (REPO_ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    assert compose_yaml.count('max-size: "10m"') == 3
    assert compose_yaml.count('max-file: "3"') == 3


def test_regression_ignores_out_of_state_tcp_teardown_blocks(tmp_path: Path) -> None:
    """Ensure out-of-state TCP blocks (FA, FPA, A, R without SYN) do not trigger false-positive Tier 1 alerts."""
    cfg = _base_config(tmp_path)
    engine = ZeroTokenFilterEngine(cfg)
    now = datetime.now(tz=UTC)

    events = [
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="outbound_blocked",
            src_ip="192.168.50.60",
            dst_ip="162.159.140.98",
            dst_port="443",
            proto="tcp",
            action="block",
            tcp_flags="FPA",
            hit_count=11,
        ),
        NormalizedLogEvent(
            timestamp=now,
            security_tier="tier_1_outbound_suspicious",
            sub_type="internal_lateral_blocked",
            src_ip="192.168.50.111",
            dst_ip="192.168.50.1",
            dst_port="80",
            proto="tcp",
            action="block",
            tcp_flags="FA",
            hit_count=6,
        ),
    ]

    result = engine.evaluate(events, now, now)
    assert result.should_invoke_ai is False
    assert result.tier1_anomalies == []


def test_regression_okf_wiki_integrity_and_links() -> None:
    """Lint the `wiki/` directory according to Karpathy LLM Wiki + Google OKF SPEC.md."""
    wiki_dir = REPO_ROOT / "wiki"
    index_file = wiki_dir / "index.md"
    log_file = wiki_dir / "log.md"
    assert index_file.exists(), "wiki/index.md must exist"
    assert log_file.exists(), "wiki/log.md must exist"

    index_text = index_file.read_text(encoding="utf-8")
    assert 'okf_version: "1.0"' in index_text

    # Every concept/component/runbook/raw file must have `type:` frontmatter and be linked in index.md
    for subdir in ("concepts", "components", "runbooks", "raw"):
        for md_file in (wiki_dir / subdir).glob("*.md"):
            content = md_file.read_text(encoding="utf-8")
            assert content.startswith("---\n"), f"{md_file} missing YAML frontmatter"
            assert "\ntype:" in content or "type:" in content.splitlines()[1], (
                f"{md_file} missing required OKF `type` field"
            )
            rel_from_wiki = md_file.relative_to(wiki_dir).as_posix()
            assert rel_from_wiki in index_text, f"{rel_from_wiki} is orphan (not listed in wiki/index.md)"

            # Verify all relative markdown links inside the wiki file resolve to existing files
            for match in re.finditer(r"\[[^\]]+\]\(([^)#]+)\)", content):
                link_target = match.group(1).strip()
                if link_target.startswith(("http://", "https://", "mailto:")):
                    continue
                resolved = (md_file.parent / link_target).resolve()
                assert resolved.exists(), f"Broken link in {md_file}: {link_target} -> {resolved}"


def test_regression_hermes_skill_geoip_batch_enrichment() -> None:
    """Verify resolve_geoip_batch handles RFC1918 locally and batches public IPs."""
    import importlib.util
    import urllib.request

    skill_path = REPO_ROOT / "hermes_skill" / "query_pfsense_loki.py"
    spec = importlib.util.spec_from_file_location("query_pfsense_loki", skill_path)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)

    fake_batch_response = [
        {
            "status": "success",
            "query": "109.205.211.205",
            "country": "The Netherlands",
            "countryCode": "NL",
            "city": "Amsterdam",
            "isp": "MEVSPACE sp. z o.o.",
            "org": "Colocatel Inc",
            "as": "AS201814 MEVSPACE sp. z o.o.",
        }
    ]

    mock_resp = MagicMock()
    mock_resp.__enter__.return_value.read.return_value = json.dumps(
        fake_batch_response
    ).encode("utf-8")

    with patch.object(urllib.request, "urlopen", return_value=mock_resp) as mock_open:
        res = module.resolve_geoip_batch(["192.168.50.117", "109.205.211.205"])

    assert mock_open.call_count == 1
    assert res["192.168.50.117"]["country_code"] == "LAN"
    assert res["109.205.211.205"]["country"] == "The Netherlands"
    assert res["109.205.211.205"]["country_code"] == "NL"
    assert res["109.205.211.205"]["asn"] == "AS201814 MEVSPACE sp. z o.o."


def test_regression_ollama_local_provider_no_api_key_and_think_tags(tmp_path: Path) -> None:
    """Verify Ollama works without an API key, appends /v1, and strips <think>...</think> blocks."""
    cfg = AppConfig(
        llm_provider="ollama",
        llm_base_url="http://localhost:11434",
        llm_model="deepseek-r1:14b",
        state_file_path=tmp_path / "dedup.json",
    )
    assert cfg.llm_base_url == "http://localhost:11434/v1"
    analyst = AnthropicSOCAnalyst(config=cfg)
    assert analyst.client is None

    evaluation = FilterEvaluationResult(
        window_start=datetime.now(tz=UTC),
        window_end=datetime.now(tz=UTC),
        should_invoke_ai=True,
        trigger_reasons=["Tier 1 test"],
    )

    ollama_payload = {
        "choices": [
            {
                "message": {
                    "content": (
                        "<think>\nLet me analyze the firewall telemetry first...\n"
                        "Internal host 192.168.1.50 connected to 4444.\n</think>\n"
                        '{"severity": "CRITICAL", "title": "Ollama Local Detection", '
                        '"executive_summary": "Rilevato C2 da modello locale.", '
                        '"key_findings": ["192.168.1.50 -> 4444"], '
                        '"recommended_actions": ["Isolare host"], '
                        '"suspicious_ips": ["192.168.1.50"]}'
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 310, "completion_tokens": 95},
    }

    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = ollama_payload

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        report = analyst.analyze(evaluation)

    assert mock_post.call_count == 1
    called_url = mock_post.call_args.args[0]
    assert called_url == "http://localhost:11434/v1/chat/completions"
    assert report.severity == "CRITICAL"
    assert report.title == "Ollama Local Detection"
    assert report.model_used == "deepseek-r1:14b"
    assert report.input_tokens == 310
    assert report.output_tokens == 95


def test_regression_openrouter_provider_headers_and_endpoint(tmp_path: Path) -> None:
    """Verify OpenRouter sends HTTP-Referer and X-Title headers to /v1/chat/completions."""
    cfg = AppConfig(
        llm_provider="openrouter",
        llm_api_key="sk-or-v1-test-key",
        llm_model="google/gemini-2.5-flash",
        state_file_path=tmp_path / "dedup.json",
    )
    assert cfg.llm_base_url == "https://openrouter.ai/api/v1"
    analyst = AnthropicSOCAnalyst(config=cfg)

    evaluation = FilterEvaluationResult(
        window_start=datetime.now(tz=UTC),
        window_end=datetime.now(tz=UTC),
        should_invoke_ai=True,
        trigger_reasons=["Tier 3 scan"],
    )

    or_payload = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "severity": "WARNING",
                            "title": "OpenRouter Scan Alert",
                            "executive_summary": "Port scan detected via OpenRouter.",
                            "key_findings": ["Scan on 12 ports"],
                            "recommended_actions": ["Monitor IP"],
                            "suspicious_ips": ["185.220.101.42"],
                        }
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 450, "completion_tokens": 110},
    }

    mock_resp = MagicMock()
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = or_payload

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        report = analyst.analyze(evaluation)

    called_url = mock_post.call_args.args[0]
    called_headers = mock_post.call_args.kwargs["headers"]
    assert called_url == "https://openrouter.ai/api/v1/chat/completions"
    assert called_headers["Authorization"] == "Bearer sk-or-v1-test-key"
    assert called_headers["X-Title"] == "PfsenseMon"
    assert "HTTP-Referer" in called_headers
    assert report.severity == "WARNING"
    assert report.model_used == "google/gemini-2.5-flash"


def test_regression_openai_local_vs_cloud_api_key_requirement(tmp_path: Path) -> None:
    """Verify local OpenAI-compatible endpoints (LM Studio) work without API key while cloud requires one."""
    local_cfg = AppConfig(
        llm_provider="openai",
        llm_base_url="http://host.docker.internal:1234/v1",
        llm_model="lmstudio-community/qwen2.5-7b",
        state_file_path=tmp_path / "dedup1.json",
    )
    local_analyst = AnthropicSOCAnalyst(config=local_cfg)
    assert not local_analyst._requires_api_key()

    cloud_cfg = AppConfig(
        llm_provider="openai",
        llm_base_url="https://api.openai.com/v1",
        llm_model="gpt-4o-mini",
        state_file_path=tmp_path / "dedup2.json",
    )
    cloud_analyst = AnthropicSOCAnalyst(config=cloud_cfg)
    assert cloud_analyst._requires_api_key()


def test_regression_analyzer_geoip_enrichment_and_telegram_rendering(tmp_path: Path) -> None:
    """Verify enrich_evaluation_with_geoip populates GeoIPInfo and TelegramNotifier renders it."""
    evaluation = FilterEvaluationResult(
        window_start=datetime.now(tz=UTC),
        window_end=datetime.now(tz=UTC),
        should_invoke_ai=True,
        trigger_reasons=["Tier 1 & Tier 3 anomalies"],
        tier1_anomalies=[
            OutboundAnomalySummary(
                src_ip="192.168.1.145",
                dst_ip="198.51.100.77",
                dst_port="4444",
                proto="tcp",
                action="block",
                sub_type="outbound_blocked",
                total_hits=4,
            )
        ],
        tier3_offenders=[
            WanOffenderSummary(
                src_ip="185.220.101.42",
                total_blocked_hits=65,
                distinct_ports_count=12,
                targeted_ports=["22", "80", "443"],
                protocols=["tcp"],
                is_port_scanner=True,
                is_high_volume=True,
            )
        ],
    )

    fake_batch = [
        {
            "status": "success",
            "query": "198.51.100.77",
            "country": "United States",
            "countryCode": "US",
            "city": "Ashburn",
            "isp": "Example Cloud LLC",
            "org": "Example Cloud",
            "as": "AS64500 Example Cloud LLC",
        },
        {
            "status": "success",
            "query": "185.220.101.42",
            "country": "Germany",
            "countryCode": "DE",
            "city": "Falkenstein",
            "isp": "Hetzner Online GmbH",
            "org": "Hetzner",
            "as": "AS24940 Hetzner Online GmbH",
        },
    ]

    mock_geo_resp = MagicMock()
    mock_geo_resp.raise_for_status.return_value = None
    mock_geo_resp.json.return_value = fake_batch

    with patch("httpx.Client.post", return_value=mock_geo_resp):
        enrich_evaluation_with_geoip(evaluation)

    assert evaluation.tier1_anomalies[0].dst_geoip is not None
    assert evaluation.tier1_anomalies[0].dst_geoip.country_code == "US"
    assert evaluation.tier3_offenders[0].src_geoip is not None
    assert (
        evaluation.tier3_offenders[0].src_geoip.short_label()
        == "DE · Hetzner Online GmbH · AS24940"
    )

    cfg = _base_config(tmp_path)
    notifier = TelegramNotifier(config=cfg)
    report = AISecurityReport(
        severity="CRITICAL",
        title="GeoIP Enriched Alert",
        executive_summary="Detected scan and C2.",
        key_findings=["Scan from DE"],
        recommended_actions=["Block IP"],
        suspicious_ips=["185.220.101.42", "192.168.1.145"],
        model_used="MiniMax-M3",
        input_tokens=500,
        output_tokens=200,
    )

    sent_messages: list[str] = []

    def fake_send_html(text: str) -> bool:
        sent_messages.append(text)
        return True

    with patch.object(notifier, "_send_html_message", side_effect=fake_send_html):
        notifier.send_ai_report(report, evaluation)
        notifier.send_raw_fallback_alert(evaluation, "Simulated timeout")

    assert len(sent_messages) == 2
    assert "<code>185.220.101.42</code> (DE · Hetzner Online GmbH · AS24940)" in sent_messages[0]
    assert "<code>198.51.100.77:4444/tcp</code> (US · Example Cloud LLC · AS64500)" in sent_messages[1]
    assert "<code>185.220.101.42</code> (DE · Hetzner Online GmbH · AS24940)" in sent_messages[1]


def test_regression_openai_structured_output_json_schema(tmp_path: Path) -> None:
    """Verify OpenAI-compatible endpoints receive json_schema response_format when enabled."""
    cfg = AppConfig(
        llm_provider="openai",
        llm_base_url="http://host.docker.internal:1234/v1",
        llm_model="qwen/qwen3.5-9b",
        llm_structured_output=True,
        state_file_path=tmp_path / "dedup.json",
    )
    analyst = AnthropicSOCAnalyst(config=cfg)

    evaluation = FilterEvaluationResult(
        window_start=datetime.now(tz=UTC),
        window_end=datetime.now(tz=UTC),
        should_invoke_ai=True,
        trigger_reasons=["Structured Output Test"],
    )

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.raise_for_status.return_value = None
    mock_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "severity": "WARNING",
                            "title": "Structured Output Title",
                            "executive_summary": "Schema-enforced summary.",
                            "key_findings": ["Strict JSON received"],
                            "recommended_actions": ["No action required"],
                            "suspicious_ips": ["198.51.100.23"],
                        }
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 120, "completion_tokens": 60},
    }

    with patch("httpx.Client.post", return_value=mock_resp) as mock_post:
        report = analyst.analyze(evaluation)

    assert mock_post.call_count == 1
    called_body = mock_post.call_args.kwargs["json"]
    assert "response_format" in called_body
    assert called_body["response_format"]["type"] == "json_schema"
    assert called_body["response_format"]["json_schema"]["strict"] is True
    assert report.severity == "WARNING"
    assert report.title == "Structured Output Title"


def test_regression_openai_structured_output_fallback_on_rejection(tmp_path: Path) -> None:
    """Verify graceful fallback and retry without response_format if provider rejects json_schema with 400."""
    cfg = AppConfig(
        llm_provider="openai",
        llm_base_url="http://host.docker.internal:1234/v1",
        llm_model="legacy-model",
        llm_structured_output=True,
        state_file_path=tmp_path / "dedup.json",
    )
    analyst = AnthropicSOCAnalyst(config=cfg)

    evaluation = FilterEvaluationResult(
        window_start=datetime.now(tz=UTC),
        window_end=datetime.now(tz=UTC),
        should_invoke_ai=True,
        trigger_reasons=["Fallback Test"],
    )

    # First attempt: 400 rejection on response_format
    first_resp = MagicMock()
    first_resp.status_code = 400
    first_resp.text = "Error: 'response_format' is unsupported for this model."

    # Second attempt: 200 OK without response_format
    second_resp = MagicMock()
    second_resp.status_code = 200
    second_resp.raise_for_status.return_value = None
    second_resp.json.return_value = {
        "choices": [
            {
                "message": {
                    "content": json.dumps(
                        {
                            "severity": "INFO",
                            "title": "Fallback Success",
                            "executive_summary": "Parsed without structured output.",
                            "key_findings": ["Recovered cleanly"],
                            "recommended_actions": [],
                            "suspicious_ips": [],
                        }
                    )
                }
            }
        ],
        "usage": {"prompt_tokens": 100, "completion_tokens": 40},
    }

    with patch("httpx.Client.post", side_effect=[first_resp, second_resp]) as mock_post:
        report = analyst.analyze(evaluation)

    assert mock_post.call_count == 2
    # Verify second call removed response_format
    first_body = mock_post.call_args_list[0].kwargs["json"]
    second_body = mock_post.call_args_list[1].kwargs["json"]
    assert "response_format" in first_body
    assert "response_format" not in second_body
    assert report.title == "Fallback Success"


def test_regression_wiki_sensitive_data_anonymization() -> None:
    """Verify that all markdown documents in wiki/ are free from sensitive data and un-anonymized public IPs."""
    wiki_dir = REPO_ROOT / "wiki"
    ip_pattern = re.compile(r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b")
    secret_patterns = [
        re.compile(r"\b(?:sk-[a-zA-Z0-9_\-]{20,})\b"),
        re.compile(r"\b(?:AAF-[a-zA-Z0-9_\-]{20,})\b"),
        # Real Telegram bot token shape: "<numeric bot id>:AA<secret>"
        re.compile(r"(?<!\d)\d{6,}:AA[a-zA-Z0-9_\-]{30,}"),
        re.compile(r"\b(?:ghp_[a-zA-Z0-9]{36})\b"),
    ]

    for md_file in wiki_dir.rglob("*.md"):
        content = md_file.read_text(encoding="utf-8")

        # 1. Check for live API keys or tokens
        for pattern in secret_patterns:
            matches = pattern.findall(content)
            assert not matches, f"Exposed live secret/token found in {md_file}: {matches}"

        # 2. Check for un-anonymized public IPv4 addresses
        for ip in set(ip_pattern.findall(content)):
            parts = [int(p) for p in ip.split(".")]
            if any(p > 255 for p in parts):
                continue
            if ip in ("0.0.0.0", "127.0.0.1"):
                continue

            # RFC 1918 Private Ranges (allowed for internal examples)
            is_rfc1918 = (
                parts[0] == 10
                or (parts[0] == 172 and 16 <= parts[1] <= 31)
                or (parts[0] == 192 and parts[1] == 168)
            )

            # RFC 5737 Documentation Ranges (mandatory for public examples)
            # 192.0.2.0/24 (TEST-NET-1), 198.51.100.0/24 (TEST-NET-2), 203.0.113.0/24 (TEST-NET-3)
            is_rfc5737 = (
                (parts[0] == 192 and parts[1] == 0 and parts[2] == 2)
                or (parts[0] == 198 and parts[1] == 51 and parts[2] == 100)
                or (parts[0] == 203 and parts[1] == 0 and parts[2] == 113)
            )

            assert is_rfc1918 or is_rfc5737, (
                f"Un-anonymized public IP address '{ip}' detected in {md_file.relative_to(REPO_ROOT)}. "
                f"Public IPs must use RFC 5737 documentation subnets (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24)."
            )

