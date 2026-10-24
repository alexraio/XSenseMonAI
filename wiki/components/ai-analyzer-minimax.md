---
type: Component
title: Python AI Analyzer, Multi-Provider LLM & GeoIP Enrichment
description: Containerized Python 3.12 service performing Zero-Token filtering, Post-Filter GeoIP/ASN enrichment, Multi-Provider LLM analysis (Anthropic/MiniMax, Ollama, OpenAI, OpenRouter), Loki report persistence, and Telegram Bot alerting.
resource: analyzer/src/main.py
tags:
  - python
  - minimax
  - anthropic
  - ollama
  - openrouter
  - geoip
  - telegram
  - analyzer
timestamp: 2026-10-24T15:30:00Z
---

# Python AI Analyzer, Multi-Provider LLM & GeoIP Enrichment

The `pfsensemon-analyzer` container (`analyzer/`) is the brain of **PfsenseMon**. It runs a periodic evaluation loop (default every 15 minutes, configured in live production at 60 minutes) that queries [Grafana Loki](loki-and-grafana.md), filters events through the [Zero-Token Pre-Filter](../concepts/zero-token-filter.md), enriches anomalous public IPs with GeoIP/ASN metadata, calls the configured LLM provider (**MiniMax / Anthropic**, **Local Ollama**, **OpenAI / LM Studio / vLLM**, or **OpenRouter**), writes the resulting report back to Loki (`security_tier="ai_report"`), and sends a formatted HTML alert via Telegram.

---

## 1. Module Architecture (`analyzer/src/`)

- [`config.py`](../../analyzer/src/config.py) (`AppConfig`): Loads `.env` settings, resolves `LLM_PROVIDER` (`anthropic`, `ollama`, `openai`, `openrouter`), normalizes base URLs via `normalize_anthropic_base_url()` and `normalize_openai_base_url()`, and detects local endpoints via `is_local_endpoint()`.
- [`models.py`](../../analyzer/src/models.py): Pydantic v2 models (`NormalizedLogEvent`, `GeoIPInfo`, `FilterEvaluationResult`, `AISecurityReport`).
- [`loki_client.py`](../../analyzer/src/loki_client.py) (`LokiClient`): Queries Loki (`query_range`) and pushes AI reports back (`push`).
- [`filter_engine.py`](../../analyzer/src/filter_engine.py) (`ZeroTokenFilterEngine`, `DeduplicationCache`): Threshold evaluation and persistent TTL anti-spam cache.
- [`geoip.py`](../../analyzer/src/geoip.py) (`resolve_geoip_batch`, `enrich_evaluation_with_geoip`): Post-filter batch GeoIP/ASN lookup (`country`, `country_code`, `city`, `isp`, `asn`) triggered only when `should_invoke_ai == True` and `ENABLE_GEOIP=true`.
- [`ai_analyst.py`](../../analyzer/src/ai_analyst.py) (`AnthropicSOCAnalyst` / `SOCAnalyst`): Multi-provider LLM client with exponential backoff, `<think>...</think>` reasoning tag stripping, and structured JSON extraction.
- [`notifier.py`](../../analyzer/src/notifier.py) (`TelegramNotifier`): Sends HTML-formatted Telegram alerts with automatic numeric `chat_id` discovery via `getUpdates`, inline GeoIP/ASN labels (`DE · Hetzner · AS24940`), and raw fallback alerts if the LLM API is unreachable.
- [`main.py`](../../analyzer/src/main.py): Daemon loop and CLI (`--once`, `--dry-run`, `--lookback-minutes`, `--reset-dedup`).

---

## 2. Multi-Provider & Local LLM Support (`LLM_PROVIDER`)

1. **`anthropic` (Default — MiniMax & Anthropic Cloud)**:
   - Uses `/v1/messages` via the official `anthropic` SDK (with `httpx` fallback).
   - Default `ANTHROPIC_BASE_URL=https://api.minimax.io/anthropic`, `ANTHROPIC_MODEL=MiniMax-M3` (or `MiniMax-M2.5`).
   - Does not pass `temperature` to `Messages.create()` and filters `response.content` blocks by `type == "text"`.
2. **`ollama` (Local Ollama Runtime)**:
   - Uses `/v1/chat/completions` (`LLM_BASE_URL=http://host.docker.internal:11434/v1`, automatically appending `/v1` if omitted).
   - **No API key required**; [`docker-compose.yml`](../../docker-compose.yml) configures `extra_hosts: ["host.docker.internal:host-gateway"]` so the container can reach Ollama on the host.
3. **`openai` (OpenAI Cloud, LM Studio, vLLM, llama.cpp)**:
   - Uses `/v1/chat/completions`. When pointing to a local endpoint (`localhost`, `host.docker.internal`, or RFC1918 IP), no API key is required.
4. **`openrouter` (OpenRouter Multi-Model Gateway)**:
   - Uses `https://openrouter.ai/api/v1/chat/completions` with `HTTP-Referer` and `X-Title: PfsenseMon` headers.
5. **Reasoning `<think>` Block Stripping**:
   - `_parse_json_response()` strips `<think>...</think>` blocks emitted by local or OpenRouter reasoning models (`deepseek-r1`, `qwen3`, etc.) before parsing the JSON report.
6. **OpenAI Strict Structured Output (`json_schema`)**:
   - When using `openai` (or local runtimes like LM Studio / vLLM), requests include `response_format: {"type": "json_schema", "json_schema": {"name": "pfsense_security_report", "strict": true, "schema": ...}}` enforced by `LLM_STRUCTURED_OUTPUT=true`.
   - Includes automatic graceful fallback: if an endpoint rejects `json_schema` with HTTP 400, the request is immediately retried without `response_format`.

---

## 3. Post-Filter GeoIP & ASN Enrichment (`analyzer/src/geoip.py`)

- Executed **only after** `ZeroTokenFilterEngine.evaluate()` sets `should_invoke_ai = True` (preserving 0 external HTTP calls during normal quiet windows).
- Classifies private RFC1918 addresses locally via `ipaddress` without sending them externally.
- Enriches both the JSON payload sent to the LLM (`dst_geoip` / `src_geoip`) and the Telegram alert (`📌 Involved IPs` and Raw Fallback items). Can be disabled via `ENABLE_GEOIP=false`.

---

## 4. Telegram `chat_id` Auto-Discovery

If `TELEGRAM_CHAT_ID` is initially set to a non-numeric string (such as the bot's username `demo_pfsense_bot`), `TelegramNotifier._resolve_chat_id()` calls `https://api.telegram.org/bot<TOKEN>/getUpdates` to automatically resolve the user's numeric `chat_id` (e.g., `123456789`).

---

## Related Pages

- [Zero-Token Pre-Filter & Deduplication](../concepts/zero-token-filter.md)
- [2026-10-23 End-to-End Live Verification](../raw/2026-10-23-e2e-verification-minimax.md)
- [2026-10-24 Local LLM Benchmark & Comparison (LM Studio)](../raw/2026-10-24-local-llm-benchmark.md)
