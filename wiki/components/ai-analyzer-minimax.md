---
type: Component
title: Python AI Analyzer & MiniMax Integration
description: Containerized Python 3.12 service performing Zero-Token filtering, MiniMax/Anthropic API evaluation, Loki report persistence, and Telegram Bot alerting.
resource: analyzer/src/main.py
tags:
  - python
  - minimax
  - anthropic
  - telegram
  - analyzer
timestamp: 2026-10-23T21:55:00Z
---

# Python AI Analyzer & MiniMax Integration

The `pfsensemon-analyzer` container (`analyzer/`) is the brain of **PfsenseMon**. It runs a periodic evaluation loop (default every 15 minutes, configured in live production at 60 minutes) that queries [Grafana Loki](loki-and-grafana.md), filters events through the [Zero-Token Pre-Filter](../concepts/zero-token-filter.md), calls the **MiniMax** (or Anthropic) API via the Anthropic Messages standard, writes the resulting report back to Loki (`security_tier="ai_report"`), and sends a formatted HTML alert via Telegram.

---

## 1. Module Architecture (`analyzer/src/`)

- [`config.py`](../../analyzer/src/config.py) (`AppConfig`): Loads `.env` settings and normalizes `ANTHROPIC_BASE_URL` via `normalize_anthropic_base_url()`.
- [`models.py`](../../analyzer/src/models.py): Pydantic v2 models (`NormalizedLogEvent`, `FilterEvaluationResult`, `AISecurityReport`).
- [`loki_client.py`](../../analyzer/src/loki_client.py) (`LokiClient`): Queries Loki (`query_range`) and pushes AI reports back (`push`).
- [`filter_engine.py`](../../analyzer/src/filter_engine.py) (`ZeroTokenFilterEngine`, `DeduplicationCache`): Threshold evaluation and persistent TTL anti-spam cache.
- [`ai_analyst.py`](../../analyzer/src/ai_analyst.py) (`AnthropicSOCAnalyst`): Calls `Anthropic(api_key=..., base_url=...)` with exponential backoff and extracts structured JSON.
- [`notifier.py`](../../analyzer/src/notifier.py) (`TelegramNotifier`): Sends HTML-formatted Telegram alerts with automatic numeric `chat_id` discovery via `getUpdates` and raw fallback alerts if the LLM API is unreachable.
- [`main.py`](../../analyzer/src/main.py): Daemon loop and CLI (`--once`, `--dry-run`, `--lookback-minutes`, `--reset-dedup`).

---

## 2. MiniMax Anthropic-Compatible Standard Notes

- **Base URL**: `ANTHROPIC_BASE_URL=https://api.minimax.io/anthropic`
- **Model**: `ANTHROPIC_MODEL=MiniMax-M3` (or `MiniMax-M2.5`, `MiniMax-M3.1-Flash`).
- **SDK Compatibility (`anthropic==2.2.0`)**:
  - Do **not** pass `temperature` to `client.messages.create()` when targeting `MiniMax-M3` (`Messages.create() got an unexpected keyword argument 'temperature'` in `anthropic 2.2.0` / MiniMax reasoning endpoints).
  - Filter `response.content` blocks by `getattr(block, "type", "text") == "text"` so any `thinking` blocks emitted by reasoning models are skipped before JSON extraction.

---

## 3. Telegram `chat_id` Auto-Discovery

If `TELEGRAM_CHAT_ID` is initially set to a non-numeric string (such as the bot's username `your_pfsense_bot`), `TelegramNotifier._resolve_chat_id()` calls `https://api.telegram.org/bot<TOKEN>/getUpdates` to automatically resolve the user's numeric `chat_id` (e.g., `123456789`).

---

## 4. Planned Next Feature: Local LLM Support

- **Goal**: Extend `analyzer/src/ai_analyst.py` and `analyzer/src/config.py` so the AI Analyzer can optionally target **local LLM runtimes** (such as **Ollama**, **LM Studio**, **vLLM**, or **llama.cpp**) via OpenAI-compatible (`/v1/chat/completions`) or Anthropic-compatible (`/v1/messages`) local endpoints without requiring an external cloud API key.

---

## Related Pages

- [Zero-Token Pre-Filter & Deduplication](../concepts/zero-token-filter.md)
- [2026-10-23 End-to-End Live Verification](../raw/2026-10-23-e2e-verification-minimax.md)
