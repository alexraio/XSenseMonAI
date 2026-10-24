# PfsenseMon — Chronological Project & Knowledge Log

This file is the append-only chronological log (`log.md`) defined by the [LLM Wiki Pattern](SCHEMA.md) and the [Open Knowledge Format (OKF)](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md).

---

## [2026-10-23]brainstorm | Validated 3-Tier Hybrid Architecture & Tool Selection

- Conducted structured brainstorming session to define the pfSense AI security monitoring workflow.
- Selected the [3-Tier Hybrid Monitoring Strategy](concepts/three-tier-hybrid-strategy.md) to solve the "Internet background radiation" problem on the WAN interface while capturing high-value outbound (`LAN -> WAN`) and authentication anomalies.
- Decided to reuse the user's **existing Grafana server** (deploying only Vector + Loki + Python Analyzer in Docker) and integrate with the user's **Hermes Agent** (running on an Ubuntu VM in an isolated VLAN) via a scoped `TCP 3100` firewall rule and a custom [Hermes Agent Interactive SOC Skill](components/hermes-agent-skill.md).
- Established the mandatory language policy in [`AGENTS.md`](../AGENTS.md): user conversation in Italian, all code and documentation in English.

---

## [2026-10-23] build | Implemented 4-Phase Docker, Vector, Loki, Python & Hermes Stack

- Created [`docker-compose.yml`](../docker-compose.yml), [`.env.example`](../.env.example), [`config/loki/loki-config.yaml`](../config/loki/loki-config.yaml) (30-day retention), and [`config/vector/vector.yaml`](../config/vector/vector.yaml) ([Vector Syslog & VRL Pipeline](components/vector-pipeline.md)).
- Implemented the [Python AI Analyzer](components/ai-analyzer-minimax.md) (`analyzer/src/`) featuring the [Zero-Token Pre-Filter & Deduplication](concepts/zero-token-filter.md) engine, Loki LogQL client, AI SOC analyst, and Telegram Bot notifier with raw statistical fallback.
- Created the zero-dependency [Hermes Agent Interactive SOC Skill](components/hermes-agent-skill.md) (`hermes_skill/query_pfsense_loki.py` and `hermes_skill/SKILL.md`), the Grafana dashboard JSON (`config/grafana/dashboard-pfsense.json`), and the synthetic syslog generator (`scripts/simulate_pfsense_logs.py`).

---

## [2026-10-23] ingest | Added MiniMax Anthropic-Compatible API Support

- Configured [`analyzer/src/config.py`](../analyzer/src/config.py) and [`analyzer/src/ai_analyst.py`](../analyzer/src/ai_analyst.py) to support `ANTHROPIC_BASE_URL` (defaulting to `https://api.minimax.io/anthropic`) and model `MiniMax-M3` / `MiniMax-M2.5`.
- Implemented `normalize_anthropic_base_url()` to strip accidental `/v1` or `/v1/messages` suffixes so both the official `anthropic` Python SDK and the `httpx` fallback work seamlessly.
- Filtered response content blocks by `type == "text"` to ignore `thinking` blocks returned by reasoning models.

---

## [2026-10-23] verify | Live End-to-End Verification (Vector -> Loki -> MiniMax-M3 -> Telegram)

- Launched the Docker stack on macOS Docker Desktop and diagnosed/fixed two live issues:
  1. **Vector VRL Type Safety**: Refined infallible `to_string()` and `is_ipv4()` assignments in [`config/vector/vector.yaml`](../config/vector/vector.yaml) so `vector:0.39.0-alpine` passes healthchecks cleanly.
  2. **MiniMax Parameter & Telegram Auto-Discovery**: Removed the unsupported `temperature` parameter for `MiniMax-M3` in [`analyzer/src/ai_analyst.py`](../analyzer/src/ai_analyst.py) and added automatic numeric `chat_id` discovery via Telegram `getUpdates` in [`analyzer/src/notifier.py`](../analyzer/src/notifier.py).
- Sent synthetic pfSense traffic (5 background noise packets, 65 WAN port-scan packets across 12 ports from `185.220.101.42`, 6 suspicious outbound C2 packets from `192.168.1.145 -> 198.51.100.77:4444`, and 6 SSH/WebGUI auth failures from `45.155.205.99`).
- Verified that Vector compressed the 65 WAN scan packets into 12 aggregated records in Loki, `MiniMax-M3` produced a `CRITICAL` security assessment in Italian (`1055` input tokens / `728` output tokens), stored the report in Loki, and delivered the alert to Telegram (`chat_id=123456789`). See [Raw Verification Snapshot](raw/2026-10-23-e2e-verification-minimax.md).

---

## [2026-10-23] setup | Initialized Git Repository, `uv` Virtual Environment & OKF Wiki

- Initialized Git repository on `main` (`37e33aa`) with `.env` and `.venv/` excluded via [`.gitignore`](../.gitignore).
- Created local Python 3.13 virtual environment (`.venv`) with `uv` and verified all 5 unit tests pass via `.venv/bin/pytest -v`.
- Initialized the `wiki/` knowledge base following Andrej Karpathy's LLM Wiki pattern and Google Cloud's Open Knowledge Format (`okf/SPEC.md`).

---

## [2026-10-23] test-and-ci | Added Pytest Regression Suite, Automated Wiki Linter & GitHub Actions CI

- Created [`tests/test_regressions.py`](../tests/test_regressions.py) covering MiniMax-M3 `temperature`/`thinking` block handling, Telegram `getUpdates` auto-discovery & HTML escaping, Zero-Token strict 0-call guarantee, raw fallback alerting, Loki stream parsing, Vector VRL static checks, and automated OKF Wiki health linting (`lint`).
- Created [`.github/workflows/ci.yml`](../.github/workflows/ci.yml) to run `ruff`, `pytest` (Python 3.12 & 3.13 via `uv`), official Vector VRL config validation (`timberio/vector:0.39.0-alpine validate`), and `docker compose build` on every push and pull request.
- Updated [pfSense Configuration & End-to-End Testing Runbook](runbooks/pfsense-and-e2e-testing.md) and aligned [`README.md`](../README.md) with MiniMax configuration, Telegram `chat_id` auto-discovery, `uv` environment setup, regression tests, GitHub Actions CI, and the OKF `wiki/` structure.

---

## [2026-10-23] tune | Live pfSense Syslog Ingestion & Out-of-State TCP Filter

- Verified live pfSense syslog reception from interfaces `igc0` (WAN) and `igc1` (`192.168.50.0/24` VLAN).
- Identified false-positive Tier 1 alerts caused by out-of-state TCP teardown/keepalive packets (`FPA`, `FA`, `A` without `SYN`) when client sessions expire in pfSense's state table.
- Added VRL filter (`if proto == "tcp" && action == "block" && !contains(tcp_flags, "S") { abort }`) in [`config/vector/vector.yaml`](../config/vector/vector.yaml) and defense-in-depth filtering in [`analyzer/src/filter_engine.py`](../analyzer/src/filter_engine.py), plus regression test coverage in [`tests/test_regressions.py`](../tests/test_regressions.py).

---

## [2026-10-23] ci-fix | Synced Private GitHub Repository & Fixed GitHub Actions CI Workflow

- Created private GitHub repository `alexraio/XSenseMonAI` via GitHub MCP (`create_repository`) and pushed `main`.
- Investigated GitHub Actions Run #1 failure:
  1. Replaced `uv pip install --system -r analyzer/requirements.txt pytest ruff` (which failed on Ubuntu runners when mixing `-r` with positional packages under PEP 668 externally-managed Python) with `actions/setup-python@v5` + `python -m pip install` in [`.github/workflows/ci.yml`](../.github/workflows/ci.yml).
  2. Resolved all 25 Ruff lint findings across `analyzer/`, `hermes_skill/`, `scripts/`, and `tests/` (`UP017` `datetime.UTC`, `I001` import sorting, `SIM103`, `BLE001` specific exception types, and `EXE001` executable script permissions) and configured `[tool.ruff.lint]` in [`pyproject.toml`](../pyproject.toml).
- Verified GitHub Actions Run #2 (`b5ddca1`) passed all 3 jobs (`Python 3.12`, `Python 3.13`, and `Validate Vector VRL & Docker Compose Build`).
- Verified live production cycle (`20:33 -> 21:33 UTC`): 707 events fetched from Loki, 0 false-positive Tier 1 alerts after non-SYN TCP filtering, 7 Tier 3 WAN offenders analyzed by `MiniMax-M3` (`WARNING`) and delivered to Loki and Telegram.
- Logged upcoming roadmap item in [Python AI Analyzer & MiniMax Integration](components/ai-analyzer-minimax.md): **Local LLM provider support** (Ollama / LM Studio / vLLM / OpenAI-compatible local endpoints).

---

## [2026-10-24] enhance | Added Automatic GeoIP & ASN Enrichment to Hermes SOC Skill

- Enhanced [`hermes_skill/query_pfsense_loki.py`](../hermes_skill/query_pfsense_loki.py) (`resolve_geoip_batch`) to automatically enrich `summary` (Tier 3 top WAN offenders) and `inspect-ip` with **country, country_code, city, ISP, and ASN** metadata using Python's standard library (`urllib.request` batch POST + `ipaddress` local RFC1918 detection).
- Added `--no-geoip` flag for offline/air-gapped execution and graceful fail-open handling on network timeouts.
- Updated [`hermes_skill/SKILL.md`](../hermes_skill/SKILL.md), [Hermes Agent Interactive SOC Skill](components/hermes-agent-skill.md), and regression tests in [`tests/test_regressions.py`](../tests/test_regressions.py).

---

## [2026-10-24] governance | Added Apache License 2.0 (`LICENSE`)

- Added [`LICENSE`](../LICENSE) (Apache License, Version 2.0) in preparation for future open-source release.
- Declared `license = { file = "LICENSE" }` in [`pyproject.toml`](../pyproject.toml) and added a License section to [`README.md`](../README.md).

---

## [2026-10-24] sanitize | Sanitized PII & Hardened Gitignore for Public Readiness

- Replaced personal Telegram chat ID and bot username across [`README.md`](../README.md), [`tests/test_regressions.py`](../tests/test_regressions.py), and `wiki/` ([`components/ai-analyzer-minimax.md`](components/ai-analyzer-minimax.md), [`raw/2026-10-23-e2e-verification-minimax.md`](raw/2026-10-23-e2e-verification-minimax.md), [`log.md`](log.md)) with generic placeholders (`123456789`, `demo_pfsense_bot`).
- Hardened [`.gitignore`](../.gitignore) to defensively ignore deduplication cache states (`*dedup_cache*.json`, `state.json`), TLS/SSH key material (`*.pem`, `*.key`), packet captures (`*.pcap*`), scratch files (`scratch/`, `*.tmp`), local databases (`*.sqlite*`), and editor/OS artifacts.

---

## [2026-10-24] ops | Configured Docker Container Log Rotation (`json-file`)

- Added `logging` rotation policy (`driver: "json-file"`, `max-size: "10m"`, `max-file: "3"`) to `loki`, `vector`, and `analyzer` services in [`docker-compose.yml`](../docker-compose.yml) to cap host container logs at 30 MB per service alongside Loki's 30-day (`720h`) TSDB compactor retention and Vector's 256 MB disk buffer cap.
- Updated [Grafana Loki & Dashboard Integration](components/loki-and-grafana.md) and [`tests/test_regressions.py`](../tests/test_regressions.py).

---

## [2026-10-24] feat | Added Multi-Provider / Local LLM Support & Analyzer GeoIP Enrichment (`feat/local-llm-provider`)

- Completed structured `brainstorming` workflow and implemented multi-provider LLM support in [`analyzer/src/config.py`](../analyzer/src/config.py) and [`analyzer/src/ai_analyst.py`](../analyzer/src/ai_analyst.py):
  - Added `LLM_PROVIDER` (`anthropic`, `ollama`, `openai`, `openrouter`) with 100% backward compatibility for existing `ANTHROPIC_*` `.env` files.
  - Added `/v1/chat/completions` client via `httpx` supporting local **Ollama** (`http://host.docker.internal:11434/v1` without API key), **LM Studio / vLLM / OpenAI**, and **OpenRouter** (`https://openrouter.ai/api/v1` with `HTTP-Referer` and `X-Title` headers).
  - Added `<think>...</think>` block stripping in `_parse_json_response()` for reasoning models (`deepseek-r1`, `qwen3`, etc.) and `extra_hosts: ["host.docker.internal:host-gateway"]` in [`docker-compose.yml`](../docker-compose.yml).
- Implemented post-filter GeoIP & ASN enrichment in [`analyzer/src/geoip.py`](../analyzer/src/geoip.py) (`enrich_evaluation_with_geoip`), [`analyzer/src/models.py`](../analyzer/src/models.py) (`GeoIPInfo`), [`analyzer/src/main.py`](../analyzer/src/main.py), and [`analyzer/src/notifier.py`](../analyzer/src/notifier.py):
  - Triggers only when `should_invoke_ai == True` and `ENABLE_GEOIP=true`, enriching both the LLM prompt payload and Telegram alerts (`send_ai_report` + `send_raw_fallback_alert`).
- Added 4 regression tests in [`tests/test_regressions.py`](../tests/test_regressions.py) and updated [Python AI Analyzer, Multi-Provider LLM & GeoIP Enrichment](components/ai-analyzer-minimax.md), [`DESIGN.md`](../DESIGN.md), and [`README.md`](../README.md).

---

## [2026-10-24] feat | Implemented OpenAI Strict Structured Output (`json_schema`) & LM Studio 16k Context Verification

- Implemented OpenAI-compatible `response_format` with `type: "json_schema"`, `strict: True`, and `SECURITY_REPORT_JSON_SCHEMA` in [`analyzer/src/ai_analyst.py`](../analyzer/src/ai_analyst.py):
  - Guarantees 100% compliant JSON responses matching `AISecurityReport` fields without conversational prelude or unclosed JSON blocks.
  - Added automatic graceful fallback: if an endpoint returns HTTP 400 rejecting `json_schema`, the request is automatically retried without `response_format`.
  - Added `llm_structured_output: bool = True` in [`analyzer/src/config.py`](../analyzer/src/config.py) and `LLM_STRUCTURED_OUTPUT=true` in [`.env.example`](../.env.example).
- Increased `MAX_PROMPT_ITEMS_PER_TIER=15` in [`.env`](../.env) to leverage larger context windows (16384 tokens) in LM Studio.
- Completed live end-to-end verification with `qwen/qwen3.5-9b` (LM Studio on macOS host):
  - Processed 3831 real pfSense firewall events from Loki.
  - Enriched 15 aggressive WAN offenders (Tier 3) + 2 outbound flows (Tier 1) with GeoIP and ASN.
  - Ingested 5508 input tokens into LM Studio, generated 916 output tokens of high-quality Italian security analysis via Structured Output, successfully pushed to Loki (`204 No Content`), and delivered to Telegram (`200 OK`).
- Added 2 regression tests (`test_regression_openai_structured_output_json_schema`, `test_regression_openai_structured_output_fallback_on_rejection`) in [`tests/test_regressions.py`](../tests/test_regressions.py). All 19 tests pass cleanly.
