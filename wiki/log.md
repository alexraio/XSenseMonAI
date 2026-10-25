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
- Sent synthetic pfSense traffic (5 background noise packets, 65 WAN port-scan packets across 12 ports from `198.51.100.42`, 6 suspicious outbound C2 packets from `192.168.1.145 -> 198.51.100.77:4444`, and 6 SSH/WebGUI auth failures from `203.0.113.99`).
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

---

## [2026-10-24] benchmark | Evaluated Local LLMs on Apple Silicon (Gemma 4B/12B, Qwen 9B) & Ingested Benchmark Page

- Conducted exhaustive live comparative benchmark of local LLMs hosted in LM Studio (Apple Silicon Mac) processing real pfSense firewall telemetry against cloud reference `MiniMax-M3`.
- Tested models:
  1. `google/gemma-4-e4b` (4B): Fast lightweight option (~39s, 300 output tokens), correctly identified critical anomalies.
  2. `qwen/qwen3.5-9b` (9B): Outstanding detail (~1m 19s for 15 offenders, 916 output tokens), granular per-port and GeoIP breakdown.
  3. `google/gemma-4-12b` (12B with Thinking): High execution time spent on internal thought tokens, choking output budget (112 tokens, empty findings).
  4. `google/gemma-4-12b` (12B without Thinking): Benchmark winner for incident response (~1m 13s, 498 output tokens), producing actionable remediation (host isolation of `172.16.30.16`, target mapping `192.168.50.117`, VLAN ACL reinforcement).
- Key Architectural Insight: Disabling internal reasoning/thinking when using strict OpenAI Structured Output (`json_schema`) increases usable payload tokens by +345% and eliminates JSON schema truncation.
- Ingested immutable benchmark record in [`wiki/raw/2026-10-24-local-llm-benchmark.md`](raw/2026-10-24-local-llm-benchmark.md) and linked it in [`wiki/index.md`](index.md) and [`wiki/components/ai-analyzer-minimax.md`](components/ai-analyzer-minimax.md).

---

## [2026-10-24] roadmap | Next Milestone: Interactive Onboarding & Installation Wizard (`setup.sh`)

- Formulated upcoming roadmap goal to streamline deployment for end users:
  - Evaluate the creation of an interactive `setup.sh` (or CLI wizard) to automate prerequisite validation (Docker, Docker Compose, port availability on `5140` and `3100`).
  - Interactive `.env` creation (guiding user through cloud vs. local LLM options, Telegram token configuration, and auto-discovery testing).
  - One-click launch and automated synthetic log injection to verify end-to-end functionality in under 2 minutes.
  - Review feasibility, ergonomics, and maintenance trade-offs during the next session.

---

## [2026-10-24] governance | Mandatory Pre-Push Sensitive Data Anonymization Policy Codified & Verified

- Codified a mandatory security and privacy policy governing all commits and pushes destined for GitHub:
  - Added Section 3 (`Pre-Push Security & Sensitive Data Anonymization Policy`) to [`AGENTS.md`](../AGENTS.md).
  - Added Section 4 (`Sensitive Data Anonymization & Privacy Standard`) to [`wiki/SCHEMA.md`](SCHEMA.md).
- Enforced strict pre-push requirements:
  - Zero tolerance for live API keys, tokens, webhook secrets, Telegram bot tokens, or numeric chat IDs.
  - Strict anonymization of public WAN IPs, ISP gateways, and external threat/scanner IPs using RFC 5737 documentation subnets (`192.0.2.0/24`, `198.51.100.0/24`, `203.0.113.0/24`) and RFC 3849 for IPv6.
  - Special protection for `wiki/`: all historical traces, raw evidence (`wiki/raw/`), benchmark logs, and runbooks must undergo thorough sanitization before push.
- Sanitized historical raw logs in [`wiki/raw/2026-10-24-local-llm-benchmark.md`](raw/2026-10-24-local-llm-benchmark.md) and [`wiki/raw/2026-10-23-e2e-verification-minimax.md`](raw/2026-10-23-e2e-verification-minimax.md).
- Implemented automated regression testing (`test_regression_wiki_sensitive_data_anonymization`) in [`tests/test_regressions.py`](../tests/test_regressions.py) ensuring CI blocks any non-RFC5737/non-RFC1918 IPs or credential leaks in `wiki/`.

---

## [2026-10-25] fix | Docker Log Audit: Sleep-Resilient Scheduler, Secret Redaction & Provider-Aware Logging

- Audited live `pfsensemon-loki`, `pfsensemon-vector` and `pfsensemon-analyzer` container logs and correlated them with macOS `pmset` sleep/wake history:
  - Loki `context canceled` / `empty ring` errors occur only at container shutdown/startup (benign).
  - Recurring Loki ring errors (`too many unhealthy instances in the ring`, `auto-forgetting instance`) coincide exactly with host DarkWake/Wake events: heartbeats go stale while Docker Desktop is suspended (benign, self-healing; transient Grafana 500s possible right after wake).
  - Root cause of real issues: host sleep. UDP syslog received during sleep is lost (host-level, not addressed in code), and the analyzer skipped windows.
- Fixed analyzer window skipping after host suspension (new [`analyzer/src/scheduler.py`](../analyzer/src/scheduler.py)): wall-clock deadline scheduling, persisted cursor (`scheduler_state.json`), contiguous interval-sized backfill bounded by new `MAX_CATCHUP_MINUTES` (default `1440`). `docker-compose.yml` now sets `STATE_FILE_PATH=/app/state/dedup_cache.json` so the dedup cache and cursor persist on the `analyzer_state` volume (previously defaulted to `/tmp` inside the container).
- Fixed Telegram bot token leakage in `docker logs` (new [`analyzer/src/log_redaction.py`](../analyzer/src/log_redaction.py)): `httpx`/`httpcore` set to `WARNING`, handler-level secret redaction (messages and tracebacks), masked chat IDs. Strengthened `test_regression_wiki_sensitive_data_anonymization` with the real Telegram token shape.
- Fixed Zero-Token skip log line to report the configured provider instead of always "Anthropic".
- Added 18 tests in [`tests/test_scheduler_and_redaction.py`](../tests/test_scheduler_and_redaction.py); full suite: 37 passed, `ruff` clean. Updated [AI Analyzer component page](components/ai-analyzer-minimax.md) (sections 5–6).

---

## [2026-10-25] governance | Mandatory Git Branching Strategy for Substantial Changes Codified

- Codified a mandatory project rule governing Git workflows:
  - Added Section 4 (`Git Branching Strategy for Substantial Changes`) to [`AGENTS.md`](../AGENTS.md).
- Enforced requirements:
  - For substantial, architectural, multi-file, or breaking changes, the agent MUST create and switch to a dedicated branch prior to editing code or documentation.
  - Standardized semantic branch naming prefixes: `feature/*`, `refactor/*`, `fix/*`, and `chore/*` / `test/*`.
  - Main branch (`main`) remains deployable and changes are merged only after test verification and user confirmation.

---

## [2026-10-25] feat | Implemented Interactive Quick-Start & Onboarding Wizard (`setup.sh` on `feature/setup-wizard`)

- Completed structured `brainstorming` workflow (Understanding Lock, NFRs, 3 architectural options, incremental design validation, and Decision Log) documented in [`DESIGN.md`](../DESIGN.md) (Section 7).
- Implemented self-contained defensive Bash Quick-Start wizard [`setup.sh`](../setup.sh) (compatible with macOS Bash 3.2+ and Linux Bash 4+/5+, requiring zero host Python packages):
  - **Pre-Flight Checks (`--check`)**: Validates `curl`, `docker`, `docker compose` v2, daemon readiness, UDP `5140` / TCP `3100` port availability, and auto-detects the host LAN IP.
  - **Idempotent `.env` Wizard**: Detects existing `.env` files (offering to keep, reconfigure with `0600` `.env.bak` backup, or jump to E2E smoke testing) and writes `.env` atomically with `chmod 600`.
  - **Live Auto-Discovery**: Probes `/v1/models` on local (`LM Studio`, `Ollama` via `localhost` while persisting `host.docker.internal` for the container) and cloud endpoints using a multi-fallback JSON helper (`python3` -> `jq` -> POSIX `grep`/`sed`); verifies Telegram bot tokens via `/getMe` and resolves numeric `TELEGRAM_CHAT_ID` interactively via `/getUpdates`.
  - **Two-Speed E2E Smoke Test (`--test-only`)**: Supports both a Fast Smoke Test (~10s, Tier 1 & Tier 2 forwarded 1:1) and a Full 3-Tier Smoke Test (~65s, including Vector's 60s `reduce` flush) in Live AI or Dry-Run mode.
- Added 5 automated tests in [`tests/test_setup_wizard.py`](../tests/test_setup_wizard.py) covering Bash 3.2 syntax compatibility, `--help`/`--version`, `--non-interactive` `0600` `.env` & `.env.bak` generation, `--check` validation, and mocked HTTP `/v1/models` auto-discovery.
- Updated [`README.md`](../README.md), [`wiki/runbooks/pfsense-and-e2e-testing.md`](runbooks/pfsense-and-e2e-testing.md), and [`wiki/index.md`](index.md).

---

## [2026-10-25] fix | Resolved LLM Variable Precedence Conflict & Wizard Cleanup (`feature/setup-wizard`)

- Diagnosed live `Connection error.` during Anthropic / MiniMax execution on Raspberry Pi caused by lingering local LLM environment variables (`LLM_BASE_URL=http://host.docker.internal:1234/v1` and `LLM_API_KEY=not-needed`) taking priority over `ANTHROPIC_BASE_URL` and `ANTHROPIC_API_KEY`.
- Updated [`analyzer/src/config.py`](../analyzer/src/config.py) (`AppConfig.__post_init__`):
  - When `LLM_PROVIDER == "anthropic"`, `ANTHROPIC_*` settings (`anthropic_api_key`, `anthropic_base_url`, `anthropic_model`) now strictly take precedence over generic `LLM_*` variables.
- Updated [`setup.sh`](../setup.sh):
  - In `run_env_wizard`, selecting cloud providers (MiniMax, Anthropic, OpenRouter) now automatically clears conflicting local LLM variables (`CFG_LLM_BASE_URL=""`, `CFG_LLM_API_KEY=""`, `CFG_LLM_MODEL=""`), and selecting local providers clears cloud keys.
  - Reset default initial values in `load_cfg_defaults` for `CFG_LLM_BASE_URL` and `CFG_LLM_API_KEY` to prevent cross-profile leakage.
- Added 2 regression tests:
  - `test_regression_anthropic_precedence_over_lingering_local_llm_vars` in [`tests/test_regressions.py`](../tests/test_regressions.py).
  - `test_setup_sh_interactive_minimax_clears_conflicting_llm_vars` in [`tests/test_setup_wizard.py`](../tests/test_setup_wizard.py).
- Verified full test suite passes (44 tests in `2.24s`, `ruff` clean).

---

## [2026-10-25] roadmap | Future Strategic Directions: SOAR Active Defense, Multi-Source Telemetry & Host Profiling

- Conducted comprehensive architecture review and brainstorming session to define future evolution milestones for PfsenseMon:
  1. **Direction A (SOAR Active Defense & Interactive Telegram Bot)**:
     - Two-way interactive Telegram bot with inline action buttons (`[🔴 Block IP]`, `[⚪ Whitelist]`, `[🔍 Deep Investigate]`).
     - pfSense enforcement mechanism: dynamic URL Table Alias served via a lightweight HTTP endpoint or direct pfSense management (e.g. pfSense alias / `pfctl` table).
     - Conversational SOC commands (`/status`, `/investigate <ip>`, `/blocked`, `/whitelist`).
  2. **Direction B (Multi-Source Telemetry: DNS & L7 IDS/IPS)**:
     - Ingestion of pfSense Unbound DNS logs to correlate Tier 1 outbound connection alerts with resolved domain names (FQDNs / DGA / C2 domains).
     - Ingestion of Suricata / Snort EVE JSON logs for application-layer signature and CVE exploit correlation.
  3. **Direction C (Asset Inventory & Behavioral Baseline Profiling)**:
     - Internal LAN host inventory and profiling (IoT, servers, workstations).
     - Behavioral anomaly detection (flagging deviations from normal communication baselines even without firewall rule violations).
- Selected **Direction A (SOAR Active Defense & Interactive Telegram Bot)** as the primary focus for structured architectural brainstorming.

---

## [2026-10-25] brainstorm | Architectural Review, YAGNI Pivot & Unbound DNS Roadmap Checkpoint

- **Brainstorming Session Review**:
  - Initially explored **Direction A (SOAR Active Defense / Telegram Blocklist)**: analyzed native pfSense *URL Table (IPs)* alias, Telegram Long Polling, Human-in-the-Loop button interactions, and configurable `AUTO_BLOCK_CRITICAL` hybrid mode.
  - **Critical YAGNI Realization**: User correctly highlighted that pfSense already enforces *Default Deny* on the WAN interface, automatically dropping all unsolicited inbound traffic. Without extensive exposed WAN services or port forwarding, dynamic inbound blocklists introduce unnecessary complexity for minimal real-world defensive gain.
  - **Strategic Pivot to Direction B (Network Observability & Unbound DNS)**: Realigned the project vision around its true core mission: **deep internal and external network observability** ("understanding what is genuinely happening across the LAN and WAN in plain human language").
  - Identified **pfSense Unbound DNS Resolver** query logging as the missing link to bridge anonymous L3/L4 IP connections with real domain names (FQDNs, CDNs, tracking/telemetry endpoints, and C2/DGA anomalies).
- **Exact Resume Checkpoint for Next Session**:
  - Resume structured brainstorming on **Direction B: Unbound DNS Integration**:
    - **Step 2 Alignment Question Pending**: Select between:
      1. *(Recommended) Full Approach*: Both connection flow enrichment (mapping IP packets to resolved domain names) AND dedicated DNS anomaly detection (high-entropy/DGA domains, excessive NXDOMAIN bursts, anomalous query rates from IoT).
      2. *Flow Enrichment Only*: Pure reverse mapping from IP flows to domain names.
      3. *Top Talkers & Dashboard Focus*: Grafana-centric aggregation of top querying hosts, domains, and external DNS servers.

---

## [2026-10-25] doc | Updated README.md with Core Homelabber Mission, Plain-Language Intervention & Multi-Brand Roadmap

- Updated [`README.md`](../README.md) to formalize the foundational project goal and vision:
  - **Empowering Homelabbers & Everyday Users**: Addressing "firewall blindness" where non-enterprise users are overwhelmed by cryptic syslog lines and false alarms from internet noise.
  - **Plain-Language Intelligence & Actionable Intervention**: Turning raw firewall logs into human-understandable findings with prioritized, concrete steps on how to intervene (e.g. isolating IoT devices, adjusting firewall rules, or inspecting local anomalies).
  - **Universal Multi-Brand Router Roadmap**: Established the explicit strategic roadmap to expand beyond pfSense and OPNsense to **Ubiquiti UniFi OS**, **MikroTik RouterOS**, and **OpenWrt**.
  - Added dedicated `🎯 Project Mission & Goals` section, updated the Mermaid architecture diagram, and introduced the `🗺️ Strategic Roadmap & Multi-Vendor Ecosystem` milestone matrix.

