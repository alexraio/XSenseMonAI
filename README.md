# XSenseMonAI — AI-Powered pfSense and OPNsense Security Monitoring System

**XSenseMonAI** is a containerized security telemetry pipeline and AI anomaly detection system for **pfSense** and **OPNsense** firewalls. It combines **Vector** (high-speed Syslog parsing and 60-second edge aggregation), **Grafana Loki** (lightweight log storage connected to your existing **Grafana** server), a **Python AI Analyzer** supporting both cloud APIs (**MiniMax**, **Anthropic Claude**, **OpenRouter**) and completely private, air-gapped **Local LLM runtimes** (**LM Studio**, **Ollama**, **vLLM**, **llama.cpp**), **Telegram Bot** mobile alerting, and an interactive CLI skill for **Hermes Agent**.

---

## Key Features

- **3-Tier Hybrid Security Monitoring**:
  - 🔴 **Tier 1 (`tier_1_outbound_suspicious`)**: Captures 100% of blocked outbound (`LAN/VLAN -> WAN`) connections, outbound traffic to non-standard ports, and blocked inter-VLAN lateral movement to detect compromised internal hosts, malware C2 callbacks, or data exfiltration.
  - 🟠 **Tier 2 (`tier_2_access_and_auth`)**: Captures 100% of pfSense authentication events (`sshd`, WebGUI `webConfigurator`, OpenVPN, WireGuard, IPsec) and inbound WAN `pass` connections.
  - 🟡 **Tier 3 (`tier_3_wan_blocked`)**: Pre-aggregates repetitive inbound WAN `block` events in 60-second windows by `(src_ip, dst_port, proto)` using Vector's `reduce` transform—cutting storage and token noise by ~90% while preserving full statistical visibility (`hit_count`).
- **Zero-Token Pre-Filter Engine**: The Python Analyzer queries Loki periodically (e.g. every 15 or 60 minutes) and evaluates thresholds locally. If only harmless Internet background noise is present, **0 LLM API tokens are spent**.
- **Multi-Provider & Local LLM Support**:
  - **Cloud APIs**: Official **Anthropic** (`claude-3-5-sonnet`), **MiniMax** (`MiniMax-M3`, `MiniMax-M2.5`), and **OpenRouter** (`LLM_PROVIDER=openrouter`).
  - **Local & Private Models**: **LM Studio**, **Ollama**, **vLLM**, and **llama.cpp** (`LLM_PROVIDER=ollama` or `LLM_PROVIDER=openai`). Local endpoints require **zero API keys** and run 100% on-premises.
  - **OpenAI Strict Structured Output (`json_schema`)**: Enforces 100% schema compliance for local engines (LM Studio v0.3+, vLLM, OpenAI), eliminating formatting hallucinations, with automatic graceful fallback.
  - **Reasoning Tag Stripping**: Automatically purges `<think>...</think>` blocks emitted by reasoning models (DeepSeek-R1, Qwen 3.5, etc.) before parsing.
- **Post-Filter GeoIP & ASN Enrichment**: Automatically enriches anomalous external IPs with **Country, City, ISP, and ASN** metadata only when an alert triggers (`ENABLE_GEOIP=true`), injecting rich geographical context into the LLM prompt and Telegram alerts.
- **Anti-Spam Deduplication, Telegram Auto-Discovery & Raw Fallback**: Suppresses repeated alerts for the same ongoing scanner (configurable TTL cooldown), automatically discovers your numeric Telegram `chat_id` via `getUpdates` when you press `/start` on your bot, and sends a raw statistical Telegram alert if the AI engine is temporarily unreachable.
- **Hermes Agent SOC Integration**: Includes a zero-dependency Python CLI tool and `SKILL.md` for your isolated Ubuntu **Hermes Agent**, enabling on-demand conversational threat hunting over Loki (`TCP 3100`).
- **Self-Maintaining LLM Wiki (Karpathy Pattern + Google OKF)**: Includes a structured knowledge base under [`wiki/`](wiki/index.md) following Andrej Karpathy's *LLM Wiki* pattern and Google Cloud's *Open Knowledge Format (`okf/SPEC.md`)*, audited automatically by `pytest`.

---

## Tech Stack

- **Log Ingestion & Edge Aggregation**: [Vector](https://vector.dev/) (`timberio/vector:0.39.0-alpine`) using VRL (Vector Remap Language)
- **Log Storage**: [Grafana Loki](https://grafana.com/oss/loki/) (`grafana/loki:3.0.0`) with 30-day automatic TSDB retention
- **Visualization**: Integrates as a Data Source into your **existing Grafana server** (pre-built dashboard included)
- **AI Analyzer Service**: Python 3.12+, `anthropic` SDK (`>=2.2.0`), `httpx`, `pydantic` v2
- **Supported LLM Runtimes**: LM Studio, Ollama, vLLM, OpenAI, MiniMax, Anthropic, OpenRouter
- **Package & Environment Management**: [`uv`](https://docs.astral.sh/uv/), `pytest`, `ruff`
- **CI/CD**: GitHub Actions (`.github/workflows/ci.yml`) validating Python 3.12/3.13, Vector VRL syntax, OKF Wiki integrity, and Docker builds
- **Alerting**: Telegram Bot HTTP API + `[AI_REPORT]` stream ingestion back into Loki
- **Interactive SOC Agent**: Hermes Agent custom skill (`hermes_skill/`)

---

## Architecture

```mermaid
flowchart LR
    PFS["pfSense / OPNsense Firewall<br/>(Syslog UDP 5140)"] -->|Raw CSV filterlog + Auth| VEC["Vector<br/>(Docker Container)"]
    VEC -->|Tier 1 & 2: 1:1 JSON<br/>Tier 3: 60s Reduced JSON| LOKI["Grafana Loki<br/>(Docker - TCP 3100)"]
    LOKI <-->|Data Source| GRAF["Existing Grafana Server"]
    LOKI <-->|LogQL Poll (e.g. 15m)| PY["PfsenseMon Analyzer<br/>(Python Docker Container)"]
    PY -->|Only on Threshold Breach| LLM["AI SOC Analyst<br/>(Local LM Studio / Ollama / Cloud MiniMax / Claude)"]
    PY -->|Alert Notification| TG["Telegram Bot"]
    PY -->|Store AI Report| LOKI
    HERMES["Hermes Agent<br/>(Ubuntu VM - Isolated VLAN)"] -.->|FW Rule: TCP 3100 Only<br/>On-Demand Queries| LOKI
```

---

## Directory Structure

```text
PfsenseMon/
├── .github/
│   └── workflows/
│       └── ci.yml                   # GitHub Actions CI (Ruff, Pytest, Vector VRL validate, Docker build)
├── AGENTS.md                        # Project rules (Italian chat / English code & docs + OKF Wiki policy)
├── DESIGN.md                        # Architecture specification & decision log
├── LICENSE                          # Apache License 2.0
├── README.md                        # Complete setup & operations guide
├── pyproject.toml                   # Python project metadata & pytest/ruff config
├── docker-compose.yml               # Vector + Loki + Python Analyzer stack
├── .env.example                     # Environment variables template
├── config/
│   ├── vector/
│   │   └── vector.yaml              # Syslog UDP 5140 source, VRL parser, 3-Tier router & 60s reduce
│   ├── loki/
│   │   └── loki-config.yaml         # Loki TSDB configuration with 30-day retention
│   └── grafana/
│       └── dashboard-pfsense.json   # Ready-to-import Grafana dashboard JSON
├── analyzer/
│   ├── Dockerfile                   # Non-root Python 3.12 container image
│   ├── requirements.txt             # Python dependencies
│   └── src/
│       ├── __init__.py
│       ├── config.py                # Multi-provider configuration & URL normalization
│       ├── models.py                # Pydantic v2 data models & GeoIP metadata
│       ├── geoip.py                 # Post-filter batch GeoIP & ASN resolver
│       ├── loki_client.py           # LogQL query_range & report push client
│       ├── filter_engine.py         # Zero-Token threshold evaluator & TTL deduplication cache
│       ├── ai_analyst.py            # Multi-provider LLM client with JSON schema & thinking filter
│       ├── notifier.py              # Telegram Bot HTML notifier with paragraph chunking & auto-discovery
│       └── main.py                  # Periodic scheduler & CLI entrypoint
├── hermes_skill/
│   ├── SKILL.md                     # Hermes Agent skill definition
│   └── query_pfsense_loki.py        # Zero-dependency CLI script for Hermes Ubuntu VM with GeoIP
├── scripts/
│   └── simulate_pfsense_logs.py     # Synthetic pfSense UDP syslog generator for testing
├── tests/
│   ├── test_filter_engine.py        # Core unit tests (Zero-Token filter, dedup, URL normalization)
│   └── test_regressions.py          # Regression suite (Local LLMs, Structured Output, GeoIP, VRL & Wiki lint)
└── wiki/                            # Karpathy LLM Wiki + Google Cloud OKF Knowledge Base
    ├── index.md                     # Root OKF catalog (okf_version: "1.0") for progressive disclosure
    ├── log.md                       # Chronological project & operational log
    ├── SCHEMA.md                    # Wiki governance & OKF YAML frontmatter specification
    ├── concepts/                    # Architectural & security concepts
    ├── components/                  # Detailed component documentation
    ├── runbooks/                    # Operational & testing procedures
    └── raw/                         # Immutable verification traces & benchmark reports
```

---

## Prerequisites

- **Docker** and **Docker Compose v2** installed on the host running `PfsenseMon`.
- Network reachability from your **pfSense/OPNsense firewall** to the Docker host on **UDP port `5140`**.
- An AI Backend of your choice:
  - **Local Model**: [LM Studio](https://lmstudio.ai/) (v0.3+ recommended) or [Ollama](https://ollama.ai/) running on your host machine or LAN.
  - **Cloud API**: A **MiniMax API Key** ([platform.minimax.io](https://platform.minimax.io/)), **Anthropic API Key** ([console.anthropic.com](https://console.anthropic.com/)), or **OpenRouter API Key** ([openrouter.ai](https://openrouter.ai/)).
- A **Telegram Bot Token** (created via `@BotFather`) and a Telegram account to receive alerts.

---

## Step-by-Step Setup Guide

### Step 1: Configure Environment Variables

Copy `.env.example` to `.env`:

```bash
cp .env.example .env
```

Edit `.env` according to your preferred AI backend and network settings:

#### Option A: Local LM Studio (Recommended for macOS Apple Silicon & Privacy)

```dotenv
LLM_PROVIDER=openai
LLM_API_KEY=not-needed
LLM_BASE_URL=http://host.docker.internal:1234/v1
LLM_MODEL=google/gemma-4-12b
LLM_TIMEOUT_SECONDS=240
LLM_MAX_TOKENS=2500
LLM_STRUCTURED_OUTPUT=true
MAX_PROMPT_ITEMS_PER_TIER=15
```

> **LM Studio Best Practices**:
> 1. **Disable "Thinking" / Internal Reasoning**: When using Structured Output schemas, disabling the thinking feature in LM Studio allocates 100% of the token budget to actionable security findings, improving content density by **+345%**.
> 2. **Context Length**: Set Context Length in LM Studio to **16,384** tokens so the analyzer can inspect up to 15 top offenders simultaneously without hitting context limits.

#### Option B: Local Ollama

```dotenv
LLM_PROVIDER=ollama
LLM_BASE_URL=http://host.docker.internal:11434/v1
LLM_MODEL=qwen2.5:14b
LLM_TIMEOUT_SECONDS=180
LLM_MAX_TOKENS=2000
```

#### Option C: Cloud MiniMax / Anthropic Claude

```dotenv
LLM_PROVIDER=anthropic
ANTHROPIC_API_KEY=sk-cp-your-minimax-or-claude-key
ANTHROPIC_BASE_URL=https://api.minimax.io/anthropic
ANTHROPIC_MODEL=MiniMax-M3
LLM_MAX_TOKENS=2500
```

#### Option D: OpenRouter (Multi-Model Cloud Gateway)

```dotenv
LLM_PROVIDER=openrouter
OPENROUTER_API_KEY=sk-or-v1-your-key
LLM_MODEL=google/gemini-2.5-flash
```

---

### Step 2: Environment Variables Reference

| Variable | Description | Default / Example |
| :--- | :--- | :--- |
| `LLM_PROVIDER` | AI backend engine (`anthropic`, `ollama`, `openai`, `openrouter`) | `anthropic` |
| `LLM_API_KEY` | API key (required for cloud; leave blank/any text for local LM Studio & Ollama) | `sk-...` |
| `LLM_BASE_URL` | Base URL for the LLM endpoint | `http://host.docker.internal:1234/v1` |
| `LLM_MODEL` | Model identifier loaded in your provider | `google/gemma-4-12b` or `MiniMax-M3` |
| `LLM_STRUCTURED_OUTPUT` | Enforce OpenAI strict JSON schema (`json_schema`) | `true` |
| `LLM_TIMEOUT_SECONDS` | HTTP inference timeout in seconds (increase for local models) | `90` (cloud) / `240` (local) |
| `LLM_MAX_TOKENS` | Maximum completion tokens allocated to the AI report | `2500` |
| `AI_REPORT_LANGUAGE` | Language used by the AI exclusively for report fields | `Italian` |
| `ENABLE_GEOIP` | Automatically enrich anomalous external IPs with Country, ISP, and ASN | `true` |
| `MAX_PROMPT_ITEMS_PER_TIER` | Max number of top offenders included per security tier | `15` (or `5` for small models) |
| `TELEGRAM_BOT_TOKEN` | Telegram Bot token from `@BotFather` | `123456:AAF...` |
| `TELEGRAM_CHAT_ID` | Numeric Telegram chat ID (or bot username for auto-discovery) | `123456789` |
| `VECTOR_SYSLOG_PORT` | UDP port exposed for pfSense syslog | `5140` |
| `LOKI_HTTP_PORT` | TCP port exposed for Grafana & Hermes | `3100` |
| `ANALYSIS_INTERVAL_MINUTES` | Frequency of automated AI checks | `15` |
| `MAX_CATCHUP_MINUTES` | Max look-back to backfill windows missed during host sleep/downtime | `1440` |
| `WAN_BLOCK_HIT_THRESHOLD` | Blocked packets from 1 IP to trigger Tier 3 | `50` |
| `WAN_PORT_SCAN_THRESHOLD` | Distinct ports from 1 IP to flag a Port Scan | `8` |
| `ALERT_DEDUP_TTL_MINUTES` | Cooldown before re-alerting on the same offender | `120` |
| `WHITELIST_INTERNAL_IPS` | Comma-separated LAN IPs excluded from Tier 1 | `192.168.1.50` |
| `WHITELIST_OUTBOUND_PORTS` | Standard outbound ports excluded from Tier 1 pass | `53,80,123,443,465,587,853,993,51820,1194` |

> **Automatic Telegram `chat_id` Discovery**: If you don't know your numeric Telegram `chat_id`, put your bot's username in `TELEGRAM_CHAT_ID`, open Telegram, search for your bot, and press **Start (`/start`)**. On the next analysis cycle, `TelegramNotifier` automatically resolves your numeric ID via `/getUpdates`.

---

### Step 3: Start the Docker Compose Stack

Build and launch **Loki**, **Vector**, and the **Python AI Analyzer**:

```bash
docker compose up -d --build
```

Verify that all three containers are running and healthy:

```bash
docker compose ps
docker compose logs -f vector analyzer
```

---

### Step 4: Test the Pipeline End-to-End

Run the synthetic log generator inside the `analyzer` container to send realistic pfSense syslog packets (background noise, a 65-packet 12-port WAN scan, suspicious LAN outbound C2, and failed SSH/WebGUI logins) to Vector on `UDP 5140`:

```bash
docker compose exec analyzer python /app/scripts/simulate_pfsense_logs.py --host vector --port 5140 --scenario all
```

Wait ~60 seconds for Vector's `reduce` window to flush aggregated events to Loki, then trigger an analysis cycle:

```bash
# Dry-run check (verifies Loki query & Zero-Token filter without invoking the LLM):
docker compose exec analyzer python -m src.main --once --dry-run --reset-dedup

# Full live run (calls configured LLM, delivers Telegram alert, and archives report in Loki):
docker compose exec analyzer python -m src.main --once --reset-dedup
```

---

### Step 5: Configure pfSense Remote Syslog Forwarding

1. Log in to your **pfSense WebGUI**.
2. Navigate to **Status** → **System Logs** → **Settings**.
3. Scroll down to the **Remote Logging Options** section:
   - Check **Enable Remote Logging** (`Send log messages to remote syslog server`).
   - **Source Address**: Select your **LAN** interface (or the interface that can reach your Docker host).
   - **IP Protocol**: `IPv4`.
   - **Remote log servers**: Enter `<DOCKER_HOST_IP>:5140` (e.g., `192.168.1.20:5140`).
   - **Remote Syslog Contents**: Check:
     - ✅ **Firewall Events**
     - ✅ **System Events** / **General**
     - ✅ **SSH Daemon** / **Authentication**
     - ✅ **VPN Events** (OpenVPN / WireGuard / IPsec, if used)
4. Click **Save** at the bottom of the page.

> **Tip**: Under **Status → System Logs → Settings**, ensure **Log packets matched from the default block rules in the ruleset** is checked (enabled by default in pfSense).

---

### Step 6: Connect Your Existing Grafana Server

1. Open your existing **Grafana** web interface.
2. Go to **Connections** → **Data sources** → **Add new data source** → Select **Loki**.
3. Set the **HTTP URL** to:
   ```text
   http://<DOCKER_HOST_IP>:3100
   ```
4. Click **Save & test** (Grafana will confirm *"Data source successfully connected"*).
5. To import the ready-made dashboard:
   - Go to **Dashboards** → **New** → **Import**.
   - Upload [`config/grafana/dashboard-pfsense.json`](config/grafana/dashboard-pfsense.json).
   - Select your **Loki** data source and click **Import**.

---

### Step 7: Configure Hermes Agent (Isolated VLAN Integration)

To allow **Hermes Agent** (running on its isolated Ubuntu VM) to investigate pfSense logs on demand without exposing the rest of your network:

#### 7.1 Create the Scoped Firewall Rule on pfSense
1. In pfSense WebGUI, go to **Firewall** → **Rules** → Select the **Hermes VLAN** tab.
2. Click **Add** (top of the list, **above** any block/isolation rule):
   - **Action**: `Pass`
   - **Interface**: `Hermes VLAN`
   - **Address Family**: `IPv4`
   - **Protocol**: `TCP`
   - **Source**: `Single host or alias` → `<HERMES_UBUNTU_VM_IP>`
   - **Destination**: `Single host or alias` → `<DOCKER_HOST_IP>`
   - **Destination Port Range**: `3100` to `3100`
   - **Description**: `Allow Hermes Agent read-only query access to PfsenseMon Loki`
3. Click **Save** and **Apply Changes**.

#### 7.2 Install the Skill on the Hermes Ubuntu VM
Copy the `hermes_skill` folder to your Hermes skills directory on the Ubuntu VM:

```bash
mkdir -p ~/.hermes/skills/pfsense-security-monitor
cp hermes_skill/SKILL.md hermes_skill/query_pfsense_loki.py ~/.hermes/skills/pfsense-security-monitor/
chmod +x ~/.hermes/skills/pfsense-security-monitor/query_pfsense_loki.py
```

Add `LOKI_URL` to `~/.hermes/.env` on the Ubuntu VM:

```bash
echo "LOKI_URL=http://<DOCKER_HOST_IP>:3100" >> ~/.hermes/.env
```

Test connectivity directly from the Hermes Ubuntu VM:

```bash
python3 ~/.hermes/skills/pfsense-security-monitor/query_pfsense_loki.py summary --hours 24
```

Now you can message Hermes on Telegram at any time:
- *"Hermes, dammi un riassunto della sicurezza di pfSense nelle ultime 24 ore."*
- *"Hermes, controlla su Loki cosa ha fatto l'IP 185.220.101.42 negli ultimi 7 giorni e fai un whois."*
- *"Hermes, ci sono stati dispositivi interni con traffico sospetto in uscita oggi?"*

---

## Local LLM Benchmark & Comparative Performance

We conducted extensive live evaluations using real pfSense production traffic (3,800+ events) running across local models in **LM Studio** (Apple Silicon) and cloud backends:

| Model | Host / Runtime | Context Size | Inference Time | Tokens In / Out | SOC Quality & Remediation |
| :--- | :--- | :--- | :--- | :--- | :--- |
| **`google/gemma-4-12b`** *(Thinking Off)* | LM Studio (Local) | 16,384 | **~1m 13s** | 5,800 / **498** | **Best for Incident Response**: Isolated internal compromised host (`172.16.30.16`), mapped lateral target, issued concrete mitigation steps. |
| **`qwen/qwen3.5-9b`** *(Thinking Off)* | LM Studio (Local) | 16,384 | **~1m 19s** | 5,508 / **916** | **Best for Forensic Depth**: Granular breakdown of all 15 WAN offenders, targeted ports, hit counts, and ASN details. |
| **`google/gemma-4-e4b`** (4B) | LM Studio (Local) | 8,192 | **~39s** | 2,500 / ~300 | **Fast Lightweight**: Low resource usage; good detection but more generic recommendations. |
| **`MiniMax-M3`** | Cloud (Anthropic API) | 128,000 | **~6s** | 1,670 / 1,261 | **High Speed Cloud**: Extremely fast response with detailed explanations. |

> Detailed empirical notes, exact JSON payloads, and parameter comparisons are available in the [Local LLM Benchmark Report](wiki/raw/2026-10-24-local-llm-benchmark.md).

---

## Local Development, Testing & CI (`uv` + `pytest` + GitHub Actions)

### 1. Set Up the Local Virtual Environment with `uv`

```bash
uv venv
uv pip install -r analyzer/requirements.txt pytest ruff
source .venv/bin/activate
```

### 2. Run Linter and Unit/Regression Tests

```bash
ruff check analyzer hermes_skill scripts tests
pytest -v
```

The test suite (**19 unit & regression tests** across [`tests/test_filter_engine.py`](tests/test_filter_engine.py) and [`tests/test_regressions.py`](tests/test_regressions.py)) validates:
- **Zero-Token Pre-Filter & Whitelists**: Guarantees `0` API calls when traffic is within normal bounds.
- **Port-Scan Detection & TTL Deduplication Cache**: Ensures multi-port scanners trigger once and respect cooldown windows.
- **Multi-Provider & Local LLM Support**: Tests Ollama without API keys, OpenRouter headers, LM Studio OpenAI endpoint routing, and `<think>` block stripping.
- **Strict Structured Output (`json_schema`)**: Verifies schema payload generation and graceful fallback retry if an endpoint rejects `response_format`.
- **Batch GeoIP & ASN Resolution**: Validates RFC1918 local filtering and batch attribution parsing.
- **Telegram Auto-Discovery & HTML Paragraph Chunking**: Tests automatic numeric `chat_id` resolution, entity escaping, and chunking of long messages.
- **Vector VRL Static Guard & OKF Wiki Integrity Linter**: Verifies `config/vector/vector.yaml` contains no fallible VRL anti-patterns and audits all files in [`wiki/`](wiki/index.md) for valid OKF YAML frontmatter and unbroken Markdown links.

### 3. Continuous Integration (`.github/workflows/ci.yml`)

Every `push` and `pull_request` to `main` triggers two automated GitHub Actions jobs:
1. **`lint-and-test`**: Runs `ruff check` and `pytest -v` across Python `3.12` and `3.13` using `astral-sh/setup-uv@v5`.
2. **`validate-vector-and-docker`**: Validates `config/vector/vector.yaml` using the official `timberio/vector:0.39.0-alpine` container (`validate --no-environment`) and builds the `analyzer` Docker image.

---

## Project Knowledge Base (`wiki/`)

This repository maintains a self-compounding **LLM Wiki** under [`wiki/`](wiki/index.md) combining:
- **[Andrej Karpathy's LLM Wiki Pattern](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f)** (`ingest`, `query`, `lint` workflows + immutable `raw/` evidence)
- **[Google Cloud Open Knowledge Format (OKF)](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)** (`okf_version: "1.0"`, YAML frontmatter, progressive disclosure via [`wiki/index.md`](wiki/index.md), and chronological tracking via [`wiki/log.md`](wiki/log.md)).

---

## Troubleshooting

### 1. No Logs Appearing in Loki from pfSense
- Verify UDP packets are reaching the Docker host on port `5140`:
  ```bash
  sudo tcpdump -ni any udp port 5140
  ```
- Check Vector logs for parsing status:
  ```bash
  docker compose logs -f vector
  ```

### 2. Analyzer Reports "Skipping AI API Call (0 Tokens Spent)"
- This is normal when the **Zero-Token Filter** detects no anomalies exceeding thresholds or when the same offender is within the `ALERT_DEDUP_TTL_MINUTES` cooldown window.
- To force a fresh test alert ignoring the deduplication cooldown, run:
  ```bash
  docker compose exec analyzer python -m src.main --once --reset-dedup
  ```

### 3. LM Studio / Local LLM Returning HTTP 400 (Context Length Exceeded)
- If LM Studio returns `The number of tokens to keep from the initial prompt is greater than the context length`, increase the model's **Context Length** in LM Studio (under the Model Settings tab) to **16,384** or lower `MAX_PROMPT_ITEMS_PER_TIER=5` in `.env`.

### 4. LM Studio / Local LLM Timeout
- If large local models take longer than 90 seconds to complete inference, increase `LLM_TIMEOUT_SECONDS=240` in `.env` and restart the analyzer container (`docker compose up -d analyzer`).

---

## License

This project is licensed under the **Apache License 2.0** — see the [`LICENSE`](LICENSE) file for details.
