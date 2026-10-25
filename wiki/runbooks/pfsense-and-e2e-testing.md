---
type: Runbook
title: Quick-Start Wizard, pfSense Configuration & E2E Testing Runbook
description: Operational procedures for the interactive setup.sh onboarding wizard, pfSense Syslog configuration, synthetic smoke tests, and uv/pytest verification.
resource: setup.sh
tags:
  - runbook
  - setup-wizard
  - pfsense
  - testing
  - uv
  - docker
timestamp: 2026-10-25T12:12:00Z
---

# Quick-Start Wizard, pfSense Configuration & E2E Testing Runbook

## 0. Interactive Quick-Start & Onboarding Wizard (`./setup.sh`)

Run [`setup.sh`](../../setup.sh) from the project root to perform automated pre-flight checks, interactive `.env` generation (`0600` permissions, live `/v1/models` and Telegram `/getUpdates` auto-discovery), Docker Compose startup, and two-speed E2E smoke testing:

```bash
# Interactive full onboarding flow
./setup.sh

# Non-destructive pre-flight & .env validation only
./setup.sh --check

# Run interactive E2E smoke test (Fast ~10s or Full ~65s) on active containers
./setup.sh --test-only
```

---

## 1. Local Development, Regression Tests & CI (`uv` + GitHub Actions)

Activate the `uv` virtual environment and run the unit & regression test suite ([`tests/test_filter_engine.py`](../../tests/test_filter_engine.py), [`tests/test_regressions.py`](../../tests/test_regressions.py), [`tests/test_scheduler_and_redaction.py`](../../tests/test_scheduler_and_redaction.py), and [`tests/test_setup_wizard.py`](../../tests/test_setup_wizard.py)):

```bash
source .venv/bin/activate
ruff check analyzer hermes_skill scripts tests
pytest -v
```

### What the Regression Suite Covers (`tests/test_regressions.py`)
1. **MiniMax-M3 SDK Compatibility**: Ensures `temperature` is never passed to `messages.create()` and `thinking` blocks are ignored when parsing JSON.
2. **Telegram Bot Auto-Discovery & HTML Escaping**: Verifies non-numeric `TELEGRAM_CHAT_ID` resolution via `/getUpdates` and safe escaping of `<`, `>`, `&`.
3. **Zero-Token Guarantee & Raw Fallback**: Verifies 0 LLM calls on low-volume noise and automatic raw fallback alerts if the LLM endpoint fails.
4. **Loki Stream Parsing**: Verifies multi-stream JSON and raw syslog fallback parsing.
5. **Vector VRL Static Guard & OKF Wiki Linter**: Verifies [`config/vector/vector.yaml`](../../config/vector/vector.yaml) contains no fallible VRL anti-patterns and automatically audits all `wiki/` pages for valid OKF frontmatter, `wiki/index.md` coverage, and unbroken relative Markdown links.

### GitHub Actions CI (`.github/workflows/ci.yml`)
On every `push` and `pull_request` to `main`, GitHub Actions runs:
- **`lint-and-test`**: Matrix across Python `3.12` and `3.13` using `astral-sh/setup-uv@v5`, running `ruff check` and `pytest -v`.
- **`validate-vector-and-docker`**: Validates `config/vector/vector.yaml` inside `timberio/vector:0.39.0-alpine` (`validate --no-environment`) and tests `docker compose build analyzer`.

---

## 2. Launching & Managing the Docker Stack

```bash
# Start or update all containers
docker compose up -d --build

# Check container health
docker compose ps

# Follow live logs
docker compose logs -f vector analyzer
```

---

## 3. End-to-End Synthetic Pipeline Verification

Use [`scripts/simulate_pfsense_logs.py`](../../scripts/simulate_pfsense_logs.py) to inject synthetic pfSense `filterlog` and `sshd`/`php-fpm` events into [Vector](../components/vector-pipeline.md):

```bash
# 1. Inject all 4 traffic scenarios (noise, WAN portscan, LAN->WAN C2 port 4444, SSH/WebGUI auth errors)
docker compose exec analyzer python /app/scripts/simulate_pfsense_logs.py --host vector --port 5140 --scenario all

# 2. Wait ~60 seconds for Vector's Tier 3 reduce window to flush to Loki

# 3. Trigger an immediate AI analysis & Telegram alert (resetting deduplication cache)
docker compose exec analyzer python -m src.main --once --reset-dedup
```

---

## 4. pfSense Remote Syslog Configuration

1. In pfSense WebGUI, navigate to **Status → System Logs → Settings**.
2. Enable **Send log messages to remote syslog server**.
3. Set **Remote log servers** to `<DOCKER_HOST_IP>:5140`.
4. Select **Firewall Events**, **System Events**, **SSH Daemon**, and **VPN Events**.
5. Click **Save**.

---

## Related Pages

- [Vector Syslog & VRL Pipeline](../components/vector-pipeline.md)
- [Python AI Analyzer & MiniMax Integration](../components/ai-analyzer-minimax.md)
- [2026-10-23 End-to-End Live Verification](../raw/2026-10-23-e2e-verification-minimax.md)
