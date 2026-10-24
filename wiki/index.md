---
okf_version: "1.0"
---

# PfsenseMon Knowledge Base Index

Welcome to the **PfsenseMon** LLM Wiki & Open Knowledge Format (OKF) catalog. Agents and developers should read this file first for **progressive disclosure** before navigating to specific concept, component, or runbook pages.

## Governance & Logs

- [Wiki Schema & OKF Specification](SCHEMA.md) — Rules for maintaining this wiki (`ingest`, `query`, `lint`) and OKF YAML frontmatter standards.
- [Chronological Project Log](log.md) — Append-only timeline of architectural decisions, implementation phases, bug fixes, and live verification milestones.
- [Project Design Specification](../DESIGN.md) — Original brainstorming understanding lock, assumptions, and architectural decision log.

## Architectural & Security Concepts (`concepts/`)

- [3-Tier Hybrid Monitoring Strategy](concepts/three-tier-hybrid-strategy.md) — Classification of pfSense traffic into Tier 1 (Suspicious Outbound/Lateral), Tier 2 (Auth & Allowed WAN), and Tier 3 (60s Aggregated WAN Blocks).
- [Zero-Token Pre-Filter & Deduplication](concepts/zero-token-filter.md) — Local Python threshold evaluation and TTL anti-spam cache that prevents unnecessary LLM API calls when traffic is normal.

## System Components (`components/`)

- [Vector Syslog & VRL Pipeline](components/vector-pipeline.md) — Ingestion on `UDP 5140`, CSV `filterlog` parsing, RFC1918 IP detection, and 60-second `reduce` aggregation (`config/vector/vector.yaml`).
- [Grafana Loki & Dashboard Integration](components/loki-and-grafana.md) — Single-binary TSDB storage with 30-day retention (`config/loki/loki-config.yaml`) and ready-to-import dashboard for the existing Grafana server (`config/grafana/dashboard-pfsense.json`).
- [Python AI Analyzer, Multi-Provider LLM & GeoIP Enrichment](components/ai-analyzer-minimax.md) — Custom Python 3.12 service supporting `anthropic` (MiniMax/Claude), `ollama` (local), `openai` (LM Studio/vLLM/OpenAI), and `openrouter`, plus post-filter GeoIP/ASN enrichment and Telegram Bot alerting (`analyzer/`).
- [Hermes Agent Interactive SOC Skill](components/hermes-agent-skill.md) — Zero-dependency CLI tool (`hermes_skill/query_pfsense_loki.py`) allowing the isolated Ubuntu Hermes Agent to query Loki over `TCP 3100`.

## Operational Runbooks (`runbooks/`)

- [pfSense Configuration & End-to-End Testing Runbook](runbooks/pfsense-and-e2e-testing.md) — Step-by-step instructions for pfSense Syslog forwarding, VLAN firewall rules, synthetic traffic generation (`scripts/simulate_pfsense_logs.py`), and `uv` test execution.

## Raw Evidence & Verification Snapshots (`raw/`)

- [2026-10-23 End-to-End Live Verification (MiniMax-M3 + Telegram)](raw/2026-10-23-e2e-verification-minimax.md) — Immutable log trace and JSON output from the first live end-to-end test across Vector, Loki, `MiniMax-M3`, and Telegram.
- [2026-10-24 Local LLM Benchmark & Comparison (LM Studio)](raw/2026-10-24-local-llm-benchmark.md) — Empirical benchmark and comparative analysis of local LLMs (Gemma 4B, Qwen 9B, Gemma 12B) and cloud MiniMax-M3 running live pfSense security telemetry with Structured Output.
