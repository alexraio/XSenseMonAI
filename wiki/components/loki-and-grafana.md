---
type: Component
title: Grafana Loki & Dashboard Integration
description: TSDB single-binary log storage with 30-day retention and pre-built Grafana dashboard JSON.
resource: config/loki/loki-config.yaml
tags:
  - loki
  - grafana
  - storage
  - dashboard
timestamp: 2026-10-24T14:44:00Z
---

# Grafana Loki & Dashboard Integration

**PfsenseMon** runs `grafana/loki:3.0.0` (`pfsensemon-loki`) on port `TCP 3100` and connects as a Data Source to the user's **existing Grafana server**, avoiding duplicate Grafana deployments.

---

## 1. Loki Configuration & Storage Bounds (`config/loki/loki-config.yaml`)

- **Schema**: `v13` TSDB single-store on local Docker volume `loki_data:/loki`.
- **Automatic Retention**: `retention_enabled: true` in the Compactor (`compaction_interval: 10m`) with `retention_period: 720h` (**30 days**).
- **Memory & Disk Bounds**:
  - Loki embedded query results cache capped at `max_size_mb: 100`.
  - Vector disk buffer (`vector_data`) capped at `256 MB` (`max_size: 268435488`, `when_full: drop_newest`).
  - Docker container stdout/stderr logs (`json-file` driver in [`docker-compose.yml`](../../docker-compose.yml)) rotated at `max-size: "10m"` and `max-file: "3"` (`30 MB` max per container).
- **Indexed Stream Labels**:
  - `app="pfsense"`
  - `security_tier` (`tier_1_outbound_suspicious`, `tier_2_access_and_auth`, `tier_3_wan_blocked`, `ai_report`)
  - `sub_type` (`outbound_blocked`, `outbound_uncommon_port`, `internal_lateral_blocked`, `pfsense_auth_daemon`, `wan_inbound_pass`, `wan_inbound_block`)
  - `action` (`block`, `pass`, `auth`)
  - `direction` (`in`, `out`)

---

## 2. Grafana Dashboard (`config/grafana/dashboard-pfsense.json`)

Importable directly into the existing Grafana server (`Dashboards -> New -> Import`):
- **Stat Panels**:
  - *Tier 1: Suspicious Outbound Events*
  - *Tier 2: Auth & Allowed WAN Events*
  - *Tier 3: Total Blocked WAN Packets (Aggregated)* — uses `sum(sum_over_time({app="pfsense", security_tier="tier_3_wan_blocked"} | json | unwrap hit_count [$__range]))` to reconstruct exact packet counts from Vector's 60-second summaries.
- **Log Panels**:
  - *🧠 Claude / MiniMax AI Security Reports* (`{app="pfsense", security_tier="ai_report"}`)
  - *🔴 Tier 1 Stream*, *🟠 Tier 2 Stream*, and *🟡 Tier 3 Pre-Aggregated Stream*.

---

## Related Pages

- [Vector Syslog & VRL Pipeline](vector-pipeline.md)
- [Python AI Analyzer & MiniMax Integration](ai-analyzer-minimax.md)
- [Hermes Agent Interactive SOC Skill](hermes-agent-skill.md)
