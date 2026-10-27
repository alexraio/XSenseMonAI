---
type: Architecture Concept
title: Zero-Token Pre-Filter & Deduplication
description: Local deterministic threshold evaluator, granular Known Flows store, and TTL anti-spam cache that prevent unnecessary LLM calls and alert fatigue.
resource: analyzer/src/filter_engine.py
tags:
  - cost-control
  - zero-token
  - deduplication
  - known-flows
  - python
timestamp: 2026-10-27T13:18:00Z
---

# Zero-Token Pre-Filter & Deduplication

Instead of running an autonomous LLM cron job that wakes up an agent session every 15 minutes (which would consume tokens 96 times per day even when the network is quiet), **PfsenseMon** uses a deterministic Python pre-filter (`ZeroTokenFilterEngine` in [`analyzer/src/filter_engine.py`](../../analyzer/src/filter_engine.py)).

---

## 1. How the Zero-Token Pre-Filter Works

Every `ANALYSIS_INTERVAL_MINUTES` (default: `15`), the [Python AI Analyzer](../components/ai-analyzer-minimax.md) queries [Grafana Loki](../components/loki-and-grafana.md) and evaluates events across the [3-Tier Hybrid Monitoring Strategy](three-tier-hybrid-strategy.md):

1. **Tier 1 Check**: Counts non-whitelisted `tier_1_outbound_suspicious` flows. Triggers if count $\ge$ `OUTBOUND_SUSPICIOUS_THRESHOLD` (default: `1`).
2. **Tier 2 Check**: Counts non-whitelisted `tier_2_access_and_auth` event groups. Triggers if count $\ge$ `AUTH_EVENT_THRESHOLD` (default: `1`).
3. **Tier 3 Check**: Sums `hit_count` and counts distinct `dst_port` values per external `src_ip`:
   - Flags **`is_high_volume = True`** if `total_blocked_hits` $\ge$ `WAN_BLOCK_HIT_THRESHOLD` (default: `50`).
   - Flags **`is_port_scanner = True`** if `distinct_ports_count` $\ge$ `WAN_PORT_SCAN_THRESHOLD` (default: `8`).

If none of the three conditions are met after applying whitelists and deduplication, `should_invoke_ai` is `False` and **0 API tokens are spent**.

---

## 2. Anti-Spam Deduplication Cache (`DeduplicationCache`)

When an external scanner attacks the WAN continuously for hours, re-alerting on the exact same IP every 15 minutes causes alert fatigue.
- `DeduplicationCache` persists alerted keys (`tier1:<src>:<dst>:<port>:<subtype>`, `tier2:<src>:<subtype>:<port>`, `tier3:<src>:<scan|flood>`) with a configurable cooldown `ALERT_DEDUP_TTL_MINUTES` (default: `120` minutes) in `/app/state/dedup_cache.json`.
- During manual testing, the cache can be cleared with the `--reset-dedup` CLI flag.

---

## 3. Context Window Protection

Before constructing the prompt for `MiniMax-M3` / Claude, `ZeroTokenFilterEngine` sorts offenders by hit volume and truncates each tier to `MAX_PROMPT_ITEMS_PER_TIER` (default: `25`). Even during a massive distributed scan involving thousands of IPs, the prompt size remains bounded (~1,000–1,500 tokens).

---

## 4. Granular Known Flows & LLM Topology Context (`KnownFlowsStore`)

Coarse source-IP whitelisting (`WHITELIST_INTERNAL_IPS`) is restricted solely to allowed `outbound_uncommon_port` connections (`action == "pass"`) so it never masks blocked inter-VLAN lateral movement (`internal_lateral_blocked`) or blocked outbound connections (`outbound_blocked`).

For router-agnostic, fine-grained suppression of known benign flows (e.g., an IoT smart display probing a media player across VLANs), [`analyzer/src/known_flows.py`](../../analyzer/src/known_flows.py) provides `KnownFlowsStore`:

1. **Hot-Reloaded Structured Store (`config/known_flows.json`)**:
   - Each `KnownFlowRule` has a deterministic `id` (`flow-<8hex>`), `enabled` toggle, `src_ip` (exact IP, CIDR subnet, or `*`), optional `src_ports`, `dst_ip`, `ports` (ports or `start-end` ranges), `proto`, and human-readable `description`.
   - Also supports compact `.env` rules (`WHITELIST_FLOWS=172.16.0.10>192.168.1.50:443,8080`) and CLI CRUD commands (`--list-flows`, `--add-flow`, `--remove-flow`).
2. **Dual Role (Zero-Token + LLM Enrichment)**:
   - **Zero-Token Pre-Filter**: Matching Tier 1 events are suppressed deterministically before threshold evaluation (`0` tokens spent).
   - **Source-Port (`src_ports`) Attribution for P2P/DHT Disambiguation**: `OutboundAnomalySummary` preserves up to 5 distinct `src_ports` per Tier 1 flow group so the LLM distinguishes fixed daemon/P2P source ports (e.g., `6881/UDP` BitTorrent Mainline DHT hitting random peer ports blocked by `pfBlockerNG`) from genuine malware C2 callbacks.
   - **LLM Topology Context**: When an involved host triggers an alert on an *unlisted* port (e.g. `22/SSH`), `known_authorized_flows` is injected into the LLM payload so the analyst knows the device's baseline role.
   - **Copy-Pasteable Telegram Suggestions**: Whenever Tier 1 anomalies occur, `TelegramNotifier` appends a consolidated one-tap copyable JSON snippet (`Known Flow Suppression`) grouped by `(src_ip, dst_ip)` or by fixed `src_ports` when a single daemon port contacts multiple external IPs.

---

## Related Pages

- [3-Tier Hybrid Monitoring Strategy](three-tier-hybrid-strategy.md)
- [Python AI Analyzer & MiniMax Integration](../components/ai-analyzer-minimax.md)
