---
type: Architecture Concept
title: 3-Tier Hybrid Monitoring Strategy
description: Multi-tier classification model that separates high-priority outbound/auth events from noisy WAN block events.
resource: config/vector/vector.yaml
tags:
  - security
  - pfsense
  - wan
  - lan
  - classification
timestamp: 2026-10-23T20:25:00Z
---

# 3-Tier Hybrid Monitoring Strategy

A public-facing **pfSense** WAN interface receives thousands of automated scan packets per day ("Internet background radiation"). Forwarding raw firewall block logs directly to an LLM wastes context window tokens and obscures genuine compromise indicators.

To solve this, **PfsenseMon** classifies every incoming syslog event inside the [Vector Syslog & VRL Pipeline](../components/vector-pipeline.md) into three distinct security tiers before indexing in [Grafana Loki](../components/loki-and-grafana.md).

---

## Tier Definitions

### 🔴 Tier 1: Suspicious Outbound & Internal Lateral Traffic (`tier_1_outbound_suspicious`)
- **What it captures**:
  1. **`outbound_blocked`**: Traffic originating from an internal RFC1918 IP (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) heading to a public WAN IP that was **blocked** by pfSense firewall rules or `pfBlockerNG`.
  2. **`outbound_uncommon_port`**: Allowed outbound connections from an internal host to a destination port **not** in `WHITELIST_OUTBOUND_PORTS` (default benign ports: `53, 80, 123, 443, 465, 587, 853, 993, 51820, 1194`).
  3. **`internal_lateral_blocked`**: Blocked traffic between internal private subnets/VLANs (excluding benign local broadcast discovery ports `137, 138, 1900, 5353`).
- **Retention Granularity**: **1:1 (No aggregation loss)**.
- **Security Rationale**: Compromised LAN/IoT devices, reverse shells, and Command-and-Control (C2) beacons reveal themselves when attempting outbound connections on non-standard ports or hitting egress block rules.

### 🟠 Tier 2: Authentication & Allowed WAN Access (`tier_2_access_and_auth`)
- **What it captures**:
  1. **`pfsense_auth_daemon`**: Control-plane and authentication logs from `sshd`, `webConfigurator` (`php-fpm`), `openvpn`, `wireguard`, and `charon` (IPsec).
  2. **`wan_inbound_pass`**: Any inbound packet from a public IP on the WAN with `action="pass"`.
- **Retention Granularity**: **1:1 (No aggregation loss)**.
- **Security Rationale**: Tracks brute-force attempts against administrative interfaces and monitors traffic entering exposed port-forwards or VPN endpoints.

### 🟡 Tier 3: Blocked Inbound WAN Traffic (`tier_3_wan_blocked`)
- **What it captures**:
  - **`wan_inbound_block`**: Inbound packets from external public IPs blocked by pfSense (`action="block"`).
- **Retention Granularity**: **Aggregated in 60-second windows** by `(src_ip, dst_port, proto, interface)` with a summed `hit_count` counter.
- **Security Rationale**: Compresses repetitive port scans and botnet noise by ~90% while preserving exact packet counts (`hit_count`) and targeted port diversity for the [Zero-Token Pre-Filter](zero-token-filter.md) and Grafana charts.

---

## Related Pages

- [Vector Syslog & VRL Pipeline](../components/vector-pipeline.md)
- [Zero-Token Pre-Filter & Deduplication](zero-token-filter.md)
- [Python AI Analyzer & MiniMax Integration](../components/ai-analyzer-minimax.md)
