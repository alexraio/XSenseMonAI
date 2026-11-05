---
type: Architecture Concept
title: Multi-Source DNS Resolver Telemetry & FQDN Flow Correlation
description: Decoupled, router-agnostic DNS ingestion, flow-to-domain attribution, and Zero-Token DNS anomaly detection architecture.
resource: config/vector/vector.yaml
tags:
  - dns
  - unbound
  - dnsmasq
  - fqdn-correlation
  - dga-detection
  - zero-token
timestamp: 2026-10-27T17:10:00Z
---

# Multi-Source DNS Resolver Telemetry & FQDN Flow Correlation

## 1. Overview & Problem Statement

PfsenseMon natively processes Layer 3 and Layer 4 firewall events (`filterlog`), capturing:
$$\text{Source IP:Port} \longrightarrow \text{Destination IP:Port}$$

In modern cloud and Content Delivery Network (CDN) architectures (e.g. Cloudflare, AWS CloudFront, Fastly, Akamai), thousands of distinct websites and services share the exact same Anycast IP address. This causes **"firewall blindness"**:
1. An internal host connecting to `198.51.100.231:443` could be synchronizing an IoT temperature sensor (`api.tuya.com`), checking the weather, or communicating with a malware Command & Control (C2) node.
2. Inbound and outbound malware employing **Domain Generation Algorithms (DGA)** generates hundreds of pseudorandom domains per day. When these domains do not exist, the resolver responds with `NXDOMAIN`, meaning no Layer 3/4 packet is ever emitted. The firewall remains completely blind to the reconnaissance activity.
3. Exfiltration via **DNS Tunneling** transmits encoded payloads inside subdomains over standard UDP/TCP port 53 without triggering standard firewall drop rules.

By ingesting DNS resolver query logs, PfsenseMon captures intent *at the name resolution layer* before network connections occur, and exposes threats that never establish an L3/L4 connection.

---

## 2. Multi-Router Compatibility & Universal Ingestion

DNS setups vary substantially across home and small-office environments:
- **pfSense & OPNsense**: Standardized on **Unbound** as the native recursive resolver with syslog query logging.
- **OpenWrt & Ubiquiti UniFi**: Standardized on **dnsmasq** (or lightweight embedded resolvers).
- **MikroTik RouterOS**: Proprietary DNS cache with remote syslog topics.
- **Dedicated Sinkholes**: Many homelabbers run **Pi-hole** (`FTL`) or **AdGuard Home** on separate containers or Raspberry Pis.

### Universal Normalizer Architecture (Vector)
To avoid hardcoding PfsenseMon to Unbound, Vector acts as the universal normalizer:
1. Listens on a dedicated syslog port (`UDP 5141`) to completely decouple DNS ingestion from `UDP 5140` firewall telemetry.
2. Applies a Vector Remap Language (VRL) transform that maps router-specific lines into a standard schema:
   ```json
   {
     "event_type": "dns_query",
     "client_ip": "192.168.1.145",
     "query_domain": "api.tuya.com",
     "qtype": "A",
     "rcode": "NOERROR",
     "resolved_ips": ["198.51.100.231"],
     "timestamp": "2026-10-27T16:00:00Z"
   }
   ```
3. Reduces repetitive `NOERROR` queries over 60-second windows while forwarding all errors (`NXDOMAIN`, `SERVFAIL`) and unique IP mappings to Grafana Loki stream `{service="dns"}` with a dedicated 7-day retention policy.

---

## 3. Correlation & Zero-Token Anomaly Detection

During the periodic analysis window (e.g. 60 minutes), the Python Analyzer executes a two-phase evaluation:

### Phase 1: Flow-to-Domain Attribution (FQDN Mapping)
- The analyzer queries Loki for `{service="dns"}` over the active window and builds an in-memory dictionary:
  $$(\text{client\_ip}, \text{resolved\_ip}) \longrightarrow \text{query\_domain}$$
- When [`analyzer/src/filter_engine.py`](../../analyzer/src/filter_engine.py) processes Tier 1 outbound anomalies or Tier 3 WAN offenders, it resolves the destination IP to its corresponding domain name, populating `resolved_domain`.
- The AI Analyst prompt converts generic IP alerts into human-readable narratives:
  > *"Host `192.168.1.145` opened an unusual outbound connection to `198.51.100.77:4444`. DNS telemetry reveals this destination was resolved seconds prior as `malicious-dga-node.biz`, confirming active C2 beaconing."*

### Phase 2: Native DNS Anomaly Detection (Zero-Token Guarantees)
The analyzer mathematically inspects query patterns per client before invoking the LLM:
1. **`NXDOMAIN` Storms**: Flags clients receiving $\ge 15$ unique `NXDOMAIN` errors within the window (indicating malware DGA sweeping or misconfigured beaconing).
2. **Shannon Entropy (DGA Identification)**: Evaluates character randomness on queried domain names. Domains with high entropy and consonant-to-vowel imbalances are marked as DGA candidates.
3. **Tunneling Heuristics**: Detects abnormal subdomain length ($> 50$ characters) or bursts of `TXT` queries.
4. **Local Noise Filtering**: Automatically ignores local network suffixes (`.lan`, `.local`, `.home.arpa`, `in-addr.arpa`).

If all DNS metrics are within baseline and no firewall rules were violated, **0 LLM tokens are consumed**.

---

## 4. Operational Boundaries (Non-Goals)

1. **Strictly Passive Monitoring**: PfsenseMon never injects DNS responses, alters resolver configurations, or acts as a recursive DNS server.
2. **No Active Sinkholing**: PfsenseMon does not maintain blocklists or mutate Pi-hole/`pfBlockerNG` configurations.
3. **Fail-Open Resilience**: If DNS logging is disabled or absent, the pipeline logs an `INFO` note and continues monitoring firewall traffic uninterrupted.

---

## 5. Related Components & Concepts

- [3-Tier Hybrid Monitoring Strategy](three-tier-hybrid-strategy.md) — Base L3/L4 firewall classification engine.
- [Zero-Token Pre-Filter & Deduplication](zero-token-filter.md) — Cost and alert management philosophy.
- [Vector Syslog & VRL Pipeline](../components/vector-pipeline.md) — Syslog edge processor.
- [Project Design Specification](../../DESIGN.md) — Section 8 architectural decision log.
