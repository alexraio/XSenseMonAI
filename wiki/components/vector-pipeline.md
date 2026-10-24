---
type: Component
title: Vector Syslog & VRL Pipeline
description: High-performance UDP 5140 Syslog receiver, pfSense filterlog CSV parser, 3-Tier router, and 60-second reduce aggregator.
resource: config/vector/vector.yaml
tags:
  - vector
  - vrl
  - syslog
  - pfsense
  - aggregation
timestamp: 2026-10-23T20:25:00Z
---

# Vector Syslog & VRL Pipeline

The `pfsensemon-vector` container (`timberio/vector:0.39.0-alpine`) is the ingestion and edge-aggregation engine of **PfsenseMon**, configured via [`config/vector/vector.yaml`](../../config/vector/vector.yaml).

---

## Pipeline Stages

1. **`pfsense_syslog` (Source)**:
   - Listens on `0.0.0.0:5140/UDP` (`type: socket`). Using a raw UDP socket with VRL regex extraction avoids strict RFC 5424 header rejections when pfSense is configured in default BSD (RFC 3164) syslog mode.
2. **`parse_and_classify` (VRL Remap Transform)**:
   - **Branch A (`filterlog`)**: Extracts the comma-separated payload after `filterlog[pid]:`, parses IPv4 (`ip_ver == "4"`) and IPv6 (`ip_ver == "6"`) fields (`interface`, `action`, `direction`, `proto`, `src_ip`, `dst_ip`, `src_port`, `dst_port`, `tcp_flags`), drops multicast/broadcast/IGMP chatter, drops out-of-state TCP teardown packets (`proto == "tcp" && action == "block" && !contains(tcp_flags, "S")`, such as `FA`, `FPA`, `A`, `R` from expired stateful sessions), and detects private RFC1918 vs public IPs using `is_ipv4()` and `ip_cidr_contains()`.
   - **Branch B (Auth Daemons)**: Matches control-plane logs (`sshd`, `openvpn`, `wireguard`, `charon`, `webConfigurator`, authentication errors) and extracts referenced IPv4 addresses.
   - Assigns `.security_tier` according to the [3-Tier Hybrid Monitoring Strategy](../concepts/three-tier-hybrid-strategy.md).
3. **`route_by_tier` (Route Transform)**:
   - Splits `high_priority` (`Tier 1` + `Tier 2`) from `wan_blocked` (`Tier 3`).
4. **`aggregate_wan_blocks` (Reduce Transform)**:
   - Groups `Tier 3` events over `expire_after_ms: 60000` (60 seconds) by `(src_ip, dst_port, proto, interface, security_tier, sub_type, action, direction)` and sums `hit_count`.
5. **`normalize_for_loki` & `loki_sink`**:
   - Ships structured JSON events to [Grafana Loki](loki-and-grafana.md) (`http://loki:3100`) with a 256 MB disk buffer (`buffer.type: disk`) so no logs are lost if Loki restarts.

---

## VRL Type-Safety Notes (Learned in Production)

In Vector 0.39 VRL:
- `to_string(.message) ?? ""` requires `??` because `.message` has type `any`.
- Once regex capture groups or `split()` results are bound (`matched.csv`, `parts[i]`), their type is `string | null`, for which `to_string(...)` is **infallible** (do not append `?? ""`, or VRL raises `error[E651]: unnecessary error coalescing operation`).
- Similarly, `is_ipv4(src_ip)` on a `string` variable is **infallible** (use `if is_ipv4(src_ip)` directly rather than `val, _ = is_ipv4(src_ip)`, avoiding `error[E104]`).

---

## Related Pages

- [3-Tier Hybrid Monitoring Strategy](../concepts/three-tier-hybrid-strategy.md)
- [Grafana Loki & Dashboard Integration](loki-and-grafana.md)
