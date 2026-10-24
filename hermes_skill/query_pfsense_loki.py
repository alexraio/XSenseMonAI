#!/usr/bin/env python3
"""Standalone zero-dependency CLI tool for Hermes Agent to query pfSense logs in Grafana Loki.

Runs with Python 3.10+ standard library only (no pip install required on the Hermes Ubuntu VM).
Set LOKI_URL environment variable (e.g. export LOKI_URL="http://192.168.1.10:3100") or pass --loki-url.
"""

from __future__ import annotations

import argparse
import ipaddress
import json
import os
import sys
import urllib.error
import urllib.parse
import urllib.request
from collections import defaultdict
from datetime import UTC, datetime, timedelta
from typing import Any

GEOIP_BATCH_URL = (
    "http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp,org,as"
)


def resolve_geoip_batch(
    ips: list[str],
    timeout: float = 5.0,
) -> dict[str, dict[str, str]]:
    """Resolve country, city, ISP, and ASN for a list of IPs using standard library only.

    Private/RFC1918 addresses are classified locally without external network calls.
    """
    results: dict[str, dict[str, str]] = {}
    public_ips: list[str] = []

    for raw_ip in dict.fromkeys(ips):
        if not raw_ip or raw_ip == "unknown":
            continue
        try:
            addr = ipaddress.ip_address(raw_ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                results[raw_ip] = {
                    "country": "Private Network (RFC1918)",
                    "country_code": "LAN",
                    "city": "",
                    "isp": "Internal Network",
                    "asn": "",
                }
            else:
                public_ips.append(raw_ip)
        except ValueError:
            continue

    if not public_ips:
        return results

    for i in range(0, len(public_ips), 100):
        chunk = public_ips[i : i + 100]
        req = urllib.request.Request(
            GEOIP_BATCH_URL,
            data=json.dumps(chunk).encode("utf-8"),
            headers={
                "Content-Type": "application/json",
                "User-Agent": "PfsenseMon-HermesSkill/1.0",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                batch_data = json.loads(resp.read().decode("utf-8"))
            if isinstance(batch_data, list):
                for item in batch_data:
                    if isinstance(item, dict) and item.get("status") == "success":
                        ip_key = str(item.get("query") or "")
                        results[ip_key] = {
                            "country": str(item.get("country") or "Unknown"),
                            "country_code": str(item.get("countryCode") or ""),
                            "city": str(item.get("city") or ""),
                            "isp": str(item.get("isp") or item.get("org") or ""),
                            "asn": str(item.get("as") or ""),
                        }
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
            # Fail open gracefully if the Hermes VM is offline or rate-limited
            break

    return results


def query_loki(
    loki_url: str,
    logql: str,
    hours: int = 24,
    limit: int = 2000,
) -> list[dict[str, Any]]:
    """Execute a LogQL query_range request against Loki using Python's standard library."""
    end_dt = datetime.now(tz=UTC)
    start_dt = end_dt - timedelta(hours=max(1, hours))

    params = urllib.parse.urlencode(
        {
            "query": logql,
            "start": str(int(start_dt.timestamp() * 1e9)),
            "end": str(int(end_dt.timestamp() * 1e9)),
            "limit": str(limit),
            "direction": "backward",
        }
    )
    url = f"{loki_url.rstrip('/')}/loki/api/v1/query_range?{params}"

    req = urllib.request.Request(url, headers={"Accept": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:
            payload = json.loads(resp.read().decode("utf-8"))
    except urllib.error.URLError as exc:
        print(
            json.dumps(
                {
                    "error": f"Failed to reach Loki at {loki_url}: {exc}",
                    "hint": "Check that the pfSense firewall rule allows TCP 3100 from the Hermes VLAN to the Loki host.",
                },
                indent=2,
            )
        )
        sys.exit(1)

    records: list[dict[str, Any]] = []
    for stream in payload.get("data", {}).get("result", []):
        labels = stream.get("stream", {})
        for ts_ns, raw_line in stream.get("values", []):
            try:
                entry = json.loads(raw_line)
                if not isinstance(entry, dict):
                    entry = {"raw_log": str(raw_line)}
            except json.JSONDecodeError:
                entry = {"raw_log": raw_line}

            entry["_timestamp_utc"] = datetime.fromtimestamp(
                int(ts_ns) / 1e9, tz=UTC
            ).isoformat()
            entry.setdefault("security_tier", labels.get("security_tier", "unknown"))
            records.append(entry)

    return records


def cmd_summary(loki_url: str, hours: int, enrich_geoip: bool = True) -> None:
    """Print an aggregated security summary across all tiers for the requested window."""
    records = query_loki(loki_url, '{app="pfsense"}', hours=hours, limit=4000)

    tier1_flows: dict[str, int] = defaultdict(int)
    tier2_events: dict[str, int] = defaultdict(int)
    tier3_ips: dict[str, int] = defaultdict(int)
    tier3_ports: dict[str, set[str]] = defaultdict(set)
    ai_reports: list[dict[str, Any]] = []

    for r in records:
        tier = r.get("security_tier")
        hits = int(r.get("hit_count") or 1)
        src_ip = str(r.get("src_ip") or "unknown")
        dst_ip = str(r.get("dst_ip") or "unknown")
        dst_port = str(r.get("dst_port") or "0")
        proto = str(r.get("proto") or "unknown")
        sub_type = str(r.get("sub_type") or "unknown")

        if tier == "tier_1_outbound_suspicious":
            key = f"{src_ip} -> {dst_ip}:{dst_port}/{proto} ({sub_type})"
            tier1_flows[key] += hits
        elif tier == "tier_2_access_and_auth":
            key = f"{src_ip} [{sub_type}] port={dst_port}/{proto}"
            tier2_events[key] += hits
        elif tier == "tier_3_wan_blocked":
            tier3_ips[src_ip] += hits
            if dst_port != "0":
                tier3_ports[src_ip].add(dst_port)
        elif tier == "ai_report":
            ai_reports.append(
                {
                    "timestamp": r.get("_timestamp_utc"),
                    "severity": r.get("severity"),
                    "title": r.get("title"),
                    "summary": r.get("executive_summary"),
                }
            )

    sorted_tier3 = sorted(tier3_ips.items(), key=lambda x: x[1], reverse=True)[:15]
    geoip_map = (
        resolve_geoip_batch([ip for ip, _ in sorted_tier3]) if enrich_geoip else {}
    )

    top_wan_attackers = [
        {
            "src_ip": ip,
            "country": geoip_map.get(ip, {}).get("country", "Unknown"),
            "country_code": geoip_map.get(ip, {}).get("country_code", ""),
            "city": geoip_map.get(ip, {}).get("city", ""),
            "isp": geoip_map.get(ip, {}).get("isp", ""),
            "asn": geoip_map.get(ip, {}).get("asn", ""),
            "blocked_hits": count,
            "distinct_ports_targeted": len(tier3_ports[ip]),
            "sample_ports": sorted(tier3_ports[ip])[:15],
        }
        for ip, count in sorted_tier3
    ]

    output = {
        "window_hours": hours,
        "total_records_inspected": len(records),
        "tier_1_suspicious_outbound": [
            {"flow": k, "hits": v}
            for k, v in sorted(tier1_flows.items(), key=lambda x: x[1], reverse=True)[:20]
        ],
        "tier_2_auth_and_allowed_wan": [
            {"event": k, "hits": v}
            for k, v in sorted(tier2_events.items(), key=lambda x: x[1], reverse=True)[:20]
        ],
        "tier_3_top_wan_offenders": top_wan_attackers,
        "recent_ai_reports": ai_reports[:5],
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


def cmd_inspect_ip(
    loki_url: str,
    ip_address: str,
    hours: int,
    enrich_geoip: bool = True,
) -> None:
    """Inspect all firewall and authentication events involving a specific IP address."""
    clean_ip = ip_address.strip()
    try:
        ipaddress.ip_address(clean_ip)
        safe_ip = clean_ip
    except ValueError:
        safe_ip = clean_ip.replace('"', "").replace("\n", "").replace("\r", "")

    logql = f'{{app="pfsense"}} |= "{safe_ip}"'
    records = query_loki(loki_url, logql, hours=hours, limit=1000)
    geoip_info = (
        resolve_geoip_batch([safe_ip]).get(safe_ip, {}) if enrich_geoip else {}
    )

    total_hits = sum(int(r.get("hit_count") or 1) for r in records)
    ports_targeted: set[str] = set()
    tiers_seen: set[str] = set()
    timeline: list[dict[str, Any]] = []

    for r in records:
        tiers_seen.add(str(r.get("security_tier", "unknown")))
        dst_port = str(r.get("dst_port") or "0")
        if dst_port != "0":
            ports_targeted.add(f"{dst_port}/{r.get('proto', 'unknown')}")
        if len(timeline) < 30:
            timeline.append(
                {
                    "timestamp": r.get("_timestamp_utc"),
                    "tier": r.get("security_tier"),
                    "sub_type": r.get("sub_type"),
                    "src_ip": r.get("src_ip"),
                    "dst_ip": r.get("dst_ip"),
                    "dst_port": dst_port,
                    "proto": r.get("proto"),
                    "action": r.get("action"),
                    "hit_count": r.get("hit_count", 1),
                    "raw_log": r.get("raw_log", "")[:160],
                }
            )

    output = {
        "inspected_ip": ip_address,
        "geoip": geoip_info,
        "window_hours": hours,
        "matching_log_entries": len(records),
        "total_packet_hits": total_hits,
        "security_tiers_triggered": sorted(tiers_seen),
        "distinct_ports_involved": sorted(ports_targeted)[:30],
        "recent_timeline": timeline,
    }
    print(json.dumps(output, indent=2, ensure_ascii=False))


def cmd_outbound(loki_url: str, hours: int) -> None:
    """List all Tier 1 suspicious outbound or lateral movement events."""
    logql = '{app="pfsense", security_tier="tier_1_outbound_suspicious"}'
    records = query_loki(loki_url, logql, hours=hours, limit=500)
    print(
        json.dumps(
            {
                "window_hours": hours,
                "count": len(records),
                "events": records[:50],
            },
            indent=2,
            ensure_ascii=False,
        )
    )


def cmd_ai_reports(loki_url: str, hours: int) -> None:
    """Retrieve historical Claude AI security reports stored in Loki."""
    logql = '{app="pfsense", security_tier="ai_report"}'
    records = query_loki(loki_url, logql, hours=hours, limit=50)
    print(
        json.dumps(
            {
                "window_hours": hours,
                "reports_count": len(records),
                "reports": records,
            },
            indent=2,
            ensure_ascii=False,
        )
    )


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Hermes Agent CLI tool for querying pfSense security telemetry in Grafana Loki."
    )
    parser.add_argument(
        "--loki-url",
        default=os.getenv("LOKI_URL", "http://localhost:3100"),
        help="Base URL of the Grafana Loki instance (default: $LOKI_URL or http://localhost:3100)",
    )
    parser.add_argument(
        "--no-geoip",
        action="store_true",
        help="Disable external GeoIP/ASN batch enrichment",
    )

    subparsers = parser.add_subparsers(dest="command", required=True)

    p_sum = subparsers.add_parser("summary", help="Get a 3-Tier security summary")
    p_sum.add_argument("--hours", type=int, default=24, help="Lookback window in hours (default: 24)")
    p_sum.add_argument("--no-geoip", action="store_true", help="Disable GeoIP/ASN enrichment")

    p_ip = subparsers.add_parser("inspect-ip", help="Investigate a specific external or internal IP")
    p_ip.add_argument("ip", help="IPv4 or IPv6 address to investigate")
    p_ip.add_argument("--hours", type=int, default=168, help="Lookback window in hours (default: 168 / 7d)")
    p_ip.add_argument("--no-geoip", action="store_true", help="Disable GeoIP/ASN enrichment")

    p_out = subparsers.add_parser("outbound", help="List Tier 1 suspicious outbound LAN->WAN traffic")
    p_out.add_argument("--hours", type=int, default=24, help="Lookback window in hours (default: 24)")

    p_ai = subparsers.add_parser("ai-reports", help="List recent Claude AI security assessments")
    p_ai.add_argument("--hours", type=int, default=72, help="Lookback window in hours (default: 72)")

    args = parser.parse_args()
    enrich_geoip = not getattr(args, "no_geoip", False)

    if args.command == "summary":
        cmd_summary(args.loki_url, args.hours, enrich_geoip=enrich_geoip)
    elif args.command == "inspect-ip":
        cmd_inspect_ip(args.loki_url, args.ip, args.hours, enrich_geoip=enrich_geoip)
    elif args.command == "outbound":
        cmd_outbound(args.loki_url, args.hours)
    elif args.command == "ai-reports":
        cmd_ai_reports(args.loki_url, args.hours)


if __name__ == "__main__":
    main()
