"""Post-filter GeoIP and ASN enrichment for public IP addresses."""

from __future__ import annotations

import ipaddress
import json
import logging

import httpx

from .models import FilterEvaluationResult, GeoIPInfo

logger = logging.getLogger(__name__)

GEOIP_BATCH_URL = (
    "http://ip-api.com/batch?fields=status,query,country,countryCode,city,isp,org,as"
)


def resolve_geoip_batch(
    ips: list[str],
    timeout: float = 5.0,
) -> dict[str, GeoIPInfo]:
    """Resolve Country, City, ISP, and ASN for a batch of IPs.

    Private/RFC1918 addresses are classified locally without external HTTP requests.
    Fails open gracefully on network errors or rate-limiting.
    """
    results: dict[str, GeoIPInfo] = {}
    public_ips: list[str] = []

    for raw_ip in dict.fromkeys(ips):
        if not raw_ip or raw_ip == "unknown":
            continue
        try:
            addr = ipaddress.ip_address(raw_ip)
            if addr.is_private or addr.is_loopback or addr.is_link_local:
                results[raw_ip] = GeoIPInfo(
                    country="Private Network (RFC1918)",
                    country_code="LAN",
                    city="",
                    isp="Internal Network",
                    asn="",
                )
            else:
                public_ips.append(raw_ip)
        except ValueError:
            continue

    if not public_ips:
        return results

    try:
        with httpx.Client(timeout=timeout) as client:
            for i in range(0, len(public_ips), 100):
                chunk = public_ips[i : i + 100]
                resp = client.post(
                    GEOIP_BATCH_URL,
                    json=chunk,
                    headers={"User-Agent": "PfsenseMon-Analyzer/1.1"},
                )
                resp.raise_for_status()
                batch_data = resp.json()
                if isinstance(batch_data, list):
                    for item in batch_data:
                        if isinstance(item, dict) and item.get("status") == "success":
                            ip_key = str(item.get("query") or "")
                            if ip_key:
                                results[ip_key] = GeoIPInfo(
                                    country=str(item.get("country") or "Unknown"),
                                    country_code=str(item.get("countryCode") or ""),
                                    city=str(item.get("city") or ""),
                                    isp=str(item.get("isp") or item.get("org") or ""),
                                    asn=str(item.get("as") or ""),
                                )
    except (httpx.HTTPError, json.JSONDecodeError, OSError, ValueError) as exc:
        logger.warning("GeoIP batch lookup failed (continuing fail-open): %s", exc)

    return results


def enrich_evaluation_with_geoip(
    evaluation: FilterEvaluationResult,
    timeout: float = 5.0,
) -> FilterEvaluationResult:
    """Enrich an anomaly evaluation result with GeoIP/ASN metadata in-place."""
    candidate_ips: list[str] = []
    for t1 in evaluation.tier1_anomalies:
        candidate_ips.append(t1.dst_ip)
    for t2 in evaluation.tier2_events:
        candidate_ips.append(t2.src_ip)
    for t3 in evaluation.tier3_offenders:
        candidate_ips.append(t3.src_ip)

    geo_map = resolve_geoip_batch(candidate_ips, timeout=timeout)
    evaluation.ip_geoip_map = geo_map

    for t1 in evaluation.tier1_anomalies:
        if t1.dst_ip in geo_map:
            t1.dst_geoip = geo_map[t1.dst_ip]
    for t2 in evaluation.tier2_events:
        if t2.src_ip in geo_map:
            t2.src_geoip = geo_map[t2.src_ip]
    for t3 in evaluation.tier3_offenders:
        if t3.src_ip in geo_map:
            t3.src_geoip = geo_map[t3.src_ip]

    return evaluation
