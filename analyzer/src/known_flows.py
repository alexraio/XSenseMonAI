"""Structured Known Flows & Suppression Rules store for router-agnostic Tier 1 filtering.

Designed to support:
1. Hand-editable JSON configuration (`config/known_flows.json`) with hot-reload.
2. Identity-aware selectors (`src_host`/`dst_host`, `src_mac`/`dst_mac`, `src_ip`/`dst_ip`)
   that remain persistent when DHCP reassigns dynamic IP addresses.
3. Compact `.env` / CLI flow expressions (`src>dst:port1,port2[/proto]`) where `src` and `dst`
   are automatically classified as IP/CIDR, MAC address, or Hostname.
4. Deterministic Zero-Token pre-filtering in `ZeroTokenFilterEngine`.
5. Baseline network topology context enrichment for the LLM (`AnthropicSOCAnalyst`).
6. Clean CRUD operations and stable rule IDs ready for a future Web UI / REST API frontend.
"""

from __future__ import annotations

import hashlib
import ipaddress
import json
import logging
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from pydantic import BaseModel, Field, model_validator

from .device_identity import (
    hostname_matches,
    is_mac_address,
    mac_matches,
    normalize_hostname,
    normalize_mac,
)
from .models import NormalizedLogEvent, OutboundAnomalySummary

logger = logging.getLogger(__name__)

_COMPACT_FLOW_RE = re.compile(
    r"^\s*(?P<src>.+?)\s*(?:->|>)\s*(?P<dst>[^/\s]+?)"
    r"(?:/(?P<proto>[a-zA-Z0-9*]+))?\s*$"
)


def _is_ip_or_cidr(value: str) -> bool:
    """Return True if `value` is a valid IPv4/IPv6 literal or CIDR network."""
    cleaned = value.strip()
    if not cleaned or cleaned in {"*", "any"}:
        return False
    try:
        if "/" in cleaned:
            ipaddress.ip_network(cleaned, strict=False)
        else:
            ipaddress.ip_address(cleaned)
        return True
    except ValueError:
        return False


def _classify_endpoint_selector(raw_value: str | None) -> tuple[str, str, str]:
    """Classify a generic endpoint token into `(ip_pattern, host_pattern, mac_pattern)`."""
    if not raw_value:
        return "*", "*", "*"
    cleaned = raw_value.strip()
    if not cleaned or cleaned.lower() in {"*", "any"}:
        return "*", "*", "*"
    if _is_ip_or_cidr(cleaned):
        return cleaned, "*", "*"
    if is_mac_address(cleaned):
        norm_mac = normalize_mac(cleaned) or cleaned.lower()
        return "*", "*", norm_mac
    norm_host = normalize_hostname(cleaned) or cleaned.lower()
    return "*", norm_host, "*"


def _compute_rule_id(
    src_ip: str,
    dst_ip: str,
    ports: list[str],
    proto: str,
    sub_types: list[str],
    src_ports: list[str] | None = None,
    src_host: str = "*",
    dst_host: str = "*",
    src_mac: str = "*",
    dst_mac: str = "*",
) -> str:
    """Compute a deterministic 8-hex-char rule ID from canonical flow attributes."""
    payload: dict[str, Any] = {
        "src_ip": src_ip.strip().lower(),
        "dst_ip": dst_ip.strip().lower(),
        "ports": sorted(p.strip() for p in ports if p.strip()),
        "proto": proto.strip().lower() or "*",
        "sub_types": sorted(s.strip() for s in sub_types if s.strip()),
    }
    if src_ports:
        payload["src_ports"] = sorted(p.strip() for p in src_ports if p.strip())
    if src_host and src_host != "*":
        payload["src_host"] = src_host.strip().lower()
    if dst_host and dst_host != "*":
        payload["dst_host"] = dst_host.strip().lower()
    if src_mac and src_mac != "*":
        payload["src_mac"] = src_mac.strip().lower()
    if dst_mac and dst_mac != "*":
        payload["dst_mac"] = dst_mac.strip().lower()
    canonical = json.dumps(payload, sort_keys=True)
    digest = hashlib.sha256(canonical.encode("utf-8")).hexdigest()[:8]
    return f"flow-{digest}"


def _normalize_ports(raw_ports: Any) -> list[str]:
    """Normalize port specifications from list, int, or comma-separated string."""
    if raw_ports is None or raw_ports == "" or raw_ports == "*":
        return []
    if isinstance(raw_ports, int):
        return [str(raw_ports)]
    if isinstance(raw_ports, str):
        items = [p.strip() for p in raw_ports.split(",") if p.strip()]
    elif isinstance(raw_ports, (list, tuple, set)):
        items = []
        for item in raw_ports:
            if item is None:
                continue
            for sub in str(item).split(","):
                cleaned = sub.strip()
                if cleaned:
                    items.append(cleaned)
    else:
        items = [str(raw_ports).strip()]

    if "*" in items or "any" in {i.lower() for i in items}:
        return []

    seen: set[str] = set()
    result: list[str] = []
    for port_token in items:
        if port_token not in seen:
            seen.add(port_token)
            result.append(port_token)
    return result


def _ip_matches(candidate_ip: str, pattern: str) -> bool:
    """Return True if `candidate_ip` matches exact IP, CIDR subnet, or wildcard `*`."""
    cleaned_pattern = pattern.strip().lower()
    if cleaned_pattern in {"*", "any", ""}:
        return True

    cleaned_candidate = candidate_ip.strip().lower()
    if cleaned_candidate == cleaned_pattern:
        return True

    if "/" in cleaned_pattern:
        try:
            network = ipaddress.ip_network(cleaned_pattern, strict=False)
            addr = ipaddress.ip_address(cleaned_candidate)
            return addr in network
        except ValueError:
            return False

    return False


def _port_matches(candidate_port: str, rule_ports: list[str]) -> bool:
    """Return True if `candidate_port` matches any port or `start-end` port range in `rule_ports`."""
    if not rule_ports:
        return True

    cand_str = candidate_port.strip()
    if cand_str in rule_ports or "*" in rule_ports:
        return True

    if not cand_str.isdigit():
        return False

    cand_num = int(cand_str)
    for token in rule_ports:
        if "-" in token:
            parts = token.split("-", 1)
            if len(parts) == 2 and parts[0].strip().isdigit() and parts[1].strip().isdigit():
                low, high = int(parts[0].strip()), int(parts[1].strip())
                if low <= cand_num <= high:
                    return True
    return False


class KnownFlowRule(BaseModel):
    """Represents a single authorized/known network flow rule.

    Supports matching by `src_host`/`dst_host` (DHCP or DNS hostname),
    `src_mac`/`dst_mac` (MAC address), and/or `src_ip`/`dst_ip` (IP or CIDR).
    """

    id: str = ""
    enabled: bool = True
    src_ip: str = "*"
    src_host: str = "*"
    src_mac: str = "*"
    src_ports: list[str] = Field(default_factory=list)
    dst_ip: str = "*"
    dst_host: str = "*"
    dst_mac: str = "*"
    ports: list[str] = Field(default_factory=list)
    proto: str = "*"
    sub_types: list[str] = Field(default_factory=list)
    description: str = ""
    created_at: str | None = None

    @model_validator(mode="before")
    @classmethod
    def _normalize_aliases(cls, data: Any) -> Any:
        if not isinstance(data, dict):
            return data

        normalized = dict(data)
        if "src" in normalized:
            raw_src = str(normalized.pop("src") or "*").strip()
            s_ip, s_host, s_mac = _classify_endpoint_selector(raw_src)
            if s_ip != "*" and "src_ip" not in normalized:
                normalized["src_ip"] = s_ip
            if s_host != "*" and "src_host" not in normalized:
                normalized["src_host"] = s_host
            if s_mac != "*" and "src_mac" not in normalized:
                normalized["src_mac"] = s_mac

        if "dst" in normalized:
            raw_dst = str(normalized.pop("dst") or "*").strip()
            d_ip, d_host, d_mac = _classify_endpoint_selector(raw_dst)
            if d_ip != "*" and "dst_ip" not in normalized:
                normalized["dst_ip"] = d_ip
            if d_host != "*" and "dst_host" not in normalized:
                normalized["dst_host"] = d_host
            if d_mac != "*" and "dst_mac" not in normalized:
                normalized["dst_mac"] = d_mac

        if "src_ports" not in normalized and "src_port" in normalized:
            normalized["src_ports"] = normalized.pop("src_port")
        if "ports" not in normalized and "port" in normalized:
            normalized["ports"] = normalized.pop("port")
        if "src_host" not in normalized and "src_hostname" in normalized:
            normalized["src_host"] = normalized.pop("src_hostname")
        if "dst_host" not in normalized and "dst_hostname" in normalized:
            normalized["dst_host"] = normalized.pop("dst_hostname")
        if "description" not in normalized:
            for alias in ("reason", "comment", "label", "name"):
                if alias in normalized:
                    normalized["description"] = normalized.pop(alias)
                    break

        raw_src_ip = str(normalized.get("src_ip", "*") or "*").strip()
        raw_dst_ip = str(normalized.get("dst_ip", "*") or "*").strip()
        raw_src_host = str(normalized.get("src_host", "*") or "*").strip()
        raw_dst_host = str(normalized.get("dst_host", "*") or "*").strip()
        raw_src_mac = str(normalized.get("src_mac", "*") or "*").strip()
        raw_dst_mac = str(normalized.get("dst_mac", "*") or "*").strip()

        # If a user put a hostname or MAC inside `src_ip` / `dst_ip`, auto-route it cleanly
        if raw_src_ip not in {"*", "any"} and not _is_ip_or_cidr(raw_src_ip):
            _, s_host, s_mac = _classify_endpoint_selector(raw_src_ip)
            if s_mac != "*" and raw_src_mac in {"*", "any"}:
                raw_src_mac = s_mac
                raw_src_ip = "*"
            elif s_host != "*" and raw_src_host in {"*", "any"}:
                raw_src_host = s_host
                raw_src_ip = "*"

        if raw_dst_ip not in {"*", "any"} and not _is_ip_or_cidr(raw_dst_ip):
            _, d_host, d_mac = _classify_endpoint_selector(raw_dst_ip)
            if d_mac != "*" and raw_dst_mac in {"*", "any"}:
                raw_dst_mac = d_mac
                raw_dst_ip = "*"
            elif d_host != "*" and raw_dst_host in {"*", "any"}:
                raw_dst_host = d_host
                raw_dst_ip = "*"

        normalized["src_ip"] = "*" if raw_src_ip.lower() in {"", "any", "*"} else raw_src_ip
        normalized["dst_ip"] = "*" if raw_dst_ip.lower() in {"", "any", "*"} else raw_dst_ip
        normalized["src_host"] = (
            "*"
            if raw_src_host.lower() in {"", "any", "*"}
            else (normalize_hostname(raw_src_host) or raw_src_host.lower())
        )
        normalized["dst_host"] = (
            "*"
            if raw_dst_host.lower() in {"", "any", "*"}
            else (normalize_hostname(raw_dst_host) or raw_dst_host.lower())
        )
        normalized["src_mac"] = (
            "*"
            if raw_src_mac.lower() in {"", "any", "*"}
            else (normalize_mac(raw_src_mac) or raw_src_mac.lower())
        )
        normalized["dst_mac"] = (
            "*"
            if raw_dst_mac.lower() in {"", "any", "*"}
            else (normalize_mac(raw_dst_mac) or raw_dst_mac.lower())
        )

        normalized["src_ports"] = _normalize_ports(normalized.get("src_ports"))
        normalized["ports"] = _normalize_ports(normalized.get("ports"))

        raw_proto = str(normalized.get("proto", "*") or "*").strip().lower()
        normalized["proto"] = "*" if raw_proto in {"", "any", "*"} else raw_proto

        raw_sub_types = normalized.get("sub_types")
        if isinstance(raw_sub_types, str):
            normalized["sub_types"] = [s.strip() for s in raw_sub_types.split(",") if s.strip()]
        elif isinstance(raw_sub_types, list):
            normalized["sub_types"] = [str(s).strip() for s in raw_sub_types if str(s).strip()]
        else:
            normalized["sub_types"] = []

        if not normalized.get("id"):
            normalized["id"] = _compute_rule_id(
                src_ip=normalized["src_ip"],
                dst_ip=normalized["dst_ip"],
                ports=normalized["ports"],
                proto=normalized["proto"],
                sub_types=normalized["sub_types"],
                src_ports=normalized["src_ports"],
                src_host=normalized["src_host"],
                dst_host=normalized["dst_host"],
                src_mac=normalized["src_mac"],
                dst_mac=normalized["dst_mac"],
            )

        return normalized

    def matches_event(self, event: NormalizedLogEvent) -> bool:
        """Return True if this enabled rule matches a Tier 1 `NormalizedLogEvent`."""
        if not self.enabled:
            return False
        if event.security_tier != "tier_1_outbound_suspicious":
            return False
        if self.sub_types and event.sub_type not in self.sub_types:
            return False
        if self.proto != "*" and event.proto.lower() != self.proto:
            return False
        if not _ip_matches(event.src_ip, self.src_ip):
            return False
        if not hostname_matches(event.src_host, self.src_host):
            return False
        if not mac_matches(event.src_mac, self.src_mac):
            return False
        if not _port_matches(event.src_port, self.src_ports):
            return False
        if not _ip_matches(event.dst_ip, self.dst_ip):
            return False
        if not hostname_matches(event.dst_host, self.dst_host):
            return False
        if not mac_matches(event.dst_mac, self.dst_mac):
            return False
        return _port_matches(event.dst_port, self.ports)

    def to_file_dict(self) -> dict[str, Any]:
        """Serialize to a clean dictionary for `known_flows.json` persistence."""
        payload: dict[str, Any] = {
            "id": self.id,
            "enabled": self.enabled,
        }
        if self.src_host != "*":
            payload["src_host"] = self.src_host
        if self.src_mac != "*":
            payload["src_mac"] = self.src_mac
        if self.src_ip != "*" or (self.src_host == "*" and self.src_mac == "*"):
            payload["src_ip"] = self.src_ip
        if self.src_ports:
            payload["src_ports"] = self.src_ports

        if self.dst_host != "*":
            payload["dst_host"] = self.dst_host
        if self.dst_mac != "*":
            payload["dst_mac"] = self.dst_mac
        if self.dst_ip != "*" or (self.dst_host == "*" and self.dst_mac == "*"):
            payload["dst_ip"] = self.dst_ip

        payload["ports"] = self.ports
        if self.proto != "*":
            payload["proto"] = self.proto
        if self.sub_types:
            payload["sub_types"] = self.sub_types
        payload["description"] = self.description
        if self.created_at:
            payload["created_at"] = self.created_at
        return payload

    def to_llm_context_dict(self) -> dict[str, Any]:
        """Compact representation injected into the LLM prompt as baseline network context."""
        ctx: dict[str, Any] = {}
        if self.src_host != "*":
            ctx["src_host"] = self.src_host
        if self.src_mac != "*":
            ctx["src_mac"] = self.src_mac
        if self.src_ip != "*" or not ctx:
            ctx["src_ip"] = self.src_ip
        if self.src_ports:
            ctx["src_ports"] = self.src_ports

        if self.dst_host != "*":
            ctx["dst_host"] = self.dst_host
        if self.dst_mac != "*":
            ctx["dst_mac"] = self.dst_mac
        if self.dst_ip != "*" or ("dst_host" not in ctx and "dst_mac" not in ctx):
            ctx["dst_ip"] = self.dst_ip

        ctx["ports"] = self.ports or ["*"]
        ctx["proto"] = self.proto
        ctx["description"] = self.description or "Authorized known flow"
        return ctx


class KnownFlowSuggestion(BaseModel):
    """Copy-pasteable suppression suggestion generated from observed Tier 1 anomalies.

    Follows the `Hostname -> MAC -> IP` priority hierarchy so suggested rules remain
    valid across dynamic DHCP lease renewals.
    """

    src_ip: str = "*"
    src_host: str = "*"
    src_mac: str = "*"
    src_ports: list[str] = Field(default_factory=list)
    dst_ip: str = "*"
    dst_host: str = "*"
    dst_mac: str = "*"
    ports: list[str]
    proto: str = "*"
    sub_type: str = ""
    total_hits: int = 0
    description: str = "Authorized device flow"

    def to_json_snippet(self) -> str:
        """Return a single-line JSON object ready to paste into `config/known_flows.json`."""
        obj: dict[str, Any] = {}
        if self.src_host and self.src_host != "*":
            obj["src_host"] = self.src_host
        elif self.src_mac and self.src_mac != "*":
            obj["src_mac"] = self.src_mac
        else:
            obj["src_ip"] = self.src_ip

        if self.src_ports:
            obj["src_ports"] = self.src_ports

        if self.dst_host and self.dst_host != "*":
            obj["dst_host"] = self.dst_host
        elif self.dst_mac and self.dst_mac != "*":
            obj["dst_mac"] = self.dst_mac
        else:
            obj["dst_ip"] = self.dst_ip

        obj["ports"] = self.ports
        if self.proto != "*":
            obj["proto"] = self.proto
        obj["description"] = self.description
        return json.dumps(obj, ensure_ascii=False)

    def to_compact_expr(self) -> str:
        """Return compact CLI / `.env` flow expression (`src>dst:port1,port2`)."""
        src_token = (
            self.src_host
            if self.src_host != "*"
            else (self.src_mac if self.src_mac != "*" else self.src_ip)
        )
        dst_token = (
            self.dst_host
            if self.dst_host != "*"
            else (self.dst_mac if self.dst_mac != "*" else self.dst_ip)
        )
        ports_str = ",".join(self.ports) if self.ports else "*"
        return f"{src_token}>{dst_token}:{ports_str}"


def parse_compact_flow_rule(expr: str, description: str = "") -> KnownFlowRule:
    """Parse a compact flow string (`src>dst:port1,port2[/proto]`) into a `KnownFlowRule`.

    Endpoints are automatically classified into IP/CIDR, MAC (`aa:bb:cc:dd:ee:ff`), or Hostname.
    """
    match = _COMPACT_FLOW_RE.match(expr)
    if not match:
        raise ValueError(
            f"Invalid flow expression '{expr}'. Expected format: 'src>dst:port1,port2[/proto]'."
        )
    src_raw = match.group("src").strip()
    dst_and_ports = match.group("dst").strip()
    if not src_raw or not dst_and_ports or ">" in src_raw or ">" in dst_and_ports:
        raise ValueError(
            f"Invalid flow expression '{expr}'. Expected format: 'src>dst:port1,port2[/proto]'."
        )
    proto = (match.group("proto") or "*").strip().lower()

    dst_raw = dst_and_ports
    ports: list[str] = []

    if not is_mac_address(dst_and_ports) and ":" in dst_and_ports:
        maybe_dst, maybe_ports = dst_and_ports.rsplit(":", 1)
        if maybe_dst.strip():
            dst_raw = maybe_dst.strip()
            ports = _normalize_ports(maybe_ports)

    src_ip, src_host, src_mac = _classify_endpoint_selector(src_raw)
    dst_ip, dst_host, dst_mac = _classify_endpoint_selector(dst_raw)

    return KnownFlowRule(
        src_ip=src_ip,
        src_host=src_host,
        src_mac=src_mac,
        dst_ip=dst_ip,
        dst_host=dst_host,
        dst_mac=dst_mac,
        ports=ports,
        proto=proto,
        description=description or "Configured via WHITELIST_FLOWS / CLI",
        created_at=datetime.now(tz=UTC).isoformat(),
    )


def _select_preferred_identity(
    ip: str,
    host: str,
    mac: str,
) -> tuple[str, str, str, str]:
    """Return `(src_ip, src_host, src_mac, human_label)` following Hostname -> MAC -> IP priority."""
    if host:
        label = f"{host} ({mac})" if mac else host
        return "*", host, "*", label
    if mac:
        return "*", "*", mac, mac
    return ip, "*", "*", ip


def build_flow_suggestions(
    anomalies: list[OutboundAnomalySummary],
    max_suggestions: int = 3,
) -> list[KnownFlowSuggestion]:
    """Consolidate Tier 1 anomalies into copy-pasteable flow suggestions.

    - Prioritizes `Hostname -> MAC -> IP` for internal endpoints so DHCP IP changes
      never break the suggested rule.
    - If a source host contacts 2+ distinct external IPs using the exact same non-ephemeral
      source port (e.g. BitTorrent DHT `6881/udp`), consolidates them into a single
      source-port-scoped suggestion (`src_ports: ["6881"], dst_ip: "*", ports: ["*"]`).
    """
    suggestions: list[KnownFlowSuggestion] = []
    handled_indices: set[int] = set()

    # 1. Detect fixed source-port P2P/daemon pattern across multiple destination IPs
    by_src_and_sport: dict[tuple[str, str, str], list[int]] = {}
    for idx, item in enumerate(anomalies):
        if (
            item.sub_type in {"outbound_blocked", "outbound_uncommon_port"}
            and len(item.src_ports) == 1
            and item.src_ports[0].isdigit()
            and int(item.src_ports[0]) < 49152
        ):
            sport = item.src_ports[0]
            src_key = item.src_host or item.src_mac or item.src_ip
            by_src_and_sport.setdefault((src_key, sport, item.proto.lower()), []).append(idx)

    for (_src_key, sport, proto), indices in by_src_and_sport.items():
        distinct_dsts = {anomalies[i].dst_ip for i in indices}
        if len(distinct_dsts) >= 2:
            handled_indices.update(indices)
            sample = anomalies[indices[0]]
            total_hits = sum(anomalies[i].total_hits for i in indices)
            s_ip, s_host, s_mac, s_label = _select_preferred_identity(
                sample.src_ip, sample.src_host, sample.src_mac
            )
            desc_target = f" from {s_label}" if (sample.src_host or sample.src_mac) else ""
            suggestions.append(
                KnownFlowSuggestion(
                    src_ip=s_ip,
                    src_host=s_host,
                    src_mac=s_mac,
                    src_ports=[sport],
                    dst_ip="*",
                    ports=["*"],
                    proto=proto if proto != "unknown" else "*",
                    sub_type=sample.sub_type,
                    total_hits=total_hits,
                    description=f"Authorized P2P/daemon outbound flow{desc_target} (src_port {sport})",
                )
            )

    # 2. Standard grouping by source identity and destination identity for remaining anomalies
    grouped_ports: dict[tuple[str, str], list[str]] = {}
    grouped_hits: dict[tuple[str, str], int] = {}
    grouped_sample: dict[tuple[str, str], OutboundAnomalySummary] = {}

    for idx, item in enumerate(anomalies):
        if idx in handled_indices:
            continue
        src_key = item.src_host or item.src_mac or item.src_ip
        dst_key = (
            (item.dst_host or item.dst_mac or item.dst_ip)
            if item.sub_type == "internal_lateral_blocked"
            else item.dst_ip
        )
        key = (src_key, dst_key)
        if key not in grouped_ports:
            grouped_ports[key] = []
            grouped_hits[key] = 0
            grouped_sample[key] = item
        if item.dst_port and item.dst_port != "0" and item.dst_port not in grouped_ports[key]:
            grouped_ports[key].append(item.dst_port)
        grouped_hits[key] += item.total_hits

    sorted_keys = sorted(grouped_hits.keys(), key=lambda k: grouped_hits[k], reverse=True)
    for key in sorted_keys:
        if len(suggestions) >= max_suggestions:
            break
        sample = grouped_sample[key]
        ports = sorted(
            grouped_ports[key],
            key=lambda p: int(p) if p.isdigit() else 99999,
        )
        s_ip, s_host, s_mac, s_label = _select_preferred_identity(
            sample.src_ip, sample.src_host, sample.src_mac
        )
        if sample.sub_type == "internal_lateral_blocked":
            d_ip, d_host, d_mac, d_label = _select_preferred_identity(
                sample.dst_ip, sample.dst_host, sample.dst_mac
            )
            default_desc = (
                f"Authorized inter-VLAN flow ({s_label} -> {d_label})"
                if (sample.src_host or sample.src_mac or sample.dst_host or sample.dst_mac)
                else "Authorized inter-VLAN flow"
            )
        else:
            d_ip, d_host, d_mac = sample.dst_ip, "*", "*"
            default_desc = (
                f"Authorized outbound flow ({s_label})"
                if (sample.src_host or sample.src_mac)
                else "Authorized outbound flow"
            )

        suggestions.append(
            KnownFlowSuggestion(
                src_ip=s_ip,
                src_host=s_host,
                src_mac=s_mac,
                dst_ip=d_ip,
                dst_host=d_host,
                dst_mac=d_mac,
                ports=ports,
                sub_type=sample.sub_type,
                total_hits=grouped_hits[key],
                description=default_desc,
            )
        )
    return suggestions[:max_suggestions]


class KnownFlowsStore:
    """Persistent, hot-reloading repository of `KnownFlowRule` items.

    Supports both file-backed rules (`config/known_flows.json`) and inline
    environment rules (`WHITELIST_FLOWS`), with CRUD methods designed for CLI
    and future REST API / Frontend integration.
    """

    def __init__(
        self,
        file_path: Path | None = None,
        inline_expressions: list[str] | set[str] | None = None,
    ) -> None:
        self.file_path = file_path
        self._file_rules: list[KnownFlowRule] = []
        self._inline_rules: list[KnownFlowRule] = []
        self._last_mtime_ns: int | None = None
        self._last_size: int | None = None

        if inline_expressions:
            for expr in sorted(inline_expressions):
                cleaned = expr.strip()
                if not cleaned:
                    continue
                try:
                    self._inline_rules.append(parse_compact_flow_rule(cleaned))
                except ValueError as exc:
                    logger.warning("Skipping invalid WHITELIST_FLOWS entry '%s': %s", cleaned, exc)

        self.reload_if_changed(force=True)

    def reload_if_changed(self, force: bool = False) -> bool:
        """Reload rules from `self.file_path` if the file was created, modified, or deleted."""
        if self.file_path is None:
            return False

        if not self.file_path.exists():
            if self._file_rules or force:
                self._file_rules = []
                self._last_mtime_ns = None
                self._last_size = None
                return True
            return False

        try:
            stat = self.file_path.stat()
        except OSError as exc:
            logger.warning("Unable to stat known_flows file %s: %s", self.file_path, exc)
            return False

        if (
            not force
            and self._last_mtime_ns == stat.st_mtime_ns
            and self._last_size == stat.st_size
        ):
            return False

        try:
            raw_text = self.file_path.read_text(encoding="utf-8").strip()
            if not raw_text:
                loaded_rules: list[KnownFlowRule] = []
            else:
                parsed = json.loads(raw_text)
                if isinstance(parsed, dict):
                    raw_items = parsed.get("flows", parsed.get("rules", []))
                elif isinstance(parsed, list):
                    raw_items = parsed
                else:
                    raise ValueError("Root JSON element must be a list of flow objects or {'flows': [...]}")

                loaded_rules = [KnownFlowRule.model_validate(item) for item in raw_items]

            self._file_rules = loaded_rules
            self._last_mtime_ns = stat.st_mtime_ns
            self._last_size = stat.st_size
            logger.debug(
                "Loaded %d known flow rule(s) from %s",
                len(self._file_rules),
                self.file_path,
            )
            return True
        except (OSError, json.JSONDecodeError, ValueError) as exc:
            logger.warning(
                "Failed to parse known_flows file %s (retaining %d previous rule(s)): %s",
                self.file_path,
                len(self._file_rules),
                exc,
            )
            return False

    def list_rules(self, include_disabled: bool = True) -> list[KnownFlowRule]:
        """Return all known flow rules (file-backed + inline `.env` rules)."""
        self.reload_if_changed()
        combined: list[KnownFlowRule] = []
        seen_ids: set[str] = set()
        for rule in [*self._file_rules, *self._inline_rules]:
            if not include_disabled and not rule.enabled:
                continue
            if rule.id not in seen_ids:
                seen_ids.add(rule.id)
                combined.append(rule)
        return combined

    def get_rule(self, rule_id: str) -> KnownFlowRule | None:
        """Retrieve a single rule by its `id`."""
        for rule in self.list_rules(include_disabled=True):
            if rule.id == rule_id:
                return rule
        return None

    def match_event(self, event: NormalizedLogEvent) -> KnownFlowRule | None:
        """Return the first enabled `KnownFlowRule` matching `event`, or `None`."""
        for rule in self._file_rules:
            if rule.matches_event(event):
                return rule
        for rule in self._inline_rules:
            if rule.matches_event(event):
                return rule
        return None

    def get_llm_context(
        self,
        relevant_ips: set[str] | None = None,
        relevant_hosts: set[str] | None = None,
        relevant_macs: set[str] | None = None,
    ) -> list[dict[str, Any]]:
        """Return enabled known flows formatted as baseline topology context for the LLM.

        Matches rules whose IP, Hostname, or MAC corresponds to any device active in the window.
        """
        enabled_rules = self.list_rules(include_disabled=False)
        if not enabled_rules:
            return []

        if not relevant_ips and not relevant_hosts and not relevant_macs:
            return [r.to_llm_context_dict() for r in enabled_rules[:20]]

        ips = relevant_ips or set()
        hosts = {h for h in (relevant_hosts or set()) if h}
        macs = {m for m in (relevant_macs or set()) if m}

        matched: list[dict[str, Any]] = []
        for rule in enabled_rules:
            ip_hit = any(
                (rule.src_ip != "*" and _ip_matches(ip, rule.src_ip))
                or (rule.dst_ip != "*" and _ip_matches(ip, rule.dst_ip))
                for ip in ips
            )
            host_hit = any(
                (rule.src_host != "*" and hostname_matches(h, rule.src_host))
                or (rule.dst_host != "*" and hostname_matches(h, rule.dst_host))
                for h in hosts
            )
            mac_hit = any(
                (rule.src_mac != "*" and mac_matches(m, rule.src_mac))
                or (rule.dst_mac != "*" and mac_matches(m, rule.dst_mac))
                for m in macs
            )
            if ip_hit or host_hit or mac_hit:
                matched.append(rule.to_llm_context_dict())
        return matched[:20]

    def add_rule(self, new_rule: KnownFlowRule) -> KnownFlowRule:
        """Add or merge a rule into the persistent JSON file and return the stored rule."""
        self.reload_if_changed()
        if not new_rule.created_at:
            new_rule = new_rule.model_copy(
                update={"created_at": datetime.now(tz=UTC).isoformat()}
            )

        updated_list: list[KnownFlowRule] = []
        merged_rule: KnownFlowRule | None = None

        for existing in self._file_rules:
            if existing.id == new_rule.id:
                merged_rule = new_rule
                updated_list.append(merged_rule)
            elif (
                existing.src_ip == new_rule.src_ip
                and existing.src_host == new_rule.src_host
                and existing.src_mac == new_rule.src_mac
                and existing.dst_ip == new_rule.dst_ip
                and existing.dst_host == new_rule.dst_host
                and existing.dst_mac == new_rule.dst_mac
                and existing.proto == new_rule.proto
                and existing.sub_types == new_rule.sub_types
                and existing.ports
                and new_rule.ports
            ):
                # Merge port lists for identical endpoint/protocol selectors
                merged_ports = _normalize_ports([*existing.ports, *new_rule.ports])
                desc = new_rule.description or existing.description
                merged_rule = KnownFlowRule(
                    src_ip=existing.src_ip,
                    src_host=existing.src_host,
                    src_mac=existing.src_mac,
                    dst_ip=existing.dst_ip,
                    dst_host=existing.dst_host,
                    dst_mac=existing.dst_mac,
                    ports=merged_ports,
                    proto=existing.proto,
                    sub_types=existing.sub_types,
                    enabled=new_rule.enabled,
                    description=desc,
                    created_at=existing.created_at or new_rule.created_at,
                )
                updated_list.append(merged_rule)
            else:
                updated_list.append(existing)

        if merged_rule is None:
            merged_rule = new_rule
            updated_list.append(merged_rule)

        self._file_rules = updated_list
        self._save_to_disk()
        return merged_rule

    def remove_rule(self, rule_id: str) -> bool:
        """Delete a file-backed rule by `id`. Returns True if removed."""
        self.reload_if_changed()
        before = len(self._file_rules)
        self._file_rules = [r for r in self._file_rules if r.id != rule_id]
        if len(self._file_rules) == before:
            return False
        self._save_to_disk()
        return True

    def set_rule_enabled(self, rule_id: str, enabled: bool) -> KnownFlowRule | None:
        """Enable or disable a file-backed rule by `id` (ready for future UI toggle switches)."""
        self.reload_if_changed()
        target: KnownFlowRule | None = None
        updated_list: list[KnownFlowRule] = []
        for rule in self._file_rules:
            if rule.id == rule_id:
                target = rule.model_copy(update={"enabled": enabled})
                updated_list.append(target)
            else:
                updated_list.append(rule)
        if target is None:
            return None
        self._file_rules = updated_list
        self._save_to_disk()
        return target

    def _save_to_disk(self) -> None:
        """Atomically persist `self._file_rules` to `self.file_path`."""
        if self.file_path is None:
            return
        self.file_path.parent.mkdir(parents=True, exist_ok=True)
        payload = [rule.to_file_dict() for rule in self._file_rules]
        tmp_path = self.file_path.with_suffix(".tmp")
        tmp_path.write_text(
            json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
            encoding="utf-8",
        )
        tmp_path.replace(self.file_path)
        try:
            stat = self.file_path.stat()
            self._last_mtime_ns = stat.st_mtime_ns
            self._last_size = stat.st_size
        except OSError:
            pass
