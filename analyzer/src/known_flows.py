"""Structured Known Flows & Suppression Rules store for router-agnostic Tier 1 filtering.

Designed to support:
1. Hand-editable JSON configuration (`config/known_flows.json`) with hot-reload.
2. Compact `.env` / CLI flow expressions (`src_ip>dst_ip:port1,port2[/proto]`).
3. Deterministic Zero-Token pre-filtering in `ZeroTokenFilterEngine`.
4. Baseline network topology context enrichment for the LLM (`AnthropicSOCAnalyst`).
5. Clean CRUD operations and stable rule IDs ready for a future Web UI / REST API frontend.
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

from .models import NormalizedLogEvent, OutboundAnomalySummary

logger = logging.getLogger(__name__)

_COMPACT_FLOW_RE = re.compile(
    r"^\s*(?P<src>[^>-]+?)\s*(?:->|>)\s*(?P<dst>[^:/\s]+)"
    r"(?::(?P<ports>[^/\s]+))?"
    r"(?:/(?P<proto>[a-zA-Z0-9*]+))?\s*$"
)


def _compute_rule_id(
    src_ip: str,
    dst_ip: str,
    ports: list[str],
    proto: str,
    sub_types: list[str],
) -> str:
    """Compute a deterministic 8-hex-char rule ID from canonical flow attributes."""
    canonical = json.dumps(
        {
            "src_ip": src_ip.strip().lower(),
            "dst_ip": dst_ip.strip().lower(),
            "ports": sorted(p.strip() for p in ports if p.strip()),
            "proto": proto.strip().lower() or "*",
            "sub_types": sorted(s.strip() for s in sub_types if s.strip()),
        },
        sort_keys=True,
    )
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

    Designed for both human-edited `config/known_flows.json` files and future
    REST API / Web Frontend CRUD operations.
    """

    id: str = ""
    enabled: bool = True
    src_ip: str = "*"
    dst_ip: str = "*"
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
        if "src_ip" not in normalized and "src" in normalized:
            normalized["src_ip"] = normalized.pop("src")
        if "dst_ip" not in normalized and "dst" in normalized:
            normalized["dst_ip"] = normalized.pop("dst")
        if "ports" not in normalized and "port" in normalized:
            normalized["ports"] = normalized.pop("port")
        if "description" not in normalized:
            for alias in ("reason", "comment", "label", "name"):
                if alias in normalized:
                    normalized["description"] = normalized.pop(alias)
                    break

        normalized["src_ip"] = str(normalized.get("src_ip", "*") or "*").strip()
        normalized["dst_ip"] = str(normalized.get("dst_ip", "*") or "*").strip()
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
        if not _ip_matches(event.dst_ip, self.dst_ip):
            return False
        return _port_matches(event.dst_port, self.ports)

    def to_file_dict(self) -> dict[str, Any]:
        """Serialize to a clean dictionary for `known_flows.json` persistence."""
        payload: dict[str, Any] = {
            "id": self.id,
            "enabled": self.enabled,
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ports": self.ports,
        }
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
        return {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ports": self.ports or ["*"],
            "proto": self.proto,
            "description": self.description or "Authorized known flow",
        }


class KnownFlowSuggestion(BaseModel):
    """Copy-pasteable suppression suggestion generated from observed Tier 1 anomalies."""

    src_ip: str
    dst_ip: str
    ports: list[str]
    proto: str = "*"
    sub_type: str = ""
    total_hits: int = 0
    description: str = "Authorized device flow"

    def to_json_snippet(self) -> str:
        """Return a single-line JSON object ready to paste into `config/known_flows.json`."""
        obj: dict[str, Any] = {
            "src_ip": self.src_ip,
            "dst_ip": self.dst_ip,
            "ports": self.ports,
            "description": self.description,
        }
        return json.dumps(obj, ensure_ascii=False)

    def to_compact_expr(self) -> str:
        """Return compact CLI / `.env` flow expression (`src>dst:port1,port2`)."""
        ports_str = ",".join(self.ports) if self.ports else "*"
        return f"{self.src_ip}>{self.dst_ip}:{ports_str}"


def parse_compact_flow_rule(expr: str, description: str = "") -> KnownFlowRule:
    """Parse a compact flow string like `172.16.0.10>192.168.1.50:443,8080/tcp` into a `KnownFlowRule`."""
    match = _COMPACT_FLOW_RE.match(expr)
    if not match:
        raise ValueError(
            f"Invalid flow expression '{expr}'. Expected format: 'src_ip>dst_ip:port1,port2[/proto]'."
        )
    src_ip = match.group("src").strip()
    dst_ip = match.group("dst").strip()
    ports = _normalize_ports(match.group("ports"))
    proto = (match.group("proto") or "*").strip().lower()
    return KnownFlowRule(
        src_ip=src_ip,
        dst_ip=dst_ip,
        ports=ports,
        proto=proto,
        description=description or "Configured via WHITELIST_FLOWS / CLI",
        created_at=datetime.now(tz=UTC).isoformat(),
    )


def build_flow_suggestions(
    anomalies: list[OutboundAnomalySummary],
    max_suggestions: int = 3,
) -> list[KnownFlowSuggestion]:
    """Consolidate Tier 1 anomalies by `(src_ip, dst_ip)` into copy-pasteable flow suggestions."""
    grouped_ports: dict[tuple[str, str], list[str]] = {}
    grouped_hits: dict[tuple[str, str], int] = {}
    grouped_sub_type: dict[tuple[str, str], str] = {}

    for item in anomalies:
        key = (item.src_ip, item.dst_ip)
        if key not in grouped_ports:
            grouped_ports[key] = []
            grouped_hits[key] = 0
            grouped_sub_type[key] = item.sub_type
        if item.dst_port and item.dst_port != "0" and item.dst_port not in grouped_ports[key]:
            grouped_ports[key].append(item.dst_port)
        grouped_hits[key] += item.total_hits

    sorted_keys = sorted(grouped_hits.keys(), key=lambda k: grouped_hits[k], reverse=True)
    suggestions: list[KnownFlowSuggestion] = []
    for src_ip, dst_ip in sorted_keys[:max_suggestions]:
        ports = sorted(
            grouped_ports[(src_ip, dst_ip)],
            key=lambda p: int(p) if p.isdigit() else 99999,
        )
        sub_type = grouped_sub_type[(src_ip, dst_ip)]
        default_desc = (
            "Authorized inter-VLAN flow"
            if sub_type == "internal_lateral_blocked"
            else "Authorized outbound flow"
        )
        suggestions.append(
            KnownFlowSuggestion(
                src_ip=src_ip,
                dst_ip=dst_ip,
                ports=ports,
                sub_type=sub_type,
                total_hits=grouped_hits[(src_ip, dst_ip)],
                description=default_desc,
            )
        )
    return suggestions


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

    def get_llm_context(self, relevant_ips: set[str] | None = None) -> list[dict[str, Any]]:
        """Return enabled known flows formatted as baseline topology context for the LLM.

        If `relevant_ips` is provided, prioritizes rules whose `src_ip` or `dst_ip`
        matches one of the IPs active in the current evaluation window.
        """
        enabled_rules = self.list_rules(include_disabled=False)
        if not enabled_rules:
            return []

        if not relevant_ips:
            return [r.to_llm_context_dict() for r in enabled_rules[:20]]

        matched: list[dict[str, Any]] = []
        for rule in enabled_rules:
            if any(
                _ip_matches(ip, rule.src_ip) or _ip_matches(ip, rule.dst_ip)
                for ip in relevant_ips
            ):
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
                and existing.dst_ip == new_rule.dst_ip
                and existing.proto == new_rule.proto
                and existing.sub_types == new_rule.sub_types
                and existing.ports
                and new_rule.ports
            ):
                # Merge port lists for identical (src_ip, dst_ip, proto, sub_types)
                merged_ports = _normalize_ports([*existing.ports, *new_rule.ports])
                desc = new_rule.description or existing.description
                merged_rule = KnownFlowRule(
                    src_ip=existing.src_ip,
                    dst_ip=existing.dst_ip,
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
