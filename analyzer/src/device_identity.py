"""Dynamic Device Identity & DHCP Lease Resolution (`Hostname <-> MAC <-> IP`).

Passively tracks DHCP lease allocations/releases ingested via Vector/Loki (`dhcpd`,
`kea-dhcp4`, `dnsmasq`) and provides a fast Reverse DNS (`PTR`) fallback with negative
caching. Enables `KnownFlowsStore` and `ZeroTokenFilterEngine` to match devices by
`src_host`/`dst_host` or `src_mac`/`dst_mac` even when DHCP reassigns dynamic IPs.
"""

from __future__ import annotations

import ipaddress
import json
import logging
import re
import socket
from datetime import UTC, datetime
from fnmatch import fnmatchcase
from pathlib import Path
from typing import Any

from pydantic import BaseModel

from .models import NormalizedLogEvent

logger = logging.getLogger(__name__)

# Local domain suffixes stripped during hostname normalization so DHCP option-12 names
# (e.g. "apple-tv-salotto") and Unbound PTR FQDNs ("apple-tv-salotto.home.arpa.") match.
LOCAL_DOMAIN_SUFFIXES = (
    ".home.arpa",
    ".localdomain",
    ".localnet",
    ".internal",
    ".local",
    ".lan",
    ".home",
)

_HEX_DIGITS = frozenset("0123456789abcdef")

# Fallback regexes for raw syslog lines if fields were not pre-extracted by Vector
_ISC_DHCPACK_RE = re.compile(
    r"DHCPACK\s+on\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+to\s+"
    r"(?P<mac>[0-9a-fA-F:.\-]{11,17})(?:\s+\((?P<host>[^)]+)\))?",
    re.IGNORECASE,
)
_ISC_DHCPRELEASE_RE = re.compile(
    r"DHCPRELEASE\s+of\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+from\s+"
    r"(?P<mac>[0-9a-fA-F:.\-]{11,17})",
    re.IGNORECASE,
)
_KEA_ALLOC_RE = re.compile(
    r"DHCP4_LEASE_ALLOC\b.*?(?:hwtype=\d+\s+)?(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"
    r".*?lease\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+has\s+been\s+allocated"
    r"(?:.*?(?:hostname[=\s\"'(]+)(?P<host>[a-zA-Z0-9_.\-]+))?",
    re.IGNORECASE,
)
_KEA_RELEASE_RE = re.compile(
    r"DHCP4_LEASE_RELEASE\b.*?(?:hwtype=\d+\s+)?(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})"
    r".*?lease\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})",
    re.IGNORECASE,
)
_DNSMASQ_DHCP_RE = re.compile(
    r"DHCP(?P<verb>ACK|RELEASE)\([^)]*\)\s+(?P<ip>(?:\d{1,3}\.){3}\d{1,3})\s+"
    r"(?P<mac>(?:[0-9a-fA-F]{2}:){5}[0-9a-fA-F]{2})(?:\s+(?P<host>[a-zA-Z0-9_.\-]+))?",
    re.IGNORECASE,
)


_MAC_COLON_OR_HYPHEN_RE = re.compile(
    r"^(?:[0-9a-f]{2}:){5}[0-9a-f]{2}$|^(?:[0-9a-f]{2}-){5}[0-9a-f]{2}$"
)
_MAC_CISCO_DOT_RE = re.compile(r"^(?:[0-9a-f]{4}\.){2}[0-9a-f]{4}$")


def normalize_mac(raw_mac: str | None) -> str:
    """Normalize a MAC address to canonical lowercase `aa:bb:cc:dd:ee:ff` or return `""`."""
    if not raw_mac:
        return ""
    cleaned = raw_mac.strip().lower()
    if not cleaned or cleaned in {"*", "any", "unknown"}:
        return ""

    if not (_MAC_COLON_OR_HYPHEN_RE.match(cleaned) or _MAC_CISCO_DOT_RE.match(cleaned)):
        return ""

    hex_only = re.sub(r"[:.\-]", "", cleaned)
    return ":".join(hex_only[i : i + 2] for i in range(0, 12, 2))


def is_mac_address(value: str | None) -> bool:
    """Return True if `value` is a valid MAC address or MAC prefix pattern (e.g. `00:00:5e:*`)."""
    if not value:
        return False
    cleaned = value.strip().lower()
    if normalize_mac(cleaned):
        return True
    if cleaned.endswith(":*"):
        prefix_parts = cleaned[:-2].split(":")
        return 1 <= len(prefix_parts) <= 5 and all(
            len(p) == 2 and all(c in _HEX_DIGITS for c in p) for p in prefix_parts
        )
    return False


def normalize_hostname(raw_host: str | None) -> str:
    """Normalize a DHCP or DNS hostname to lowercase short form without local domain suffixes."""
    if not raw_host:
        return ""
    cleaned = raw_host.strip().strip("\"'()").rstrip(".").lower()
    if not cleaned or cleaned in {"*", "any", "unknown", "localhost"}:
        return ""

    # Reject raw IP literals or CIDR blocks masquerading as hostnames
    try:
        ipaddress.ip_network(cleaned, strict=False)
        return ""
    except ValueError:
        pass

    for suffix in LOCAL_DOMAIN_SUFFIXES:
        if cleaned.endswith(suffix) and len(cleaned) > len(suffix):
            cleaned = cleaned[: -len(suffix)]
            break

    # Strip any remaining custom router DNS domain suffix (e.g. "host.router.domain" -> "host")
    # unless the pattern starts with a leading subdomain wildcard ("*.domain").
    if "." in cleaned and not cleaned.startswith("*."):
        cleaned = cleaned.split(".", 1)[0]

    return cleaned


def hostname_matches(candidate_host: str, pattern: str) -> bool:
    """Return True if `candidate_host` matches `pattern` (exact or glob `*`, case-insensitive)."""
    cleaned_pattern = pattern.strip().lower()
    if cleaned_pattern in {"*", "any", ""}:
        return True

    norm_pattern = normalize_hostname(cleaned_pattern) or cleaned_pattern
    norm_cand = normalize_hostname(candidate_host)
    if not norm_cand:
        return False

    if norm_cand == norm_pattern:
        return True
    if "*" in norm_pattern or "?" in norm_pattern:
        return fnmatchcase(norm_cand, norm_pattern)
    return False


def mac_matches(candidate_mac: str, pattern: str) -> bool:
    """Return True if `candidate_mac` matches `pattern` (exact MAC or OUI wildcard `aa:bb:cc:*`)."""
    cleaned_pattern = pattern.strip().lower()
    if cleaned_pattern in {"*", "any", ""}:
        return True

    norm_cand = normalize_mac(candidate_mac)
    if not norm_cand:
        return False

    norm_pattern = normalize_mac(cleaned_pattern)
    if norm_pattern:
        return norm_cand == norm_pattern

    if "*" in cleaned_pattern:
        return fnmatchcase(norm_cand, cleaned_pattern)
    return False


_RFC1918_NETWORKS = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("fc00::/7"),
)


def is_private_ip(ip_str: str) -> bool:
    """Return True if `ip_str` is an internal RFC1918 IPv4 or ULA IPv6 address."""
    try:
        addr = ipaddress.ip_address(ip_str.strip())
        return any(addr in net for net in _RFC1918_NETWORKS)
    except ValueError:
        return False


def parse_raw_dhcp_log(raw_log: str) -> tuple[str, str, str, str] | None:
    """Extract `(action, ip, mac, hostname)` from a raw ISC dhcpd, Kea, or dnsmasq log line."""
    if not raw_log:
        return None

    m_ack = _ISC_DHCPACK_RE.search(raw_log)
    if m_ack:
        return (
            "lease_ack",
            m_ack.group("ip"),
            normalize_mac(m_ack.group("mac")),
            normalize_hostname(m_ack.group("host")),
        )

    m_rel = _ISC_DHCPRELEASE_RE.search(raw_log)
    if m_rel:
        return (
            "lease_release",
            m_rel.group("ip"),
            normalize_mac(m_rel.group("mac")),
            "",
        )

    m_kea_alloc = _KEA_ALLOC_RE.search(raw_log)
    if m_kea_alloc:
        return (
            "lease_ack",
            m_kea_alloc.group("ip"),
            normalize_mac(m_kea_alloc.group("mac")),
            normalize_hostname(m_kea_alloc.group("host")),
        )

    m_kea_rel = _KEA_RELEASE_RE.search(raw_log)
    if m_kea_rel:
        return (
            "lease_release",
            m_kea_rel.group("ip"),
            normalize_mac(m_kea_rel.group("mac")),
            "",
        )

    m_dnsmasq = _DNSMASQ_DHCP_RE.search(raw_log)
    if m_dnsmasq:
        verb = m_dnsmasq.group("verb").upper()
        return (
            "lease_ack" if verb == "ACK" else "lease_release",
            m_dnsmasq.group("ip"),
            normalize_mac(m_dnsmasq.group("mac")),
            normalize_hostname(m_dnsmasq.group("host")),
        )

    return None


class DeviceIdentity(BaseModel):
    """Represents the resolved identity (Hostname and/or MAC) currently bound to an IP."""

    ip: str
    mac: str = ""
    hostname: str = ""
    interface: str = ""
    source: str = "dhcp"
    updated_at: str = ""

    def display_label(self) -> str:
        """Return a human-readable identity tag (e.g. `apple-tv-salotto` or `apple-tv-salotto | 00:00:5e:00:53:10`)."""
        if self.hostname and self.mac:
            return f"{self.hostname} | {self.mac}"
        if self.hostname:
            return self.hostname
        if self.mac:
            return self.mac
        return ""


class DeviceIdentityStore:
    """Persistent store mapping active dynamic IPs to `(hostname, mac)` with PTR fallback."""

    def __init__(
        self,
        file_path: Path | None = None,
        lease_ttl_hours: int = 168,
        enable_ptr_fallback: bool = True,
        ptr_timeout_seconds: float = 1.0,
    ) -> None:
        self.file_path = file_path
        self.lease_ttl_seconds = max(3600, lease_ttl_hours * 3600)
        self.enable_ptr_fallback = enable_ptr_fallback
        self.ptr_timeout_seconds = max(0.2, ptr_timeout_seconds)
        self._leases_by_ip: dict[str, DeviceIdentity] = {}
        self._ptr_negative_cache: set[str] = set()
        self._load()

    def _load(self) -> None:
        """Load persisted DHCP leases from disk and prune expired records."""
        if not self.file_path or not self.file_path.exists():
            return
        try:
            raw_text = self.file_path.read_text(encoding="utf-8").strip()
            if not raw_text:
                return
            data = json.loads(raw_text)
            raw_items: list[dict[str, Any]] = []
            if isinstance(data, dict):
                if "leases" in data and isinstance(data["leases"], list):
                    raw_items = data["leases"]
                else:
                    raw_items = [v for v in data.values() if isinstance(v, dict)]
            elif isinstance(data, list):
                raw_items = [v for v in data if isinstance(v, dict)]

            now = datetime.now(tz=UTC)
            loaded: dict[str, DeviceIdentity] = {}
            for item in raw_items:
                identity = DeviceIdentity.model_validate(item)
                identity.mac = normalize_mac(identity.mac)
                identity.hostname = normalize_hostname(identity.hostname)
                if not identity.ip or not (identity.mac or identity.hostname):
                    continue
                if not self._is_expired(identity.updated_at, now):
                    loaded[identity.ip] = identity
            self._leases_by_ip = loaded
        except (OSError, json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning("Could not load DHCP lease store %s: %s", self.file_path, exc)

    def _is_expired(self, updated_at_iso: str, now: datetime) -> bool:
        if not updated_at_iso:
            return False
        try:
            dt = datetime.fromisoformat(updated_at_iso)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
            return (now - dt).total_seconds() > self.lease_ttl_seconds
        except ValueError:
            return False

    def save(self) -> None:
        """Atomically persist active leases to `self.file_path`."""
        if not self.file_path:
            return
        try:
            self.file_path.parent.mkdir(parents=True, exist_ok=True)
            payload = {
                "updated_at": datetime.now(tz=UTC).isoformat(),
                "leases": [
                    lease.model_dump()
                    for _, lease in sorted(self._leases_by_ip.items(), key=lambda x: x[0])
                ],
            }
            tmp_path = self.file_path.with_suffix(".tmp")
            tmp_path.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False) + "\n",
                encoding="utf-8",
            )
            tmp_path.replace(self.file_path)
        except (OSError, TypeError, ValueError) as exc:
            logger.warning("Could not persist DHCP lease store %s: %s", self.file_path, exc)

    def update_lease(
        self,
        ip: str,
        mac: str = "",
        hostname: str = "",
        action: str = "lease_ack",
        interface: str = "",
        timestamp: datetime | None = None,
        source: str = "dhcp",
        persist: bool = True,
    ) -> DeviceIdentity | None:
        """Apply a DHCP lease allocation/release or PTR resolution to the active map.

        Enforces anti-stale ownership:
        1. If the same MAC (or same hostname when MAC is identical/absent) previously held a
           different IP, that old IP is evicted.
        2. If `ip` was previously held by a different device, `ip` is immediately overwritten
           so the new device never inherits the previous device's Known Flows.
        """
        clean_ip = ip.strip()
        if not clean_ip or clean_ip == "unknown":
            return None

        norm_mac = normalize_mac(mac)
        norm_host = normalize_hostname(hostname)
        act = action.strip().lower()

        if act in {"lease_release", "release", "dhcprelease"}:
            existing = self._leases_by_ip.get(clean_ip)
            if existing is not None and (not norm_mac or not existing.mac or existing.mac == norm_mac):
                del self._leases_by_ip[clean_ip]
                if persist:
                    self.save()
            return None

        if not norm_mac and not norm_host:
            return None

        ts_iso = (timestamp or datetime.now(tz=UTC)).astimezone(UTC).isoformat()

        # 1. Evict any previous IP held by this same physical device (MAC or Hostname migration)
        stale_ips: list[str] = []
        for other_ip, other_lease in self._leases_by_ip.items():
            if other_ip == clean_ip:
                continue
            if (norm_mac and other_lease.mac and other_lease.mac == norm_mac) or (
                norm_host
                and other_lease.hostname
                and other_lease.hostname == norm_host
                and (not norm_mac or not other_lease.mac or other_lease.mac == norm_mac)
            ):
                stale_ips.append(other_ip)

        for stale_ip in stale_ips:
            # Before deleting stale_ip, if the new DHCPACK (e.g. Kea) only included the MAC
            # and not the hostname, carry over the known hostname for that same MAC.
            old_entry = self._leases_by_ip.pop(stale_ip)
            if not norm_host and norm_mac and old_entry.mac == norm_mac and old_entry.hostname:
                norm_host = old_entry.hostname

        # 2. Check existing entry on the target IP
        prev_on_ip = self._leases_by_ip.get(clean_ip)
        if prev_on_ip is not None:
            same_device = (
                (norm_mac and prev_on_ip.mac and norm_mac == prev_on_ip.mac)
                or (not norm_mac and norm_host and prev_on_ip.hostname == norm_host)
                or (source == "ptr" and not norm_mac)
            )
            if same_device:
                norm_mac = norm_mac or prev_on_ip.mac
                norm_host = norm_host or prev_on_ip.hostname
                interface = interface or prev_on_ip.interface
                if prev_on_ip.source == "dhcp":
                    source = "dhcp"

        identity = DeviceIdentity(
            ip=clean_ip,
            mac=norm_mac,
            hostname=norm_host,
            interface=interface if interface != "unknown" else "",
            source=source,
            updated_at=ts_iso,
        )
        self._leases_by_ip[clean_ip] = identity
        self._ptr_negative_cache.discard(clean_ip)
        if persist:
            self.save()
        return identity

    def ingest_dhcp_events(self, events: list[NormalizedLogEvent]) -> int:
        """Process all `tier_0_dhcp_identity` / `dhcp_lease` events in chronological order."""
        dhcp_events = [
            ev
            for ev in events
            if ev.security_tier == "tier_0_dhcp_identity" or ev.sub_type == "dhcp_lease"
        ]
        if not dhcp_events:
            return 0

        dhcp_events.sort(key=lambda e: e.timestamp)
        updated_count = 0

        for ev in dhcp_events:
            ip = ev.src_ip
            mac = ev.src_mac
            host = ev.src_host
            action = ev.action

            if (not mac and not host) and ev.raw_log:
                parsed = parse_raw_dhcp_log(ev.raw_log)
                if parsed is not None:
                    action, ip, mac, host = parsed

            self.update_lease(
                ip=ip,
                mac=mac,
                hostname=host,
                action=action,
                interface=ev.interface,
                timestamp=ev.timestamp,
                source="dhcp",
                persist=False,
            )
            if (
                action not in {"lease_release", "release", "dhcprelease"}
                and not host
                and self.enable_ptr_fallback
                and is_private_ip(ip)
            ):
                self.resolve_ptr_hostname(ip)
            updated_count += 1

        if updated_count > 0:
            self.save()
        return updated_count

    def resolve_ptr_hostname(self, ip: str) -> str:
        """Perform a fast Reverse DNS (`PTR`) lookup for a private IP if not cached."""
        if not self.enable_ptr_fallback or not is_private_ip(ip):
            return ""
        if ip in self._ptr_negative_cache:
            return ""

        prev_timeout = socket.getdefaulttimeout()
        try:
            socket.setdefaulttimeout(self.ptr_timeout_seconds)
            fqdn, _, _ = socket.gethostbyaddr(ip)
            norm = normalize_hostname(fqdn)
            if norm:
                self.update_lease(
                    ip=ip,
                    hostname=norm,
                    source="ptr",
                    persist=True,
                )
                return norm
        except (OSError, ValueError):
            pass
        finally:
            socket.setdefaulttimeout(prev_timeout)

        self._ptr_negative_cache.add(ip)
        return ""

    def get_identity(self, ip: str, allow_ptr: bool = True) -> DeviceIdentity | None:
        """Return the resolved `DeviceIdentity` for `ip`, using Reverse DNS fallback if needed."""
        clean_ip = ip.strip()
        if not clean_ip or clean_ip == "unknown":
            return None

        existing = self._leases_by_ip.get(clean_ip)
        if existing is not None:
            if not existing.hostname and allow_ptr and self.enable_ptr_fallback:
                self.resolve_ptr_hostname(clean_ip)
                existing = self._leases_by_ip.get(clean_ip)
            return existing

        if allow_ptr and self.enable_ptr_fallback and is_private_ip(clean_ip):
            resolved = self.resolve_ptr_hostname(clean_ip)
            if resolved:
                return self._leases_by_ip.get(clean_ip)

        return None

    def enrich_events(self, events: list[NormalizedLogEvent]) -> None:
        """Ingest any DHCP lease events in `events` and populate `src_host/mac` & `dst_host/mac`."""
        self.ingest_dhcp_events(events)

        for ev in events:
            if ev.security_tier == "tier_0_dhcp_identity":
                continue

            if is_private_ip(ev.src_ip):
                src_id = self.get_identity(ev.src_ip)
                if src_id is not None:
                    if not ev.src_host and src_id.hostname:
                        ev.src_host = src_id.hostname
                    if not ev.src_mac and src_id.mac:
                        ev.src_mac = src_id.mac

            if is_private_ip(ev.dst_ip):
                dst_id = self.get_identity(ev.dst_ip)
                if dst_id is not None:
                    if not ev.dst_host and dst_id.hostname:
                        ev.dst_host = dst_id.hostname
                    if not ev.dst_mac and dst_id.mac:
                        ev.dst_mac = dst_id.mac

    def list_leases(self) -> list[DeviceIdentity]:
        """Return all active leases sorted by IP."""
        return [
            lease
            for _, lease in sorted(self._leases_by_ip.items(), key=lambda x: x[0])
        ]
