#!/usr/bin/env python3
"""Synthetic pfSense Syslog Generator for testing PfsenseMon end-to-end.

Sends realistic pfSense `filterlog` (CSV) and authentication (`sshd`, `webConfigurator`)
UDP packets to Vector (default: 127.0.0.1:5140).
"""

from __future__ import annotations

import argparse
import socket
import time


def send_udp_syslog(host: str, port: int, message: str) -> None:
    """Send a single RFC 3164 syslog line over UDP."""
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.sendto(message.encode("utf-8"), (host, port))


def build_filterlog_ipv4(
    interface: str,
    action: str,
    direction: str,
    proto: str,
    src_ip: str,
    dst_ip: str,
    src_port: int,
    dst_port: int,
    tcp_flags: str = "S",
) -> str:
    """Build a realistic pfSense filterlog CSV syslog line."""
    proto_id = {"tcp": 6, "udp": 17, "icmp": 1}.get(proto.lower(), 6)
    return (
        f"<134>Oct 23 18:30:00 pfSense.localdomain filterlog[41205]: "
        f"4,,,1000000103,{interface},match,{action},{direction},4,0x0,,64,12345,0,none,"
        f"{proto_id},{proto},60,{src_ip},{dst_ip},{src_port},{dst_port},0,{tcp_flags},123456,,65535,,mss"
    )


def simulate_background_noise(host: str, port: int) -> None:
    """Send harmless low-volume WAN background blocks (should NOT trigger AI analysis alone)."""
    print("[1/4] Sending harmless background WAN noise (5 packets)...")
    for i in range(5):
        msg = build_filterlog_ipv4(
            interface="igb0",
            action="block",
            direction="in",
            proto="tcp",
            src_ip=f"93.184.216.{10 + i}",
            dst_ip="203.0.113.2",
            src_port=45000 + i,
            dst_port=8080,
        )
        send_udp_syslog(host, port, msg)


def simulate_wan_port_scan(host: str, port: int) -> None:
    """Simulate an aggressive external scanner hitting 12 distinct ports and 65 total hits (Tier 3)."""
    attacker_ip = "185.220.101.42"
    scanned_ports = [21, 22, 23, 80, 443, 445, 1433, 3306, 3389, 5432, 8080, 8443]
    print(f"[2/4] Simulating Tier 3 aggressive WAN port scan from {attacker_ip} (65 packets across 12 ports)...")
    for idx in range(65):
        target_port = scanned_ports[idx % len(scanned_ports)]
        msg = build_filterlog_ipv4(
            interface="igb0",
            action="block",
            direction="in",
            proto="tcp",
            src_ip=attacker_ip,
            dst_ip="203.0.113.2",
            src_port=52000 + idx,
            dst_port=target_port,
            tcp_flags="S",
        )
        send_udp_syslog(host, port, msg)
        time.sleep(0.005)


def simulate_suspicious_outbound(host: str, port: int) -> None:
    """Simulate an internal LAN host attempting suspicious outbound C2 communication (Tier 1)."""
    internal_host = "192.168.1.145"
    c2_server = "198.51.100.77"
    print(
        f"[3/4] Simulating Tier 1 suspicious outbound C2 traffic from {internal_host} -> {c2_server}:4444/TCP..."
    )
    for idx in range(6):
        msg = build_filterlog_ipv4(
            interface="igb1",
            action="block",
            direction="in",
            proto="tcp",
            src_ip=internal_host,
            dst_ip=c2_server,
            src_port=60100 + idx,
            dst_port=4444,
            tcp_flags="S",
        )
        send_udp_syslog(host, port, msg)


def simulate_auth_anomaly(host: str, port: int) -> None:
    """Simulate pfSense SSH / WebGUI failed login attempts (Tier 2)."""
    attacker_ip = "45.155.205.99"
    print(f"[4/4] Simulating Tier 2 failed SSH & WebGUI authentication events from {attacker_ip}...")
    for _ in range(3):
        ssh_msg = (
            f"<38>Oct 23 18:31:00 pfSense.localdomain sshd[88210]: "
            f"error: PAM: Authentication error for root from {attacker_ip}"
        )
        web_msg = (
            f"<37>Oct 23 18:31:02 pfSense.localdomain php-fpm[34112]: "
            f"/index.php: webConfigurator authentication error for user 'admin' from: {attacker_ip}"
        )
        send_udp_syslog(host, port, ssh_msg)
        send_udp_syslog(host, port, web_msg)


def simulate_lateral_blocked(
    host: str,
    port: int,
    src_ip: str = "172.16.0.10",
    dst_ip: str = "192.168.1.50",
    dst_ports: list[int] | None = None,
    src_port: int | None = None,
    proto: str = "tcp",
    hits_per_port: int = 4,
) -> None:
    """Simulate blocked inter-VLAN or custom outbound traffic (`tier_1_outbound_suspicious`)."""
    ports = dst_ports or [443, 8080]
    print(
        f"[Flow] Simulating Tier 1 blocked traffic {src_ip}:{src_port or 'ephemeral'} -> {dst_ip} on ports {ports}/{proto}..."
    )
    for p_idx, dst_port in enumerate(ports):
        for i in range(hits_per_port):
            effective_sport = src_port if src_port is not None else (51000 + (p_idx * 100) + i)
            msg = build_filterlog_ipv4(
                interface="igc1",
                action="block",
                direction="in",
                proto=proto,
                src_ip=src_ip,
                dst_ip=dst_ip,
                src_port=effective_sport,
                dst_port=dst_port,
                tcp_flags="S" if proto.lower() == "tcp" else "",
            )
            send_udp_syslog(host, port, msg)


def main() -> None:
    parser = argparse.ArgumentParser(description="Simulate pfSense Syslog traffic for PfsenseMon.")
    parser.add_argument("--host", default="127.0.0.1", help="Vector UDP host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=5140, help="Vector UDP port (default: 5140)")
    parser.add_argument(
        "--scenario",
        choices=["all", "noise", "portscan", "outbound", "auth", "lateral"],
        default="all",
        help="Traffic scenario to simulate (default: all)",
    )
    parser.add_argument("--src-ip", default="172.16.0.10", help="Source IP for lateral scenario")
    parser.add_argument(
        "--src-port",
        type=int,
        default=None,
        help="Optional fixed source port (e.g. 6881 for BitTorrent DHT)",
    )
    parser.add_argument("--dst-ip", default="192.168.1.50", help="Destination IP for lateral scenario")
    parser.add_argument(
        "--dst-ports",
        default="443,8080",
        help="Comma-separated destination ports for lateral scenario (default: 443,8080)",
    )
    parser.add_argument("--proto", default="tcp", help="Protocol for lateral scenario (tcp or udp)")
    args = parser.parse_args()

    print(f"Sending synthetic pfSense Syslog packets to {args.host}:{args.port}/UDP...")
    if args.scenario in ("all", "noise"):
        simulate_background_noise(args.host, args.port)
    if args.scenario in ("all", "portscan"):
        simulate_wan_port_scan(args.host, args.port)
    if args.scenario in ("all", "outbound"):
        simulate_suspicious_outbound(args.host, args.port)
    if args.scenario in ("all", "auth"):
        simulate_auth_anomaly(args.host, args.port)
    if args.scenario == "lateral":
        parsed_ports = [int(p.strip()) for p in args.dst_ports.split(",") if p.strip().isdigit()]
        simulate_lateral_blocked(
            args.host,
            args.port,
            src_ip=args.src_ip,
            dst_ip=args.dst_ip,
            dst_ports=parsed_ports,
            src_port=args.src_port,
            proto=args.proto,
        )

    print(
        "\nDone! Note: Vector's 60-second reduce window flushes Tier 3 summaries within ~60s.\n"
        "You can trigger an immediate Analyzer check with:\n"
        "  docker compose exec analyzer python -m src.main --once"
    )


if __name__ == "__main__":
    main()
