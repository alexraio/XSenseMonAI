---
name: pfsense-security-monitor
description: "Query and investigate pfSense firewall logs, suspicious outbound LAN traffic, WAN port scans, and AI security reports stored in Grafana Loki."
---

# pfSense Security Monitor Skill (PfsenseMon)

Use this skill whenever the user asks to:
- Check the security status of the pfSense firewall or WAN interface
- Investigate a specific IP address (`src_ip` or `dst_ip`) reported in a Telegram security alert
- Check whether any internal LAN/VLAN device made suspicious outbound connections (`Tier 1`)
- Inspect authentication logs (`sshd`, WebGUI, VPN) or allowed WAN connections (`Tier 2`)
- Review top blocked WAN scanners/attackers (`Tier 3`) or recent Claude AI Security Reports

## Prerequisites on the Hermes Ubuntu VM

1. Copy `query_pfsense_loki.py` to `/usr/local/bin/query_pfsense_loki.py` (or `~/.hermes/skills/pfsense-security-monitor/query_pfsense_loki.py`) and make it executable (`chmod +x`).
2. Set `LOKI_URL` in `~/.hermes/.env`:
   ```bash
   LOKI_URL=http://<DOCKER_HOST_IP>:3100
   ```
3. Ensure pfSense has a firewall rule on the Hermes VLAN interface allowing **TCP port 3100** from the Hermes Ubuntu VM IP to `<DOCKER_HOST_IP>`.

## Available Commands

Run the script via terminal tool and parse its JSON output. Both `summary` and `inspect-ip` automatically enrich public IPs with **GeoIP country, city, ISP, and ASN** metadata via batch lookup (pass `--no-geoip` to disable external GeoIP resolution):

### 1. Overall Security Summary (3 Tiers + GeoIP/ASN + Recent AI Reports)
```bash
python3 ~/.hermes/skills/pfsense-security-monitor/query_pfsense_loki.py summary --hours 24
```

### 2. Deep-Dive Investigation on a Specific IP Address (with GeoIP/ASN)
When the user asks *"What did IP 185.220.101.42 do?"* or *"Check internal host 192.168.1.50"*:
```bash
python3 ~/.hermes/skills/pfsense-security-monitor/query_pfsense_loki.py inspect-ip 185.220.101.42 --hours 168
```
*(Note: The output JSON includes a `geoip` object with `country`, `country_code`, `city`, `isp`, and `asn`. Combine with `whois` or `dig -x` if deeper RIR contact details are needed.)*

### 3. Inspect Suspicious Outbound / Internal Lateral Traffic (Tier 1)
```bash
python3 ~/.hermes/skills/pfsense-security-monitor/query_pfsense_loki.py outbound --hours 24
```

### 4. View Recent AI Security Assessments
```bash
python3 ~/.hermes/skills/pfsense-security-monitor/query_pfsense_loki.py ai-reports --hours 72
```
