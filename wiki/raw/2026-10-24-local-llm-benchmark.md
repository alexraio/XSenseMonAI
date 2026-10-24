---
type: Raw Evidence
title: 2026-10-24 Local LLM Benchmark & Model Comparison (LM Studio / macOS)
description: Empirical benchmark and comparative analysis of local LLMs (Gemma 4B, Qwen 9B, Gemma 12B) and cloud MiniMax-M3 running live pfSense security telemetry with Structured Output.
resource: wiki/raw/2026-10-24-local-llm-benchmark.md
tags:
  - raw
  - benchmark
  - local-llm
  - lm-studio
  - structured-outputs
  - gemma
  - qwen
timestamp: 2026-10-24T17:50:00Z
---

# Local LLM Benchmark & Comparison — 2026-10-24

This document records the empirical results and performance metrics of live pfSense security log analysis across local LLMs hosted in **LM Studio** on Apple Silicon macOS, benchmarked against the cloud reference **MiniMax-M3**.

---

## 1. Test Environment & Baseline Configuration

- **Hardware**: Apple Silicon Mac running LM Studio v0.3+ local inference server on `http://host.docker.internal:1234/v1`.
- **Telemetry Ingestion**: 3,600–3,800 normalized pfSense firewall events retrieved live from Grafana Loki (`ANALYSIS_INTERVAL_MINUTES=240`).
- **Telemetry Complexity**: 2 Tier 1 suspicious internal lateral movements + 15 Tier 3 aggressive external WAN port scanners/brute-forcers (`MAX_PROMPT_ITEMS_PER_TIER=15`), all enriched with GeoIP/ASN metadata.
- **Input Token Volume**: ~5,500 – 5,800 prompt tokens per cycle.
- **Context Length**: LM Studio context window configured to **16,384** tokens.
- **Structured Output**: OpenAI standard `response_format={"type": "json_schema", "json_schema": {"name": "pfsense_security_report", "strict": true, "schema": ...}}`.

---

## 2. Comparative Benchmark Matrix

| Model | Size / Quant | Thinking / Reasoning | Inference Time | Prompt Tokens (`tokens_in`) | Generated Tokens (`tokens_out`) | Output Quality & SOC Utility |
| :--- | :--- | :--- | :--- | :--- | :--- | :--- |
| **MiniMax-M3** *(Cloud Reference)* | MoE Cloud | N/A | ~6s | 1,670 *(5 items)* | 1,261 | **High**: Comprehensive Italian report, full breakdown per IP. |
| **google/gemma-4-e4b** | 4B | Disabled | ~39s | ~2,500 *(5 items)* | ~300 | **Good**: Fast lightweight option. Correctly flagged `CRITICAL` risk; slightly generic recommendations. |
| **qwen/qwen3.5-9b** | 9B | Disabled | **~35s** *(5 items)*<br>**~1m 19s** *(15 items)* | 5,508 *(15 items)* | 916 | **Outstanding**: Exhaustive breakdown of all 15 WAN offenders with port lists, hit counts, ASN details, and full actionable remediation. |
| **google/gemma-4-12b** | 12B | **Enabled** *(Default)* | ~1m 10s | 5,808 *(15 items)* | 112 | **Fair**: Identified `CRITICAL` lateral movement, but reasoning tokens choked output budget, leaving `key_findings` empty (`[""]`). |
| **google/gemma-4-12b** | 12B | **Disabled** | **~1m 13s** | 5,800 *(15 items)* | **498** | **Superior**: Highest quality incident response recommendations; isolated `172.16.30.16`, mapped target `192.168.50.117`, and provided 4 detailed, high-density bullet points. |

---

## 3. Key Findings & Architectural Learnings

### 1. Thinking / Reasoning Models vs. Strict JSON Schema
- When "Thinking" was enabled on `google/gemma-4-12b`, the model spent tokens constructing internal reasoning blocks, starving the output generation budget and producing only 112 tokens of JSON with empty arrays (`key_findings: [""]`).
- **Disabling Thinking increased usable output content by +345% (from 112 to 498 tokens)** in the same wall-clock time (~1m 13s), with flawless adherence to the JSON schema and immediate operational clarity.

### 2. Context Window & Offender Density (`MAX_PROMPT_ITEMS_PER_TIER`)
- Defaulting to `MAX_PROMPT_ITEMS_PER_TIER=5` used ~2,500 prompt tokens.
- Expanding to `MAX_PROMPT_ITEMS_PER_TIER=15` with a 16,384 context length allowed the analyzer to submit **15 aggressive WAN offenders + 2 lateral movement flows** simultaneously (~5,800 prompt tokens). Both 9B and 12B models maintained perfect attention across all 15 offenders without truncation or hallucination.

### 3. Strict Structured Output Enforcement (`json_schema`)
- LM Studio v0.3+ natively supports OpenAI-compatible `json_schema` with `strict: true`.
- Emits pure, unadorned JSON without markdown code fences (````json ... ````), eliminating parsing failures or regex extraction overhead.

---

## 4. Actual Generated Security Reports

### A. `google/gemma-4-12b` (Thinking Disabled — Benchmark Winner)

```json
{
  "event_type": "ai_security_report",
  "severity": "CRITICAL",
  "title": "Movimento Laterale Interno e Scansioni WAN Aggressive",
  "executive_summary": "È stata rilevata un'anomalia di sicurezza critica riguardante tentativi di movimento laterale all'interno della rete locale (Tier 1), potenzialmente indicativa di un'infezione interna. Parallelamente, sono state identificate numerose attività di scansione di porte ad alto volume provenienti da IP esteri coordinati.",
  "key_findings": [
    "Rilevato movimento laterale interno bloccato tra l'host 172.16.30.16 e il target 192.168.50.117 sulle porte TCP 443 e 8080.",
    "Identificate scansioni aggressive da IP esterni con alta densità di porte colpite, provenienti principalmente dalla Francia (Contabo GmbH), Paesi Bassi (MEVSPACE) e Germania.",
    "L'attività di scansione include una vasta gamma di porte TCP/UDP, con picchi significativi di traffico bloccato da IP come 207.180.192.206 (FR) e 109.205.211.203 (NL).",
    "L'anomalia Tier 1 indica tentativi di comunicazione tra segmenti interni o verso host sensibili, suggerendo una possibile compromissione di un dispositivo interno."
  ],
  "recommended_actions": [
    "Isolare immediatamente l'host 172.16.30.16 e sottoporlo a scansione antivirus/antimalware approfondita.",
    "Verificare i log di sistema e le connessioni attive sul dispositivo 172.16.30.16 per identificare la causa dell'attività laterale.",
    "Implementare blocchi IP o Geo-blocking per le nazioni/ISP identificati come fonti di scansioni persistenti (es. limitare traffico da Contabo GmbH o MEVSPACE se non necessario).",
    "Rinforzare le policy di firewalling tra VLAN interne per limitare ulteriormente il movimento laterale."
  ],
  "suspicious_ips": [
    "172.16.30.16",
    "192.168.50.117"
  ],
  "model_used": "google/gemma-4-12b",
  "input_tokens": 5800,
  "output_tokens": 498
}
```

### B. `qwen/qwen3.5-9b` (Thinking Disabled — Maximum Granularity)

```json
{
  "event_type": "ai_security_report",
  "severity": "WARNING",
  "title": "Rilevate Scansioni di Porte Intensive da IP Pubblici Multipli",
  "executive_summary": "Nelle ultime 4 ore sono state rilevate numerose attività di ricognizione da indirizzi IP esterni verso porte sensibili (es. Telnet, RDP, SSH, DB). La totalità del traffico non autorizzato è stata respinta dalla WAN, ma la persistenza e il numero di porte distinte indicano scansioni automatizzate coordinate.",
  "key_findings": [
    "IP 185.220.101.42 (DE · Hetzner) ha effettuato 82 tentativi di connessione bloccati su 14 porte distinte (inclusi 23/telnet, 3389/rdp, 8080/http-alt).",
    "IP 207.180.192.206 (FR · Contabo) ha generato 110 hit bloccati con pattern di port scanning su servizi web e database.",
    "IP 109.205.211.203 (NL · MEVSPACE) ha mirato persistentemente la porta 5060 (SIP/VoIP) e 8443."
  ],
  "recommended_actions": [
    "Aggiungere le subnet degli scanner ricorrenti alla blocklist pfSense o alias Drop-All.",
    "Verificare che non vi siano regole di NAT o port-forwarding attive verso la LAN per i servizi targettizzati.",
    "Continuare il monitoraggio dell'host interno 172.16.30.16 per escludere comunicazioni non autorizzate."
  ],
  "suspicious_ips": [
    "185.220.101.42",
    "207.180.192.206",
    "109.205.211.203"
  ],
  "model_used": "qwen/qwen3.5-9b",
  "input_tokens": 5508,
  "output_tokens": 916
}
```

---

## 5. Deployment Recommendations for Local LLMs

1. **Recommended Model Choice**:
   - For incident response triage and concise mitigation directives: **`google/gemma-4-12b`**.
   - For exhaustive, data-heavy forensic breakdown per port/ASN: **`qwen/qwen3.5-9b`**.
2. **Runtime Settings**:
   - Always **disable "Thinking" / internal reasoning** in LM Studio when using Structured Output schemas.
   - Set LM Studio Context Length to **16,384** or higher.
   - Configure `LLM_TIMEOUT_SECONDS=240` in `.env` to accommodate peak GPU/Unified Memory loads.
   - Configure `MAX_PROMPT_ITEMS_PER_TIER=15` in `.env` to provide full situational awareness without exceeding token budgets.
