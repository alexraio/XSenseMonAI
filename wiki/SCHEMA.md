---
type: Specification
title: PfsenseMon LLM Wiki & OKF Schema
description: Governance, directory conventions, YAML frontmatter schema, and agent operations (ingest, query, lint) for the PfsenseMon knowledge base.
resource: wiki/SCHEMA.md
tags:
  - wiki
  - okf
  - karpathy-llm-wiki
  - schema
timestamp: 2026-10-23T20:25:00Z
---

# PfsenseMon Wiki Schema (Karpathy LLM Wiki + Google OKF)

This directory implements a hybrid knowledge base combining:
1. **Andrej Karpathy's LLM Wiki Pattern** ([gist](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f)): An LLM-maintained, compounding Markdown wiki with explicit `raw/` sources, synthesized concept/component pages, `index.md`, `log.md`, and three core agent workflows (`ingest`, `query`, `lint`).
2. **Google Cloud Open Knowledge Format (OKF)** ([SPEC.md](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md)): Standardized YAML frontmatter (`type` required, plus `title`, `description`, `resource`, `tags`, `timestamp`), progressive disclosure via `index.md`, chronological tracking via `log.md`, and graph relationships expressed via standard relative Markdown links.

---

## 1. Directory Layout

```text
wiki/
├── index.md                         # Root OKF catalog (okf_version: "1.0") for progressive disclosure
├── log.md                           # Chronological append-only log of project milestones & wiki updates
├── SCHEMA.md                        # This specification file
├── concepts/                        # Architectural & security concepts
│   ├── three-tier-hybrid-strategy.md
│   └── zero-token-filter.md
├── components/                      # Technical components & integrations
│   ├── vector-pipeline.md
│   ├── loki-and-grafana.md
│   ├── ai-analyzer-minimax.md
│   └── hermes-agent-skill.md
├── runbooks/                        # Operational & testing procedures
│   └── pfsense-and-e2e-testing.md
└── raw/                             # Immutable raw logs, test outputs & reference snapshots
    └── 2026-10-23-e2e-verification-minimax.md
```

---

## 2. OKF YAML Frontmatter Standard

Every concept, component, and runbook page MUST start with YAML frontmatter:

```yaml
---
type: Component | Architecture Concept | Runbook | Raw Evidence
title: Human-readable title
description: One-sentence summary used for progressive disclosure.
resource: path/to/code/or/config
tags:
  - tag1
  - tag2
timestamp: YYYY-MM-DDTHH:MM:SSZ
---
```

---

## 3. Core Agent Workflows

### A. `ingest` (Adding New Knowledge or Project Progress)
1. Save any immutable raw evidence (e.g., benchmark outputs, incident logs, raw test traces) in `wiki/raw/` if applicable.
2. Create or update the affected pages in `wiki/concepts/`, `wiki/components/`, or `wiki/runbooks/`, maintaining bidirectional relative Markdown links.
3. Ensure `wiki/index.md` lists all pages with an accurate one-line summary.
4. Append a timestamped entry to `wiki/log.md` using the format:
   `## [YYYY-MM-DD] <operation> | <short title>`

### B. `query` (Reading & Answering Questions)
1. Read `wiki/index.md` first to locate relevant concept/component files without loading unnecessary files into the context window.
2. Traverse relative Markdown links between pages to gather full context.
3. If a query produces a new architectural insight or troubleshooting rule, persist it into the wiki.

### C. `lint` (Knowledge Base Health Check)
1. Verify that every `.md` file in `concepts/`, `components/`, `runbooks/`, and `raw/` is listed in `wiki/index.md`.
2. Verify that all relative Markdown links (`[Label](../path/file.md)`) resolve to existing files.
3. Verify that no concept claims contradict the current implementation in `analyzer/`, `config/`, or `docker-compose.yml`.
4. Verify that no raw credentials, secrets, tokens, or un-anonymized public/internal IPs exist in any wiki file prior to pushing to remote repositories.

---

## 4. Sensitive Data Anonymization & Privacy Standard

To ensure that the persistent knowledge base is safe for version control and remote publication (e.g. GitHub):
1. **Zero Credential Exposure**: Never record live API keys, Telegram bot tokens, actual numeric chat IDs, passwords, or authentication headers in any wiki page. Always use placeholder tokens (`your-api-key`, `123456789`).
2. **RFC 5737 IP Anonymization**: All public IPv4 addresses appearing in verification snapshots (`wiki/raw/`), architecture examples (`wiki/concepts/`), components (`wiki/components/`), or runbooks (`wiki/runbooks/`) MUST use RFC 5737 reserved documentation ranges:
   - `192.0.2.0/24` (TEST-NET-1)
   - `198.51.100.0/24` (TEST-NET-2)
   - `203.0.113.0/24` (TEST-NET-3)
   For IPv6, use RFC 3849 (`2001:db8::/32`).
3. **Sanitized Raw Logs (`wiki/raw/`)**: When capturing empirical test results or model benchmarks, redact or anonymize all live hostnames, external WAN IPs, and internal topology specifics prior to committing.
4. **Pre-Push Verification**: Every wiki addition or update must be audited for sensitive data before any `git push` to remote repositories.
