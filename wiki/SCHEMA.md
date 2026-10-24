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
