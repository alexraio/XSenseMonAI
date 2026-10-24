# Project Rules & Guidelines (PfsenseMon)

## 1. Language Policy (Mandatory)
1. **User Conversation Language**: Always communicate and converse with the user in **Italian**.
2. **Code & Documentation Language**: All source code, variable/function/class names, inline comments, docstrings, configuration files (`docker-compose.yml`, `vector.yaml`, `loki-config.yaml`, `.env.example`), project documentation (`README.md`, `DESIGN.md`), and the **Project Wiki (`wiki/`)** MUST be written in **English**.

## 2. LLM Wiki & Open Knowledge Format (OKF) Policy
This repository maintains a persistent, self-compounding knowledge base under `wiki/` combining:
- **Andrej Karpathy's LLM Wiki Pattern** ([gist:442a6bf555914893e9891c11519de94f](https://gist.github.com/karpathy/442a6bf555914893e9891c11519de94f))
- **Google Cloud Open Knowledge Format (OKF)** ([okf/SPEC.md](https://github.com/GoogleCloudPlatform/knowledge-catalog/blob/main/okf/SPEC.md))

### Agent Responsibilities for `wiki/`:
1. **Progressive Disclosure First (`query`)**: When answering architectural or historical questions about the project, read `wiki/index.md` and `wiki/log.md` first before scanning the entire codebase.
2. **Continuous Compilation (`ingest`)**: Whenever a new feature, architectural change, bug fix, or verified test milestone is completed:
   - Update or create the relevant OKF concept/component page in `wiki/` (preserving valid YAML frontmatter with `type`, `title`, `description`, `resource`, `tags`, and `timestamp`).
   - Update `wiki/index.md` if any new page is added or its summary changes.
   - Append a chronological entry to `wiki/log.md` (`## [YYYY-MM-DD] <operation> | <title>`).
3. **Health Checks (`lint`)**: Periodically ensure all relative Markdown links inside `wiki/` resolve cleanly, YAML frontmatter is valid, and no orphan pages exist.
See [`wiki/SCHEMA.md`](wiki/SCHEMA.md) for full formatting rules.
