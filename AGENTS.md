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

## 3. Pre-Push Security & Sensitive Data Anonymization Policy (Mandatory)
Before executing any `git push` to GitHub (or committing code and documentation destined for remote repositories), the agent **MUST** perform a rigorous, comprehensive security and privacy audit. Any sensitive, confidential, or identifying data **MUST** be thoroughly sanitized and anonymized.

### 3.1 Strict Data Sanitization & Anonymization Rules
1. **Zero Credential & Secret Leakage**:
   - API keys (`ANTHROPIC_API_KEY`, `OPENROUTER_API_KEY`, `OPENAI_API_KEY`, GeoIP API tokens, etc.).
   - Telegram Bot tokens (`TELEGRAM_BOT_TOKEN`), webhook secrets, passwords, password hashes, TLS private keys, certificates, or SSH keys.
   - Numeric Telegram chat IDs (`TELEGRAM_CHAT_ID`) — must always use dummy placeholders (e.g. `123456789`).
   - Never commit or track `.env` or any unversioned credential file.
2. **IP Addresses & Network Topologies**:
   - **Public WAN IPs**: Real firewall external WAN IPs and upstream ISP gateway IPs must NEVER be committed. Replace them with RFC 5737 reserved documentation subnets:
     - `192.0.2.0/24` (TEST-NET-1)
     - `198.51.100.0/24` (TEST-NET-2)
     - `203.0.113.0/24` (TEST-NET-3)
     For IPv6, use RFC 3849 (`2001:db8::/32`).
   - **External Threat & Scanner IPs**: In documentation, benchmark logs, and raw traces, external public scanner IPs must be sanitized or replaced with RFC 5737 documentation addresses.
   - **Internal Topologies & Hardware Details**: Do not expose real physical interface MAC addresses, private DNS domain names, user-specific internal hostnames, or production VLAN structures that reveal internal infrastructure details. Use standard RFC 1918 documentation subnets (`192.168.1.0/24`, `10.0.0.0/24`, `172.16.0.0/24`) and generic hostnames (`internal-host-1`, `webgui-host`).
3. **Personal Identifiable Information (PII)**:
   - Real personal names, email addresses (except official git author settings), subscriber identities, and physical geolocation specifics that link directly to private individuals.

### 3.2 Special Focus on the Project Wiki (`wiki/`)
The `wiki/` directory contains compounding knowledge, operational runbooks, raw log traces (`wiki/raw/`), benchmark snapshots, and historical entries (`wiki/log.md`). Agents must enforce maximum rigor on `wiki/`:
- **`wiki/raw/` (Raw Evidence & Snapshots)**: Never paste un-anonymized firewall logs, live packet traces, raw JSON payloads, or real system outputs. All raw traces must undergo redaction and anonymization prior to saving and pushing.
- **`wiki/log.md` & `wiki/index.md`**: Ensure milestone summaries, interface descriptions, IP ranges, and incident details do not leak real infrastructure information.
- **`wiki/runbooks/` & `wiki/components/`**: Ensure all examples use sanitized sample IPs, placeholder tokens, and generic interface/VLAN conventions.

### 3.3 Mandatory Pre-Push Verification Checklist
Every time before issuing a `git push` (or committing code/documentation destined for push), the agent must:
1. **Diff Audit**: Review `git status` and `git diff` for all modified and newly staged files.
2. **Secret & Pattern Scan**: Run a regex/grep check across all changes for tokens, API keys, and non-RFC5737/non-RFC1918 public IP addresses.
3. **Wiki Scrutiny**: Perform a dedicated inspection of all modified files under `wiki/` to ensure full compliance with the anonymization standard.
4. **Immediate Redaction**: If any sensitive or un-anonymized item is found, sanitize it immediately prior to push.
