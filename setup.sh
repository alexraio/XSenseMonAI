#!/usr/bin/env bash
# ==============================================================================
# PfsenseMon (XSenseMonAI) — Interactive Quick-Start & Onboarding Wizard
# ==============================================================================
# Compatible with macOS (Bash 3.2+) and Linux (Bash 4+/5+).
# Zero Python package dependencies required on the host machine.
#
# Usage:
#   ./setup.sh                     Interactive Quick-Start wizard (default)
#   ./setup.sh --check             Run pre-flight & .env validation only
#   ./setup.sh --test-only         Run E2E smoke test on the active Docker stack
#   ./setup.sh --non-interactive   Generate .env from environment/defaults
#   ./setup.sh --env-file <path>   Custom path for .env file
#   ./setup.sh --help              Show usage instructions
# ==============================================================================

set -Eeuo pipefail

readonly SCRIPT_VERSION="1.0.0"
SCRIPT_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
readonly SCRIPT_DIR

# Default CLI flags
MODE="interactive"
ENV_FILE="${SCRIPT_DIR}/.env"
SKIP_DOCKER_DEPLOY="${PFSENSEMON_ENV_ONLY:-0}"
SKIP_DOCKER_CHECK="${PFSENSEMON_SKIP_DOCKER_CHECK:-0}"

# Temporary files list for cleanup on exit
TEMP_FILES=()

cleanup() {
  local f
  if [[ ${#TEMP_FILES[@]} -gt 0 ]]; then
    for f in "${TEMP_FILES[@]}"; do
      if [[ -n "$f" && -e "$f" ]]; then
        rm -f -- "$f"
      fi
    done
  fi
}
trap cleanup EXIT INT TERM

# ==============================================================================
# 1. Terminal Colors & UI Helpers
# ==============================================================================
if [[ -t 1 && -z "${NO_COLOR:-}" ]]; then
  readonly C_RESET=$'\033[0m'
  readonly C_BOLD=$'\033[1m'
  readonly C_DIM=$'\033[2m'
  readonly C_GREEN=$'\033[32m'
  readonly C_YELLOW=$'\033[33m'
  readonly C_RED=$'\033[31m'
  readonly C_CYAN=$'\033[36m'
  readonly C_BLUE=$'\033[34m'
else
  readonly C_RESET=""
  readonly C_BOLD=""
  readonly C_DIM=""
  readonly C_GREEN=""
  readonly C_YELLOW=""
  readonly C_RED=""
  readonly C_CYAN=""
  readonly C_BLUE=""
fi

log_info() {
  printf "%s[INFO]%s %s\n" "${C_CYAN}" "${C_RESET}" "$*"
}

log_ok() {
  printf "%s[ OK ]%s %s\n" "${C_GREEN}" "${C_RESET}" "$*"
}

log_warn() {
  printf "%s[WARN]%s %s\n" "${C_YELLOW}" "${C_RESET}" "$*" >&2
}

log_error() {
  printf "%s[ERR ]%s %s\n" "${C_RED}" "${C_RESET}" "$*" >&2
}

print_banner() {
  printf "\n%s==============================================================================%s\n" "${C_BLUE}" "${C_RESET}"
  printf "%s  XSenseMonAI / PfsenseMon — Quick-Start & Onboarding Wizard (v%s)%s\n" "${C_BOLD}" "${SCRIPT_VERSION}" "${C_RESET}"
  printf "%s  Vector (Syslog) -> Grafana Loki -> Zero-Token Filter -> AI -> Telegram%s\n" "${C_DIM}" "${C_RESET}"
  printf "%s==============================================================================%s\n\n" "${C_BLUE}" "${C_RESET}"
}

print_section() {
  printf "\n%s--- %s ---%s\n" "${C_BOLD}${C_CYAN}" "$1" "${C_RESET}"
}

usage() {
  cat <<EOF
Usage: $(basename "$0") [OPTIONS]

Interactive Quick-Start and onboarding script for PfsenseMon.
Guides you through host pre-flight checks, .env configuration with live
model and Telegram chat_id auto-discovery, Docker Compose deployment,
and end-to-end synthetic syslog verification.

Options:
  --check              Run pre-flight checks and validate existing .env without modifying files
  --test-only          Skip setup and run the interactive E2E smoke test on the active stack
  --non-interactive    Generate .env from environment variables/defaults without interactive prompts
  --env-file <path>    Target .env file path (default: ./.env)
  --version            Print script version and exit
  -h, --help           Show this help message and exit

Examples:
  ./setup.sh
  ./setup.sh --check
  ./setup.sh --test-only
EOF
}

# Prompt user for text input with a default value.
# Usage: prompt_input "Label" "default_val" RESULT_VAR
prompt_input() {
  local label="$1"
  local default_val="$2"
  local __resultvar="$3"
  local input=""

  if [[ -n "$default_val" ]]; then
    printf "%s%s%s [%s%s%s]: " "${C_BOLD}" "$label" "${C_RESET}" "${C_CYAN}" "$default_val" "${C_RESET}"
  else
    printf "%s%s%s: " "${C_BOLD}" "$label" "${C_RESET}"
  fi

  if ! IFS= read -r input; then
    input=""
  fi
  if [[ -z "$input" ]]; then
    input="$default_val"
  fi
  printf -v "$__resultvar" '%s' "$input"
}

# Prompt user for secret input (masked on TTY).
# Usage: prompt_secret "Label" "default_val" RESULT_VAR
prompt_secret() {
  local label="$1"
  local default_val="$2"
  local __resultvar="$3"
  local input=""

  if [[ -n "$default_val" ]]; then
    printf "%s%s%s [press Enter to keep current/default]: " "${C_BOLD}" "$label" "${C_RESET}"
  else
    printf "%s%s%s (input hidden): " "${C_BOLD}" "$label" "${C_RESET}"
  fi

  if [[ -t 0 ]]; then
    if ! IFS= read -r -s input; then
      input=""
    fi
    printf "\n"
  else
    if ! IFS= read -r input; then
      input=""
    fi
  fi

  if [[ -z "$input" ]]; then
    input="$default_val"
  fi
  printf -v "$__resultvar" '%s' "$input"
}

# Prompt user for a Yes/No confirmation. Returns 0 for Yes, 1 for No.
# Usage: if prompt_yes_no "Question?" "N"; then ...
prompt_yes_no() {
  local label="$1"
  local default_ans="${2:-N}"
  local hint="[y/N]"
  local input=""

  if [[ "$default_ans" =~ ^[Yy]$ ]]; then
    hint="[Y/n]"
  fi

  printf "%s%s%s %s: " "${C_BOLD}" "$label" "${C_RESET}" "$hint"
  if ! IFS= read -r input; then
    input=""
  fi
  if [[ -z "$input" ]]; then
    input="$default_ans"
  fi

  case "$input" in
    [Yy] | [Yy][Ee][Ss] | [Ss] | [Ss][Ii]) return 0 ;;
    *) return 1 ;;
  esac
}

# Display a numbered menu and store the 1-based chosen index in CHOICE_INDEX.
# Usage: prompt_choice "Header" default_idx "Option 1" "Option 2" ...
CHOICE_INDEX=1
prompt_choice() {
  local header="$1"
  local default_idx="$2"
  shift 2
  local options=("$@")
  local count=${#options[@]}
  local idx=1
  local input=""

  printf "\n%s%s%s\n" "${C_BOLD}" "$header" "${C_RESET}"
  for opt in "${options[@]}"; do
    if [[ "$idx" -eq "$default_idx" ]]; then
      printf "  %s%d)%s %s %s(default)%s\n" "${C_CYAN}${C_BOLD}" "$idx" "${C_RESET}" "$opt" "${C_DIM}" "${C_RESET}"
    else
      printf "  %s%d)%s %s\n" "${C_CYAN}" "$idx" "${C_RESET}" "$opt"
    fi
    idx=$((idx + 1))
  done

  while true; do
    printf "Select an option [1-%d] (default: %d): " "$count" "$default_idx"
    if ! IFS= read -r input; then
      input="$default_idx"
    fi
    if [[ -z "$input" ]]; then
      input="$default_idx"
    fi
    if [[ "$input" =~ ^[0-9]+$ ]] && [[ "$input" -ge 1 && "$input" -le "$count" ]]; then
      CHOICE_INDEX="$input"
      return 0
    fi
    log_warn "Please enter a valid number between 1 and ${count}."
  done
}

# ==============================================================================
# 2. Multi-Fallback JSON Helpers (python3 -> jq -> POSIX grep/sed)
# ==============================================================================
extract_model_ids_from_json() {
  local raw_json="$1"
  if [[ -z "$raw_json" ]]; then
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    items = data.get("data") if isinstance(data, dict) else None
    if items is None and isinstance(data, dict):
        items = data.get("models", [])
    for m in (items or []):
        if isinstance(m, dict):
            mid = m.get("id") or m.get("name")
            if mid:
                print(str(mid).strip())
except Exception:
    pass
' <<<"$raw_json" 2>/dev/null && return 0
  fi

  if command -v jq >/dev/null 2>&1; then
    jq -r '(.data // .models // [])[] | (.id // .name // empty)' <<<"$raw_json" 2>/dev/null && return 0
  fi

  printf '%s\n' "$raw_json" |
    grep -o '"id"[[:space:]]*:[[:space:]]*"[^"]*"' |
    sed 's/.*"id"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || true
}

extract_telegram_bot_username() {
  local raw_json="$1"
  if [[ -z "$raw_json" ]]; then
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    if data.get("ok") and isinstance(data.get("result"), dict):
        print(data["result"].get("username", ""))
except Exception:
    pass
' <<<"$raw_json" 2>/dev/null && return 0
  fi

  if command -v jq >/dev/null 2>&1; then
    jq -r 'if .ok then (.result.username // empty) else empty end' <<<"$raw_json" 2>/dev/null && return 0
  fi

  if printf '%s' "$raw_json" | grep -q '"ok"[[:space:]]*:[[:space:]]*true'; then
    printf '%s\n' "$raw_json" |
      grep -o '"username"[[:space:]]*:[[:space:]]*"[^"]*"' |
      head -n 1 |
      sed 's/.*"username"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/' || true
  fi
}

extract_telegram_chat_id() {
  local raw_json="$1"
  if [[ -z "$raw_json" ]]; then
    return 0
  fi

  if command -v python3 >/dev/null 2>&1; then
    python3 -c '
import json, sys
try:
    data = json.load(sys.stdin)
    results = data.get("result") or []
    for item in reversed(results):
        for key in ("message", "edited_message", "my_chat_member", "channel_post"):
            msg = item.get(key)
            if isinstance(msg, dict) and isinstance(msg.get("chat"), dict):
                cid = msg["chat"].get("id")
                if cid is not None:
                    print(str(cid))
                    sys.exit(0)
except Exception:
    pass
' <<<"$raw_json" 2>/dev/null && return 0
  fi

  if command -v jq >/dev/null 2>&1; then
    jq -r '.result // [] | reverse | .[] | (.message.chat.id // .my_chat_member.chat.id // empty)' <<<"$raw_json" 2>/dev/null | head -n 1 && return 0
  fi

  printf '%s\n' "$raw_json" |
    grep -o '"chat"[[:space:]]*:[[:space:]]*{[^}]*"id"[[:space:]]*:[[:space:]]*-\?[0-9]\+' |
    tail -n 1 |
    grep -o '"id"[[:space:]]*:[[:space:]]*-\?[0-9]\+' |
    sed 's/.*"id"[[:space:]]*:[[:space:]]*\(-\?[0-9]\+\).*/\1/' || true
}

mask_secret() {
  local s="$1"
  local len=${#s}
  if [[ "$len" -eq 0 ]]; then
    printf "(empty)"
  elif [[ "$len" -le 8 ]]; then
    printf "****"
  else
    printf "%s...%s" "${s:0:4}" "${s:$((len - 4)):4}"
  fi
}

# Read a specific key from an existing .env file without sourcing arbitrary code
read_env_key() {
  local file="$1"
  local key="$2"
  local default_val="${3:-}"
  if [[ ! -f "$file" ]]; then
    printf '%s' "$default_val"
    return 0
  fi
  local line
  line="$(grep -E "^[[:space:]]*${key}=" "$file" | tail -n 1 || true)"
  if [[ -z "$line" ]]; then
    printf '%s' "$default_val"
    return 0
  fi
  local val="${line#*=}"
  # Strip optional surrounding single or double quotes
  val="${val#\"}"
  val="${val%\"}"
  val="${val#\'}"
  val="${val%\'}"
  printf '%s' "$val"
}

# ==============================================================================
# 3. Pre-Flight & Host Detection Checks
# ==============================================================================
detect_host_ip() {
  local ip=""
  case "$(uname -s)" in
    Darwin*)
      local default_if=""
      default_if="$(route -n get default 2>/dev/null | awk '/interface:/{print $2}' || true)"
      if [[ -n "$default_if" ]]; then
        ip="$(ipconfig getifaddr "$default_if" 2>/dev/null || true)"
      fi
      if [[ -z "$ip" ]]; then
        ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
      fi
      ;;
    Linux*)
      if command -v ip >/dev/null 2>&1; then
        ip="$(ip -4 route get 1.1.1.1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") {print $(i+1); exit}}' || true)"
      fi
      if [[ -z "$ip" ]] && command -v hostname >/dev/null 2>&1; then
        ip="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
      fi
      ;;
  esac

  if [[ -z "$ip" ]]; then
    ip="<DOCKER_HOST_IP>"
  fi
  printf '%s' "$ip"
}

check_port_status() {
  local proto="$1"
  local port="$2"
  local expected_container="$3"
  local proto_upper="TCP"

  if [[ "$proto" == "udp" ]]; then
    proto_upper="UDP"
  fi

  if ! command -v lsof >/dev/null 2>&1; then
    return 0
  fi

  local lsof_flag="-iTCP:${port}"
  if [[ "$proto" == "udp" ]]; then
    lsof_flag="-iUDP:${port}"
  fi

  if lsof -nP "$lsof_flag" >/dev/null 2>&1; then
    if [[ "$SKIP_DOCKER_CHECK" != "1" ]] && command -v docker >/dev/null 2>&1; then
      if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${expected_container}$"; then
        log_ok "Port ${proto_upper} ${port} is active (already used by container ${expected_container})."
        return 0
      fi
    fi
    log_warn "Port ${proto_upper} ${port} appears to be in use on the host. You can customize it in Advanced Settings if needed."
  else
    log_ok "Port ${proto_upper} ${port} is available."
  fi
}

run_preflight_checks() {
  print_section "Step 1: Host Pre-Flight Checks"

  if ! command -v curl >/dev/null 2>&1; then
    log_error "'curl' is required but was not found in PATH. Please install curl and retry."
    return 1
  fi
  log_ok "Found curl: $(command -v curl)"

  if [[ "$SKIP_DOCKER_CHECK" == "1" ]]; then
    log_info "Skipping Docker daemon checks (PFSENSEMON_SKIP_DOCKER_CHECK=1)."
  else
    if ! command -v docker >/dev/null 2>&1; then
      log_error "'docker' CLI was not found. Please install Docker Engine or Docker Desktop first."
      return 1
    fi
    log_ok "Found Docker CLI: $(command -v docker)"

    if ! docker compose version >/dev/null 2>&1; then
      log_error "'docker compose' (v2 plugin) is not available. Please install Docker Compose v2."
      return 1
    fi
    local compose_ver
    compose_ver="$(docker compose version --short 2>/dev/null || echo "v2")"
    log_ok "Found Docker Compose: ${compose_ver}"

    if ! docker info >/dev/null 2>&1; then
      log_error "Docker daemon is not running or current user lacks permissions. Start Docker and retry."
      return 1
    fi
    log_ok "Docker daemon is running and reachable."
  fi

  local syslog_port="5140"
  local loki_port="3100"
  if [[ -f "$ENV_FILE" ]]; then
    syslog_port="$(read_env_key "$ENV_FILE" "VECTOR_SYSLOG_PORT" "5140")"
    loki_port="$(read_env_key "$ENV_FILE" "LOKI_HTTP_PORT" "3100")"
  fi

  check_port_status "udp" "$syslog_port" "pfsensemon-vector"
  check_port_status "tcp" "$loki_port" "pfsensemon-loki"

  local host_ip
  host_ip="$(detect_host_ip)"
  log_info "Detected Docker Host LAN IP: ${C_BOLD}${host_ip}${C_RESET}"
  return 0
}

validate_existing_env() {
  local file="$1"
  if [[ ! -f "$file" ]]; then
    log_error "Configuration file not found at: ${file}"
    return 1
  fi

  local provider
  provider="$(read_env_key "$file" "LLM_PROVIDER" "anthropic")"
  local tg_token
  tg_token="$(read_env_key "$file" "TELEGRAM_BOT_TOKEN" "")"
  local tg_chat
  tg_chat="$(read_env_key "$file" "TELEGRAM_CHAT_ID" "")"

  case "$provider" in
    anthropic | ollama | openai | openrouter)
      log_ok "Valid LLM_PROVIDER in $(basename "$file"): ${provider}"
      ;;
    *)
      log_error "Unsupported LLM_PROVIDER='${provider}' in ${file} (expected: anthropic, ollama, openai, openrouter)."
      return 1
      ;;
  esac

  if [[ "$provider" == "anthropic" ]]; then
    local ak
    ak="$(read_env_key "$file" "ANTHROPIC_API_KEY" "")"
    local lk
    lk="$(read_env_key "$file" "LLM_API_KEY" "")"
    if [[ -z "$ak" && -z "$lk" ]] || [[ "$ak" == "your-minimax-or-anthropic-api-key" ]]; then
      log_error "Missing or placeholder ANTHROPIC_API_KEY in ${file}."
      return 1
    fi
  elif [[ "$provider" == "openrouter" ]]; then
    local ok
    ok="$(read_env_key "$file" "OPENROUTER_API_KEY" "")"
    local lk
    lk="$(read_env_key "$file" "LLM_API_KEY" "")"
    if [[ -z "$ok" && -z "$lk" ]] || [[ "$ok" == "sk-or-v1-replace-with-your-openrouter-key" ]]; then
      log_error "Missing or placeholder OPENROUTER_API_KEY in ${file}."
      return 1
    fi
  fi

  if [[ -z "$tg_token" || "$tg_token" == "1234567890:AAF-replace-with-your-botfather-token" ]]; then
    log_warn "TELEGRAM_BOT_TOKEN in ${file} is empty or still set to the example placeholder."
  else
    log_ok "TELEGRAM_BOT_TOKEN is configured ($(mask_secret "$tg_token"))."
  fi

  if [[ -z "$tg_chat" ]]; then
    log_warn "TELEGRAM_CHAT_ID in ${file} is empty."
  else
    log_ok "TELEGRAM_CHAT_ID is configured."
  fi

  return 0
}

# ==============================================================================
# 4. Interactive Auto-Discovery Helpers (Models & Telegram)
# ==============================================================================
discover_and_select_model() {
  local probe_url="$1"
  local auth_header="$2"
  local default_model="$3"
  local __outvar="$4"

  log_info "Probing ${probe_url} for available models..."
  local raw_json=""
  if [[ -n "$auth_header" ]]; then
    raw_json="$(curl -fsS --max-time 5 -H "$auth_header" "$probe_url" 2>/dev/null || true)"
  else
    raw_json="$(curl -fsS --max-time 5 "$probe_url" 2>/dev/null || true)"
  fi

  local models_list=()
  if [[ -n "$raw_json" ]]; then
    while IFS= read -r line; do
      if [[ -n "$line" ]]; then
        models_list+=("$line")
      fi
    done < <(extract_model_ids_from_json "$raw_json")
  fi

  if [[ ${#models_list[@]} -gt 0 ]]; then
    log_ok "Discovered ${#models_list[@]} model(s) on endpoint!"
    local menu_opts=()
    local m
    local count=0
    for m in "${models_list[@]}"; do
      menu_opts+=("$m")
      count=$((count + 1))
      if [[ "$count" -ge 15 ]]; then
        break
      fi
    done
    menu_opts+=("Enter a custom model name manually")

    prompt_choice "Select the model to use:" 1 "${menu_opts[@]}"
    if [[ "$CHOICE_INDEX" -le "$count" ]]; then
      local chosen="${models_list[$((CHOICE_INDEX - 1))]}"
      printf -v "$__outvar" '%s' "$chosen"
      return 0
    fi
  else
    log_warn "Could not auto-discover models from ${probe_url} (server may be offline or not exposing /v1/models)."
  fi

  local manual_model=""
  prompt_input "Enter model identifier" "$default_model" manual_model
  printf -v "$__outvar" '%s' "$manual_model"
}

configure_telegram_interactive() {
  local current_token="$1"
  local current_chat_id="$2"
  local __token_var="$3"
  local __chat_var="$4"

  print_section "Telegram Bot Alerting Setup"
  local token=""
  prompt_secret "Enter your Telegram Bot Token (from @BotFather)" "$current_token" token

  local bot_username=""
  if [[ -n "$token" && "$token" != "1234567890:AAF-replace-with-your-botfather-token" ]]; then
    log_info "Verifying Telegram Bot token via /getMe..."
    local me_json=""
    me_json="$(curl -fsS --max-time 5 "https://api.telegram.org/bot${token}/getMe" 2>/dev/null || true)"
    bot_username="$(extract_telegram_bot_username "$me_json")"
    if [[ -n "$bot_username" ]]; then
      log_ok "Telegram token verified! Connected to bot: @${bot_username}"
    else
      log_warn "Could not verify token via /getMe (check token or internet connection)."
    fi
  fi

  local chat_id="$current_chat_id"
  if [[ -n "$bot_username" ]]; then
    if prompt_yes_no "Auto-detect your numeric TELEGRAM_CHAT_ID now by sending /start to @${bot_username}?" "Y"; then
      printf "\n  1. Open Telegram and open a chat with %s@%s%s\n" "${C_BOLD}" "$bot_username" "${C_RESET}"
      printf "  2. Press %sStart (/start)%s or send any message to the bot.\n" "${C_BOLD}" "${C_RESET}"
      printf "  3. Press %sEnter%s here once you have sent the message..." "${C_BOLD}" "${C_RESET}"
      IFS= read -r _ || true

      local updates_json=""
      updates_json="$(curl -fsS --max-time 5 "https://api.telegram.org/bot${token}/getUpdates" 2>/dev/null || true)"
      local detected_id=""
      detected_id="$(extract_telegram_chat_id "$updates_json")"
      if [[ -n "$detected_id" ]]; then
        log_ok "Auto-discovered numeric TELEGRAM_CHAT_ID: ${detected_id}"
        chat_id="$detected_id"
      else
        log_warn "No recent messages found in /getUpdates yet."
        log_info "Note: You can enter your numeric chat_id manually, or leave @${bot_username} so the Analyzer resolves it on the next cycle."
        prompt_input "Telegram Chat ID (or bot username)" "${current_chat_id:-$bot_username}" chat_id
      fi
    else
      prompt_input "Telegram Chat ID (numeric ID or @${bot_username} for runtime auto-discovery)" "${current_chat_id:-$bot_username}" chat_id
    fi
  else
    prompt_input "Telegram Chat ID (numeric ID, e.g. 123456789)" "${current_chat_id:-123456789}" chat_id
  fi

  printf -v "$__token_var" '%s' "$token"
  printf -v "$__chat_var" '%s' "$chat_id"
}

# ==============================================================================
# 5. Atomic .env File Generator (chmod 600)
# ==============================================================================
write_env_file() {
  local target_file="$1"
  local tmp_env
  tmp_env="$(mktemp "${target_file}.tmp.XXXXXX")"
  TEMP_FILES+=("$tmp_env")
  chmod 600 "$tmp_env"

  cat >"$tmp_env" <<EOF
# ==============================================================================
# PfsenseMon (XSenseMonAI) — Environment Configuration
# Generated by setup.sh on $(date -u +"%Y-%m-%dT%H:%M:%SZ")
# File permissions: 0600 (owner read/write only)
# ==============================================================================

# ------------------------------------------------------------------------------
# 1. LLM Provider & AI Configuration
# ------------------------------------------------------------------------------
LLM_PROVIDER=${CFG_LLM_PROVIDER}

# Anthropic / MiniMax settings (used when LLM_PROVIDER=anthropic)
ANTHROPIC_API_KEY=${CFG_ANTHROPIC_API_KEY}
ANTHROPIC_BASE_URL=${CFG_ANTHROPIC_BASE_URL}
ANTHROPIC_MODEL=${CFG_ANTHROPIC_MODEL}

# Unified Multi-Provider / Local LLM settings (Ollama, LM Studio, vLLM, OpenRouter, OpenAI)
LLM_API_KEY=${CFG_LLM_API_KEY}
LLM_BASE_URL=${CFG_LLM_BASE_URL}
LLM_MODEL=${CFG_LLM_MODEL}
OPENROUTER_API_KEY=${CFG_OPENROUTER_API_KEY}

# Inference tuning & Structured Output
LLM_TIMEOUT_SECONDS=${CFG_LLM_TIMEOUT_SECONDS}
LLM_MAX_TOKENS=${CFG_LLM_MAX_TOKENS}
LLM_STRUCTURED_OUTPUT=${CFG_LLM_STRUCTURED_OUTPUT}
AI_REPORT_LANGUAGE=${CFG_AI_REPORT_LANGUAGE}
ENABLE_GEOIP=${CFG_ENABLE_GEOIP}

# ------------------------------------------------------------------------------
# 2. Telegram Bot Configuration
# ------------------------------------------------------------------------------
TELEGRAM_BOT_TOKEN=${CFG_TELEGRAM_BOT_TOKEN}
TELEGRAM_CHAT_ID=${CFG_TELEGRAM_CHAT_ID}
TELEGRAM_ENABLE_RAW_FALLBACK=${CFG_TELEGRAM_ENABLE_RAW_FALLBACK}

# ------------------------------------------------------------------------------
# 3. Network & Service Ports
# ------------------------------------------------------------------------------
VECTOR_SYSLOG_PORT=${CFG_VECTOR_SYSLOG_PORT}
LOKI_HTTP_PORT=${CFG_LOKI_HTTP_PORT}
LOKI_INTERNAL_URL=http://loki:3100
PFSENSE_WAN_INTERFACES=${CFG_PFSENSE_WAN_INTERFACES}

# ------------------------------------------------------------------------------
# 4. Zero-Token Pre-Filter & Detection Thresholds
# ------------------------------------------------------------------------------
ANALYSIS_INTERVAL_MINUTES=${CFG_ANALYSIS_INTERVAL_MINUTES}
MAX_CATCHUP_MINUTES=${CFG_MAX_CATCHUP_MINUTES}
WAN_BLOCK_HIT_THRESHOLD=${CFG_WAN_BLOCK_HIT_THRESHOLD}
WAN_PORT_SCAN_THRESHOLD=${CFG_WAN_PORT_SCAN_THRESHOLD}
OUTBOUND_SUSPICIOUS_THRESHOLD=${CFG_OUTBOUND_SUSPICIOUS_THRESHOLD}
AUTH_EVENT_THRESHOLD=${CFG_AUTH_EVENT_THRESHOLD}
ALERT_DEDUP_TTL_MINUTES=${CFG_ALERT_DEDUP_TTL_MINUTES}
MAX_PROMPT_ITEMS_PER_TIER=${CFG_MAX_PROMPT_ITEMS_PER_TIER}

# ------------------------------------------------------------------------------
# 5. Whitelists & Known Flows
# ------------------------------------------------------------------------------
WHITELIST_INTERNAL_IPS=${CFG_WHITELIST_INTERNAL_IPS}
WHITELIST_EXTERNAL_IPS=${CFG_WHITELIST_EXTERNAL_IPS}
WHITELIST_OUTBOUND_PORTS=${CFG_WHITELIST_OUTBOUND_PORTS}
WHITELIST_FLOWS=${CFG_WHITELIST_FLOWS}
KNOWN_FLOWS_PATH=${CFG_KNOWN_FLOWS_PATH}
EOF

  chmod 600 "$tmp_env"
  mv -f -- "$tmp_env" "$target_file"
  chmod 600 "$target_file"
  if [[ -d "${SCRIPT_DIR}/config" && ! -f "${SCRIPT_DIR}/config/known_flows.json" ]]; then
    printf '[]\n' > "${SCRIPT_DIR}/config/known_flows.json"
  fi
  log_ok "Saved configuration to ${target_file} (permissions: 0600)."
}

# Resolve configuration value with priority:
# 1) Explicit process environment variable
# 2) Existing .env file value
# 3) Built-in default value
cfg_val() {
  local src_file="$1"
  local key="$2"
  local default_val="${3:-}"
  local env_val="${!key:-}"

  if [[ -n "$env_val" ]]; then
    printf '%s' "$env_val"
    return 0
  fi
  read_env_key "$src_file" "$key" "$default_val"
}

# Initialize CFG_* variables from environment, existing .env, or sensible defaults
load_cfg_defaults() {
  local src_file="$1"
  CFG_LLM_PROVIDER="$(cfg_val "$src_file" "LLM_PROVIDER" "anthropic")"
  CFG_ANTHROPIC_API_KEY="$(cfg_val "$src_file" "ANTHROPIC_API_KEY" "")"
  CFG_ANTHROPIC_BASE_URL="$(cfg_val "$src_file" "ANTHROPIC_BASE_URL" "https://api.minimax.io/anthropic")"
  CFG_ANTHROPIC_MODEL="$(cfg_val "$src_file" "ANTHROPIC_MODEL" "MiniMax-M3")"
  CFG_LLM_API_KEY="$(cfg_val "$src_file" "LLM_API_KEY" "")"
  CFG_LLM_BASE_URL="$(cfg_val "$src_file" "LLM_BASE_URL" "")"
  CFG_LLM_MODEL="$(cfg_val "$src_file" "LLM_MODEL" "")"
  CFG_OPENROUTER_API_KEY="$(cfg_val "$src_file" "OPENROUTER_API_KEY" "")"
  CFG_LLM_TIMEOUT_SECONDS="$(cfg_val "$src_file" "LLM_TIMEOUT_SECONDS" "90")"
  CFG_LLM_MAX_TOKENS="$(cfg_val "$src_file" "LLM_MAX_TOKENS" "2500")"
  CFG_LLM_STRUCTURED_OUTPUT="$(cfg_val "$src_file" "LLM_STRUCTURED_OUTPUT" "true")"
  CFG_AI_REPORT_LANGUAGE="$(cfg_val "$src_file" "AI_REPORT_LANGUAGE" "Italian")"
  CFG_ENABLE_GEOIP="$(cfg_val "$src_file" "ENABLE_GEOIP" "true")"
  CFG_TELEGRAM_BOT_TOKEN="$(cfg_val "$src_file" "TELEGRAM_BOT_TOKEN" "1234567890:AAF-replace-with-your-botfather-token")"
  CFG_TELEGRAM_CHAT_ID="$(cfg_val "$src_file" "TELEGRAM_CHAT_ID" "123456789")"
  CFG_TELEGRAM_ENABLE_RAW_FALLBACK="$(cfg_val "$src_file" "TELEGRAM_ENABLE_RAW_FALLBACK" "true")"
  CFG_VECTOR_SYSLOG_PORT="$(cfg_val "$src_file" "VECTOR_SYSLOG_PORT" "5140")"
  CFG_LOKI_HTTP_PORT="$(cfg_val "$src_file" "LOKI_HTTP_PORT" "3100")"
  CFG_PFSENSE_WAN_INTERFACES="$(cfg_val "$src_file" "PFSENSE_WAN_INTERFACES" "wan,igb0,em0,vtnet0,pppoe0,ix0,re0,igc0")"
  CFG_ANALYSIS_INTERVAL_MINUTES="$(cfg_val "$src_file" "ANALYSIS_INTERVAL_MINUTES" "15")"
  CFG_MAX_CATCHUP_MINUTES="$(cfg_val "$src_file" "MAX_CATCHUP_MINUTES" "1440")"
  CFG_WAN_BLOCK_HIT_THRESHOLD="$(cfg_val "$src_file" "WAN_BLOCK_HIT_THRESHOLD" "50")"
  CFG_WAN_PORT_SCAN_THRESHOLD="$(cfg_val "$src_file" "WAN_PORT_SCAN_THRESHOLD" "8")"
  CFG_OUTBOUND_SUSPICIOUS_THRESHOLD="$(cfg_val "$src_file" "OUTBOUND_SUSPICIOUS_THRESHOLD" "1")"
  CFG_AUTH_EVENT_THRESHOLD="$(cfg_val "$src_file" "AUTH_EVENT_THRESHOLD" "1")"
  CFG_ALERT_DEDUP_TTL_MINUTES="$(cfg_val "$src_file" "ALERT_DEDUP_TTL_MINUTES" "120")"
  CFG_MAX_PROMPT_ITEMS_PER_TIER="$(cfg_val "$src_file" "MAX_PROMPT_ITEMS_PER_TIER" "15")"
  CFG_WHITELIST_INTERNAL_IPS="$(cfg_val "$src_file" "WHITELIST_INTERNAL_IPS" "")"
  CFG_WHITELIST_EXTERNAL_IPS="$(cfg_val "$src_file" "WHITELIST_EXTERNAL_IPS" "")"
  CFG_WHITELIST_OUTBOUND_PORTS="$(cfg_val "$src_file" "WHITELIST_OUTBOUND_PORTS" "53,80,123,443,465,587,853,993,51820,1194")"
  CFG_WHITELIST_FLOWS="$(cfg_val "$src_file" "WHITELIST_FLOWS" "")"
  CFG_KNOWN_FLOWS_PATH="$(cfg_val "$src_file" "KNOWN_FLOWS_PATH" "config/known_flows.json")"
}

run_env_wizard() {
  print_section "Step 2: Environment Configuration (.env Wizard)"
  load_cfg_defaults "$ENV_FILE"

  if [[ -f "$ENV_FILE" ]]; then
    log_info "Detected existing configuration file: ${ENV_FILE}"
    log_info "Current provider: ${C_BOLD}${CFG_LLM_PROVIDER}${C_RESET} | Telegram Token: $(mask_secret "$CFG_TELEGRAM_BOT_TOKEN")"

    prompt_choice "How would you like to proceed with the existing .env file?" 1 \
      "Keep current .env and proceed to Docker startup & E2E verification" \
      "Reconfigure .env (backs up current file to .env.bak with chmod 600)" \
      "Run E2E diagnostic smoke test only (skip setup and Docker build)"

    if [[ "$CHOICE_INDEX" -eq 1 ]]; then
      log_ok "Keeping existing ${ENV_FILE}."
      return 0
    elif [[ "$CHOICE_INDEX" -eq 3 ]]; then
      MODE="test-only"
      return 0
    else
      local bak_file="${ENV_FILE}.bak"
      (umask 077 && cp -f -- "$ENV_FILE" "$bak_file" && chmod 600 "$bak_file")
      log_ok "Created secure backup at ${bak_file} (permissions: 0600)."
    fi
  fi

  prompt_choice "Choose your AI SOC Analyst Backend (LLM Provider):" 1 \
    "LM Studio (Local on Host — Recommended for Apple Silicon & 100% Privacy)" \
    "Ollama (Local on Host — Zero API Key required)" \
    "MiniMax Cloud (Fast Anthropic-Compatible API — MiniMax-M3 / M2.5)" \
    "Anthropic Claude Cloud (Official Anthropic API)" \
    "OpenRouter Cloud (Multi-Model Gateway)" \
    "Custom OpenAI-Compatible Endpoint (vLLM / llama.cpp / OpenAI Cloud)"

  case "$CHOICE_INDEX" in
    1)
      # LM Studio Local
      CFG_LLM_PROVIDER="openai"
      CFG_LLM_API_KEY="not-needed"
      CFG_ANTHROPIC_API_KEY=""
      CFG_ANTHROPIC_BASE_URL=""
      CFG_ANTHROPIC_MODEL=""
      CFG_OPENROUTER_API_KEY=""
      local lms_port="1234"
      prompt_input "LM Studio HTTP port on host" "1234" lms_port
      CFG_LLM_BASE_URL="http://host.docker.internal:${lms_port}/v1"
      CFG_LLM_TIMEOUT_SECONDS="240"
      CFG_LLM_MAX_TOKENS="2500"
      CFG_LLM_STRUCTURED_OUTPUT="true"
      CFG_MAX_PROMPT_ITEMS_PER_TIER="15"

      discover_and_select_model "http://localhost:${lms_port}/v1/models" "" "${CFG_LLM_MODEL:-google/gemma-4-12b}" CFG_LLM_MODEL
      printf "\n  %s💡 LM Studio Best Practice:%s Disable 'Thinking' in LM Studio when using Structured\n" "${C_YELLOW}" "${C_RESET}"
      printf "     Output and set Context Length to %s16384%s tokens for optimal SOC reports.\n\n" "${C_BOLD}" "${C_RESET}"
      ;;
    2)
      # Ollama Local
      CFG_LLM_PROVIDER="ollama"
      CFG_LLM_API_KEY="ollama"
      CFG_ANTHROPIC_API_KEY=""
      CFG_ANTHROPIC_BASE_URL=""
      CFG_ANTHROPIC_MODEL=""
      CFG_OPENROUTER_API_KEY=""
      local ollama_port="11434"
      prompt_input "Ollama HTTP port on host" "11434" ollama_port
      CFG_LLM_BASE_URL="http://host.docker.internal:${ollama_port}/v1"
      CFG_LLM_TIMEOUT_SECONDS="180"
      CFG_LLM_MAX_TOKENS="2000"
      CFG_LLM_STRUCTURED_OUTPUT="true"
      CFG_MAX_PROMPT_ITEMS_PER_TIER="15"

      discover_and_select_model "http://localhost:${ollama_port}/v1/models" "" "${CFG_LLM_MODEL:-qwen2.5:14b}" CFG_LLM_MODEL
      ;;
    3)
      # MiniMax Cloud
      CFG_LLM_PROVIDER="anthropic"
      CFG_ANTHROPIC_BASE_URL="https://api.minimax.io/anthropic"
      CFG_LLM_API_KEY=""
      CFG_LLM_BASE_URL=""
      CFG_LLM_MODEL=""
      CFG_OPENROUTER_API_KEY=""
      prompt_secret "Enter your MiniMax API Key" "$CFG_ANTHROPIC_API_KEY" CFG_ANTHROPIC_API_KEY
      prompt_input "MiniMax Model Name" "${CFG_ANTHROPIC_MODEL:-MiniMax-M3}" CFG_ANTHROPIC_MODEL
      CFG_LLM_TIMEOUT_SECONDS="90"
      CFG_LLM_MAX_TOKENS="2500"
      CFG_MAX_PROMPT_ITEMS_PER_TIER="25"
      ;;
    4)
      # Official Anthropic Cloud
      CFG_LLM_PROVIDER="anthropic"
      CFG_ANTHROPIC_BASE_URL="https://api.anthropic.com"
      CFG_LLM_API_KEY=""
      CFG_LLM_BASE_URL=""
      CFG_LLM_MODEL=""
      CFG_OPENROUTER_API_KEY=""
      prompt_secret "Enter your Anthropic API Key (sk-ant-...)" "$CFG_ANTHROPIC_API_KEY" CFG_ANTHROPIC_API_KEY
      prompt_input "Anthropic Claude Model" "${CFG_ANTHROPIC_MODEL:-claude-sonnet-4-5}" CFG_ANTHROPIC_MODEL
      CFG_LLM_TIMEOUT_SECONDS="90"
      CFG_LLM_MAX_TOKENS="2500"
      CFG_MAX_PROMPT_ITEMS_PER_TIER="25"
      ;;
    5)
      # OpenRouter Cloud
      CFG_LLM_PROVIDER="openrouter"
      CFG_LLM_BASE_URL="https://openrouter.ai/api/v1"
      CFG_ANTHROPIC_API_KEY=""
      CFG_ANTHROPIC_BASE_URL=""
      CFG_ANTHROPIC_MODEL=""
      prompt_secret "Enter your OpenRouter API Key (sk-or-v1-...)" "$CFG_OPENROUTER_API_KEY" CFG_OPENROUTER_API_KEY
      CFG_LLM_API_KEY="$CFG_OPENROUTER_API_KEY"
      prompt_input "OpenRouter Model ID" "${CFG_LLM_MODEL:-google/gemini-2.5-flash}" CFG_LLM_MODEL
      CFG_LLM_TIMEOUT_SECONDS="90"
      CFG_LLM_MAX_TOKENS="2500"
      CFG_LLM_STRUCTURED_OUTPUT="true"
      CFG_MAX_PROMPT_ITEMS_PER_TIER="25"
      ;;
    6)
      # Custom OpenAI-compatible
      CFG_LLM_PROVIDER="openai"
      CFG_ANTHROPIC_API_KEY=""
      CFG_ANTHROPIC_BASE_URL=""
      CFG_ANTHROPIC_MODEL=""
      CFG_OPENROUTER_API_KEY=""
      prompt_input "OpenAI-Compatible Base URL (use host.docker.internal for host services)" "${CFG_LLM_BASE_URL:-http://host.docker.internal:1234/v1}" CFG_LLM_BASE_URL
      prompt_secret "API Key (or 'not-needed' for local endpoints)" "${CFG_LLM_API_KEY:-not-needed}" CFG_LLM_API_KEY
      local probe_base="${CFG_LLM_BASE_URL/host.docker.internal/localhost}"
      probe_base="${probe_base%/}/models"
      local auth_hdr=""
      if [[ -n "$CFG_LLM_API_KEY" && "$CFG_LLM_API_KEY" != "not-needed" ]]; then
        auth_hdr="Authorization: Bearer ${CFG_LLM_API_KEY}"
      fi
      discover_and_select_model "$probe_base" "$auth_hdr" "${CFG_LLM_MODEL:-local-model}" CFG_LLM_MODEL
      ;;
  esac

  prompt_input "Language for AI Security Reports (e.g. Italian, English)" "$CFG_AI_REPORT_LANGUAGE" CFG_AI_REPORT_LANGUAGE

  if prompt_yes_no "Enable automatic GeoIP & ASN enrichment for external threat IPs?" "Y"; then
    CFG_ENABLE_GEOIP="true"
  else
    CFG_ENABLE_GEOIP="false"
  fi

  configure_telegram_interactive \
    "$CFG_TELEGRAM_BOT_TOKEN" \
    "$CFG_TELEGRAM_CHAT_ID" \
    CFG_TELEGRAM_BOT_TOKEN \
    CFG_TELEGRAM_CHAT_ID

  if prompt_yes_no "Customize advanced settings (ports, Zero-Token thresholds, IP/port whitelists)?" "N"; then
    print_section "Advanced Settings"
    prompt_input "Vector Syslog UDP Port on Host" "$CFG_VECTOR_SYSLOG_PORT" CFG_VECTOR_SYSLOG_PORT
    prompt_input "Loki HTTP TCP Port on Host" "$CFG_LOKI_HTTP_PORT" CFG_LOKI_HTTP_PORT
    prompt_input "Analysis Interval (minutes)" "$CFG_ANALYSIS_INTERVAL_MINUTES" CFG_ANALYSIS_INTERVAL_MINUTES
    prompt_input "Tier 3 WAN Block Hit Threshold" "$CFG_WAN_BLOCK_HIT_THRESHOLD" CFG_WAN_BLOCK_HIT_THRESHOLD
    prompt_input "Tier 3 WAN Distinct Port Scan Threshold" "$CFG_WAN_PORT_SCAN_THRESHOLD" CFG_WAN_PORT_SCAN_THRESHOLD
    prompt_input "Alert Deduplication Cooldown TTL (minutes)" "$CFG_ALERT_DEDUP_TTL_MINUTES" CFG_ALERT_DEDUP_TTL_MINUTES
    prompt_input "Whitelisted Internal LAN IPs (comma-separated)" "$CFG_WHITELIST_INTERNAL_IPS" CFG_WHITELIST_INTERNAL_IPS
    prompt_input "Whitelisted External WAN IPs (comma-separated)" "$CFG_WHITELIST_EXTERNAL_IPS" CFG_WHITELIST_EXTERNAL_IPS
    prompt_input "Whitelisted Outbound Ports (comma-separated)" "$CFG_WHITELIST_OUTBOUND_PORTS" CFG_WHITELIST_OUTBOUND_PORTS
    prompt_input "Whitelisted Flows (src>dst:ports; semicolon-separated)" "$CFG_WHITELIST_FLOWS" CFG_WHITELIST_FLOWS
  fi

  write_env_file "$ENV_FILE"
}

# ==============================================================================
# 6. Docker Compose Deployment & Readiness Polling
# ==============================================================================
deploy_docker_stack() {
  if [[ "$SKIP_DOCKER_DEPLOY" == "1" ]]; then
    log_info "Skipping Docker Compose deployment (PFSENSEMON_ENV_ONLY=1)."
    return 0
  fi

  print_section "Step 3: Building & Starting Docker Compose Stack"
  log_info "Running: docker compose up -d --build"
  (cd "$SCRIPT_DIR" && docker compose up -d --build)

  local loki_port
  loki_port="$(read_env_key "$ENV_FILE" "LOKI_HTTP_PORT" "3100")"
  local ready_url="http://localhost:${loki_port}/ready"

  log_info "Waiting for Grafana Loki (${ready_url}) to report ready..."
  local elapsed=0
  local max_wait=40
  while [[ "$elapsed" -lt "$max_wait" ]]; do
    if curl -fsS --max-time 2 "$ready_url" >/dev/null 2>&1; then
      log_ok "Grafana Loki is healthy and ready on TCP port ${loki_port}!"
      break
    fi
    sleep 2
    elapsed=$((elapsed + 2))
  done

  if [[ "$elapsed" -ge "$max_wait" ]]; then
    log_warn "Loki did not respond on ${ready_url} within ${max_wait}s. Showing recent container status:"
    (cd "$SCRIPT_DIR" && docker compose ps) || true
  fi

  local svc
  for svc in pfsensemon-loki pfsensemon-vector pfsensemon-analyzer; do
    if docker ps --format '{{.Names}}' 2>/dev/null | grep -q "^${svc}$"; then
      log_ok "Container ${svc} is running."
    else
      log_error "Container ${svc} is not running! Recent logs:"
      (cd "$SCRIPT_DIR" && docker compose logs --tail=20) || true
      return 1
    fi
  done
}

# ==============================================================================
# 7. Two-Speed End-to-End Smoke Test (Fast ~10s vs Full ~65s)
# ==============================================================================
run_smoke_test() {
  if [[ "$SKIP_DOCKER_DEPLOY" == "1" ]]; then
    return 0
  fi

  print_section "Step 4: End-to-End Synthetic Smoke Test"
  prompt_choice "Would you like to run an End-to-End smoke test now?" 1 \
    "Fast Smoke Test (~10s — injects Tier 1 Outbound C2 & Tier 2 Auth failures, forwarded 1:1 immediately)" \
    "Full 3-Tier Smoke Test (~65s — includes 65-packet WAN Port Scan & waits 60s for Vector reduce flush)" \
    "Skip smoke test"

  if [[ "$CHOICE_INDEX" -eq 3 ]]; then
    log_info "Skipping E2E smoke test. You can run it anytime with: ./setup.sh --test-only"
    return 0
  fi

  local test_mode="$CHOICE_INDEX"

  prompt_choice "Choose Analyzer execution mode for the test:" 1 \
    "Live AI + Telegram Alert (verifies full pipeline: Vector -> Loki -> LLM -> Telegram)" \
    "Dry-Run Mode (verifies Vector -> Loki & Zero-Token filter without calling LLM or Telegram)"

  local analyzer_flags=("--once" "--reset-dedup")
  if [[ "$CHOICE_INDEX" -eq 2 ]]; then
    analyzer_flags+=("--dry-run")
  fi

  if [[ "$test_mode" -eq 1 ]]; then
    log_info "Injecting synthetic Tier 1 (outbound C2) and Tier 2 (SSH/WebGUI auth) syslog packets into Vector..."
    (cd "$SCRIPT_DIR" && docker compose exec -T analyzer python /app/scripts/simulate_pfsense_logs.py --host vector --port 5140 --scenario outbound)
    (cd "$SCRIPT_DIR" && docker compose exec -T analyzer python /app/scripts/simulate_pfsense_logs.py --host vector --port 5140 --scenario auth)
    log_info "Waiting 4 seconds for Vector -> Loki ingestion..."
    sleep 4
  else
    log_info "Injecting all synthetic scenarios (noise, 65-packet WAN scan, outbound C2, auth failures)..."
    (cd "$SCRIPT_DIR" && docker compose exec -T analyzer python /app/scripts/simulate_pfsense_logs.py --host vector --port 5140 --scenario all)
    log_info "Waiting 62 seconds for Vector's 60-second Tier 3 aggregation window to flush to Loki..."
    local rem=62
    while [[ "$rem" -gt 0 ]]; do
      printf "\r  %s⏳ Flushing Vector 60s reduce window: %2ds remaining...%s" "${C_CYAN}" "$rem" "${C_RESET}"
      sleep 2
      rem=$((rem - 2))
    done
    printf "\r  %s✅ Vector 60s aggregation window flushed!                    %s\n" "${C_GREEN}" "${C_RESET}"
  fi

  log_info "Triggering Python AI Analyzer evaluation cycle (${analyzer_flags[*]})..."
  if (cd "$SCRIPT_DIR" && docker compose exec -T analyzer python -m src.main "${analyzer_flags[@]}"); then
    log_ok "End-to-End smoke test completed! Check your output above (and Telegram if Live mode was selected)."
  else
    log_error "Analyzer returned a non-zero exit code during the smoke test. Check logs with: docker compose logs analyzer"
    return 1
  fi
}

# ==============================================================================
# 8. Contextualized Final Summary ("Next Steps")
# ==============================================================================
print_next_steps() {
  local host_ip
  host_ip="$(detect_host_ip)"
  local syslog_port
  syslog_port="$(read_env_key "$ENV_FILE" "VECTOR_SYSLOG_PORT" "5140")"
  local loki_port
  loki_port="$(read_env_key "$ENV_FILE" "LOKI_HTTP_PORT" "3100")"

  print_section "Setup Complete — Next Steps & Integration Guide"
  cat <<EOF
${C_GREEN}${C_BOLD}✔ PfsenseMon is configured and ready!${C_RESET}

${C_BOLD}1. Configure pfSense / OPNsense Remote Syslog:${C_RESET}
   • WebGUI: Status -> System Logs -> Settings -> Remote Logging Options
   • Enable Remote Logging: Checked
   • Remote log servers:    ${C_CYAN}${C_BOLD}${host_ip}:${syslog_port}${C_RESET} (UDP / IPv4)
   • Remote Syslog Contents: Firewall Events, System Events, SSH/Auth, VPN

${C_BOLD}2. Connect Your Existing Grafana Server:${C_RESET}
   • Connections -> Data sources -> Add new data source -> Loki
   • HTTP URL:              ${C_CYAN}${C_BOLD}http://${host_ip}:${loki_port}${C_RESET}
   • Import Dashboard JSON: ${C_DIM}config/grafana/dashboard-pfsense.json${C_RESET}

${C_BOLD}3. Configure Hermes Agent Skill (on Isolated Ubuntu VM):${C_RESET}
   • Allow TCP ${loki_port} from Hermes VM to ${host_ip} on pfSense
   • Set in ~/.hermes/.env: ${C_CYAN}LOKI_URL=http://${host_ip}:${loki_port}${C_RESET}
   • Run on Hermes VM:      ${C_DIM}python3 query_pfsense_loki.py summary --hours 24${C_RESET}

${C_BOLD}Useful Day-2 Operations Commands:${C_RESET}
   • View live analyzer logs:   ${C_CYAN}docker compose logs -f analyzer${C_RESET}
   • Re-run E2E smoke test:     ${C_CYAN}./setup.sh --test-only${C_RESET}
   • Validate configuration:    ${C_CYAN}./setup.sh --check${C_RESET}
EOF
}

# ==============================================================================
# 9. CLI Argument Parser & Entrypoint
# ==============================================================================
parse_args() {
  while [[ $# -gt 0 ]]; do
    case "$1" in
      --check)
        MODE="check"
        shift
        ;;
      --test-only)
        MODE="test-only"
        shift
        ;;
      --non-interactive)
        MODE="non-interactive"
        shift
        ;;
      --env-file)
        if [[ $# -lt 2 ]]; then
          log_error "--env-file requires a path argument."
          exit 1
        fi
        ENV_FILE="$2"
        shift 2
        ;;
      --version)
        printf "setup.sh version %s\n" "${SCRIPT_VERSION}"
        exit 0
        ;;
      -h | --help)
        usage
        exit 0
        ;;
      *)
        log_error "Unknown option: $1"
        usage
        exit 1
        ;;
    esac
  done
}

main() {
  parse_args "$@"
  print_banner

  case "$MODE" in
    check)
      run_preflight_checks
      validate_existing_env "$ENV_FILE"
      log_ok "All pre-flight and configuration checks passed!"
      ;;
    test-only)
      run_preflight_checks
      run_smoke_test
      ;;
    non-interactive)
      run_preflight_checks
      if [[ -f "$ENV_FILE" ]]; then
        local bak_file="${ENV_FILE}.bak"
        (umask 077 && cp -f -- "$ENV_FILE" "$bak_file" && chmod 600 "$bak_file")
      fi
      load_cfg_defaults "$ENV_FILE"
      write_env_file "$ENV_FILE"
      deploy_docker_stack
      ;;
    interactive)
      run_preflight_checks
      run_env_wizard
      if [[ "$MODE" == "test-only" ]]; then
        run_smoke_test
      else
        deploy_docker_stack
        run_smoke_test
        print_next_steps
      fi
      ;;
  esac
}

main "$@"
