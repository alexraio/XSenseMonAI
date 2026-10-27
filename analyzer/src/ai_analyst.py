"""Multi-provider AI SOC Analyst client (Anthropic/MiniMax, Ollama, OpenAI/LM Studio, OpenRouter)."""

from __future__ import annotations

import json
import logging
import re
import time
from typing import Any

import httpx

try:
    from anthropic import Anthropic, APIError, APITimeoutError, RateLimitError

    HAS_ANTHROPIC_SDK = True
except ImportError:  # pragma: no cover
    Anthropic = None  # type: ignore[assignment,misc]
    APIError = Exception  # type: ignore[assignment,misc]
    APITimeoutError = Exception  # type: ignore[assignment,misc]
    RateLimitError = Exception  # type: ignore[assignment,misc]
    HAS_ANTHROPIC_SDK = False

from .config import AppConfig, is_local_endpoint
from .models import AISecurityReport, FilterEvaluationResult

logger = logging.getLogger(__name__)


SYSTEM_PROMPT_TEMPLATE = """You are a Senior Network Security & SOC Analyst monitoring a pfSense firewall.
You receive pre-aggregated telemetry across 3 Security Tiers:
1. Tier 1 (`tier1_anomalies`): Outbound traffic from internal LAN/VLAN hosts towards the public WAN that was either BLOCKED by the firewall or directed to UNCOMMON ports, plus blocked internal lateral movement. This is the highest priority signal (potential malware, C2 callback, compromised IoT/host, or policy violation).
2. Tier 2 (`tier2_events`): Authentication events on pfSense (`sshd`, WebGUI, VPN) and inbound WAN connections explicitly ALLOWED (`action=pass`). Verify whether failed logins or unexpected inbound accesses occurred.
3. Tier 3 (`tier3_offenders`): External IPs blocked on the WAN that exceeded volume or port-scanning thresholds. Distinguish targeted multi-port reconnaissance or brute-force spikes from harmless background noise.

Note: External IP entries may include `dst_geoip` or `src_geoip` metadata (`country`, `country_code`, `city`, `isp`, `asn`). Incorporate relevant geographical and ASN/ISP context into your findings.
If `known_authorized_flows` is present in the payload, it lists known legitimate internal/outbound flows for the involved hosts (already suppressed by the pre-filter). Use those descriptions to identify device roles when an host exhibits new anomalous connections on unlisted ports or targets.

CRITICAL: Do not output any thinking process, explanation, notes, or prelude. Start directly with the opening curly brace '{{' and output strictly a valid JSON object matching this exact schema:
{{
  "severity": "INFO" | "WARNING" | "CRITICAL",
  "title": "Short descriptive title of the security event",
  "executive_summary": "2-3 sentences summarizing the situation clearly",
  "key_findings": [
    "Bullet 1 with specific IPs, GeoIP/ASN, ports, and hit counts",
    "Bullet 2..."
  ],
  "recommended_actions": [
    "Actionable step 1 (e.g. inspect internal host, block external subnet, check service)",
    "Actionable step 2..."
  ],
  "suspicious_ips": ["1.2.3.4", "192.168.1.50"]
}}

IMPORTANT: Write all human-readable text fields (`title`, `executive_summary`, `key_findings`, `recommended_actions`) in {report_language}.
"""

SECURITY_REPORT_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "severity": {
            "type": "string",
            "enum": ["INFO", "WARNING", "CRITICAL"],
            "description": "Severity level of the assessed events",
        },
        "title": {
            "type": "string",
            "description": "Short descriptive title of the security event in the target language",
        },
        "executive_summary": {
            "type": "string",
            "description": "2-3 sentences summarizing the situation clearly in the target language",
        },
        "key_findings": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Bullet points with specific IPs, GeoIP/ASN, ports, and hit counts",
        },
        "recommended_actions": {
            "type": "array",
            "items": {"type": "string"},
            "description": "Actionable security steps",
        },
        "suspicious_ips": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of suspicious or attacking IP addresses identified",
        },
    },
    "required": [
        "severity",
        "title",
        "executive_summary",
        "key_findings",
        "recommended_actions",
        "suspicious_ips",
    ],
    "additionalProperties": False,
}


class AnthropicSOCAnalyst:
    """Multi-provider SOC analyst supporting Anthropic/MiniMax, Ollama, OpenAI, and OpenRouter."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.client = (
            Anthropic(
                api_key=config.llm_api_key,
                base_url=config.llm_base_url,
            )
            if (
                config.llm_provider == "anthropic"
                and HAS_ANTHROPIC_SDK
                and config.llm_api_key
                and Anthropic is not None
            )
            else None
        )

    def _requires_api_key(self) -> bool:
        """Return True if the selected LLM provider and endpoint require an API key."""
        if self.config.llm_provider == "ollama":
            return False
        return not (
            self.config.llm_provider == "openai" and is_local_endpoint(self.config.llm_base_url)
        )

    def analyze(self, evaluation: FilterEvaluationResult, max_retries: int = 3) -> AISecurityReport:
        """Send aggregated anomaly payload to the configured LLM and return an AISecurityReport."""
        if self._requires_api_key() and not self.config.llm_api_key:
            raise RuntimeError(
                f"API key (ANTHROPIC_API_KEY / LLM_API_KEY) is not configured for provider '{self.config.llm_provider}'."
            )

        payload_dict: dict[str, Any] = {
            "window_start_utc": evaluation.window_start.isoformat(),
            "window_end_utc": evaluation.window_end.isoformat(),
            "trigger_reasons": evaluation.trigger_reasons,
            "total_wan_blocked_packets_in_window": evaluation.total_raw_wan_blocks,
            "tier1_outbound_or_lateral_anomalies": [
                item.model_dump(exclude_none=True) for item in evaluation.tier1_anomalies
            ],
            "tier2_auth_and_allowed_wan_events": [
                item.model_dump(exclude_none=True) for item in evaluation.tier2_events
            ],
            "tier3_aggressive_wan_offenders": [
                item.model_dump(exclude_none=True) for item in evaluation.tier3_offenders
            ],
        }
        if evaluation.known_flows_context:
            payload_dict["known_authorized_flows"] = evaluation.known_flows_context

        user_message = (
            "Analyze the following aggregated pfSense firewall security telemetry and return "
            "the JSON security report:\n\n"
            f"{json.dumps(payload_dict, indent=2, ensure_ascii=False)}"
        )

        system_prompt = SYSTEM_PROMPT_TEMPLATE.format(
            report_language=self.config.ai_report_language
        )

        last_error: Exception | None = None
        for attempt in range(1, max_retries + 1):
            try:
                if self.config.llm_provider == "anthropic":
                    if self.client is not None:
                        response = self.client.messages.create(
                            model=self.config.llm_model,
                            max_tokens=self.config.llm_max_tokens,
                            system=system_prompt,
                            messages=[{"role": "user", "content": user_message}],
                        )
                        raw_text = ""
                        for block in response.content:
                            if getattr(block, "type", "text") == "text" and hasattr(block, "text"):
                                raw_text += block.text
                        in_tokens = getattr(response.usage, "input_tokens", 0)
                        out_tokens = getattr(response.usage, "output_tokens", 0)
                    else:
                        raw_text, in_tokens, out_tokens = self._call_via_httpx(
                            system_prompt=system_prompt,
                            user_message=user_message,
                        )
                else:
                    raw_text, in_tokens, out_tokens = self._call_openai_compatible(
                        system_prompt=system_prompt,
                        user_message=user_message,
                    )

                report = self._parse_json_response(raw_text)
                report.model_used = self.config.llm_model
                report.input_tokens = in_tokens
                report.output_tokens = out_tokens
                logger.info(
                    "LLM analysis succeeded (provider=%s, model=%s, severity=%s, tokens_in=%d, tokens_out=%d)",
                    self.config.llm_provider,
                    report.model_used,
                    report.severity,
                    report.input_tokens,
                    report.output_tokens,
                )
                return report

            except (RateLimitError, APITimeoutError, APIError, httpx.HTTPError) as exc:
                last_error = exc
                backoff = 2**attempt
                logger.warning(
                    "LLM API transient error (provider=%s, attempt %d/%d): %s. Retrying in %ds...",
                    self.config.llm_provider,
                    attempt,
                    max_retries,
                    exc,
                    backoff,
                )
                if attempt < max_retries:
                    time.sleep(backoff)

        raise RuntimeError(
            f"LLM analysis ({self.config.llm_provider}) failed after {max_retries} attempts: {last_error}"
        ) from last_error

    def _call_via_httpx(
        self,
        system_prompt: str,
        user_message: str,
    ) -> tuple[str, int, int]:
        """Direct HTTP fallback to Anthropic/MiniMax Messages API (/v1/messages)."""
        headers = {
            "x-api-key": self.config.llm_api_key,
            "Authorization": f"Bearer {self.config.llm_api_key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.config.llm_model,
            "max_tokens": self.config.llm_max_tokens,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }
        endpoint = f"{self.config.llm_base_url.rstrip('/')}/v1/messages"
        with httpx.Client(timeout=self.config.llm_timeout_seconds) as client:
            resp = client.post(endpoint, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
        raw_text = "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        )
        usage = data.get("usage", {})
        return raw_text, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))

    def _call_openai_compatible(
        self,
        system_prompt: str,
        user_message: str,
    ) -> tuple[str, int, int]:
        """Call OpenAI-compatible /v1/chat/completions endpoint (Ollama, OpenAI, LM Studio, OpenRouter)."""
        token = self.config.llm_api_key or "ollama"
        headers: dict[str, str] = {
            "Authorization": f"Bearer {token}",
            "Content-Type": "application/json",
        }
        if self.config.llm_provider == "openrouter":
            if self.config.openrouter_site_url:
                headers["HTTP-Referer"] = self.config.openrouter_site_url
            if self.config.openrouter_app_name:
                headers["X-Title"] = self.config.openrouter_app_name

        body: dict[str, Any] = {
            "model": self.config.llm_model,
            "max_tokens": self.config.llm_max_tokens,
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message},
            ],
        }
        if self.config.llm_structured_output:
            body["response_format"] = {
                "type": "json_schema",
                "json_schema": {
                    "name": "pfsense_security_report",
                    "strict": True,
                    "schema": SECURITY_REPORT_JSON_SCHEMA,
                },
            }

        endpoint = f"{self.config.llm_base_url.rstrip('/')}/chat/completions"
        with httpx.Client(timeout=self.config.llm_timeout_seconds) as client:
            resp = client.post(endpoint, headers=headers, json=body)
            status_code = getattr(resp, "status_code", 200)

            # Gracefully retry without response_format if provider rejects json_schema
            if (
                isinstance(status_code, int)
                and status_code == 400
                and "response_format" in body
            ):
                err_text = getattr(resp, "text", "")
                if any(k in err_text.lower() for k in ("response_format", "schema", "unsupported")):
                    logger.warning(
                        "LLM endpoint rejected json_schema response_format (%s); retrying without structured output.",
                        err_text,
                    )
                    retry_body = dict(body)
                    retry_body.pop("response_format", None)
                    resp = client.post(endpoint, headers=headers, json=retry_body)
                    status_code = getattr(resp, "status_code", 200)

            if isinstance(status_code, int) and status_code >= 400:
                logger.error(
                    "LLM endpoint %s returned HTTP %d: %s",
                    endpoint,
                    status_code,
                    getattr(resp, "text", ""),
                )
            resp.raise_for_status()
            data = resp.json()

        choices = data.get("choices") or []
        message = choices[0].get("message", {}) if choices else {}
        content = message.get("content", "")
        if isinstance(content, list):
            raw_text = "".join(
                str(part.get("text", ""))
                for part in content
                if isinstance(part, dict) and part.get("type", "text") == "text"
            )
        else:
            raw_text = str(content or "")

        if not raw_text.strip() and message.get("reasoning_content"):
            raw_text = str(message.get("reasoning_content"))

        usage = data.get("usage") or {}
        in_tokens = int(usage.get("prompt_tokens", usage.get("input_tokens", 0)))
        out_tokens = int(usage.get("completion_tokens", usage.get("output_tokens", 0)))
        return raw_text, in_tokens, out_tokens

    @staticmethod
    def _parse_json_response(raw_text: str) -> AISecurityReport:
        """Extract and validate JSON object from LLM response text (stripping <think> blocks if present)."""
        # Strip reasoning <think>...</think> blocks emitted by DeepSeek/Qwen/local reasoning models
        cleaned = re.sub(
            r"<think>.*?</think>",
            "",
            raw_text,
            flags=re.DOTALL | re.IGNORECASE,
        ).strip()

        # Strip optional markdown code fences if present
        fence_match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", cleaned, flags=re.DOTALL)
        if fence_match:
            cleaned = fence_match.group(1)
        else:
            brace_start = cleaned.find("{")
            brace_end = cleaned.rfind("}")
            if brace_start != -1 and brace_end != -1 and brace_end > brace_start:
                cleaned = cleaned[brace_start : brace_end + 1]

        try:
            data = json.loads(cleaned)
            return AISecurityReport.model_validate(data)
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.warning(
                "Failed to parse strict JSON from LLM response (%s); using fallback wrapper.",
                exc,
            )
            return AISecurityReport(
                severity="WARNING",
                title="pfSense AI Security Analysis",
                executive_summary=cleaned[:800] or raw_text[:800],
                key_findings=[],
                recommended_actions=[],
                suspicious_ips=[],
            )


SOCAnalyst = AnthropicSOCAnalyst
