"""Anthropic Claude API client for SOC-level analysis of aggregated pfSense telemetry."""

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

from .config import AppConfig
from .models import AISecurityReport, FilterEvaluationResult

logger = logging.getLogger(__name__)


SYSTEM_PROMPT_TEMPLATE = """You are a Senior Network Security & SOC Analyst monitoring a pfSense firewall.
You receive pre-aggregated telemetry across 3 Security Tiers:
1. Tier 1 (`tier1_anomalies`): Outbound traffic from internal LAN/VLAN hosts towards the public WAN that was either BLOCKED by the firewall or directed to UNCOMMON ports, plus blocked internal lateral movement. This is the highest priority signal (potential malware, C2 callback, compromised IoT/host, or policy violation).
2. Tier 2 (`tier2_events`): Authentication events on pfSense (`sshd`, WebGUI, VPN) and inbound WAN connections explicitly ALLOWED (`action=pass`). Verify whether failed logins or unexpected inbound accesses occurred.
3. Tier 3 (`tier3_offenders`): External IPs blocked on the WAN that exceeded volume or port-scanning thresholds. Distinguish targeted multi-port reconnaissance or brute-force spikes from harmless background noise.

Respond strictly with a valid JSON object matching this exact schema (no markdown code fences outside the JSON):
{{
  "severity": "INFO" | "WARNING" | "CRITICAL",
  "title": "Short descriptive title of the security event",
  "executive_summary": "2-3 sentences summarizing the situation clearly",
  "key_findings": [
    "Bullet 1 with specific IPs, ports, and hit counts",
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


class AnthropicSOCAnalyst:
    """Wraps the Anthropic SDK with retry logic and structured output parsing."""

    def __init__(self, config: AppConfig) -> None:
        self.config = config
        self.client = (
            Anthropic(
                api_key=config.anthropic_api_key,
                base_url=config.anthropic_base_url,
            )
            if (HAS_ANTHROPIC_SDK and config.anthropic_api_key and Anthropic is not None)
            else None
        )

    def analyze(self, evaluation: FilterEvaluationResult, max_retries: int = 3) -> AISecurityReport:
        """Send aggregated anomaly payload to Claude and return a structured AISecurityReport."""
        if not self.config.anthropic_api_key:
            raise RuntimeError("ANTHROPIC_API_KEY is not configured.")

        payload_dict: dict[str, Any] = {
            "window_start_utc": evaluation.window_start.isoformat(),
            "window_end_utc": evaluation.window_end.isoformat(),
            "trigger_reasons": evaluation.trigger_reasons,
            "total_wan_blocked_packets_in_window": evaluation.total_raw_wan_blocks,
            "tier1_outbound_or_lateral_anomalies": [
                item.model_dump() for item in evaluation.tier1_anomalies
            ],
            "tier2_auth_and_allowed_wan_events": [
                item.model_dump() for item in evaluation.tier2_events
            ],
            "tier3_aggressive_wan_offenders": [
                item.model_dump() for item in evaluation.tier3_offenders
            ],
        }

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
                if self.client is not None:
                    response = self.client.messages.create(
                        model=self.config.anthropic_model,
                        max_tokens=1200,
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

                report = self._parse_json_response(raw_text)
                report.model_used = self.config.anthropic_model
                report.input_tokens = in_tokens
                report.output_tokens = out_tokens
                logger.info(
                    "Anthropic analysis succeeded (model=%s, severity=%s, tokens_in=%d, tokens_out=%d)",
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
                    "Anthropic API transient error (attempt %d/%d): %s. Retrying in %ds...",
                    attempt,
                    max_retries,
                    exc,
                    backoff,
                )
                if attempt < max_retries:
                    time.sleep(backoff)

        raise RuntimeError(
            f"Anthropic API analysis failed after {max_retries} attempts: {last_error}"
        ) from last_error

    def _call_via_httpx(
        self,
        system_prompt: str,
        user_message: str,
    ) -> tuple[str, int, int]:
        """Direct HTTP fallback to Anthropic/MiniMax Messages API when the SDK is not installed locally."""
        headers = {
            "x-api-key": self.config.anthropic_api_key,
            "Authorization": f"Bearer {self.config.anthropic_api_key}",
            "anthropic-version": "2023-06-01",
            "content-type": "application/json",
        }
        body = {
            "model": self.config.anthropic_model,
            "max_tokens": 1200,
            "system": system_prompt,
            "messages": [{"role": "user", "content": user_message}],
        }
        endpoint = f"{self.config.anthropic_base_url.rstrip('/')}/v1/messages"
        with httpx.Client(timeout=45.0) as client:
            resp = client.post(endpoint, headers=headers, json=body)
            resp.raise_for_status()
            data = resp.json()
        raw_text = "".join(
            block.get("text", "") for block in data.get("content", []) if block.get("type") == "text"
        )
        usage = data.get("usage", {})
        return raw_text, int(usage.get("input_tokens", 0)), int(usage.get("output_tokens", 0))

    @staticmethod
    def _parse_json_response(raw_text: str) -> AISecurityReport:
        """Extract and validate JSON object from Claude's response text."""
        cleaned = raw_text.strip()
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
                "Failed to parse strict JSON from Claude response (%s); using fallback wrapper.",
                exc,
            )
            return AISecurityReport(
                severity="WARNING",
                title="pfSense AI Security Analysis",
                executive_summary=raw_text[:800],
                key_findings=[],
                recommended_actions=[],
                suspicious_ips=[],
            )
