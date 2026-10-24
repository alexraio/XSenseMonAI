"""Telegram Bot notification client with raw fallback support."""

from __future__ import annotations

import html
import logging

import httpx

from .config import AppConfig
from .models import AISecurityReport, FilterEvaluationResult

logger = logging.getLogger(__name__)

SEVERITY_EMOJI = {
    "INFO": "ℹ️",
    "WARNING": "⚠️",
    "CRITICAL": "🚨",
}


class TelegramNotifier:
    """Sends formatted security alerts to a Telegram chat via the Bot HTTP API."""

    def __init__(self, config: AppConfig, timeout_seconds: float = 15.0) -> None:
        self.config = config
        self.timeout = timeout_seconds
        self._resolved_chat_id: str | None = None

    @property
    def is_configured(self) -> bool:
        return bool(self.config.telegram_bot_token and self.config.telegram_chat_id)

    def _resolve_chat_id(self, client: httpx.Client) -> str:
        """Return a valid numeric chat_id, auto-discovering via getUpdates if a bot username was provided."""
        if self._resolved_chat_id:
            return self._resolved_chat_id

        configured = self.config.telegram_chat_id.strip()
        # If already a numeric ID (positive user ID or negative group/channel ID), use it directly
        if configured.lstrip("-").isdigit():
            self._resolved_chat_id = configured
            return configured

        logger.info(
            "TELEGRAM_CHAT_ID '%s' is not numeric; querying getUpdates to auto-discover user chat_id...",
            configured,
        )
        updates_url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/getUpdates"
        try:
            resp = client.get(updates_url)
            resp.raise_for_status()
            data = resp.json()
            for item in reversed(data.get("result", [])):
                msg = item.get("message") or item.get("my_chat_member") or item.get("channel_post") or {}
                chat = msg.get("chat", {})
                chat_id = chat.get("id")
                if chat_id is not None:
                    self._resolved_chat_id = str(chat_id)
                    logger.info(
                        "Auto-discovered numeric Telegram chat_id=%s (please update TELEGRAM_CHAT_ID in .env)",
                        self._resolved_chat_id,
                    )
                    return self._resolved_chat_id
        except httpx.HTTPError as exc:
            logger.warning("Failed to call Telegram getUpdates for chat_id discovery: %s", exc)

        logger.warning(
            "Could not auto-discover numeric chat_id from getUpdates. "
            "Open Telegram, search for @%s, press 'Start' (/start), and run again.",
            configured.lstrip("@"),
        )
        return configured

    def send_ai_report(
        self,
        report: AISecurityReport,
        evaluation: FilterEvaluationResult,
    ) -> bool:
        """Format and deliver an AI-generated security report via Telegram."""
        if not self.is_configured:
            logger.warning("Telegram credentials not configured; skipping notification.")
            return False

        emoji = SEVERITY_EMOJI.get(report.severity, "🛡️")
        lines: list[str] = [
            f"{emoji} <b>[PfsenseMon - {html.escape(report.severity)}] {html.escape(report.title)}</b>",
            f"🕒 <i>{evaluation.window_start.strftime('%H:%M')} - {evaluation.window_end.strftime('%H:%M UTC')}</i>",
            "",
            f"<b>Summary:</b>\n{html.escape(report.executive_summary)}",
        ]

        if report.key_findings:
            lines.append("\n<b>🔍 Key Findings:</b>")
            for item in report.key_findings:
                lines.append(f"• {html.escape(item)}")

        if report.recommended_actions:
            lines.append("\n<b>🛠️ Recommended Actions:</b>")
            for action in report.recommended_actions:
                lines.append(f"• {html.escape(action)}")

        if report.suspicious_ips:
            ips_str = ", ".join(f"<code>{html.escape(ip)}</code>" for ip in report.suspicious_ips[:15])
            lines.append(f"\n<b>📌 Involved IPs:</b> {ips_str}")

        lines.append(
            f"\n<i>🤖 Model: {html.escape(report.model_used)} "
            f"({report.input_tokens} in / {report.output_tokens} out tokens)</i>"
        )

        return self._send_html_message("\n".join(lines))

    def send_raw_fallback_alert(
        self,
        evaluation: FilterEvaluationResult,
        error_reason: str,
    ) -> bool:
        """Send an emergency raw statistical alert when the Anthropic API is unreachable."""
        if not self.is_configured or not self.config.telegram_enable_raw_fallback:
            return False

        lines: list[str] = [
            "⚠️ <b>[PfsenseMon - RAW FALLBACK ALERT]</b>",
            "<i>Anthropic API was unreachable, delivering raw anomaly summary:</i>",
            f"<code>{html.escape(error_reason[:160])}</code>",
            "",
            "<b>Trigger Reasons:</b>",
        ]
        for reason in evaluation.trigger_reasons:
            lines.append(f"• {html.escape(reason)}")

        if evaluation.tier1_anomalies:
            lines.append("\n<b>🔴 Tier 1 (Suspicious Outbound/Internal):</b>")
            for t1 in evaluation.tier1_anomalies[:8]:
                lines.append(
                    f"• <code>{html.escape(t1.src_ip)}</code> → <code>{html.escape(t1.dst_ip)}:{html.escape(t1.dst_port)}/{html.escape(t1.proto)}</code> "
                    f"[{html.escape(t1.action)}] ({t1.total_hits} hits)"
                )

        if evaluation.tier2_events:
            lines.append("\n<b>🟠 Tier 2 (Auth / Allowed WAN):</b>")
            for t2 in evaluation.tier2_events[:5]:
                lines.append(
                    f"• <code>{html.escape(t2.src_ip)}</code> [{html.escape(t2.sub_type)}] ({t2.total_hits} hits)"
                )

        if evaluation.tier3_offenders:
            lines.append("\n<b>🟡 Tier 3 (Top WAN Offenders):</b>")
            for t3 in evaluation.tier3_offenders[:8]:
                lines.append(
                    f"• <code>{html.escape(t3.src_ip)}</code>: {t3.total_blocked_hits} blocked hits across {t3.distinct_ports_count} port(s)"
                )

        return self._send_html_message("\n".join(lines))

    def _send_html_message(self, text: str) -> bool:
        url = f"https://api.telegram.org/bot{self.config.telegram_bot_token}/sendMessage"
        try:
            with httpx.Client(timeout=self.timeout) as client:
                target_chat_id = self._resolve_chat_id(client)
                payload = {
                    "chat_id": target_chat_id,
                    "text": text[:4090],
                    "parse_mode": "HTML",
                    "disable_web_page_preview": True,
                }
                response = client.post(url, json=payload)
                response.raise_for_status()
            logger.info("Delivered security alert to Telegram chat %s", target_chat_id)
            return True
        except httpx.HTTPError as exc:
            logger.error("Failed to send Telegram alert: %s", exc)
            return False
