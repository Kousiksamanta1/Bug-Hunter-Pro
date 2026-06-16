"""Email and Slack notifications for newly discovered findings."""

from collections import Counter
from email.message import EmailMessage
import logging
import smtplib

import requests

import config


LOGGER = logging.getLogger(__name__)


def filter_new_findings(current, previous):
    previous_keys = {
        (item.get("title", "").strip().lower(), item.get("url", "").strip())
        for item in previous
    }
    return [
        item
        for item in current
        if (item.get("title", "").strip().lower(), item.get("url", "").strip())
        not in previous_keys
    ]


def _important(findings):
    return [item for item in findings if item.get("severity") in {"CRITICAL", "HIGH"}]


def send_email_alert(findings, target):
    important = _important(findings)
    if not important:
        return False
    if not all(
        (
            config.ALERT_EMAIL,
            config.SMTP_HOST,
            config.SMTP_PORT,
            config.SMTP_USER,
            config.SMTP_PASS,
        )
    ):
        LOGGER.warning("Email alert skipped because SMTP configuration is incomplete")
        return False
    message = EmailMessage()
    message["Subject"] = f"[Bug Hunter Pro] New vulnerabilities found in {target}"
    message["From"] = config.SMTP_USER
    message["To"] = config.ALERT_EMAIL
    lines = [
        f"Bug Hunter Pro detected {len(important)} new critical/high findings for {target}.",
        "",
    ]
    lines.extend(
        f"[{item['severity']}] {item['title']} - {item.get('url', target)}"
        for item in important
    )
    message.set_content("\n".join(lines))
    try:
        with smtplib.SMTP(config.SMTP_HOST, config.SMTP_PORT, timeout=10) as smtp:
            smtp.starttls()
            smtp.login(config.SMTP_USER, config.SMTP_PASS)
            smtp.send_message(message)
        return True
    except Exception as exc:
        LOGGER.warning("Email alert failed: %s", exc)
        return False


def send_slack_alert(findings, target):
    if not findings:
        return False
    if not config.SLACK_WEBHOOK_URL:
        LOGGER.warning("Slack alert skipped because SLACK_WEBHOOK_URL is not configured")
        return False
    counts = Counter(item.get("severity", "INFO") for item in findings)
    lines = [
        f"*Bug Hunter Pro: new findings for {target}*",
        (
            f"Critical: {counts['CRITICAL']} | High: {counts['HIGH']} | "
            f"Medium: {counts['MEDIUM']} | Low: {counts['LOW']} | Info: {counts['INFO']}"
        ),
    ]
    lines.extend(
        f"• [{item['severity']}] {item['title']}" for item in findings[:10]
    )
    try:
        response = requests.post(
            config.SLACK_WEBHOOK_URL,
            json={"text": "\n".join(lines)},
            timeout=config.SCAN_TIMEOUT,
        )
        response.raise_for_status()
        return True
    except requests.RequestException as exc:
        LOGGER.warning("Slack alert failed: %s", exc)
        return False

