"""CVSS severity and dashboard presentation helpers."""

from html import escape


SEVERITY_COLORS = {
    "CRITICAL": "#D92D20",
    "HIGH": "#E35D12",
    "MEDIUM": "#B7791F",
    "LOW": "#0077B6",
    "INFO": "#6956C7",
}


def cvss_to_severity(score):
    score = float(score or 0)
    if score >= 9.0:
        return "CRITICAL"
    if score >= 7.0:
        return "HIGH"
    if score >= 4.0:
        return "MEDIUM"
    if score >= 0.1:
        return "LOW"
    return "INFO"


def severity_color(severity):
    return SEVERITY_COLORS.get(str(severity).upper(), SEVERITY_COLORS["INFO"])


def severity_badge(severity):
    value = str(severity).upper()
    color = severity_color(value)
    return (
        f'<span class="severity-badge severity-{escape(value.lower())}" '
        f'style="color:{color};border-color:{color}">{escape(value)}</span>'
    )
