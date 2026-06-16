"""Finding aggregation, de-duplication, and risk scoring."""

from collections import Counter


SEVERITY_ORDER = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
DEFAULT_OWASP = {
    "sql": "A03:2021 Injection",
    "xss": "A03:2021 Injection",
    "redirect": "A01:2021 Broken Access Control",
    "auth": "A01:2021 Broken Access Control",
    "credential": "A07:2021 Identification and Authentication Failures",
    "tls": "A02:2021 Cryptographic Failures",
    "cipher": "A02:2021 Cryptographic Failures",
    "header": "A05:2021 Security Misconfiguration",
    "exposure": "A05:2021 Security Misconfiguration",
    "cors": "A05:2021 Security Misconfiguration",
}


def _map_owasp(finding):
    if finding.get("owasp"):
        return finding["owasp"]
    title = finding.get("title", "").lower()
    for keyword, category in DEFAULT_OWASP.items():
        if keyword in title:
            return category
    return "A05:2021 Security Misconfiguration"


def aggregate_findings(scanners, total_checks=None):
    unique = {}
    for scanner in scanners:
        items = scanner.get_findings() if hasattr(scanner, "get_findings") else scanner
        for original in items:
            finding = dict(original)
            finding["owasp"] = _map_owasp(finding)
            key = (finding.get("title", "").strip().lower(), finding.get("url", "").strip())
            unique.setdefault(key, finding)

    findings = sorted(
        unique.values(),
        key=lambda item: (
            SEVERITY_ORDER.get(item.get("severity", "INFO"), 5),
            -float(item.get("cvss_score", 0)),
            item.get("title", ""),
        ),
    )
    counts = Counter(item.get("severity", "INFO") for item in findings)
    denominator = max(int(total_checks or len(findings) or 1), 1)
    weighted = (
        counts["CRITICAL"] * 10
        + counts["HIGH"] * 7
        + counts["MEDIUM"] * 4
        + counts["LOW"]
    )
    risk_score = min(10.0, round(weighted / denominator, 2))
    stats = {
        "total_findings": len(findings),
        "critical_count": counts["CRITICAL"],
        "high_count": counts["HIGH"],
        "medium_count": counts["MEDIUM"],
        "low_count": counts["LOW"],
        "info_count": counts["INFO"],
        "risk_score": risk_score,
    }
    return findings, stats

