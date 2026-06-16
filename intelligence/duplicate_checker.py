"""Public-source duplicate and prior-art research for findings."""

import logging
import re
from urllib.parse import urlparse

from bs4 import BeautifulSoup
import requests

import config


LOGGER = logging.getLogger(__name__)


class DuplicateChecker:
    CVE_PATTERN = re.compile(r"\bCVE-\d{4}-\d{4,}\b", re.I)

    def __init__(self):
        self.session = requests.Session()
        self.session.headers["User-Agent"] = (
            f"Bug-Hunter-Pro/{config.APP_VERSION} Duplicate-Research"
        )

    def check_finding(self, finding):
        title = finding.get("title", "")
        target_domain = urlparse(finding.get("url", "")).hostname or ""
        cve_match = self.CVE_PATTERN.search(
            f"{title} {finding.get('description', '')} {finding.get('evidence', '')}"
        )
        results = {
            "nvd": self._check_nvd(title, cve_match.group(0) if cve_match else None),
            "hackerone": self._check_hackerone_disclosed(title, target_domain),
            "github": self._check_github(title, target_domain),
        }
        results["uniqueness"] = self._calculate_uniqueness_score(results)
        return results

    def _check_nvd(self, title, cve_id=None):
        params = {"cveId": cve_id.upper()} if cve_id else {
            "keywordSearch": title,
            "resultsPerPage": 3,
        }
        headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        try:
            response = self.session.get(
                "https://services.nvd.nist.gov/rest/json/cves/2.0",
                params=params,
                headers=headers,
                timeout=config.SCAN_TIMEOUT,
            )
            response.raise_for_status()
            vulnerabilities = response.json().get("vulnerabilities", [])
            if not vulnerabilities:
                return {"is_known_cve": False, "cve_id": "", "cvss": 0, "published": ""}
            cve = vulnerabilities[0].get("cve", {})
            score = 0.0
            for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
                metrics = cve.get("metrics", {}).get(key, [])
                if metrics:
                    score = metrics[0].get("cvssData", {}).get("baseScore", 0)
                    break
            return {
                "is_known_cve": True,
                "cve_id": cve.get("id", ""),
                "cvss": score,
                "published": cve.get("published", ""),
            }
        except (requests.RequestException, ValueError) as exc:
            LOGGER.warning("NVD duplicate lookup failed: %s", exc)
            return {"is_known_cve": False, "error": str(exc)}

    def _check_hackerone_disclosed(self, title, target_domain):
        try:
            response = self.session.get(
                "https://hackerone.com/reports",
                params={"filter[keyword]": f"{title} {target_domain}".strip(), "filter[disclosed]": "true"},
                timeout=config.SCAN_TIMEOUT,
            )
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            reports = []
            for link in soup.select('a[href*="/reports/"]')[:10]:
                href = link.get("href", "")
                text = " ".join(link.get_text(" ", strip=True).split())
                if text and href:
                    reports.append(
                        {
                            "title": text,
                            "url": href if href.startswith("http") else f"https://hackerone.com{href}",
                            "severity": "",
                            "bounty": "",
                        }
                    )
            return {"similar_reports": reports}
        except requests.RequestException as exc:
            LOGGER.warning("HackerOne duplicate lookup failed: %s", exc)
            return {"similar_reports": [], "error": str(exc)}

    def _check_github(self, title, target_domain):
        headers = {"Accept": "application/vnd.github+json"}
        if config.GITHUB_TOKEN:
            headers["Authorization"] = f"Bearer {config.GITHUB_TOKEN}"
        try:
            response = self.session.get(
                "https://api.github.com/search/issues",
                params={"q": f"{title} {target_domain}".strip(), "per_page": 10},
                headers=headers,
                timeout=config.SCAN_TIMEOUT,
            )
            response.raise_for_status()
            return {
                "github_issues": [
                    {
                        "title": item.get("title", ""),
                        "url": item.get("html_url", ""),
                        "repo": item.get("repository_url", "").rsplit("/", 1)[-1],
                        "date": item.get("created_at", ""),
                    }
                    for item in response.json().get("items", [])
                ]
            }
        except (requests.RequestException, ValueError) as exc:
            LOGGER.warning("GitHub duplicate lookup failed: %s", exc)
            return {"github_issues": [], "error": str(exc)}

    @staticmethod
    def _calculate_uniqueness_score(results):
        score = 100
        breakdown = []
        if results.get("nvd", {}).get("is_known_cve"):
            score -= 40
            breakdown.append({"reason": "Known CVE", "deduction": 40})
        if results.get("hackerone", {}).get("similar_reports"):
            score -= 30
            breakdown.append({"reason": "Similar disclosed HackerOne report", "deduction": 30})
        if results.get("github", {}).get("github_issues"):
            score -= 20
            breakdown.append({"reason": "Related GitHub issue", "deduction": 20})
        return {"score": max(0, score), "breakdown": breakdown}
