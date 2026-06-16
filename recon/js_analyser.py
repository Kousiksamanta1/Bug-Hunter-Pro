"""JavaScript endpoint and exposed-secret analysis."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import logging
import re
import uuid
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import requests

import config
from core.http import create_session
from database import models


LOGGER = logging.getLogger(__name__)


class JSAnalyser:
    COMMON_PATHS = (
        "/main.js", "/app.js", "/bundle.js", "/static/js/main.chunk.js",
        "/assets/index.js",
    )
    PATTERNS = (
        ("API endpoint", re.compile(r"""['"](/api/[^'"]+)['"]""", re.I)),
        ("API endpoint", re.compile(r"""['"](https?://[^'"]+/api/[^'"]+)['"]""", re.I)),
        ("API endpoint", re.compile(r"""fetch\(\s*['"]([^'"]+)['"]""", re.I)),
        ("API endpoint", re.compile(r"""axios\.\w+\(\s*['"]([^'"]+)['"]""", re.I)),
        ("API endpoint", re.compile(r"""url\s*:\s*['"]([^'"]+)['"]""", re.I)),
        ("API key", re.compile(r"""(?:api_key|apikey|api-key|APIKEY)\s*[:=]\s*['"]([^'"]{8,})['"]""")),
        ("AWS access key", re.compile(r"\b(AKIA[0-9A-Z]{16})\b")),
        ("AWS secret", re.compile(r"""['"]([0-9a-zA-Z/+]{40})['"]""")),
        ("GitHub token", re.compile(r"\b(ghp_[a-zA-Z0-9]{36})\b")),
        ("Slack token", re.compile(r"\b(xox[baprs]-[0-9a-zA-Z-]{10,48})\b")),
        ("Google API key", re.compile(r"\b(AIza[0-9A-Za-z_-]{35})\b")),
        ("Private key", re.compile(r"(-----BEGIN [A-Z]+ PRIVATE KEY-----)")),
        ("JWT", re.compile(r"\b(eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.?[A-Za-z0-9_.+/=-]*)\b")),
        ("Password in code", re.compile(r"""(?:password|passwd|pwd|secret)\s*[:=]\s*['"]([^'"]{4,})['"]""", re.I)),
        ("Bearer token", re.compile(r"Bearer\s+([A-Za-z0-9_.=-]+)", re.I)),
        ("Internal domain", re.compile(r"https?://([a-z0-9.-]+\.(?:internal|corp|local|dev|staging))[^'\"\s]*", re.I)),
        ("Internal IP", re.compile(r"https?://((?:10\.\d+\.\d+\.\d+)|(?:192\.168\.\d+\.\d+))[^'\"\s]*", re.I)),
        ("Internal host", re.compile(r"https?://(localhost:\d+)[^'\"\s]*", re.I)),
        ("Hidden endpoint comment", re.compile(r"//\s*(?:TODO|FIXME|HACK|NOTE).*?(?:endpoint|api|url|route)[^\n]*", re.I)),
        ("Hidden endpoint comment", re.compile(r"/\*[\s\S]*?(?:endpoint|api_url|base_url)[\s\S]*?\*/", re.I)),
    )

    def __init__(self, scan_id=None):
        self.scan_id = scan_id or str(uuid.uuid4())
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )
        self.session.headers["User-Agent"] = (
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )
        self.js_files = []

    def analyse(self, target_url):
        self.js_files = self._find_js_files(target_url)
        findings = []
        with ThreadPoolExecutor(max_workers=min(config.MAX_THREADS, 10)) as pool:
            futures = [pool.submit(self._extract_from_js, url) for url in self.js_files]
            for future in as_completed(futures):
                try:
                    findings.extend(future.result())
                except Exception as exc:
                    LOGGER.debug("JavaScript analysis failed: %s", exc)
        unique = {}
        for finding in findings:
            key = (finding["finding_type"], finding["value"], finding["js_file"])
            unique.setdefault(key, finding)
        results = list(unique.values())
        for item in results:
            item["scan_id"] = self.scan_id
            models.insert_js_finding(item)
        return results

    def _find_js_files(self, target_url):
        urls = {urljoin(target_url, path) for path in self.COMMON_PATHS}
        try:
            response = self.session.get(target_url, timeout=config.SCAN_TIMEOUT)
            response.raise_for_status()
            soup = BeautifulSoup(response.text, "html.parser")
            urls.update(
                urljoin(response.url, script["src"])
                for script in soup.find_all("script", src=True)
            )
        except requests.RequestException as exc:
            LOGGER.warning("Unable to discover JavaScript files: %s", exc)
        verified = []
        for url in sorted(urls):
            try:
                response = self.session.get(url, timeout=config.SCAN_TIMEOUT)
                content_type = response.headers.get("Content-Type", "").lower()
                if response.status_code == 200 and (
                    "javascript" in content_type or url.split("?")[0].endswith(".js")
                ):
                    verified.append(url)
            except requests.RequestException:
                continue
        return verified

    def _extract_from_js(self, js_url):
        try:
            response = self.session.get(js_url, timeout=config.SCAN_TIMEOUT)
            response.raise_for_status()
        except requests.RequestException:
            return []
        content = response.text
        findings = []
        timestamp = datetime.now(timezone.utc).isoformat()
        for finding_type, pattern in self.PATTERNS:
            for match in pattern.finditer(content):
                value = next(
                    (group for group in match.groups() if group is not None),
                    match.group(0),
                )
                findings.append(
                    {
                        "id": str(uuid.uuid4()),
                        "js_file": js_url,
                        "finding_type": finding_type,
                        "value": value[:4000],
                        "severity": self._classify_severity(finding_type),
                        "line_approximate": content.count("\n", 0, match.start()) + 1,
                        "timestamp": timestamp,
                    }
                )
        return findings

    @staticmethod
    def _classify_severity(finding_type):
        value = finding_type.lower()
        if any(term in value for term in ("aws", "private key", "github", "password")):
            return "CRITICAL"
        if any(term in value for term in ("google", "slack", "jwt", "bearer")):
            return "HIGH"
        if "internal" in value:
            return "MEDIUM"
        return "INFO"
