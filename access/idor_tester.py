"""Object-level authorization heuristics for scoped targets."""

import json
import logging
import re
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse
import uuid

from bs4 import BeautifulSoup
import requests

import config
from core.http import create_session
from scanners.base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)


class IDORTester(BaseScanner):
    scanner_name = "idor"
    total_checks = 2
    NUMERIC_PATH = re.compile(r"/(?:users?|orders?|documents?|accounts?)/(\d+)(?:/|$)", re.I)
    UUID_PATH = re.compile(
        r"/(?:users?|orders?|documents?|accounts?)/"
        r"([0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12})",
        re.I,
    )
    ID_FIELD = re.compile(r'"(?:id|user_id|account_id)"\s*:\s*"?([0-9a-f-]+)"?', re.I)
    ERROR_WORDS = re.compile(r"\b(?:not found|forbidden|unauthorized|invalid|denied)\b", re.I)

    def __init__(self, target, *args, **kwargs):
        super().__init__(target, *args, **kwargs)
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Access-Validation"
        )

    def scan(self, target_url=None, headers=None, authorized=False):
        if not authorized:
            raise PermissionError("Explicit authorization is required")
        if target_url:
            self.target = self.normalize_target(target_url)
        headers = headers or {}
        for endpoint, original_id, kind in self._find_id_patterns(self.target, headers):
            self._test_id_manipulation(endpoint, original_id, kind, headers)
            self._test_parameter_pollution(endpoint, headers)
        self.status = "completed"
        return self.get_findings()

    def run(self):
        return self.scan(authorized=True)

    def _find_id_patterns(self, target_url, headers):
        urls = {target_url}
        try:
            response = self.session.get(
                target_url,
                headers=headers,
                timeout=config.SCAN_TIMEOUT,
            )
            soup = BeautifulSoup(response.text, "html.parser")
            urls.update(urljoin(response.url, link["href"]) for link in soup.find_all("a", href=True))
            for match in self.ID_FIELD.finditer(response.text):
                value = match.group(1)
                if value.isdigit():
                    urls.add(urljoin(response.url, f"/api/object/{value}"))
        except requests.RequestException:
            pass
        patterns = []
        for url in urls:
            numeric = self.NUMERIC_PATH.search(urlparse(url).path)
            if numeric:
                patterns.append((url, numeric.group(1), "numeric"))
            uuid_match = self.UUID_PATH.search(urlparse(url).path)
            if uuid_match:
                patterns.append((url, uuid_match.group(1), "uuid"))
            for name, value in parse_qsl(urlparse(url).query, keep_blank_values=True):
                if name.lower() in {"id", "user_id", "account_id", "order_id", "document_id"}:
                    patterns.append((url, value, "numeric" if value.isdigit() else "uuid"))
        return list(dict.fromkeys(patterns))[:30]

    @staticmethod
    def _replace_id(endpoint, original_id, tested_id):
        parsed = urlparse(endpoint)
        path = parsed.path.replace(original_id, str(tested_id), 1)
        query = [
            (name, str(tested_id) if value == original_id else value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
        ]
        return urlunparse(parsed._replace(path=path, query=urlencode(query)))

    def _test_id_manipulation(self, endpoint, original_id, kind, headers):
        try:
            original = self.session.get(endpoint, headers=headers, timeout=config.SCAN_TIMEOUT)
        except requests.RequestException:
            return
        if original.status_code != 200 or self.ERROR_WORDS.search(original.text):
            return
        if kind == "numeric" and original_id.isdigit():
            number = int(original_id)
            candidates = [1, 2, max(0, number - 1), number + 1, 1000]
        else:
            candidates = [str(uuid.uuid4()) for _ in range(5)]
        for tested_id in dict.fromkeys(str(item) for item in candidates if str(item) != original_id):
            test_url = self._replace_id(endpoint, original_id, tested_id)
            try:
                response = self.session.get(test_url, headers=headers, timeout=config.SCAN_TIMEOUT)
            except requests.RequestException:
                continue
            if response.status_code != 200 or self.ERROR_WORDS.search(response.text):
                continue
            size_ratio = len(response.content) / max(len(original.content), 1)
            has_data = self._has_structured_data(response)
            if 0.8 <= size_ratio <= 1.2 and has_data and original_id not in response.text:
                self.add_finding(
                    "Potential insecure direct object reference",
                    "CRITICAL",
                    "A manipulated object identifier returned a similarly structured object.",
                    (
                        f"Original URL: {endpoint}\nTest URL: {test_url}\n"
                        f"Original ID: {original_id}\nTested ID: {tested_id}\n"
                        f"Original bytes: {len(original.content)}\nTest bytes: {len(response.content)}"
                    ),
                    "Enforce object-level authorization for every resource lookup.",
                    9.1,
                    "A01:2021 Broken Access Control",
                    "T1213 Data from Information Repositories",
                    test_url,
                )
                return

    def _test_parameter_pollution(self, endpoint, headers):
        parsed = urlparse(endpoint)
        query = parse_qsl(parsed.query, keep_blank_values=True)
        id_items = [(name, value) for name, value in query if name.lower().endswith("id")]
        if not id_items:
            return
        name, value = id_items[0]
        variants = (
            query + [(name, "1")],
            [(f"{key}[]", val) if key == name else (key, val) for key, val in query],
        )
        for variant in variants:
            url = urlunparse(parsed._replace(query=urlencode(variant, doseq=True)))
            try:
                response = self.session.get(url, headers=headers, timeout=config.SCAN_TIMEOUT)
            except requests.RequestException:
                continue
            if response.status_code == 200 and self._has_structured_data(response) and not self.ERROR_WORDS.search(response.text):
                self.add_finding(
                    "Potential IDOR through parameter pollution",
                    "HIGH",
                    "Duplicate or array-style object identifiers returned a data response.",
                    f"URL: {url}\nStatus: {response.status_code}\nParameter: {name}={value}",
                    "Reject duplicate parameters and enforce object authorization after normalization.",
                    7.5,
                    "A01:2021 Broken Access Control",
                    "T1213 Data from Information Repositories",
                    url,
                )
                return

    @staticmethod
    def _has_structured_data(response):
        content_type = response.headers.get("Content-Type", "").lower()
        if "json" in content_type:
            try:
                data = response.json()
                return isinstance(data, (dict, list)) and bool(data)
            except (ValueError, json.JSONDecodeError):
                return False
        return len(response.text.strip()) > 100
