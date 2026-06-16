"""API endpoint discovery and security heuristics."""

import base64
import hashlib
import hmac
import json
import logging
import re
import time
from urllib.parse import urljoin, urlparse

from bs4 import BeautifulSoup
import requests

import config
from core.http import create_session
from .base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)


class APIScanner(BaseScanner):
    scanner_name = "api"
    total_checks = 6
    COMMON_PATHS = (
        "/api/",
        "/v1/",
        "/v2/",
        "/graphql",
        "/swagger",
        "/openapi.json",
        "/api-docs",
        "/rest/",
    )
    SENSITIVE_PATTERNS = {
        "Email address": (re.compile(r"[a-zA-Z0-9+_.-]+@[a-zA-Z0-9.-]+"), "HIGH", 7.0),
        "Phone number": (re.compile(r"\b\d{3}[-.]?\d{3}[-.]?\d{4}\b"), "HIGH", 7.0),
        "Social Security number": (re.compile(r"\b\d{3}-\d{2}-\d{4}\b"), "CRITICAL", 9.1),
        "API key": (
            re.compile(r"(api_key|apikey|api-key)\s*[:=]\s*\S+", re.IGNORECASE),
            "CRITICAL",
            9.1,
        ),
        "Private key": (
            re.compile(r"-----BEGIN (RSA|EC|DSA) PRIVATE KEY-----"),
            "CRITICAL",
            9.8,
        ),
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Security-Scanner"
        )
        self.session.headers.update(
            {"User-Agent": f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Security-Scanner"}
        )
        self.endpoints = []
        self.responses = {}

    def _request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", config.SCAN_TIMEOUT)
        self.checked_urls.add(url)
        try:
            response = self.session.request(method, url, **kwargs)
            self.responses[url] = response
            return response
        except requests.RequestException as exc:
            LOGGER.debug("API request failed for %s: %s", url, exc)
            return None

    def run(self):
        self.status = "running"
        checks = [
            self.discover_endpoints,
            self.check_broken_authentication,
            self.test_rate_limits,
            self.detect_idor,
            self.check_jwt,
            self.check_sensitive_data,
        ]
        for index, check in enumerate(checks, start=1):
            if self.should_stop():
                self.status = "stopped"
                break
            try:
                check()
            except Exception as exc:
                LOGGER.exception("API check %s failed: %s", check.__name__, exc)
            self.set_progress(index / len(checks) * 100, check.__name__)
        else:
            self.status = "completed"
        return self.get_findings()

    def _add_endpoint(self, url):
        if url.startswith(("http://", "https://")) and url not in self.endpoints:
            self.endpoints.append(url)

    def discover_endpoints(self):
        for path in self.COMMON_PATHS:
            if self.should_stop():
                return
            url = urljoin(f"{self.target}/", path.lstrip("/"))
            response = self._request("GET", url, allow_redirects=False)
            if response is not None and response.status_code < 500 and response.status_code != 404:
                self._add_endpoint(url)
        for source in ("/robots.txt", "/sitemap.xml"):
            response = self._request("GET", urljoin(f"{self.target}/", source.lstrip("/")))
            if response is None or response.status_code != 200:
                continue
            for match in re.findall(r"https?://[^\s<\"']+|/[A-Za-z0-9_./?=&-]+", response.text):
                if any(token in match.lower() for token in ("/api", "/v1", "/v2", "graphql", "rest")):
                    self._add_endpoint(urljoin(self.target, match))
        response = self._request("GET", self.target)
        if response is not None:
            try:
                soup = BeautifulSoup(response.text, "html.parser")
                for element in soup.find_all(["a", "form"]):
                    value = element.get("href") or element.get("action")
                    if value and any(token in value.lower() for token in ("/api", "/v1", "/v2", "graphql")):
                        self._add_endpoint(urljoin(response.url, value))
            except Exception:
                pass
        self.endpoints = self.endpoints[:30]

    @staticmethod
    def _looks_like_data(response):
        content_type = response.headers.get("Content-Type", "").lower()
        body = response.text.strip()
        return len(body) > 20 and (
            "json" in content_type
            or body.startswith(("{", "["))
            or any(term in body.lower() for term in ("email", "username", "account", "token"))
        )

    def check_broken_authentication(self):
        for endpoint in self.endpoints:
            if self.should_stop():
                return
            response = self._request("GET", endpoint, headers={"Authorization": ""})
            if response is None:
                continue
            if response.status_code == 200 and self._looks_like_data(response):
                self.add_finding(
                    "API endpoint exposes data without authentication",
                    "HIGH",
                    "An API endpoint returned a data-bearing response without authorization.",
                    f"Endpoint: {endpoint}\nStatus: {response.status_code}\nBody sample: {response.text[:500]}",
                    "Require authentication and object-level authorization for the endpoint.",
                    8.1,
                    "A01:2021 Broken Access Control",
                    "T1078 Valid Accounts",
                    endpoint,
                )
            elif response.status_code == 403 and self._looks_like_data(response):
                self.add_finding(
                    "Sensitive data included in denied API response",
                    "MEDIUM",
                    "A forbidden response still appears to include sensitive application data.",
                    f"Endpoint: {endpoint}\nStatus: 403\nBody sample: {response.text[:500]}",
                    "Return a minimal generic authorization error body.",
                    5.3,
                    "A01:2021 Broken Access Control",
                    "",
                    endpoint,
                )

    def test_rate_limits(self):
        if config.BUG_BOUNTY_MODE:
            return
        for endpoint in self.endpoints[:10]:
            if self.should_stop():
                return
            statuses = []
            started = time.monotonic()
            for _ in range(50):
                if self.should_stop() or time.monotonic() - started > 5:
                    break
                response = self._request("GET", endpoint)
                if response is not None:
                    statuses.append(response.status_code)
            if statuses and 429 not in statuses:
                self.add_finding(
                    "API rate limiting not observed",
                    "MEDIUM",
                    "Rapid repeated requests did not trigger an HTTP 429 response.",
                    f"Endpoint: {endpoint}\nRequests completed: {len(statuses)}\nStatuses: {sorted(set(statuses))}",
                    "Apply per-client rate limits and return 429 with retry guidance.",
                    5.3,
                    "A04:2021 Insecure Design",
                    "T1499 Endpoint Denial of Service",
                    endpoint,
                )

    def detect_idor(self):
        patterns = []
        for endpoint in self.endpoints:
            parsed = urlparse(endpoint)
            if re.search(r"/(?:user|users|order|orders|document|documents|account|accounts)/\d+(?:/|$)", parsed.path, re.I):
                patterns.append(endpoint)
        if patterns:
            self.add_finding(
                "Potential IDOR endpoint pattern",
                "MEDIUM",
                "Sequential numeric identifiers may allow object enumeration.",
                "\n".join(patterns[:20]),
                "Enforce object-level authorization and prefer non-predictable public identifiers.",
                6.5,
                "A01:2021 Broken Access Control",
                "T1213 Data from Information Repositories",
                patterns[0],
            )

    @staticmethod
    def _b64decode(value):
        return base64.urlsafe_b64decode(value + "=" * (-len(value) % 4))

    @staticmethod
    def _b64encode(value):
        return base64.urlsafe_b64encode(value).rstrip(b"=").decode()

    def _extract_tokens(self):
        token_pattern = re.compile(r"eyJ[a-zA-Z0-9_-]+\.[a-zA-Z0-9_-]+(?:\.[a-zA-Z0-9_-]*)?")
        tokens = set()
        for response in self.responses.values():
            for value in list(response.headers.values()) + list(response.cookies.values()):
                tokens.update(token_pattern.findall(str(value)))
        return tokens

    def check_jwt(self):
        for token in self._extract_tokens():
            parts = token.split(".")
            if len(parts) != 3:
                continue
            try:
                header = json.loads(self._b64decode(parts[0]))
                payload = json.loads(self._b64decode(parts[1]))
            except (ValueError, json.JSONDecodeError, UnicodeDecodeError):
                continue
            algorithm = str(header.get("alg", "")).lower()
            if algorithm == "none":
                self.add_finding(
                    "JWT accepts or advertises the none algorithm",
                    "CRITICAL",
                    "A discovered JWT uses an unsigned algorithm.",
                    f"Header: {json.dumps(header)}",
                    "Reject unsigned JWTs and enforce an explicit asymmetric algorithm.",
                    9.8,
                    "A02:2021 Cryptographic Failures",
                    "T1552 Unsecured Credentials",
                )
            if "exp" not in payload:
                self.add_finding(
                    "JWT has no expiration claim",
                    "HIGH",
                    "A discovered JWT does not contain an exp claim.",
                    f"Payload keys: {', '.join(payload.keys())}",
                    "Issue short-lived tokens with a validated exp claim.",
                    7.4,
                    "A02:2021 Cryptographic Failures",
                    "T1550.001 Application Access Token",
                )
            if algorithm == "hs256":
                signing_input = f"{parts[0]}.{parts[1]}".encode()
                for secret in ("secret", "password", "123456"):
                    signature = hmac.new(secret.encode(), signing_input, hashlib.sha256).digest()
                    if hmac.compare_digest(self._b64encode(signature), parts[2]):
                        self.add_finding(
                            "JWT signed with a common secret",
                            "CRITICAL",
                            "A discovered HS256 token could be verified with a common secret.",
                            f"Algorithm: HS256\nMatched secret: {secret}",
                            "Rotate the signing key and use a high-entropy secret or asymmetric signatures.",
                            9.8,
                            "A02:2021 Cryptographic Failures",
                            "T1552 Unsecured Credentials",
                        )
                        break

    def check_sensitive_data(self):
        for endpoint, response in list(self.responses.items()):
            body = response.text[:1_000_000]
            for label, (pattern, severity, score) in self.SENSITIVE_PATTERNS.items():
                match = pattern.search(body)
                if match:
                    sample = match.group(0)
                    if len(sample) > 120:
                        sample = sample[:117] + "..."
                    self.add_finding(
                        f"Sensitive data exposed in API response: {label}",
                        severity,
                        "An API response contains data matching a sensitive-data pattern.",
                        f"Endpoint: {endpoint}\nMatched sample: {sample}",
                        "Remove unnecessary sensitive fields, mask responses, and enforce authorization.",
                        score,
                        "A02:2021 Cryptographic Failures",
                        "T1552 Unsecured Credentials",
                        endpoint,
                    )
