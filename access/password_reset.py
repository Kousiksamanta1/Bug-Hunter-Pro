"""Password-reset flow discovery and safe response hygiene checks."""

import logging
import math
import re
from urllib.parse import urljoin

from bs4 import BeautifulSoup
import requests

import config
from core.http import create_session
from scanners.base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)


class PasswordResetTester(BaseScanner):
    scanner_name = "password_reset"
    total_checks = 4
    PATHS = (
        "/forgot-password", "/reset-password", "/password/reset",
        "/account/recover", "/auth/forgot",
    )
    TOKEN_PATTERN = re.compile(r"(?:token|code)=([A-Za-z0-9._~-]+)", re.I)

    def __init__(self, target, *args, **kwargs):
        super().__init__(target, *args, **kwargs)
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Access-Validation"
        )

    def scan(self, target_url=None, authorized=False):
        if not authorized:
            raise PermissionError("Explicit authorization is required")
        if target_url:
            self.target = self.normalize_target(target_url)
        endpoint = self._find_reset_endpoint(self.target)
        if endpoint:
            responses = self._test_host_header_injection(endpoint)
            tokens = self._extract_tokens(responses)
            self._test_token_predictability(endpoint, tokens)
            self._test_response_manipulation(endpoint, responses)
        self.status = "completed"
        return self.get_findings()

    def run(self):
        return self.scan(authorized=True)

    def _find_reset_endpoint(self, target_url):
        candidates = {urljoin(f"{target_url.rstrip('/')}/", path.lstrip("/")) for path in self.PATHS}
        try:
            response = self.session.get(target_url, timeout=config.SCAN_TIMEOUT)
            soup = BeautifulSoup(response.text, "html.parser")
            candidates.update(
                urljoin(response.url, link["href"])
                for link in soup.find_all("a", href=True)
                if any(term in link["href"].lower() for term in ("forgot", "reset", "recover"))
            )
        except requests.RequestException:
            pass
        for url in candidates:
            try:
                response = self.session.get(url, timeout=config.SCAN_TIMEOUT)
                if response.status_code not in {404, 405}:
                    return url
            except requests.RequestException:
                continue
        return None

    def _test_host_header_injection(self, reset_url):
        variants = (
            {"Host": "invalid.example"},
            {"X-Forwarded-Host": "invalid.example"},
            {"X-Host": "invalid.example"},
        )
        responses = []
        for headers in variants:
            try:
                response = self.session.post(
                    reset_url,
                    data={"email": "bughunter-nonexistent@example.invalid"},
                    headers=headers,
                    timeout=config.SCAN_TIMEOUT,
                    allow_redirects=False,
                )
                responses.append(response)
            except requests.RequestException:
                continue
            combined = f"{response.text}\n{response.headers.get('Location', '')}"
            if "invalid.example" in combined:
                self.add_finding(
                    "Password reset host-header injection",
                    "CRITICAL",
                    "The reset response incorporated an untrusted host header.",
                    f"Endpoint: {reset_url}\nHeader: {headers}\nResponse evidence contains invalid.example",
                    "Build reset links from a fixed trusted origin and reject unrecognized hosts.",
                    9.1,
                    "A07:2021 Identification and Authentication Failures",
                    "T1586 Compromise Accounts",
                    reset_url,
                )
                break
        return responses

    def _extract_tokens(self, responses):
        tokens = []
        for response in responses:
            combined = f"{response.text}\n{response.headers.get('Location', '')}"
            tokens.extend(self.TOKEN_PATTERN.findall(combined))
        return tokens

    def _test_token_predictability(self, reset_url, tokens):
        for token in tokens:
            if token.isdigit():
                severity, score, reason = "CRITICAL", 9.1, "numeric or sequential token"
            elif len(token) < 16:
                severity, score, reason = "MEDIUM", 5.3, "token shorter than 16 characters"
            else:
                alphabet = max(len(set(token)), 2)
                entropy = len(token) * math.log2(alphabet)
                if entropy >= 64:
                    continue
                severity, score, reason = "MEDIUM", 5.3, f"estimated entropy {entropy:.1f} bits"
            self.add_finding(
                "Weak password reset token",
                severity,
                "A reset token exposed in the response appears predictable or low entropy.",
                f"Endpoint: {reset_url}\nToken length: {len(token)}\nReason: {reason}",
                "Use at least 128 bits of cryptographically secure randomness and single use.",
                score,
                "A07:2021 Identification and Authentication Failures",
                "T1586 Compromise Accounts",
                reset_url,
            )

    def _test_response_manipulation(self, reset_url, responses):
        for response in responses:
            location = response.headers.get("Location", "")
            referer = response.request.headers.get("Referer", "")
            if self.TOKEN_PATTERN.search(location) or self.TOKEN_PATTERN.search(referer):
                self.add_finding(
                    "Password reset token leaked through URL headers",
                    "HIGH",
                    "A reset token appears in a redirect or Referer URL.",
                    f"Location: {location}\nReferer: {referer}",
                    "Keep reset tokens out of Referer-bearing URLs and apply Referrer-Policy.",
                    7.4,
                    "A02:2021 Cryptographic Failures",
                    "T1528 Steal Application Access Token",
                    reset_url,
                )
                return
