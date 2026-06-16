"""Session cookie and optional login/logout lifecycle checks."""

import logging
from urllib.parse import urljoin

import requests

import config
from core.http import create_session
from scanners.base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)


class SessionTester(BaseScanner):
    scanner_name = "session"
    total_checks = 3

    def __init__(self, target, login_url=None, logout_url=None, credentials=None, *args, **kwargs):
        super().__init__(target, *args, **kwargs)
        self.login_url = login_url
        self.logout_url = logout_url
        self.credentials = credentials or {}

    def scan(self, target_url=None, authorized=False):
        if not authorized:
            raise PermissionError("Explicit authorization is required")
        if target_url:
            self.target = self.normalize_target(target_url)
        session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Access-Validation"
        )
        try:
            response = session.get(self.target, timeout=config.SCAN_TIMEOUT)
        except requests.RequestException:
            return []
        self._check_cookie_security(response)
        if self.login_url and self.credentials:
            self._test_session_fixation(session)
            if self.logout_url:
                self._check_session_invalidation(session)
        self.status = "completed"
        return self.get_findings()

    def run(self):
        return self.scan(authorized=True)

    def _check_cookie_security(self, response):
        cookies = response.raw.headers.getlist("Set-Cookie") if hasattr(response.raw.headers, "getlist") else []
        if not cookies and response.headers.get("Set-Cookie"):
            cookies = [response.headers["Set-Cookie"]]
        for cookie in cookies:
            lower = cookie.lower()
            missing = []
            severity = "LOW"
            score = 3.1
            if "secure" not in lower:
                missing.append("Secure")
                severity, score = "MEDIUM", 5.3
            if "httponly" not in lower:
                missing.append("HttpOnly")
                severity, score = "MEDIUM", 5.3
            if "samesite" not in lower:
                missing.append("SameSite")
            if "samesite=none" in lower and "secure" not in lower:
                severity, score = "HIGH", 7.4
            if missing:
                self.add_finding(
                    "Session cookie security attributes missing",
                    severity,
                    "A session-related cookie is missing recommended browser protections.",
                    f"Cookie: {cookie}\nMissing: {', '.join(missing)}",
                    "Set Secure, HttpOnly, and an appropriate SameSite policy.",
                    score,
                    "A07:2021 Identification and Authentication Failures",
                    "T1539 Steal Web Session Cookie",
                    response.url,
                )

    def _test_session_fixation(self, session):
        before = requests.utils.dict_from_cookiejar(session.cookies)
        try:
            session.post(
                urljoin(self.target, self.login_url),
                data=self.credentials,
                timeout=config.SCAN_TIMEOUT,
            )
        except requests.RequestException:
            return
        after = requests.utils.dict_from_cookiejar(session.cookies)
        shared = {key for key in before if before.get(key) == after.get(key)}
        if before and shared:
            self.add_finding(
                "Potential session fixation",
                "HIGH",
                "One or more session cookies did not rotate after the configured login.",
                f"Unchanged cookie names: {', '.join(sorted(shared))}",
                "Regenerate the session identifier immediately after authentication.",
                7.5,
                "A07:2021 Identification and Authentication Failures",
                "T1539 Steal Web Session Cookie",
                self.target,
            )

    def _check_session_invalidation(self, session):
        old_cookies = requests.utils.dict_from_cookiejar(session.cookies)
        try:
            session.get(
                urljoin(self.target, self.logout_url),
                timeout=config.SCAN_TIMEOUT,
            )
            response = create_session(
                f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Access-Validation"
            ).get(
                self.target,
                cookies=old_cookies,
                timeout=config.SCAN_TIMEOUT,
            )
        except requests.RequestException:
            return
        if response.status_code == 200 and old_cookies:
            self.add_finding(
                "Old session remains usable after logout",
                "HIGH",
                "The pre-logout cookie set still received a successful protected-page response.",
                f"Status using old cookies: {response.status_code}",
                "Invalidate server-side sessions on logout and rotate authentication tokens.",
                7.5,
                "A07:2021 Identification and Authentication Failures",
                "T1539 Steal Web Session Cookie",
                response.url,
            )
