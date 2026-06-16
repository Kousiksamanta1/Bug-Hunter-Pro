"""Conservative privilege-boundary trust-header validation."""

import logging
from urllib.parse import urljoin

import requests

import config
from core.http import create_session
from scanners.base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)


class PrivilegeEscalationTester(BaseScanner):
    scanner_name = "privilege_escalation"
    total_checks = 1
    PATHS = ("/admin", "/admin/", "/api/admin", "/manage", "/dashboard/admin")
    TRUST_HEADERS = (
        {"X-Role": "admin"},
        {"X-User-Role": "administrator"},
        {"X-Original-User": "admin"},
    )

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
        base_headers = headers or {}
        for path in self.PATHS:
            url = urljoin(f"{self.target.rstrip('/')}/", path.lstrip("/"))
            try:
                baseline = self.session.get(
                    url,
                    headers=base_headers,
                    timeout=config.SCAN_TIMEOUT,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue
            if baseline.status_code not in {401, 403}:
                continue
            for injected in self.TRUST_HEADERS:
                try:
                    response = self.session.get(
                        url,
                        headers={**base_headers, **injected},
                        timeout=config.SCAN_TIMEOUT,
                        allow_redirects=False,
                    )
                except requests.RequestException:
                    continue
                if response.status_code == 200 and len(response.content) > 100:
                    self.add_finding(
                        "Privilege boundary trusts client-controlled role header",
                        "CRITICAL",
                        "An administrative endpoint became accessible after adding a role-like header.",
                        (
                            f"URL: {url}\nBaseline status: {baseline.status_code}\n"
                            f"Injected header: {injected}\nResult status: {response.status_code}"
                        ),
                        "Ignore client-supplied identity headers unless set by a trusted authenticated proxy.",
                        9.1,
                        "A01:2021 Broken Access Control",
                        "T1068 Exploitation for Privilege Escalation",
                        url,
                    )
                    return self.get_findings()
        self.status = "completed"
        return self.get_findings()

    def run(self):
        return self.scan(authorized=True)
