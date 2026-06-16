"""Technology stack and interesting-path fingerprinting."""

from datetime import datetime, timezone
import json
import logging
import uuid
from urllib.parse import urljoin

import requests

import config
from core.http import create_session
from database import models


LOGGER = logging.getLogger(__name__)


class TechFingerprinter:
    COMMON_PATHS = {
        "/wp-login.php": ("cms", "WordPress", "INFO"),
        "/administrator/": ("cms", "Joomla", "INFO"),
        "/user/login": ("cms", "Drupal", "INFO"),
        "/admin/login": ("framework", "Generic admin", "INFO"),
        "/phpmyadmin/": ("framework", "phpMyAdmin", "MEDIUM"),
        "/.git/HEAD": ("finding", "Exposed Git repository", "HIGH"),
        "/elmah.axd": ("finding", "Exposed ASP.NET error log", "HIGH"),
        "/actuator/health": ("framework", "Spring Boot", "INFO"),
        "/actuator/env": ("finding", "Exposed Spring environment", "CRITICAL"),
        "/console": ("framework", "Joomla or Play Framework", "INFO"),
        "/.env": ("finding", "Exposed environment file", "CRITICAL"),
    }

    def __init__(self, scan_id=None):
        self.scan_id = scan_id or str(uuid.uuid4())
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )
        self.session.headers["User-Agent"] = (
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )

    def fingerprint(self, target_url):
        result = {
            "id": str(uuid.uuid4()),
            "scan_id": self.scan_id,
            "target": target_url,
            "server": "",
            "language": "",
            "framework": "",
            "cms": "",
            "cdn": "",
            "waf": "",
            "interesting_paths": [],
            "findings": [],
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }
        try:
            response = self.session.get(target_url, timeout=config.SCAN_TIMEOUT)
            self._merge(result, self._check_headers(response))
            self._merge(result, self._check_cookies(response))
            self._merge(result, self._check_html_patterns(response.text))
        except requests.RequestException as exc:
            LOGGER.warning("Fingerprint base request failed: %s", exc)
        path_data = self._check_common_paths(target_url)
        self._merge(result, path_data)
        result["interesting_paths"] = list(dict.fromkeys(result["interesting_paths"]))
        stored = dict(result)
        stored["interesting_paths"] = json.dumps(result["interesting_paths"])
        models.insert_tech_fingerprint(stored)
        return result

    @staticmethod
    def _merge(target, values):
        for key, value in values.items():
            if key in {"interesting_paths", "findings"}:
                target[key].extend(value)
            elif value and not target.get(key):
                target[key] = value

    @staticmethod
    def _check_headers(response):
        headers = response.headers
        server = headers.get("Server", "")
        powered = headers.get("X-Powered-By", "")
        generator = headers.get("X-Generator", "")
        via = headers.get("Via", "")
        served = headers.get("X-Served-By", "")
        lower = " ".join((server, powered, generator, via, served)).lower()
        return {
            "server": server,
            "language": (
                "PHP" if "php" in lower else
                "ASP.NET" if "asp.net" in lower else
                "JavaScript/Node.js" if "express" in lower else ""
            ),
            "framework": "Express" if "express" in lower else "",
            "cms": (
                "WordPress" if "wordpress" in lower else
                "Drupal" if "drupal" in lower else ""
            ),
            "cdn": (
                "Cloudflare" if "cloudflare" in lower else
                "Fastly" if "fastly" in lower else
                "Akamai" if "akamai" in lower else ""
            ),
            "waf": "Cloudflare" if "cloudflare" in lower else "",
        }

    @staticmethod
    def _check_cookies(response):
        names = {cookie.name.lower() for cookie in response.cookies}
        joined = " ".join(names)
        return {
            "language": (
                "PHP" if "phpsessid" in names else
                "Java" if "jsessionid" in names else
                "ASP.NET" if "asp.net_sessionid" in names else ""
            ),
            "framework": (
                "Laravel" if "laravel_session" in names else
                "Ruby on Rails" if "_rails_session" in names else ""
            ),
            "cms": "WordPress" if "wp_" in joined else "",
        }

    @staticmethod
    def _check_html_patterns(html):
        lower = html.lower()
        return {
            "cms": (
                "WordPress" if "wp-content" in lower or "wp-includes" in lower else
                "Drupal" if "/sites/default/files" in lower else
                "Joomla" if "joomla!" in lower else ""
            ),
            "framework": (
                "Angular" if "ng-version" in lower else
                "Next.js" if "__next/static" in lower else
                "Nuxt.js" if "_nuxt" in lower else
                "React" if "data-reactroot" in lower else
                "Vue.js" if "__vue" in lower else ""
            ),
        }

    def _check_common_paths(self, base_url):
        data = {"framework": "", "cms": "", "interesting_paths": [], "findings": []}
        baseline_status = None
        baseline_length = None
        baseline_url = urljoin(
            f"{base_url.rstrip('/')}/",
            f".bughunter-not-found-{uuid.uuid4().hex}",
        )
        try:
            baseline = self.session.get(
                baseline_url,
                timeout=config.SCAN_TIMEOUT,
                allow_redirects=False,
            )
            baseline_status = baseline.status_code
            baseline_length = len(baseline.content)
        except requests.RequestException:
            pass
        for path, (kind, label, severity) in self.COMMON_PATHS.items():
            url = urljoin(f"{base_url.rstrip('/')}/", path.lstrip("/"))
            try:
                response = self.session.get(
                    url,
                    timeout=config.SCAN_TIMEOUT,
                    allow_redirects=False,
                )
            except requests.RequestException:
                continue
            if response.status_code not in {200, 401, 403}:
                continue
            if (
                response.status_code == baseline_status
                and baseline_length is not None
                and abs(len(response.content) - baseline_length)
                <= max(80, baseline_length * 0.05)
            ):
                continue
            data["interesting_paths"].append(url)
            if kind in {"framework", "cms"} and not data[kind]:
                data[kind] = label
            if kind == "finding":
                data["findings"].append(
                    {
                        "title": label,
                        "severity": severity,
                        "url": url,
                        "evidence": f"HTTP {response.status_code} returned for {path}",
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                )
        return data
