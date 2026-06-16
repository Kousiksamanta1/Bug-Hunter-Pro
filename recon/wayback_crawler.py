"""Historical URL discovery through the Internet Archive CDX API."""

from concurrent.futures import ThreadPoolExecutor, as_completed
import logging
import random
from urllib.parse import urlparse

import requests

import config
from core.http import create_session


LOGGER = logging.getLogger(__name__)


class WaybackCrawler:
    SKIP_EXTENSIONS = {
        ".jpg", ".jpeg", ".png", ".gif", ".svg", ".ico", ".css", ".woff",
        ".woff2", ".ttf", ".eot", ".mp4", ".mp3", ".pdf",
    }

    def __init__(self):
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )
        self.session.headers["User-Agent"] = (
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )

    def crawl(self, domain):
        domain = str(domain).split("://")[-1].split("/")[0].split(":")[0]
        urls = self._fetch_wayback_urls(domain)
        categories = self._categorise_urls(urls)
        alive = self._check_still_alive(urls)
        return {
            "total_found": len(urls),
            "alive_count": len(alive),
            "categories": categories,
            "alive_urls": alive,
            "interesting_params": categories["interesting"],
        }

    def _fetch_wayback_urls(self, domain):
        try:
            response = self.session.get(
                "https://web.archive.org/cdx/search/cdx",
                params={
                    "url": f"*.{domain}",
                    "output": "json",
                    "fl": "original",
                    "collapse": "urlkey",
                    "limit": "10000",
                },
                timeout=max(config.SCAN_TIMEOUT, 20),
            )
            response.raise_for_status()
            rows = response.json()
        except (requests.RequestException, ValueError) as exc:
            LOGGER.warning("Wayback lookup failed: %s", exc)
            return []
        urls = set()
        for row in rows[1:] if rows else []:
            if not row:
                continue
            url = row[0]
            extension = urlparse(url).path.lower()
            if any(extension.endswith(suffix) for suffix in self.SKIP_EXTENSIONS):
                continue
            urls.add(url)
        return sorted(urls)

    def _categorise_urls(self, urls):
        categories = {
            "api_endpoints": [], "admin_panels": [], "auth_pages": [],
            "config_files": [], "backup_files": [], "interesting": [],
            "all_others": [],
        }
        for url in urls:
            lower = url.lower()
            path = urlparse(url).path.lower()
            if any(value in lower for value in ("/api/", "/v1/", "/v2/", "/graphql", "/rest/")):
                category = "api_endpoints"
            elif any(value in lower for value in ("/admin", "/dashboard", "/portal", "/manage")):
                category = "admin_panels"
            elif any(value in lower for value in ("/login", "/logout", "/signup", "/register", "/auth")):
                category = "auth_pages"
            elif path.endswith((".json", ".xml", ".yaml", ".yml", ".env", ".config")):
                category = "config_files"
            elif path.endswith((".bak", ".old", ".backup", ".zip", ".tar", ".gz")):
                category = "backup_files"
            elif any(value in lower for value in ("?id=", "?user=", "?file=", "?path=", "?redirect=")):
                category = "interesting"
            else:
                category = "all_others"
            categories[category].append(url)
        return categories

    def _check_still_alive(self, urls, sample_size=200):
        sample = random.sample(urls, min(len(urls), sample_size)) if urls else []

        def check(url):
            try:
                response = self.session.get(
                    url,
                    timeout=min(config.SCAN_TIMEOUT, 5),
                    allow_redirects=False,
                )
                if response.status_code in {200, 403}:
                    return {
                        "url": url,
                        "status": response.status_code,
                        "last_seen": "",
                    }
            except requests.RequestException:
                return None
            return None

        alive = []
        with ThreadPoolExecutor(max_workers=min(config.MAX_THREADS, 20)) as pool:
            futures = [pool.submit(check, url) for url in sample]
            for future in as_completed(futures):
                result = future.result()
                if result:
                    alive.append(result)
        return alive
