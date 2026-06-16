"""Multi-source subdomain enumeration and liveness verification."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import csv
import io
import logging
import socket
import time
import uuid

import dns.exception
import dns.resolver
import requests

import config
from core.http import create_session
from database import models


LOGGER = logging.getLogger(__name__)


class SubdomainEnumerator:
    WORDLIST = (
        "www", "mail", "ftp", "api", "dev", "staging", "test", "admin",
        "portal", "vpn", "remote", "cdn", "static", "assets", "images", "beta",
        "app", "mobile", "shop", "store", "blog", "docs", "support", "help",
        "dashboard", "internal", "corp", "intranet", "login", "auth", "sso",
        "smtp", "pop", "imap", "mx", "ns1", "ns2", "git", "gitlab", "jenkins",
        "jira", "confluence", "kibana", "grafana", "monitor", "status", "old",
        "backup",
    )

    def __init__(self, scan_id=None):
        self.scan_id = scan_id or str(uuid.uuid4())
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )
        self.session.headers["User-Agent"] = (
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Recon"
        )

    @staticmethod
    def _clean_domain(domain):
        value = str(domain or "").strip().lower()
        value = value.split("://", 1)[-1].split("/", 1)[0].split(":", 1)[0]
        return value.lstrip(".")

    def enumerate(self, domain):
        domain = self._clean_domain(domain)
        if not domain:
            return []
        sources = {
            "brute": self._dns_brute_force,
            "crt.sh": self._certificate_transparency,
            "hackertarget": self._dns_dumpster,
        }
        discovered = {}
        with ThreadPoolExecutor(max_workers=3, thread_name_prefix="recon-source") as pool:
            futures = {pool.submit(method, domain): name for name, method in sources.items()}
            for future in as_completed(futures):
                source = futures[future]
                try:
                    for hostname in future.result():
                        hostname = hostname.lower().rstrip(".")
                        if hostname == domain or hostname.endswith(f".{domain}"):
                            discovered.setdefault(hostname, set()).add(source)
                except Exception as exc:
                    LOGGER.warning("Subdomain source %s failed: %s", source, exc)
        results = self._verify_alive(discovered)
        for item in results:
            item["scan_id"] = self.scan_id
            models.insert_subdomain(item)
            try:
                scheme = "https" if str(item["redirect_url"]).startswith("https://") else "http"
                models.upsert_target(
                    f"{scheme}://{item['subdomain']}",
                    monitor_enabled=False,
                    interval="24h",
                    alerts_enabled=False,
                )
            except Exception as exc:
                LOGGER.debug("Unable to queue %s: %s", item["subdomain"], exc)
        return results

    def _dns_brute_force(self, domain):
        resolver = dns.resolver.Resolver()
        resolver.lifetime = min(config.SCAN_TIMEOUT, 5)

        def resolve(prefix):
            hostname = f"{prefix}.{domain}"
            try:
                resolver.resolve(hostname, "A")
                return hostname
            except dns.resolver.NXDOMAIN:
                return None
            except (dns.resolver.NoAnswer, dns.resolver.NoNameservers, dns.exception.Timeout):
                return None
            except Exception as exc:
                LOGGER.debug("DNS resolution failed for %s: %s", hostname, exc)
                return None

        found = []
        with ThreadPoolExecutor(max_workers=min(config.MAX_THREADS, 20)) as pool:
            for hostname in pool.map(resolve, self.WORDLIST):
                if hostname:
                    found.append(hostname)
        return found

    def _certificate_transparency(self, domain):
        try:
            response = self.session.get(
                "https://crt.sh/",
                params={"q": f"%.{domain}", "output": "json"},
                timeout=config.SCAN_TIMEOUT,
            )
            response.raise_for_status()
            values = set()
            for record in response.json():
                for hostname in str(record.get("name_value", "")).splitlines():
                    cleaned = hostname.strip().lower().removeprefix("*.")
                    if cleaned:
                        values.add(cleaned)
            return sorted(values)
        except (requests.RequestException, ValueError) as exc:
            LOGGER.warning("crt.sh lookup failed: %s", exc)
            return []

    def _dns_dumpster(self, domain):
        try:
            response = self.session.get(
                "https://api.hackertarget.com/hostsearch/",
                params={"q": domain},
                timeout=config.SCAN_TIMEOUT,
            )
            response.raise_for_status()
            if response.text.lower().startswith(("error", "api count exceeded")):
                return []
            return sorted(
                {
                    row[0].strip().lower()
                    for row in csv.reader(io.StringIO(response.text))
                    if row and row[0].strip()
                }
            )
        except requests.RequestException as exc:
            LOGGER.warning("HackerTarget lookup failed: %s", exc)
            return []

    def _verify_alive(self, subdomains):
        def verify(hostname, sources):
            ip = self._get_ip(hostname)
            for scheme in ("https", "http"):
                url = f"{scheme}://{hostname}"
                started = time.monotonic()
                try:
                    response = self.session.get(
                        url,
                        timeout=min(config.SCAN_TIMEOUT, 5),
                        allow_redirects=True,
                    )
                    return {
                        "id": str(uuid.uuid4()),
                        "subdomain": hostname,
                        "ip": ip or "",
                        "status_code": response.status_code,
                        "server_header": response.headers.get("Server", ""),
                        "redirect_url": response.url,
                        "response_time": round(time.monotonic() - started, 3),
                        "discovered_by": ",".join(sorted(sources)),
                        "timestamp": datetime.now(timezone.utc).isoformat(),
                    }
                except requests.RequestException:
                    continue
            return None

        alive = []
        with ThreadPoolExecutor(max_workers=min(config.MAX_THREADS, 20)) as pool:
            futures = [
                pool.submit(verify, hostname, sources)
                for hostname, sources in subdomains.items()
            ]
            for future in as_completed(futures):
                try:
                    result = future.result()
                    if result:
                        alive.append(result)
                except Exception as exc:
                    LOGGER.debug("Liveness verification failed: %s", exc)
        return sorted(alive, key=lambda item: item["subdomain"])

    @staticmethod
    def _get_ip(subdomain):
        try:
            return socket.gethostbyname(subdomain)
        except OSError:
            return None
