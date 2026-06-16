"""Network, service, CVE, credential, DNS, and perimeter checks."""

import ftplib
import logging
import socket
import ssl
import time
from urllib.parse import quote_plus, urlparse

import dns.query
import dns.resolver
import dns.zone
import paramiko
import requests

import config
from core.severity import cvss_to_severity
from .base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)

try:
    import nmap
except ImportError:
    nmap = None


class NetworkScanner(BaseScanner):
    scanner_name = "network"
    total_checks = 6
    CREDENTIALS = (
        ("admin", "admin"),
        ("admin", "password"),
        ("root", "root"),
        ("admin", "123456"),
        ("guest", "guest"),
        ("test", "test"),
    )

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.services = []
        self.cve_cache = {}

    def run(self):
        self.status = "running"
        checks = [
            self.scan_ports,
            self.lookup_cves,
            self.detect_weak_protocols,
            self.check_default_credentials,
            self.check_dns_security,
            self.detect_waf,
        ]
        for index, check in enumerate(checks, start=1):
            if self.should_stop():
                self.status = "stopped"
                break
            try:
                check()
            except Exception as exc:
                LOGGER.exception("Network check %s failed: %s", check.__name__, exc)
            self.set_progress(index / len(checks) * 100, check.__name__)
        else:
            self.status = "completed"
        return self.get_findings()

    def scan_ports(self):
        if nmap is None:
            self.add_finding(
                "Network scanner dependency unavailable",
                "INFO",
                "The python-nmap package is not installed.",
                "ImportError: python-nmap",
                "Install python-nmap and the system nmap executable to enable port scanning.",
                0,
                "",
                "",
            )
            return
        try:
            scanner = nmap.PortScanner()
        except Exception as exc:
            self.add_finding(
                "Nmap executable unavailable",
                "INFO",
                "Network port scanning could not start because nmap was not found.",
                str(exc),
                "Install nmap and ensure it is available on PATH.",
                0,
                "",
                "",
            )
            return
        try:
            scanner.scan(
                hosts=self.hostname,
                arguments="-sV --top-ports 1000 -T4 --host-timeout 120s",
            )
        except Exception as exc:
            LOGGER.warning("Nmap scan failed: %s", exc)
            return
        for host in scanner.all_hosts():
            for protocol in scanner[host].all_protocols():
                for port, details in scanner[host][protocol].items():
                    if details.get("state") != "open":
                        continue
                    service = {
                        "host": host,
                        "port": int(port),
                        "protocol": protocol,
                        "state": details.get("state", ""),
                        "service": details.get("name", ""),
                        "version": " ".join(
                            value
                            for value in (
                                details.get("product", ""),
                                details.get("version", ""),
                                details.get("extrainfo", ""),
                            )
                            if value
                        ),
                        "banner": details.get("cpe", ""),
                    }
                    self.services.append(service)
                    if int(port) in {21, 23, 3389}:
                        self.add_finding(
                            f"Dangerous service exposed on port {port}",
                            "MEDIUM",
                            "A commonly abused remote-access service is externally reachable.",
                            str(service),
                            "Restrict the port by firewall, VPN, and network allowlists.",
                            6.5,
                            "A05:2021 Security Misconfiguration",
                            "T1046 Network Service Discovery",
                            f"{host}:{port}",
                        )

    @staticmethod
    def _cvss(item):
        metrics = item.get("metrics", {})
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            if metrics.get(key):
                metric = metrics[key][0]
                return float(metric.get("cvssData", {}).get("baseScore", 0))
        return 0.0

    def lookup_cves(self):
        headers = {"apiKey": config.NVD_API_KEY} if config.NVD_API_KEY else {}
        for service in self.services:
            if self.should_stop():
                return
            term = f"{service['service']} {service['version']}".strip()
            if not service["version"] or term in self.cve_cache:
                continue
            try:
                response = requests.get(
                    "https://services.nvd.nist.gov/rest/json/cves/2.0",
                    params={"keywordSearch": term, "resultsPerPage": 20},
                    headers=headers,
                    timeout=config.SCAN_TIMEOUT,
                )
                response.raise_for_status()
                vulnerabilities = response.json().get("vulnerabilities", [])
                ranked = sorted(
                    (item.get("cve", {}) for item in vulnerabilities),
                    key=self._cvss,
                    reverse=True,
                )[:3]
                self.cve_cache[term] = ranked
                for cve in ranked:
                    score = self._cvss(cve)
                    if score < 7.0:
                        continue
                    cve_id = cve.get("id", "Unknown CVE")
                    descriptions = cve.get("descriptions", [])
                    description = next(
                        (item.get("value", "") for item in descriptions if item.get("lang") == "en"),
                        "No NVD description available.",
                    )
                    severity = cvss_to_severity(score)
                    self.add_finding(
                        f"{cve_id} affects {term}",
                        severity,
                        description,
                        f"CVE: {cve_id}\nService: {service}\nCVSS: {score}",
                        "Patch or upgrade the affected service after validating vendor guidance.",
                        score,
                        "A06:2021 Vulnerable and Outdated Components",
                        "T1190 Exploit Public-Facing Application",
                        f"{service['host']}:{service['port']}",
                    )
            except (requests.RequestException, ValueError, KeyError) as exc:
                LOGGER.warning("NVD lookup failed for %s: %s", term, exc)
            time.sleep(0.6)

    def detect_weak_protocols(self):
        ports = {item["port"] for item in self.services}
        if 22 in ports or 2222 in ports:
            port = 22 if 22 in ports else 2222
            try:
                transport = paramiko.Transport((self.hostname, port))
                transport.banner_timeout = 3
                transport.start_client(timeout=3)
                options = transport.get_security_options()
                algorithms = list(options.ciphers) + list(options.digests)
                weak = [
                    name
                    for name in algorithms
                    if any(value in name.lower() for value in ("arcfour", "3des", "des", "md5"))
                ]
                transport.close()
                if weak:
                    self.add_finding(
                        "Weak SSH algorithms supported",
                        "MEDIUM",
                        "The SSH service advertises obsolete cryptographic algorithms.",
                        ", ".join(weak),
                        "Disable legacy SSH ciphers and MAC algorithms.",
                        5.9,
                        "A02:2021 Cryptographic Failures",
                        "",
                        f"{self.hostname}:{port}",
                    )
            except Exception as exc:
                LOGGER.debug("SSH algorithm inspection failed: %s", exc)
        if 443 in ports or urlparse(self.target).scheme == "https":
            for protocol, label in ((ssl.TLSVersion.TLSv1, "TLSv1.0"), (ssl.TLSVersion.TLSv1_1, "TLSv1.1")):
                try:
                    context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
                    context.check_hostname = False
                    context.verify_mode = ssl.CERT_NONE
                    context.minimum_version = protocol
                    context.maximum_version = protocol
                    with socket.create_connection((self.hostname, 443), timeout=config.SCAN_TIMEOUT) as sock:
                        with context.wrap_socket(sock, server_hostname=self.hostname):
                            self.add_finding(
                                f"Deprecated protocol enabled: {label}",
                                "MEDIUM",
                                "The HTTPS service accepts an obsolete TLS protocol.",
                                f"{self.hostname}:443 accepted {label}",
                                "Disable TLS 1.0 and TLS 1.1.",
                                6.5,
                                "A02:2021 Cryptographic Failures",
                                "",
                                f"{self.hostname}:443",
                            )
                except Exception:
                    continue

    def check_default_credentials(self):
        ports = {item["port"] for item in self.services}
        if 22 in ports or 2222 in ports:
            port = 22 if 22 in ports else 2222
            for username, password in self.CREDENTIALS:
                if self.should_stop():
                    return
                client = paramiko.SSHClient()
                client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
                try:
                    client.connect(
                        self.hostname,
                        port=port,
                        username=username,
                        password=password,
                        timeout=3,
                        auth_timeout=3,
                        banner_timeout=3,
                        allow_agent=False,
                        look_for_keys=False,
                    )
                    self.add_finding(
                        "Default SSH credentials accepted",
                        "CRITICAL",
                        "The SSH service accepted a known default username and password.",
                        f"Host: {self.hostname}:{port}\nUsername: {username}\nPassword: {password}",
                        "Disable the account or rotate credentials immediately; require key-based authentication.",
                        9.8,
                        "A07:2021 Identification and Authentication Failures",
                        "T1078 Valid Accounts",
                        f"{self.hostname}:{port}",
                    )
                    break
                except Exception:
                    pass
                finally:
                    client.close()
        if 21 in ports:
            for username, password in self.CREDENTIALS:
                if self.should_stop():
                    return
                ftp = None
                try:
                    ftp = ftplib.FTP()
                    ftp.connect(self.hostname, 21, timeout=3)
                    ftp.login(username, password)
                    self.add_finding(
                        "Default FTP credentials accepted",
                        "CRITICAL",
                        "The FTP service accepted a known default username and password.",
                        f"Host: {self.hostname}:21\nUsername: {username}\nPassword: {password}",
                        "Disable FTP or rotate credentials and migrate to a protected protocol.",
                        9.8,
                        "A07:2021 Identification and Authentication Failures",
                        "T1078 Valid Accounts",
                        f"{self.hostname}:21",
                    )
                    break
                except Exception:
                    pass
                finally:
                    if ftp:
                        try:
                            ftp.close()
                        except Exception:
                            pass

    def check_dns_security(self):
        domain = self.hostname
        try:
            socket.inet_aton(domain)
            return
        except OSError:
            pass
        resolver = dns.resolver.Resolver()
        resolver.lifetime = config.SCAN_TIMEOUT
        records = {}
        for record_type in ("A", "MX", "TXT", "NS"):
            try:
                records[record_type] = [item.to_text() for item in resolver.resolve(domain, record_type)]
            except Exception:
                records[record_type] = []
        txt = " ".join(records["TXT"]).lower()
        if "v=spf1" not in txt:
            self.add_finding(
                "SPF record missing",
                "LOW",
                "The domain does not publish an SPF policy.",
                f"TXT records: {records['TXT'] or 'none'}",
                "Publish an SPF TXT record covering authorized mail senders.",
                3.1,
                "A05:2021 Security Misconfiguration",
                "",
                domain,
            )
        try:
            dmarc = [item.to_text() for item in resolver.resolve(f"_dmarc.{domain}", "TXT")]
        except Exception:
            dmarc = []
        if not any("v=dmarc1" in item.lower() for item in dmarc):
            self.add_finding(
                "DMARC record missing",
                "LOW",
                "The domain does not publish a DMARC policy.",
                f"_dmarc.{domain} TXT returned no DMARC policy.",
                "Publish and monitor a DMARC policy, then move toward enforcement.",
                3.1,
                "A05:2021 Security Misconfiguration",
                "",
                domain,
            )
        dkim_found = False
        for selector in ("default", "google", "selector1", "selector2"):
            try:
                answers = resolver.resolve(f"{selector}._domainkey.{domain}", "TXT")
                if any("v=dkim1" in item.to_text().lower() for item in answers):
                    dkim_found = True
                    break
            except Exception:
                continue
        if not dkim_found:
            self.add_finding(
                "Common DKIM selectors not detected",
                "INFO",
                "No DKIM key was found under the common selectors tested.",
                "Selectors tested: default, google, selector1, selector2",
                "Confirm that mail-sending services publish DKIM keys under the intended selectors.",
                0,
                "A05:2021 Security Misconfiguration",
                "",
                domain,
            )
        for nameserver in records["NS"]:
            server = nameserver.rstrip(".")
            try:
                zone = dns.zone.from_xfr(dns.query.xfr(server, domain, lifetime=5))
                if zone:
                    self.add_finding(
                        "DNS zone transfer permitted",
                        "HIGH",
                        "An authoritative name server allowed an AXFR zone transfer.",
                        f"Name server: {server}\nNodes transferred: {len(zone.nodes)}",
                        "Restrict zone transfers to explicitly authorized secondary servers.",
                        7.5,
                        "A05:2021 Security Misconfiguration",
                        "T1018 Remote System Discovery",
                        domain,
                    )
                    break
            except Exception:
                continue

    def detect_waf(self):
        try:
            response = requests.get(self.target, timeout=config.SCAN_TIMEOUT)
        except requests.RequestException as exc:
            LOGGER.warning("WAF request failed: %s", exc)
            return
        signatures = []
        if response.headers.get("X-Sucuri-ID"):
            signatures.append("Sucuri")
        if response.headers.get("X-Firewall"):
            signatures.append(response.headers["X-Firewall"])
        if "cloudflare" in response.headers.get("Server", "").lower():
            signatures.append("Cloudflare")
        if signatures:
            self.add_finding(
                "Web application firewall detected",
                "INFO",
                "A perimeter security service appears to protect the target.",
                f"Detected signatures: {', '.join(signatures)}",
                "Keep WAF rules current and do not treat the WAF as a substitute for remediation.",
                0,
                "",
                "",
                response.url,
            )
