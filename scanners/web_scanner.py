"""Web application security checks."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
import logging
import socket
import ssl
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

from bs4 import BeautifulSoup
import requests
import urllib3

import config
from core.http import create_session
from .base_scanner import BaseScanner


LOGGER = logging.getLogger(__name__)
urllib3.disable_warnings(urllib3.exceptions.InsecureRequestWarning)


class WebScanner(BaseScanner):
    scanner_name = "web"
    total_checks = 8
    SECURITY_HEADERS = {
        "Content-Security-Policy": "Define a restrictive Content Security Policy.",
        "Strict-Transport-Security": "Enable HSTS with an appropriate max-age.",
        "X-Frame-Options": "Set X-Frame-Options to DENY or SAMEORIGIN.",
        "X-Content-Type-Options": "Set X-Content-Type-Options to nosniff.",
        "Referrer-Policy": "Configure a restrictive Referrer-Policy.",
        "Permissions-Policy": "Disable browser capabilities not required by the application.",
        "X-XSS-Protection": "Set an explicit legacy XSS protection policy where applicable.",
    }
    SENSITIVE_PATHS = {
        "/.env": "HIGH",
        "/config.php": "HIGH",
        "/wp-config.php": "HIGH",
        "/.git/HEAD": "HIGH",
        "/backup.zip": "HIGH",
        "/admin": "MEDIUM",
        "/phpmyadmin": "HIGH",
        "/server-status": "MEDIUM",
        "/.htaccess": "HIGH",
        "/robots.txt": "INFO",
    }

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.session = create_session(
            f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Security-Scanner"
        )
        self.session.headers.update(
            {"User-Agent": f"Bug-Hunter-Pro/{config.APP_VERSION} Authorized-Security-Scanner"}
        )
        self.base_response = None
        self.forms = []

    def _request(self, method, url, **kwargs):
        kwargs.setdefault("timeout", config.SCAN_TIMEOUT)
        kwargs.setdefault("allow_redirects", True)
        kwargs.setdefault("verify", True)
        self.checked_urls.add(url)
        try:
            return self.session.request(method, url, **kwargs)
        except requests.exceptions.SSLError:
            kwargs["verify"] = False
            try:
                return self.session.request(method, url, **kwargs)
            except requests.RequestException as exc:
                LOGGER.warning("Request failed for %s: %s", url, exc)
        except requests.RequestException as exc:
            LOGGER.warning("Request failed for %s: %s", url, exc)
        return None

    def run(self):
        self.status = "running"
        checks = [
            self.check_security_headers,
            self.audit_tls,
            self.probe_xss,
            self.probe_sqli,
            self.detect_open_redirect,
            self.check_sensitive_paths,
            self.check_clickjacking,
            self.check_cors,
        ]
        self.base_response = self._request("GET", self.target)
        if self.base_response is not None:
            self._discover_forms(self.base_response)
        for index, check in enumerate(checks, start=1):
            if self.should_stop():
                self.status = "stopped"
                break
            try:
                check()
            except Exception as exc:
                LOGGER.exception("Web check %s failed: %s", check.__name__, exc)
            self.set_progress(index / len(checks) * 100, check.__name__)
        else:
            self.status = "completed"
        return self.get_findings()

    def _discover_forms(self, response):
        try:
            soup = BeautifulSoup(response.text, "html.parser")
            for form in soup.find_all("form"):
                action = urljoin(response.url, form.get("action") or response.url)
                method = (form.get("method") or "get").lower()
                inputs = [
                    element.get("name")
                    for element in form.find_all(["input", "textarea", "select"])
                    if element.get("name")
                ]
                if inputs:
                    self.forms.append({"url": action, "method": method, "inputs": inputs})
        except Exception as exc:
            LOGGER.warning("Unable to parse forms: %s", exc)

    def check_security_headers(self):
        response = self.base_response or self._request("GET", self.target)
        if response is None:
            return
        present = [name for name in self.SECURITY_HEADERS if name in response.headers]
        absent = [name for name in self.SECURITY_HEADERS if name not in response.headers]
        evidence = f"Present: {', '.join(present) or 'none'}\nAbsent: {', '.join(absent) or 'none'}"
        for name in absent:
            self.add_finding(
                f"Missing security header: {name}",
                "LOW",
                f"The response does not include the {name} security header.",
                evidence,
                self.SECURITY_HEADERS[name],
                3.1,
                "A05:2021 Security Misconfiguration",
                "",
                response.url,
            )

    def audit_tls(self):
        parsed = urlparse(self.target)
        if parsed.scheme != "https":
            self.add_finding(
                "HTTPS is not enforced",
                "HIGH",
                "The target is configured with an unencrypted HTTP URL.",
                f"Target scheme: {parsed.scheme or 'none'}",
                "Redirect all HTTP traffic to HTTPS and deploy a trusted certificate.",
                7.4,
                "A02:2021 Cryptographic Failures",
                "T1040 Network Sniffing",
            )
            return
        host, port = parsed.hostname, parsed.port or 443
        if not host:
            return
        try:
            context = ssl.create_default_context()
            with socket.create_connection((host, port), timeout=config.SCAN_TIMEOUT) as raw:
                with context.wrap_socket(raw, server_hostname=host) as secured:
                    certificate = secured.getpeercert()
                    cipher = secured.cipher()
                    tls_version = secured.version()
            expires = ssl.cert_time_to_seconds(certificate["notAfter"])
            days_left = int(
                (datetime.fromtimestamp(expires, timezone.utc) - datetime.now(timezone.utc)).days
            )
            if days_left < 30:
                severity = "HIGH" if days_left < 0 else "MEDIUM"
                self.add_finding(
                    "TLS certificate expires soon" if days_left >= 0 else "TLS certificate expired",
                    severity,
                    "The certificate lifetime is below the recommended renewal window.",
                    f"Certificate expires in {days_left} days ({certificate['notAfter']}).",
                    "Renew and deploy the certificate before expiration.",
                    7.5 if days_left < 0 else 5.3,
                    "A02:2021 Cryptographic Failures",
                    "",
                )
            if tls_version in {"TLSv1", "TLSv1.1"}:
                self.add_finding(
                    f"Deprecated TLS protocol enabled: {tls_version}",
                    "MEDIUM",
                    "The negotiated TLS protocol is obsolete.",
                    f"Negotiated protocol: {tls_version}; cipher: {cipher}",
                    "Disable TLS 1.0 and TLS 1.1; require TLS 1.2 or newer.",
                    6.5,
                    "A02:2021 Cryptographic Failures",
                    "",
                )
            cipher_name = (cipher or ("unknown",))[0].lower()
            if any(value in cipher_name for value in ("rc4", "des", "null", "md5")):
                self.add_finding(
                    "Weak TLS cipher negotiated",
                    "MEDIUM",
                    "The server negotiated a cipher with obsolete primitives.",
                    f"Cipher: {cipher}",
                    "Restrict the server to modern AEAD cipher suites.",
                    6.0,
                    "A02:2021 Cryptographic Failures",
                    "",
                )
        except ssl.SSLCertVerificationError as exc:
            self.add_finding(
                "Untrusted or self-signed TLS certificate",
                "HIGH",
                "The certificate chain could not be verified against trusted roots.",
                str(exc),
                "Install a certificate issued by a trusted authority with the full chain.",
                7.4,
                "A02:2021 Cryptographic Failures",
                "",
            )
        except (OSError, ssl.SSLError, KeyError, ValueError) as exc:
            LOGGER.warning("TLS audit failed for %s: %s", host, exc)

    def _test_form_payload(self, form, payload):
        data = {name: payload for name in form["inputs"]}
        if form["method"] == "post":
            return self._request("POST", form["url"], data=data)
        return self._request("GET", form["url"], params=data)

    def probe_xss(self):
        payloads = [
            "<script>alert(1)</script>",
            '"><img src=x onerror=alert(1)>',
            "javascript:alert(1)",
        ]
        for form in self.forms[:20]:
            for payload in payloads:
                if self.should_stop():
                    return
                response = self._test_form_payload(form, payload)
                if response is not None and payload in response.text:
                    self.add_finding(
                        "Reflected cross-site scripting",
                        "HIGH",
                        "User-controlled form input was reflected without output encoding.",
                        f"URL: {response.url}\nParameters: {', '.join(form['inputs'])}\nPayload: {payload}",
                        "Apply context-aware output encoding and validate untrusted input.",
                        8.2,
                        "A03:2021 Injection",
                        "T1059.007 JavaScript/JScript",
                        response.url,
                    )
                    break

    def _url_with_parameter(self, name, value):
        parsed = urlparse(self.target)
        query = dict(parse_qsl(parsed.query, keep_blank_values=True))
        query[name] = value
        return urlunparse(parsed._replace(query=urlencode(query)))

    def probe_sqli(self):
        parsed = urlparse(self.target)
        parameters = [name for name, _ in parse_qsl(parsed.query, keep_blank_values=True)]
        if not parameters:
            parameters = [item for form in self.forms[:10] for item in form["inputs"]]
        errors = (
            "SQL syntax",
            "mysql_fetch",
            "ORA-",
            "PostgreSQL",
            "SQLite3",
            "ODBC",
            "syntax error",
        )
        payloads = ("'", "OR 1=1--", "; DROP TABLE", "1 AND 1=2")
        for name in list(dict.fromkeys(parameters))[:20]:
            for payload in payloads:
                if self.should_stop():
                    return
                response = self._request("GET", self._url_with_parameter(name, payload))
                if response is None:
                    continue
                matched = next((value for value in errors if value.lower() in response.text.lower()), None)
                if matched:
                    severity = "CRITICAL" if "ORA-" in matched or "SQL syntax" in matched else "HIGH"
                    self.add_finding(
                        "Potential SQL injection",
                        severity,
                        "A database error was returned after injecting a test value.",
                        f"Parameter: {name}\nPayload: {payload}\nMatched error: {matched}",
                        "Use parameterized queries and avoid exposing database errors.",
                        9.1 if severity == "CRITICAL" else 8.6,
                        "A03:2021 Injection",
                        "T1190 Exploit Public-Facing Application",
                        response.url,
                    )
                    break

    def detect_open_redirect(self):
        parsed = urlparse(self.target)
        existing = dict(parse_qsl(parsed.query, keep_blank_values=True))
        names = [name for name in ("redirect", "url", "next", "return", "goto") if name in existing]
        for name in names:
            for payload in ("https://evil.com", "//evil.com", r"/\evil.com"):
                response = self._request(
                    "GET",
                    self._url_with_parameter(name, payload),
                    allow_redirects=False,
                )
                location = response.headers.get("Location", "") if response is not None else ""
                if "evil.com" in location.lower():
                    self.add_finding(
                        "Unvalidated open redirect",
                        "MEDIUM",
                        "A redirect parameter accepts an external destination.",
                        f"Parameter: {name}\nPayload: {payload}\nLocation: {location}",
                        "Allowlist local destinations and reject absolute external URLs.",
                        6.1,
                        "A01:2021 Broken Access Control",
                        "T1189 Drive-by Compromise",
                        response.url,
                    )
                    break

    def check_sensitive_paths(self):
        def check(path, severity):
            if self.should_stop():
                return
            url = urljoin(f"{self.target}/", path.lstrip("/"))
            response = self._request("GET", url, allow_redirects=False)
            if response is None or response.status_code != 200:
                return
            if path == "/robots.txt":
                sensitive = [
                    line.strip()
                    for line in response.text.splitlines()
                    if line.lower().startswith("disallow:")
                    and any(word in line.lower() for word in ("admin", "private", "backup", "config"))
                ]
                if sensitive:
                    self.add_finding(
                        "Sensitive paths disclosed by robots.txt",
                        "LOW",
                        "The robots file advertises potentially sensitive locations.",
                        "\n".join(sensitive[:20]),
                        "Avoid using robots.txt as an access-control mechanism.",
                        3.1,
                        "A05:2021 Security Misconfiguration",
                        "",
                        url,
                    )
                return
            self.add_finding(
                f"Sensitive resource exposed: {path}",
                severity,
                "A sensitive or administrative resource returned HTTP 200.",
                f"URL: {url}\nStatus: {response.status_code}\nContent-Type: {response.headers.get('Content-Type', '')}",
                "Remove public access, require authentication, and rotate any exposed secrets.",
                8.1 if severity == "HIGH" else 5.3,
                "A05:2021 Security Misconfiguration",
                "T1552 Unsecured Credentials",
                url,
            )

        with ThreadPoolExecutor(max_workers=min(config.MAX_THREADS, len(self.SENSITIVE_PATHS))) as pool:
            futures = [pool.submit(check, path, severity) for path, severity in self.SENSITIVE_PATHS.items()]
            for future in as_completed(futures):
                try:
                    future.result()
                except Exception as exc:
                    LOGGER.warning("Sensitive path check failed: %s", exc)

    def check_clickjacking(self):
        response = self.base_response or self._request("GET", self.target)
        if response is None:
            return
        csp = response.headers.get("Content-Security-Policy", "").lower()
        if "X-Frame-Options" not in response.headers and "frame-ancestors" not in csp:
            self.add_finding(
                "Clickjacking protection missing",
                "MEDIUM",
                "The page can potentially be embedded by an untrusted site.",
                f'<iframe src="{response.url}" width="1000" height="700"></iframe>',
                "Set CSP frame-ancestors and X-Frame-Options.",
                5.4,
                "A05:2021 Security Misconfiguration",
                "T1185 Browser Session Cookie",
                response.url,
            )

    def check_cors(self):
        response = self._request(
            "GET",
            self.target,
            headers={"Origin": "https://evil.com"},
        )
        if response is None:
            return
        origin = response.headers.get("Access-Control-Allow-Origin", "")
        credentials = response.headers.get("Access-Control-Allow-Credentials", "").lower() == "true"
        if origin == "https://evil.com" and credentials:
            severity, score = "CRITICAL", 9.1
        elif origin in {"*", "https://evil.com"}:
            severity, score = "MEDIUM", 6.5
        else:
            return
        self.add_finding(
            "CORS policy allows untrusted origins",
            severity,
            "The server permits cross-origin access from an untrusted origin.",
            f"Access-Control-Allow-Origin: {origin}\nAccess-Control-Allow-Credentials: {credentials}",
            "Allowlist trusted origins and never combine reflected origins with credentials.",
            score,
            "A05:2021 Security Misconfiguration",
            "T1189 Drive-by Compromise",
            response.url,
        )
