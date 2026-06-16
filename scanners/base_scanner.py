"""Common scanner contract and finding creation helpers."""

from abc import ABC, abstractmethod
from datetime import datetime, timezone
import threading
import uuid
from urllib.parse import urlparse


class BaseScanner(ABC):
    scanner_name = "base"
    total_checks = 0

    def __init__(self, target, scan_id=None, stop_event=None, progress_callback=None):
        self.target = self.normalize_target(target)
        self.findings = []
        self.scan_id = scan_id or str(uuid.uuid4())
        self.start_time = datetime.now(timezone.utc)
        self.status = "pending"
        self.stop_event = stop_event or threading.Event()
        self.progress_callback = progress_callback
        self.checked_urls = set()
        self._finding_lock = threading.Lock()

    @staticmethod
    def normalize_target(target):
        target = (target or "").strip()
        if not target:
            return ""
        parsed = urlparse(target)
        if not parsed.scheme:
            target = f"https://{target}"
        return target.rstrip("/")

    @property
    def hostname(self):
        return urlparse(self.target).hostname or self.target

    @abstractmethod
    def run(self):
        """Run scanner checks and return a list of findings."""

    def add_finding(
        self,
        title,
        severity,
        description,
        evidence,
        remediation,
        cvss_score,
        owasp="",
        mitre="",
        url=None,
    ):
        finding = {
            "id": str(uuid.uuid4()),
            "scan_id": self.scan_id,
            "title": str(title),
            "severity": str(severity).upper(),
            "cvss_score": float(cvss_score),
            "description": str(description),
            "evidence": str(evidence),
            "remediation": str(remediation),
            "owasp": str(owasp),
            "mitre": str(mitre),
            "scanner": self.scanner_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "url": url or self.target,
            "false_positive": False,
        }
        with self._finding_lock:
            self.findings.append(finding)
        if self.progress_callback:
            self.progress_callback(self.scanner_name, finding)
        return finding

    def get_findings(self):
        with self._finding_lock:
            return list(self.findings)

    def get_status(self):
        return self.status

    def should_stop(self):
        return self.stop_event.is_set()

    def set_progress(self, percent, message=""):
        if self.progress_callback:
            self.progress_callback(
                self.scanner_name,
                {"progress": max(0, min(100, int(percent))), "message": message},
            )
