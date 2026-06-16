"""ProjectDiscovery Nuclei integration."""

from datetime import datetime, timezone
import json
import logging
import os
import shutil
import subprocess
import tempfile
import uuid

import config
from database import models


LOGGER = logging.getLogger(__name__)


class NucleiRunner:
    SEVERITY_SCORES = {
        "critical": 9.8,
        "high": 8.0,
        "medium": 5.5,
        "low": 3.0,
        "info": 0.0,
        "unknown": 0.0,
    }

    def __init__(self, scan_id=None):
        self.scan_id = scan_id or str(uuid.uuid4())

    def is_nuclei_installed(self):
        return bool(shutil.which(config.NUCLEI_PATH) or os.path.isfile(config.NUCLEI_PATH))

    @staticmethod
    def install_instructions():
        return {
            "mac_linux_go": (
                "go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest"
            ),
            "mac_linux_script": (
                "curl -sSfL https://raw.githubusercontent.com/projectdiscovery/"
                "nuclei/main/install.sh | sh"
            ),
            "windows": "Download a release from https://github.com/projectdiscovery/nuclei/releases",
        }

    def run_scan(self, target_url, severity=None, tags=None):
        if not self.is_nuclei_installed():
            return {
                "status": "unavailable",
                "findings": [],
                "instructions": self.install_instructions(),
            }
        if not models.get_scan_by_id(self.scan_id):
            models.insert_scan(
                {
                    "id": self.scan_id,
                    "target": target_url,
                    "scan_type": "nuclei",
                    "status": "running",
                    "started_at": datetime.now(timezone.utc).isoformat(),
                    "completed_at": None,
                    "total_findings": 0,
                    "critical_count": 0,
                    "high_count": 0,
                    "medium_count": 0,
                    "low_count": 0,
                    "info_count": 0,
                    "risk_score": 0,
                }
            )
        output_file = os.path.join(
            tempfile.gettempdir(),
            f"bughunter-nuclei-{self.scan_id}.jsonl",
        )
        command = [
            config.NUCLEI_PATH,
            "-u", target_url,
            "-jsonl",
            "-o", output_file,
            "-silent",
        ]
        if severity and str(severity).lower() != "all":
            command.extend(["-severity", str(severity).lower()])
        if tags:
            values = tags if isinstance(tags, str) else ",".join(tags)
            command.extend(["-tags", values])
        findings = []
        try:
            process = subprocess.Popen(
                command,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                encoding="utf-8",
            )
            stdout, stderr = process.communicate(timeout=1800)
            lines = stdout.splitlines()
            if os.path.isfile(output_file):
                with open(output_file, "r", encoding="utf-8") as handle:
                    lines.extend(handle.read().splitlines())
            unique = {}
            for line in lines:
                finding = self.parse_nuclei_output(line)
                if finding:
                    unique.setdefault(
                        (finding["title"], finding["url"]),
                        finding,
                    )
            findings = list(unique.values())
            for finding in findings:
                models.insert_finding(finding)
            counts = {
                "total_findings": len(findings),
                "critical_count": sum(item["severity"] == "CRITICAL" for item in findings),
                "high_count": sum(item["severity"] == "HIGH" for item in findings),
                "medium_count": sum(item["severity"] == "MEDIUM" for item in findings),
                "low_count": sum(item["severity"] == "LOW" for item in findings),
                "info_count": sum(item["severity"] == "INFO" for item in findings),
                "risk_score": min(
                    10.0,
                    round(
                        sum(
                            self.SEVERITY_SCORES.get(item["severity"].lower(), 0)
                            for item in findings
                        )
                        / max(len(findings), 1),
                        2,
                    ),
                ),
            }
            models.update_scan_status(self.scan_id, "completed", counts)
            return {
                "status": "completed" if process.returncode == 0 else "completed_with_warnings",
                "findings": findings,
                "stderr": stderr[-2000:],
            }
        except (OSError, subprocess.SubprocessError) as exc:
            LOGGER.warning("Nuclei execution failed: %s", exc)
            models.update_scan_status(self.scan_id, "failed", {})
            return {"status": "failed", "findings": [], "error": str(exc)}
        finally:
            try:
                os.remove(output_file)
            except OSError:
                pass

    def parse_nuclei_output(self, json_line):
        try:
            item = json.loads(json_line)
        except (TypeError, json.JSONDecodeError):
            return None
        info = item.get("info", {})
        severity = str(info.get("severity", "info")).lower()
        tags = info.get("tags", [])
        if isinstance(tags, str):
            tags = [tag.strip() for tag in tags.split(",")]
        references = info.get("reference", [])
        if isinstance(references, str):
            references = [references]
        template_id = item.get("template-id") or item.get("templateID") or "nuclei"
        title = info.get("name") or template_id
        evidence = {
            "template_id": template_id,
            "matcher": item.get("matcher-name", ""),
            "curl_command": item.get("curl-command", ""),
            "references": references,
        }
        return {
            "id": str(uuid.uuid4()),
            "scan_id": self.scan_id,
            "title": title,
            "severity": severity.upper() if severity != "unknown" else "INFO",
            "cvss_score": self.SEVERITY_SCORES.get(severity, 0.0),
            "description": info.get("description", "Nuclei template matched the target."),
            "evidence": json.dumps(evidence, indent=2),
            "remediation": info.get(
                "remediation",
                "Validate the template match and apply vendor or application remediation.",
            ),
            "owasp": self._map_owasp(tags),
            "mitre": "",
            "scanner": "nuclei",
            "url": item.get("matched-at") or item.get("host") or "",
            "timestamp": item.get("timestamp") or datetime.now(timezone.utc).isoformat(),
            "false_positive": False,
            "template_id": template_id,
        }

    @staticmethod
    def _map_owasp(tags):
        joined = " ".join(tags).lower()
        if any(tag in joined for tag in ("xss", "sqli", "injection")):
            return "A03:2021 Injection"
        if any(tag in joined for tag in ("auth", "idor", "access")):
            return "A01:2021 Broken Access Control"
        if any(tag in joined for tag in ("cve", "vulnerable")):
            return "A06:2021 Vulnerable and Outdated Components"
        return "A05:2021 Security Misconfiguration"

    def update_templates(self):
        if not self.is_nuclei_installed():
            return {"success": False, "instructions": self.install_instructions()}
        try:
            completed = subprocess.run(
                [config.NUCLEI_PATH, "-update-templates"],
                capture_output=True,
                text=True,
                timeout=600,
                check=False,
            )
            return {
                "success": completed.returncode == 0,
                "output": (completed.stdout + completed.stderr)[-4000:],
                "template_count": self.get_template_count(),
            }
        except (OSError, subprocess.SubprocessError) as exc:
            return {"success": False, "error": str(exc)}

    def get_template_count(self):
        if not self.is_nuclei_installed():
            return 0
        try:
            completed = subprocess.run(
                [config.NUCLEI_PATH, "-list", "-silent"],
                capture_output=True,
                text=True,
                timeout=120,
                check=False,
            )
            return len([line for line in completed.stdout.splitlines() if line.strip()])
        except (OSError, subprocess.SubprocessError):
            return 0
