"""Bug bounty scope storage and target validation."""

from datetime import datetime, timezone
import fnmatch
import ipaddress
import json
import logging
import os
from urllib.parse import urlparse

import requests

import config
from database import models


LOGGER = logging.getLogger(__name__)


class OutOfScopeError(ValueError):
    """Raised when an active test is requested outside saved program scope."""


class ScopeManager:
    def __init__(self, program_name=None):
        self.program_name = program_name or ""
        self.scope = None

    def load_scope(self, program_name):
        self.program_name = str(program_name or "").strip()
        stored = models.get_scope(self.program_name)
        if stored:
            self.scope = stored
            return stored
        local_path = os.path.join(config.BASE_DIR, "scopes", f"{self.program_name}.json")
        if os.path.isfile(local_path):
            try:
                with open(local_path, "r", encoding="utf-8") as handle:
                    data = json.load(handle)
                return self.add_manual_scope(
                    data.get("in_scope", []),
                    data.get("out_of_scope", []),
                )
            except (OSError, ValueError) as exc:
                LOGGER.warning("Unable to load local scope: %s", exc)
        if config.H1_API_USERNAME and config.H1_API_TOKEN and self.program_name:
            try:
                response = requests.get(
                    f"https://api.hackerone.com/v1/hackers/programs/{self.program_name}",
                    auth=(config.H1_API_USERNAME, config.H1_API_TOKEN),
                    timeout=config.SCAN_TIMEOUT,
                )
                response.raise_for_status()
                attributes = response.json().get("data", {}).get("attributes", {})
                scopes = attributes.get("structured_scopes", [])
                in_scope = [
                    item.get("asset_identifier")
                    for item in scopes
                    if item.get("eligible_for_submission") and item.get("asset_identifier")
                ]
                if in_scope:
                    return self.add_manual_scope(in_scope, [])
            except (requests.RequestException, ValueError) as exc:
                LOGGER.warning("HackerOne scope lookup failed: %s", exc)
        return None

    def add_manual_scope(self, in_scope, out_of_scope):
        if not self.program_name:
            raise ValueError("Program name is required")
        clean_in = self._clean_entries(in_scope)
        clean_out = self._clean_entries(out_of_scope)
        if not clean_in:
            raise ValueError("At least one in-scope target is required")
        self.scope = models.upsert_scope(self.program_name, clean_in, clean_out)
        return self.scope

    @staticmethod
    def _clean_entries(entries):
        if isinstance(entries, str):
            entries = entries.splitlines()
        return list(
            dict.fromkeys(
                str(item).strip()
                for item in entries or []
                if str(item).strip()
            )
        )

    @staticmethod
    def _target_host(target):
        value = str(target or "").strip()
        parsed = urlparse(value if "://" in value else f"//{value}")
        return (parsed.hostname or value.split("/")[0].split(":")[0]).lower().rstrip(".")

    @classmethod
    def _matches(cls, target, rule):
        target_host = cls._target_host(target)
        rule_value = str(rule).strip().lower()
        if not rule_value:
            return False
        rule_host = cls._target_host(rule_value)
        try:
            network = ipaddress.ip_network(rule_value, strict=False)
            return ipaddress.ip_address(target_host) in network
        except ValueError:
            pass
        if rule_value.startswith("*."):
            root = rule_value[2:].rstrip(".")
            return target_host.endswith(f".{root}") and target_host != root
        if "*" in rule_value:
            return fnmatch.fnmatch(target_host, rule_host)
        return target_host == rule_host

    def is_in_scope(self, target):
        if not self.scope and self.program_name:
            self.scope = self.load_scope(self.program_name)
        if not self.scope:
            return False
        if any(self._matches(target, rule) for rule in self.scope["out_of_scope"]):
            return False
        return any(self._matches(target, rule) for rule in self.scope["in_scope"])

    def validate_before_scan(self, target):
        allowed = self.is_in_scope(target)
        LOGGER.info(
            "Scope validation program=%s target=%s allowed=%s timestamp=%s",
            self.program_name,
            target,
            allowed,
            datetime.now(timezone.utc).isoformat(),
        )
        if not allowed:
            raise OutOfScopeError(
                f"Target {target!r} is not in the saved scope for program "
                f"{self.program_name!r}"
            )
        return True
