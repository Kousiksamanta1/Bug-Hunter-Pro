"""Parallel scan execution and recurring monitoring scheduler."""

from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timedelta, timezone
import logging
import re
import threading
import time
import uuid

import schedule

import config
from core.aggregator import aggregate_findings
from core.alerts import filter_new_findings, send_email_alert, send_slack_alert
from database import models
from scanners import APIScanner, NetworkScanner, WebScanner


LOGGER = logging.getLogger(__name__)
ACTIVE_SCANS = {}
ACTIVE_SCANS_LOCK = threading.RLock()
SCHEDULER_STOP = threading.Event()
SCHEDULE_LOCK = threading.RLock()
SCANNER_CLASSES = {
    "web": WebScanner,
    "network": NetworkScanner,
    "api": APIScanner,
}


def parse_interval(interval_str):
    match = re.fullmatch(r"\s*(\d+)\s*([mhd])\s*", str(interval_str).lower())
    if not match:
        raise ValueError("Interval must use minutes, hours, or days, such as 30m, 24h, or 7d")
    amount, unit = int(match.group(1)), match.group(2)
    if amount <= 0:
        raise ValueError("Interval must be greater than zero")
    return amount * {"m": 60, "h": 3600, "d": 86400}[unit]


def _scanner_names(scan_type):
    if isinstance(scan_type, (list, tuple, set)):
        values = []
        for item in scan_type:
            values.extend(re.split(r"[,+\s]+", str(item).lower()))
        names = [item for item in values if item]
    else:
        value = str(scan_type or "all").lower()
        names = list(SCANNER_CLASSES) if value == "all" else re.split(r"[,+\s]+", value)
    names = [name for name in names if name in SCANNER_CLASSES]
    if not names:
        raise ValueError("Scan type must include web, network, api, or all")
    return list(dict.fromkeys(names))


def _initial_state(scan_id, target, names):
    return {
        "scan_id": scan_id,
        "target": target,
        "status": "running",
        "progress_percent": 0,
        "current_scanner": "initializing",
        "findings_so_far": [],
        "scanner_status": {
            name: {"status": "pending", "progress": 0, "findings": 0} for name in names
        },
        "stop_event": threading.Event(),
        "thread": None,
        "error": "",
    }


def _progress_callback(scan_id, scanner_name, event):
    with ACTIVE_SCANS_LOCK:
        state = ACTIVE_SCANS.get(scan_id)
        if not state:
            return
        row = state["scanner_status"].setdefault(
            scanner_name, {"status": "running", "progress": 0, "findings": 0}
        )
        row["status"] = "running"
        state["current_scanner"] = scanner_name
        if "id" in event:
            row["findings"] += 1
            state["findings_so_far"].append(event)
        if "progress" in event:
            row["progress"] = event["progress"]
        progresses = [item["progress"] for item in state["scanner_status"].values()]
        state["progress_percent"] = round(sum(progresses) / max(len(progresses), 1))


def _previous_findings(target, current_scan_id):
    scans = [
        scan
        for scan in models.get_all_scans(limit=100)
        if scan["target"] == target
        and scan["id"] != current_scan_id
        and scan["status"] == "completed"
    ]
    return models.get_findings_for_diff(scans[0]["id"]) if scans else []


def _run_scan(scan_id, target, scan_type, notify=False):
    names = _scanner_names(scan_type)
    with ACTIVE_SCANS_LOCK:
        state = ACTIVE_SCANS[scan_id]
        stop_event = state["stop_event"]
    scanners = [
        SCANNER_CLASSES[name](
            target,
            scan_id=scan_id,
            stop_event=stop_event,
            progress_callback=lambda scanner, event, sid=scan_id: _progress_callback(
                sid, scanner, event
            ),
        )
        for name in names
    ]
    try:
        with ThreadPoolExecutor(max_workers=len(scanners), thread_name_prefix="bughunter") as pool:
            futures = {pool.submit(scanner.run): scanner for scanner in scanners}
            for future in as_completed(futures):
                scanner = futures[future]
                try:
                    future.result()
                    scanner_status = scanner.get_status()
                except Exception as exc:
                    LOGGER.exception("%s scanner failed: %s", scanner.scanner_name, exc)
                    scanner_status = "failed"
                with ACTIVE_SCANS_LOCK:
                    state["scanner_status"][scanner.scanner_name]["status"] = scanner_status
                    state["scanner_status"][scanner.scanner_name]["progress"] = 100
        findings, stats = aggregate_findings(
            scanners,
            total_checks=sum(getattr(scanner, "total_checks", 0) for scanner in scanners),
        )
        for finding in findings:
            models.insert_finding(finding)
        final_status = "stopped" if stop_event.is_set() else "completed"
        models.update_scan_status(scan_id, final_status, stats)
        models.update_target_scan(target)
        with ACTIVE_SCANS_LOCK:
            state["status"] = final_status
            state["progress_percent"] = 100
            state["current_scanner"] = ""
            state["findings_so_far"] = findings
        if notify and final_status == "completed":
            new_findings = filter_new_findings(findings, _previous_findings(target, scan_id))
            email_sent = send_email_alert(new_findings, target)
            slack_sent = send_slack_alert(new_findings, target)
            for finding in new_findings:
                if email_sent:
                    models.insert_alert(scan_id, finding["id"], "email", "sent")
                if slack_sent:
                    models.insert_alert(scan_id, finding["id"], "slack", "sent")
    except Exception as exc:
        LOGGER.exception("Scan %s failed: %s", scan_id, exc)
        models.update_scan_status(scan_id, "failed", {})
        with ACTIVE_SCANS_LOCK:
            state["status"] = "failed"
            state["error"] = str(exc)
            state["current_scanner"] = ""


def start_scan(target, scan_type="all", mode="manual", notify=False):
    if not str(target or "").strip():
        raise ValueError("A target URL, IP address, or domain is required")
    scan_id = str(uuid.uuid4())
    names = _scanner_names(scan_type)
    if config.BUG_BOUNTY_MODE and "network" in names:
        raise ValueError(
            "Network scanning is disabled in bug bounty mode; select web and/or API"
        )
    state = _initial_state(scan_id, target, names)
    models.insert_scan(
        {
            "id": scan_id,
            "target": target,
            "scan_type": ",".join(names) if len(names) != 3 else "all",
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
    with ACTIVE_SCANS_LOCK:
        ACTIVE_SCANS[scan_id] = state
    thread = threading.Thread(
        target=_run_scan,
        args=(scan_id, target, scan_type, notify),
        name=f"scan-{scan_id[:8]}",
        daemon=True,
    )
    state["thread"] = thread
    thread.start()
    return scan_id


def get_scan_status(scan_id):
    with ACTIVE_SCANS_LOCK:
        state = ACTIVE_SCANS.get(scan_id)
        if state:
            return {
                key: value
                for key, value in state.items()
                if key not in {"stop_event", "thread"}
            }
    scan = models.get_scan_by_id(scan_id)
    if not scan:
        return None
    return {
        "scan_id": scan_id,
        "target": scan["target"],
        "status": scan["status"],
        "progress_percent": 100 if scan["status"] != "running" else 0,
        "current_scanner": "",
        "findings_so_far": models.get_findings_by_scan(scan_id),
        "scanner_status": {},
        "error": "",
    }


def stop_scan(scan_id):
    with ACTIVE_SCANS_LOCK:
        state = ACTIVE_SCANS.get(scan_id)
        if not state:
            return False
        state["stop_event"].set()
        state["status"] = "stopping"
    return True


def wait_for_scan(scan_id, poll_interval=0.25):
    while True:
        state = get_scan_status(scan_id)
        if not state or state["status"] in {"completed", "failed", "stopped"}:
            return state
        time.sleep(poll_interval)


def _scheduled_target_run(target):
    seconds = parse_interval(target["monitor_interval"])
    models.update_target_schedule(
        target["url"],
        (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(),
    )
    start_scan(
        target["url"],
        "all",
        mode="monitor",
        notify=bool(target.get("alerts_enabled", 1)),
    )


def refresh_schedules():
    with SCHEDULE_LOCK:
        schedule.clear("bug-hunter-monitor")
        if config.BUG_BOUNTY_MODE:
            return
        for target in models.get_targets():
            if not target["monitor_enabled"]:
                continue
            seconds = parse_interval(target["monitor_interval"])
            schedule.every(seconds).seconds.do(_scheduled_target_run, target).tag(
                "bug-hunter-monitor"
            )
            models.update_target_schedule(
                target["url"],
                (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat(),
            )


def monitor_status():
    statuses = []
    now = datetime.now(timezone.utc)
    scans = models.get_all_scans(limit=500)
    for target in models.get_targets():
        seconds = parse_interval(target["monitor_interval"])
        stored_next = target.get("next_run")
        if stored_next:
            try:
                next_run = datetime.fromisoformat(stored_next)
            except ValueError:
                next_run = now + timedelta(seconds=seconds)
        else:
            next_run = now + timedelta(seconds=seconds)
        statuses.append(
            {
                **target,
                "next_run": next_run.isoformat(),
                "last_run": target.get("last_run") or target.get("last_scanned"),
                "status": "enabled" if target["monitor_enabled"] else "disabled",
                "total_findings": sum(
                    int(scan.get("total_findings") or 0)
                    for scan in scans
                    if scan.get("target") == target["url"]
                ),
            }
        )
    return statuses


def run_scheduler():
    refresh_schedules()
    while not SCHEDULER_STOP.is_set():
        with SCHEDULE_LOCK:
            schedule.run_pending()
        SCHEDULER_STOP.wait(1)


def start_scheduler_thread():
    SCHEDULER_STOP.clear()
    thread = threading.Thread(
        target=run_scheduler,
        name="bug-hunter-scheduler",
        daemon=True,
    )
    thread.start()
    return thread


def shutdown(timeout=5):
    SCHEDULER_STOP.set()
    with ACTIVE_SCANS_LOCK:
        states = list(ACTIVE_SCANS.values())
        for state in states:
            state["stop_event"].set()
    deadline = time.monotonic() + timeout
    for state in states:
        thread = state.get("thread")
        if thread and thread.is_alive():
            thread.join(max(0, deadline - time.monotonic()))
