"""Flask routes for dashboard data, scan control, and report export."""

from datetime import datetime, timezone
from concurrent.futures import ThreadPoolExecutor, as_completed
import csv
import io
import json
import os
import re
import threading
import uuid

from flask import Blueprint, Response, jsonify, render_template, request, send_file

import config
from core import scheduler
from core.aggregator import aggregate_findings
from core.alerts import send_email_alert, send_slack_alert
from database import models
from access import IDORTester
from exploit import (
    AdvancedSQLiScanner,
    BlindXSSScanner,
    OAuthTester,
    SSRFDetector,
    SSTIScanner,
)
from intelligence import (
    DuplicateChecker,
    NucleiRunner,
    OutOfScopeError,
    ScopeManager,
)
from oob import callback_server
from recon import (
    GoogleDorker,
    JSAnalyser,
    SubdomainEnumerator,
    TechFingerprinter,
    WaybackCrawler,
)
from report.html_generator import generate_html_report, report_filename
from report.pdf_generator import generate_pdf_report


bp = Blueprint("bug_hunter", __name__, template_folder="../dashboard/templates")
RECON_JOBS = {}
EXPLOIT_JOBS = {}
JOB_LOCK = threading.RLock()


def _error(message, status=400):
    return jsonify({"error": message}), status


def _scan_type_list(scan_types):
    values = []
    if isinstance(scan_types, str):
        values.extend(re.split(r"[,+\s]+", scan_types))
    else:
        for item in scan_types or []:
            values.extend(re.split(r"[,+\s]+", str(item)))
    cleaned = [str(item).strip().lower() for item in values if str(item).strip()]
    return list(dict.fromkeys(cleaned))


def _scan_type_names(scan_types):
    return set(_scan_type_list(scan_types))


def _as_bool(value):
    if isinstance(value, bool):
        return value
    if value is None:
        return False
    if isinstance(value, (int, float)):
        return bool(value)
    text = str(value).strip().lower()
    if text in {"1", "true", "yes", "y", "on"}:
        return True
    if text in {"0", "false", "no", "n", "off", ""}:
        return False
    return bool(value)


def _valid_recon_modules(scan_types):
    names = _scan_type_list(scan_types)
    allowed = {"subdomain", "js", "fingerprint", "wayback", "dork"}
    selected = [name for name in names if name in allowed]
    invalid = set(names) - allowed
    return selected, invalid


def _valid_exploit_modules(scan_types):
    names = _scan_type_list(scan_types)
    allowed = {"blind_xss", "sqli", "ssrf", "ssti", "oauth", "idor"}
    selected = [name for name in names if name in allowed]
    invalid = set(names) - allowed
    return selected, invalid


def _validate_bug_bounty_target(target, program_name, scan_types=None):
    if not config.BUG_BOUNTY_MODE:
        return
    config.validate_bug_bounty_settings()
    if not str(program_name or "").strip():
        raise ValueError("A saved scope program is required in bug bounty mode")
    ScopeManager(program_name).validate_before_scan(target)
    names = _scan_type_names(scan_types)
    if "all" in names or "network" in names:
        raise ValueError(
            "Network and all-module scans are disabled in bug bounty mode; "
            "select web and/or API only"
        )


@bp.get("/")
def dashboard():
    return render_template("index.html", app_version=config.APP_VERSION)


@bp.get("/api/health")
def health():
    return jsonify({"status": "ok", "version": config.APP_VERSION})


@bp.post("/api/scan/start")
def scan_start():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip()
    if not target:
        return _error("Target is required")
    if data.get("consent") is not True:
        return _error("Explicit authorization confirmation is required")
    try:
        _validate_bug_bounty_target(
            target,
            data.get("program_name"),
            data.get("scan_type", "all"),
        )
        scan_id = scheduler.start_scan(
            target,
            data.get("scan_type", "all"),
            data.get("mode", "manual"),
            notify=_as_bool(data.get("alerts", False)),
        )
    except OutOfScopeError as exc:
        return _error(str(exc), 403)
    except ValueError as exc:
        return _error(str(exc))
    return jsonify({"scan_id": scan_id, "status": "started"}), 202


@bp.get("/api/scan/status/<scan_id>")
def scan_status(scan_id):
    status = scheduler.get_scan_status(scan_id)
    return jsonify(status) if status else _error("Scan not found", 404)


@bp.route("/api/scan/stop/<scan_id>", methods=["GET", "POST"])
def scan_stop(scan_id):
    if not scheduler.stop_scan(scan_id):
        return _error("Running scan not found", 404)
    return jsonify({"status": "stopped"})


@bp.get("/api/findings")
def findings():
    limit = min(max(request.args.get("limit", default=100, type=int), 1), 5000)
    items = models.get_all_findings(
        severity=request.args.get("severity") or None,
        scanner=request.args.get("scanner") or None,
        scan_id=request.args.get("scan_id") or None,
        limit=limit,
    )
    include_false = request.args.get("include_false", "true").lower() == "true"
    if not include_false:
        items = [item for item in items if not item["false_positive"]]
    return jsonify(items)


@bp.get("/api/findings/<finding_id>")
def finding_detail(finding_id):
    finding = models.get_finding_by_id(finding_id)
    return jsonify(finding) if finding else _error("Finding not found", 404)


@bp.post("/api/findings/<finding_id>/false-positive")
def finding_false_positive(finding_id):
    if not models.get_finding_by_id(finding_id):
        return _error("Finding not found", 404)
    return jsonify({"status": "updated", "finding": models.mark_false_positive(finding_id)})


@bp.get("/api/scans")
def scans():
    limit = min(max(request.args.get("limit", default=50, type=int), 1), 500)
    return jsonify(models.get_all_scans(limit=limit))


@bp.get("/api/scans/compare")
def compare_scans():
    first = request.args.get("first")
    second = request.args.get("second")
    if not first or not second:
        return _error("Both first and second scan IDs are required")
    old_items = models.get_findings_for_diff(first)
    new_items = models.get_findings_for_diff(second)
    old_map = {(item["title"].lower(), item["url"]): item for item in old_items}
    new_map = {(item["title"].lower(), item["url"]): item for item in new_items}
    return jsonify(
        {
            "new": [new_map[key] for key in new_map.keys() - old_map.keys()],
            "fixed": [old_map[key] for key in old_map.keys() - new_map.keys()],
            "unchanged": [new_map[key] for key in new_map.keys() & old_map.keys()],
        }
    )


@bp.get("/api/stats")
def stats():
    return jsonify(models.get_stats())


@bp.get("/api/targets")
def targets():
    return jsonify(models.get_targets())


@bp.post("/api/targets")
def add_target():
    data = request.get_json(silent=True) or {}
    url = str(data.get("url", "")).strip()
    if not url:
        return _error("Target URL is required")
    monitor_enabled = _as_bool(data.get("monitor_enabled", True))
    alerts_enabled = _as_bool(data.get("alerts", True))
    if config.BUG_BOUNTY_MODE and monitor_enabled:
        return _error("Recurring monitoring is disabled in bug bounty mode")
    try:
        scheduler.parse_interval(data.get("interval", "24h"))
    except ValueError as exc:
        return _error(str(exc))
    target = models.upsert_target(
        url,
        monitor_enabled,
        data.get("interval", "24h"),
        alerts_enabled,
    )
    scheduler.refresh_schedules()
    return jsonify(models.get_target(target["id"])), 201


@bp.delete("/api/targets/<target_id>")
def remove_target(target_id):
    if not models.delete_target(target_id):
        return _error("Target not found", 404)
    scheduler.refresh_schedules()
    return jsonify({"status": "removed"})


@bp.post("/api/targets/<target_id>/scan")
def scan_target_now(target_id):
    target = models.get_target(target_id)
    if not target:
        return _error("Target not found", 404)
    if config.BUG_BOUNTY_MODE:
        return _error(
            "Monitored-target scans are disabled in bug bounty mode; "
            "start a scoped web/API scan manually"
        )
    scan_id = scheduler.start_scan(
        target["url"],
        "all",
        "monitor",
        notify=bool(target.get("alerts_enabled", 1)),
    )
    return jsonify({"scan_id": scan_id, "status": "started"}), 202


@bp.get("/api/report/<scan_id>/pdf")
def report_pdf(scan_id):
    scan = models.get_scan_by_id(scan_id)
    if not scan:
        return _error("Scan not found", 404)
    findings_list = models.get_findings_by_scan(scan_id)
    os.makedirs(config.REPORT_OUTPUT_DIR, exist_ok=True)
    path = os.path.join(config.REPORT_OUTPUT_DIR, report_filename(scan, "pdf"))
    generate_pdf_report(scan, findings_list, path, _report_configuration(scan))
    return send_file(path, as_attachment=True, download_name=os.path.basename(path))


@bp.get("/api/report/<scan_id>/html")
def report_html(scan_id):
    scan = models.get_scan_by_id(scan_id)
    if not scan:
        return _error("Scan not found", 404)
    html = generate_html_report(
        scan,
        models.get_findings_by_scan(scan_id),
        configuration=_report_configuration(scan),
    )
    return Response(
        html,
        mimetype="text/html",
        headers={
            "Content-Disposition": f'attachment; filename="{report_filename(scan, "html")}"'
        },
    )


@bp.get("/api/report/<scan_id>/findings.csv")
def report_csv(scan_id):
    scan = models.get_scan_by_id(scan_id)
    if not scan:
        return _error("Scan not found", 404)
    output = io.StringIO()
    fields = [
        "severity",
        "title",
        "scanner",
        "url",
        "cvss_score",
        "owasp",
        "mitre",
        "description",
        "evidence",
        "remediation",
    ]
    writer = csv.DictWriter(output, fieldnames=fields, extrasaction="ignore")
    writer.writeheader()
    writer.writerows(models.get_findings_by_scan(scan_id))
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": f'attachment; filename="findings_{scan_id[:8]}.csv"'},
    )


@bp.get("/api/monitor/status")
def monitor_status():
    return jsonify(scheduler.monitor_status())


@bp.get("/api/alerts")
def alert_history():
    return jsonify(models.get_alerts(limit=100))


@bp.route("/api/settings", methods=["GET", "POST"])
def settings():
    fields = (
        "NVD_API_KEY",
        "VIRUSTOTAL_API_KEY",
        "ALERT_EMAIL",
        "SMTP_HOST",
        "SMTP_PORT",
        "SMTP_USER",
        "SMTP_PASS",
        "SLACK_WEBHOOK_URL",
        "SCAN_TIMEOUT",
        "MAX_THREADS",
        "BUG_BOUNTY_MODE",
        "BUG_BOUNTY_PROGRAM",
        "HACKERONE_HANDLE",
        "RESEARCHER_USER_AGENT",
        "RESEARCHER_HEADER_NAME",
        "RESEARCHER_HEADER_VALUE",
        "REQUESTS_PER_SECOND",
    )
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        previous = {field: getattr(config, field) for field in fields}
        try:
            for field in fields:
                if field not in data:
                    continue
                value = data[field]
                if field in {"SMTP_PORT", "SCAN_TIMEOUT", "MAX_THREADS"}:
                    value = int(value)
                elif field == "REQUESTS_PER_SECOND":
                    value = float(value)
                elif field == "BUG_BOUNTY_MODE":
                    value = _as_bool(value)
                setattr(config, field, value)
            config.validate_bug_bounty_settings()
        except (TypeError, ValueError) as exc:
            for field, value in previous.items():
                setattr(config, field, value)
            return _error(str(exc))
        return jsonify({"status": "saved"})
    masked = {}
    for field in fields:
        value = getattr(config, field)
        masked[field] = "********" if value and ("KEY" in field or "PASS" in field or "WEBHOOK" in field) else value
    return jsonify(masked)


@bp.post("/api/alerts/test/<alert_type>")
def test_alert(alert_type):
    sample = [
        {
            "severity": "HIGH",
            "title": "Bug Hunter Pro test alert",
            "url": "configuration test",
        }
    ]
    if alert_type == "email":
        sent = send_email_alert(sample, "configuration test")
    elif alert_type == "slack":
        sent = send_slack_alert(sample, "configuration test")
    else:
        return _error("Unknown alert type")
    return jsonify({"status": "sent" if sent else "failed"}), 200 if sent else 503


def _report_configuration(scan):
    return {
        "scan_type": scan.get("scan_type", "all"),
        "request_timeout_seconds": config.SCAN_TIMEOUT,
        "maximum_threads": config.MAX_THREADS,
        "generated_at": datetime.now(timezone.utc).isoformat(),
        "tool_version": config.APP_VERSION,
    }


def _new_scan_record(scan_id, target, scan_type):
    models.insert_scan(
        {
            "id": scan_id,
            "target": target,
            "scan_type": scan_type,
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


def _run_recon_job(recon_id, target, scan_types):
    modules = {
        "subdomain": lambda: SubdomainEnumerator(recon_id).enumerate(target),
        "js": lambda: JSAnalyser(recon_id).analyse(target),
        "fingerprint": lambda: TechFingerprinter(recon_id).fingerprint(target),
        "wayback": lambda: WaybackCrawler().crawl(target),
        "dork": lambda: GoogleDorker().generate_dorks(target),
    }
    selected = [name for name in scan_types if name in modules]
    with JOB_LOCK:
        RECON_JOBS[recon_id]["status"] = "running"
        RECON_JOBS[recon_id]["progress_percent"] = 0
    completed = 0
    with ThreadPoolExecutor(max_workers=max(1, min(len(selected), 5))) as pool:
        futures = {pool.submit(modules[name]): name for name in selected}
        for future in as_completed(futures):
            name = futures[future]
            try:
                result = future.result()
                error = ""
            except Exception as exc:
                result = [] if name in {"subdomain", "js"} else {}
                error = str(exc)
            with JOB_LOCK:
                RECON_JOBS[recon_id]["results"][name] = result
                if error:
                    RECON_JOBS[recon_id]["errors"][name] = error
                completed += 1
                RECON_JOBS[recon_id]["progress_percent"] = round(
                    completed / max(len(selected), 1) * 100
                )
    with JOB_LOCK:
        RECON_JOBS[recon_id]["status"] = "completed"


@bp.post("/api/recon/start")
def recon_start():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip()
    if not target:
        return _error("Target is required")
    if data.get("consent") is not True:
        return _error("Explicit authorization confirmation is required")
    scan_types = data.get(
        "scan_types",
        ["subdomain", "js", "fingerprint", "wayback", "dork"],
    )
    selected, invalid = _valid_recon_modules(scan_types)
    if invalid:
        return _error(f"Unknown recon module(s): {', '.join(sorted(invalid))}")
    if not selected:
        return _error("Select at least one recon module")
    try:
        _validate_bug_bounty_target(
            target,
            data.get("program_name"),
            selected,
        )
    except OutOfScopeError as exc:
        return _error(str(exc), 403)
    except ValueError as exc:
        return _error(str(exc))
    if config.BUG_BOUNTY_MODE and "subdomain" in selected:
        return _error("Subdomain enumeration is disabled in bug bounty mode")
    recon_id = str(uuid.uuid4())
    with JOB_LOCK:
        RECON_JOBS[recon_id] = {
            "recon_id": recon_id,
            "target": target,
            "status": "queued",
            "progress_percent": 0,
            "results": {},
            "errors": {},
        }
    thread = threading.Thread(
        target=_run_recon_job,
        args=(recon_id, target, selected),
        name=f"recon-{recon_id[:8]}",
        daemon=True,
    )
    thread.start()
    return jsonify({"recon_id": recon_id, "status": "started"}), 202


@bp.get("/api/recon/results/<scan_id>")
def recon_results(scan_id):
    with JOB_LOCK:
        job = RECON_JOBS.get(scan_id)
        if job:
            payload = json.loads(json.dumps(job, default=str))
            payload["subdomains"] = payload["results"].get("subdomain", [])
            payload["js_findings"] = payload["results"].get("js", [])
            payload["tech_stack"] = payload["results"].get("fingerprint", {})
            payload["wayback_urls"] = payload["results"].get("wayback", {})
            payload["dorks"] = payload["results"].get("dork", {})
            return jsonify(payload)
    fingerprint = models.get_tech_fingerprint(scan_id)
    if fingerprint and fingerprint.get("interesting_paths"):
        try:
            fingerprint["interesting_paths"] = json.loads(fingerprint["interesting_paths"])
        except (TypeError, json.JSONDecodeError):
            fingerprint["interesting_paths"] = []
    return jsonify(
        {
            "recon_id": scan_id,
            "status": "completed",
            "progress_percent": 100,
            "subdomains": models.get_subdomains_by_scan(scan_id),
            "js_findings": models.get_js_findings_by_scan(scan_id),
            "tech_stack": fingerprint or {},
            "wayback_urls": {},
            "dorks": {},
        }
    )


def _extract_exploit_findings(result):
    if isinstance(result, dict):
        return result.get("findings", [])
    if isinstance(result, list) and result and isinstance(result[0], dict):
        return result if "severity" in result[0] and "title" in result[0] else []
    return []


def _run_exploit_job(exploit_id, target, scan_types, callback_url, headers):
    module_factories = {
        "blind_xss": lambda: BlindXSSScanner().scan(
            target, callback_url, authorized=True
        ),
        "sqli": lambda: AdvancedSQLiScanner(target, scan_id=exploit_id).scan(
            authorized=True
        ),
        "ssrf": lambda: SSRFDetector(target, scan_id=exploit_id).scan(
            callback_url=callback_url, authorized=True
        ),
        "ssti": lambda: SSTIScanner(target, scan_id=exploit_id).scan(
            authorized=True
        ),
        "oauth": lambda: OAuthTester(target, scan_id=exploit_id).scan(
            authorized=True
        ),
        "idor": lambda: IDORTester(target, scan_id=exploit_id).scan(
            headers=headers, authorized=True
        ),
    }
    selected = [name for name in scan_types if name in module_factories]
    all_findings = []
    for index, name in enumerate(selected, start=1):
        try:
            result = module_factories[name]()
            error = ""
        except Exception as exc:
            result = {"error": str(exc), "findings": []}
            error = str(exc)
        findings_list = _extract_exploit_findings(result)
        all_findings.extend(findings_list)
        with JOB_LOCK:
            EXPLOIT_JOBS[exploit_id]["results"][name] = result
            if error:
                EXPLOIT_JOBS[exploit_id]["errors"][name] = error
            EXPLOIT_JOBS[exploit_id]["progress_percent"] = round(
                index / max(len(selected), 1) * 100
            )
    findings_list, stats = aggregate_findings(
        [all_findings],
        total_checks=max(len(selected), 1),
    )
    for finding in findings_list:
        models.insert_finding(finding)
    models.update_scan_status(exploit_id, "completed", stats)
    with JOB_LOCK:
        EXPLOIT_JOBS[exploit_id]["status"] = "completed"
        EXPLOIT_JOBS[exploit_id]["findings"] = findings_list


@bp.post("/api/exploit/start")
def exploit_start():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip()
    program_name = str(data.get("program_name", "")).strip()
    if not target:
        return _error("Target is required")
    if data.get("permission_confirmed") is not True:
        return _error("Permission confirmation is required")
    if not program_name:
        return _error("A saved scope program is required")
    try:
        config.validate_bug_bounty_settings()
    except ValueError as exc:
        return _error(str(exc))
    scope = ScopeManager(program_name)
    try:
        scope.validate_before_scan(target)
    except OutOfScopeError as exc:
        return _error(str(exc), 403)
    scan_types = data.get("scan_types", [])
    selected, invalid = _valid_exploit_modules(scan_types)
    if invalid:
        return _error(f"Unknown exploit module(s): {', '.join(sorted(invalid))}")
    if not selected:
        return _error("Select at least one exploit module")
    try:
        if not callback_server.is_running():
            callback_server.start(config.OOB_HTTP_PORT, config.OOB_DNS_PORT)
    except OSError as exc:
        return _error(f"Unable to start OOB callback server: {exc}", 503)
    callback_url = str(data.get("callback_url") or callback_server.get_callback_url())
    exploit_id = str(uuid.uuid4())
    _new_scan_record(exploit_id, target, f"exploit:{','.join(selected)}")
    with JOB_LOCK:
        EXPLOIT_JOBS[exploit_id] = {
            "exploit_id": exploit_id,
            "target": target,
            "status": "running",
            "progress_percent": 0,
            "results": {},
            "findings": [],
            "errors": {},
        }
    headers = data.get("headers") or {}
    thread = threading.Thread(
        target=_run_exploit_job,
        args=(exploit_id, target, selected, callback_url, headers),
        name=f"exploit-{exploit_id[:8]}",
        daemon=True,
    )
    thread.start()
    return jsonify(
        {
            "exploit_id": exploit_id,
            "status": "started",
            "callback_url": callback_url,
        }
    ), 202


@bp.get("/api/exploit/results/<exploit_id>")
def exploit_results(exploit_id):
    with JOB_LOCK:
        job = EXPLOIT_JOBS.get(exploit_id)
        if job:
            return jsonify(job)
    scan = models.get_scan_by_id(exploit_id)
    if not scan:
        return _error("Exploit job not found", 404)
    return jsonify(
        {
            "exploit_id": exploit_id,
            "status": scan["status"],
            "progress_percent": 100,
            "findings": models.get_findings_by_scan(exploit_id),
            "results": {},
            "errors": {},
        }
    )


@bp.get("/api/oob/callbacks")
def oob_callbacks():
    return jsonify(callback_server.get_callbacks(request.args.get("since")))


@bp.get("/api/oob/status")
def oob_status():
    return jsonify(
        {
            "running": callback_server.is_running(),
            "http_port": callback_server.http_port or config.OOB_HTTP_PORT,
            "dns_port": callback_server.dns_port or config.OOB_DNS_PORT,
            "callback_url": callback_server.get_callback_url(),
        }
    )


@bp.post("/api/intelligence/nuclei")
def intelligence_nuclei():
    data = request.get_json(silent=True) or {}
    target = str(data.get("target", "")).strip()
    program_name = str(data.get("program_name", "")).strip()
    if not target or not program_name:
        return _error("Target and saved scope program are required")
    if config.BUG_BOUNTY_MODE:
        return _error(
            "Nuclei is disabled in bug bounty mode because template volume "
            "cannot be bounded by the dashboard request limiter"
        )
    try:
        ScopeManager(program_name).validate_before_scan(target)
    except OutOfScopeError as exc:
        return _error(str(exc), 403)
    runner = NucleiRunner()
    return jsonify(
        {
            "scan_id": runner.scan_id,
            **runner.run_scan(target, data.get("severity"), data.get("tags")),
        }
    )


@bp.post("/api/intelligence/nuclei/update")
def intelligence_nuclei_update():
    return jsonify(NucleiRunner().update_templates())


@bp.get("/api/intelligence/nuclei/status")
def intelligence_nuclei_status():
    runner = NucleiRunner()
    return jsonify(
        {
            "installed": runner.is_nuclei_installed(),
            "template_count": runner.get_template_count(),
            "instructions": runner.install_instructions(),
        }
    )


@bp.get("/api/intelligence/scope/<program_name>")
def intelligence_get_scope(program_name):
    scope = models.get_scope(program_name)
    return jsonify(scope) if scope else _error("Scope not found", 404)


@bp.post("/api/intelligence/scope")
def intelligence_save_scope():
    data = request.get_json(silent=True) or {}
    program_name = str(data.get("program_name", "")).strip()
    if not program_name:
        return _error("Program name is required")
    try:
        manager = ScopeManager(program_name)
        scope = manager.add_manual_scope(
            data.get("in_scope", []),
            data.get("out_of_scope", []),
        )
    except ValueError as exc:
        return _error(str(exc))
    return jsonify(scope), 201


@bp.post("/api/intelligence/check-duplicate")
def intelligence_check_duplicate():
    data = request.get_json(silent=True) or {}
    finding = models.get_finding_by_id(data.get("finding_id"))
    if not finding:
        return _error("Finding not found", 404)
    return jsonify(DuplicateChecker().check_finding(finding))
