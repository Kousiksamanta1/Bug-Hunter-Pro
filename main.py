# LEGAL DISCLAIMER: Use Bug Hunter Pro only on systems you own or have explicit written permission to test.
"""Bug Hunter Pro application entry point."""

import argparse
import logging
import os
import signal
import socket
import sys
import threading
import time
import webbrowser
import uuid

from flask import Flask
from flask_cors import CORS

import config
from api.routes import bp
from core import scheduler
from database.models import get_findings_by_scan, get_scan_by_id, init_db, upsert_target
from intelligence import NucleiRunner, OutOfScopeError, ScopeManager
from oob import callback_server
from recon import JSAnalyser, SubdomainEnumerator, TechFingerprinter, WaybackCrawler
from report.html_generator import generate_html_report, report_filename
from report.pdf_generator import generate_pdf_report


CYAN = "\033[96m"
RESET = "\033[0m"
BANNER = r"""
 ____  _   _  ____   _   _ _   _ _   _ _____ _____ ____    ____  ____   ___
| __ )| | | |/ ___| | | | | | | | \ | |_   _| ____|  _ \  |  _ \|  _ \ / _ \
|  _ \| | | | |  _  | |_| | | | |  \| | | | |  _| | |_) | | |_) | |_) | | | |
| |_) | |_| | |_| | |  _  | |_| | |\  | | | | |___|  _ <  |  __/|  _ <| |_| |
|____/ \___/ \____| |_| |_|\___/|_| \_| |_| |_____|_| \_\ |_|   |_| \_\\___/
"""


def create_app():
    init_db()
    app = Flask(
        __name__,
        static_folder=os.path.join(config.BASE_DIR, "dashboard", "static"),
        static_url_path="/static",
    )
    app.config["JSON_SORT_KEYS"] = False
    CORS(
        app,
        resources={
            r"/api/*": {
                "origins": [
                    f"http://127.0.0.1:{config.FLASK_PORT}",
                    f"http://localhost:{config.FLASK_PORT}",
                ]
            }
        },
    )
    app.register_blueprint(bp)
    return app


def parse_args(argv=None):
    parser = argparse.ArgumentParser(
        description="Bug Hunter Pro authorized vulnerability assessment platform"
    )
    parser.add_argument("--target", help="Target URL, IP address, or domain")
    parser.add_argument(
        "--mode",
        choices=("manual", "auto", "monitor"),
        default="manual",
    )
    parser.add_argument(
        "--output",
        choices=("dashboard", "pdf", "html", "all"),
        default="dashboard",
    )
    parser.add_argument(
        "--scan",
        choices=("web", "network", "api", "all"),
        default="all",
    )
    parser.add_argument("--schedule", default="24h", help="Monitor interval, such as 24h or 7d")
    parser.add_argument(
        "--port",
        type=int,
        default=config.FLASK_PORT,
        help=f"Dashboard port (default: {config.FLASK_PORT}; falls back if occupied)",
    )
    parser.add_argument(
        "--recon",
        action="store_true",
        help="Run reconnaissance modules before the main scan",
    )
    parser.add_argument(
        "--oob",
        action="store_true",
        help="Start the local HTTP/DNS callback receiver",
    )
    parser.add_argument(
        "--nuclei",
        action="store_true",
        help="Run Nuclei after the main scan",
    )
    parser.add_argument(
        "--scope",
        help="Saved scope program name used to authorize the target",
    )
    return parser.parse_args(argv)


def _port_is_available(host, port):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            sock.bind((host, port))
        return True
    except OSError:
        return False


def _select_dashboard_port(host, preferred_port, attempts=100):
    if not 1 <= preferred_port <= 65535:
        raise SystemExit("--port must be between 1 and 65535")
    for port in range(preferred_port, min(preferred_port + attempts, 65536)):
        if _port_is_available(host, port):
            return port
    raise SystemExit(
        f"No available dashboard port found between {preferred_port} "
        f"and {min(preferred_port + attempts - 1, 65535)}"
    )


def _open_dashboard():
    webbrowser.open(f"http://127.0.0.1:{config.FLASK_PORT}")


def _show_scan_progress(scan_id):
    previous = -1
    while True:
        status = scheduler.get_scan_status(scan_id)
        if not status:
            return None
        percent = status["progress_percent"]
        if percent != previous:
            print(
                f"\rScan {scan_id[:8]}: {percent:3d}% "
                f"{status.get('current_scanner', ''):10s} "
                f"findings={len(status.get('findings_so_far', []))}",
                end="",
                flush=True,
            )
            previous = percent
        if status["status"] in {"completed", "failed", "stopped"}:
            print(f"\nScan status: {status['status']}")
            return status
        time.sleep(0.4)


def _export_reports(scan_id, output):
    scan = get_scan_by_id(scan_id)
    findings = get_findings_by_scan(scan_id)
    if not scan:
        return []
    os.makedirs(config.REPORT_OUTPUT_DIR, exist_ok=True)
    generated = []
    report_config = {
        "scan_type": scan["scan_type"],
        "request_timeout_seconds": config.SCAN_TIMEOUT,
        "maximum_threads": config.MAX_THREADS,
        "tool_version": config.APP_VERSION,
    }
    if output in {"pdf", "all"}:
        path = os.path.join(config.REPORT_OUTPUT_DIR, report_filename(scan, "pdf"))
        generated.append(generate_pdf_report(scan, findings, path, report_config))
    if output in {"html", "all"}:
        path = os.path.join(config.REPORT_OUTPUT_DIR, report_filename(scan, "html"))
        generate_html_report(scan, findings, path, report_config)
        generated.append(path)
    for path in generated:
        print(f"Report generated: {path}")
    return generated


def _install_signal_handlers():
    def handle_shutdown(signum, frame):
        del signum, frame
        print("\nStopping Bug Hunter Pro...")
        scheduler.shutdown()
        callback_server.stop()
        raise KeyboardInterrupt

    signal.signal(signal.SIGINT, handle_shutdown)
    if hasattr(signal, "SIGTERM"):
        signal.signal(signal.SIGTERM, handle_shutdown)


def _run_cli_recon(target):
    recon_id = str(uuid.uuid4())
    domain = target.split("://")[-1].split("/")[0].split(":")[0]
    print(f"Recon {recon_id[:8]}: enumerating attack surface for {domain}")
    modules = (
        ("subdomains", lambda: SubdomainEnumerator(recon_id).enumerate(domain)),
        ("JavaScript", lambda: JSAnalyser(recon_id).analyse(target)),
        ("fingerprint", lambda: TechFingerprinter(recon_id).fingerprint(target)),
        ("Wayback", lambda: WaybackCrawler().crawl(domain)),
    )
    summary = {}
    for name, operation in modules:
        try:
            result = operation()
            summary[name] = len(result) if isinstance(result, list) else result
            print(f"Recon {name}: complete")
        except Exception as exc:
            summary[name] = {"error": str(exc)}
            logging.getLogger(__name__).warning("Recon %s failed: %s", name, exc)
    return summary


def _post_process_scan(scan_id, run_nuclei=False):
    status = scheduler.wait_for_scan(scan_id)
    if not status or status["status"] != "completed":
        return
    scan = get_scan_by_id(scan_id)
    if run_nuclei and scan:
        runner = NucleiRunner()
        result = runner.run_scan(scan["target"])
        print(f"Nuclei status: {result.get('status')}")


def main(argv=None):
    args = parse_args(argv)
    args.target = args.target or config.TARGET_URL or None
    selected_port = _select_dashboard_port(config.FLASK_HOST, args.port)
    config.apply_runtime_config(target=args.target, flask_port=selected_port)
    logging.basicConfig(
        level=os.getenv("LOG_LEVEL", "INFO"),
        format="%(asctime)s %(levelname)s %(name)s: %(message)s",
    )
    print(f"{CYAN}{BANNER}{RESET}")
    print("Authorized use only. Confirm permission before scanning any target.\n")
    if selected_port != args.port:
        print(f"Port {args.port} is in use; using port {selected_port} instead.")
    print(f"Dashboard: http://127.0.0.1:{selected_port}\n")
    app = create_app()
    _install_signal_handlers()
    if config.BUG_BOUNTY_MODE:
        try:
            config.validate_bug_bounty_settings()
        except ValueError as exc:
            raise SystemExit(str(exc)) from exc
        if args.recon:
            raise SystemExit(
                "CLI --recon is disabled in bug bounty mode; "
                "use scoped passive modules from the dashboard"
            )
        if args.nuclei:
            raise SystemExit("CLI --nuclei is disabled in bug bounty mode")
        if args.target and not args.scope:
            raise SystemExit("--scope is required with --target in bug bounty mode")
        if args.scan in {"network", "all"}:
            raise SystemExit(
                "--scan must be web or api in bug bounty mode"
            )
    if args.target and args.scope:
        try:
            ScopeManager(args.scope).validate_before_scan(args.target)
        except OutOfScopeError as exc:
            raise SystemExit(str(exc)) from exc
    if args.oob:
        try:
            callback_url = callback_server.start(
                config.OOB_HTTP_PORT,
                config.OOB_DNS_PORT,
            )
            print(f"OOB callback URL: {callback_url}")
            print(
                f"OOB DNS listener: {callback_server.get_dns_host()}:"
                f"{callback_server.dns_port}\n"
            )
        except OSError as exc:
            raise SystemExit(f"Unable to start OOB callback server: {exc}") from exc
    if args.recon:
        if not args.target:
            raise SystemExit("--target is required with --recon")
        _run_cli_recon(args.target)

    if args.mode == "auto":
        if not args.target:
            raise SystemExit("--target is required in auto mode")
        scan_id = scheduler.start_scan(args.target, args.scan, mode="auto")
        result = _show_scan_progress(scan_id)
        if result and result["status"] == "completed":
            _post_process_scan(scan_id, args.nuclei)
            output = "all" if args.output == "dashboard" else args.output
            _export_reports(scan_id, output)
        scheduler.shutdown()
        callback_server.stop()
        return 0 if result and result["status"] == "completed" else 1

    if args.mode == "monitor":
        if args.target:
            scheduler.parse_interval(args.schedule)
            upsert_target(args.target, True, args.schedule)
    elif args.target:
        scan_id = scheduler.start_scan(args.target, args.scan, mode="manual")
        if args.nuclei:
            post_thread = threading.Thread(
                target=_post_process_scan,
                args=(scan_id, args.nuclei),
                name=f"post-process-{scan_id[:8]}",
                daemon=True,
            )
            post_thread.start()

    scheduler.start_scheduler_thread()
    timer = threading.Timer(1.0, _open_dashboard)
    timer.daemon = True
    timer.start()
    try:
        app.run(
            host=config.FLASK_HOST,
            port=config.FLASK_PORT,
            threaded=True,
            use_reloader=False,
        )
    except KeyboardInterrupt:
        pass
    finally:
        scheduler.shutdown()
        callback_server.stop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
