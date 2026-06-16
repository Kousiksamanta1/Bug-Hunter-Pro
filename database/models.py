"""Thread-safe SQLite data access using one connection per operation."""

from collections import Counter
from datetime import datetime, timedelta, timezone
import os
import sqlite3
import threading
import uuid

import config


_db_lock = threading.RLock()


def _connect():
    os.makedirs(os.path.dirname(config.DB_PATH), exist_ok=True)
    connection = sqlite3.connect(config.DB_PATH, timeout=30)
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys = ON")
    connection.execute("PRAGMA journal_mode = WAL")
    return connection


def init_db():
    with _db_lock, _connect() as connection:
        connection.executescript(
            """
            CREATE TABLE IF NOT EXISTS scans (
                id TEXT PRIMARY KEY,
                target TEXT NOT NULL,
                scan_type TEXT NOT NULL,
                status TEXT NOT NULL,
                started_at TEXT NOT NULL,
                completed_at TEXT,
                total_findings INTEGER DEFAULT 0,
                critical_count INTEGER DEFAULT 0,
                high_count INTEGER DEFAULT 0,
                medium_count INTEGER DEFAULT 0,
                low_count INTEGER DEFAULT 0,
                info_count INTEGER DEFAULT 0,
                risk_score REAL DEFAULT 0
            );
            CREATE TABLE IF NOT EXISTS findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT NOT NULL,
                title TEXT NOT NULL,
                severity TEXT NOT NULL,
                cvss_score REAL DEFAULT 0,
                description TEXT,
                evidence TEXT,
                remediation TEXT,
                owasp TEXT,
                mitre TEXT,
                scanner TEXT,
                url TEXT,
                timestamp TEXT,
                false_positive INTEGER DEFAULT 0,
                FOREIGN KEY(scan_id) REFERENCES scans(id) ON DELETE CASCADE
            );
            CREATE TABLE IF NOT EXISTS targets (
                id TEXT PRIMARY KEY,
                url TEXT UNIQUE NOT NULL,
                added_at TEXT NOT NULL,
                last_scanned TEXT,
                total_scans INTEGER DEFAULT 0,
                monitor_enabled INTEGER DEFAULT 0,
                monitor_interval TEXT DEFAULT '24h',
                last_run TEXT,
                next_run TEXT,
                alerts_enabled INTEGER DEFAULT 1
            );
            CREATE TABLE IF NOT EXISTS alerts (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                finding_id TEXT,
                alert_type TEXT,
                sent_at TEXT,
                status TEXT
            );
            CREATE TABLE IF NOT EXISTS subdomains (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                subdomain TEXT,
                ip TEXT,
                status_code INTEGER,
                server_header TEXT,
                redirect_url TEXT,
                response_time REAL,
                discovered_by TEXT,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS js_findings (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                js_file TEXT,
                finding_type TEXT,
                value TEXT,
                severity TEXT,
                line_approximate INTEGER,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS tech_fingerprints (
                id TEXT PRIMARY KEY,
                scan_id TEXT,
                target TEXT,
                server TEXT,
                language TEXT,
                framework TEXT,
                cms TEXT,
                cdn TEXT,
                waf TEXT,
                interesting_paths TEXT,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS oob_callbacks (
                id TEXT PRIMARY KEY,
                callback_type TEXT,
                source_ip TEXT,
                path TEXT,
                headers TEXT,
                body TEXT,
                data TEXT,
                timestamp TEXT
            );
            CREATE TABLE IF NOT EXISTS scope (
                id TEXT PRIMARY KEY,
                program_name TEXT UNIQUE,
                in_scope TEXT,
                out_of_scope TEXT,
                added_at TEXT
            );
            CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_findings_severity ON findings(severity);
            CREATE INDEX IF NOT EXISTS idx_scans_started ON scans(started_at);
            CREATE INDEX IF NOT EXISTS idx_subdomains_scan ON subdomains(scan_id);
            CREATE INDEX IF NOT EXISTS idx_js_findings_scan ON js_findings(scan_id);
            CREATE INDEX IF NOT EXISTS idx_oob_timestamp ON oob_callbacks(timestamp);
            """
        )
        target_columns = {
            row["name"] for row in connection.execute("PRAGMA table_info(targets)").fetchall()
        }
        for column, definition in (
            ("last_run", "TEXT"),
            ("next_run", "TEXT"),
            ("alerts_enabled", "INTEGER DEFAULT 1"),
        ):
            if column not in target_columns:
                connection.execute(f"ALTER TABLE targets ADD COLUMN {column} {definition}")


def insert_scan(scan_dict):
    fields = (
        "id",
        "target",
        "scan_type",
        "status",
        "started_at",
        "completed_at",
        "total_findings",
        "critical_count",
        "high_count",
        "medium_count",
        "low_count",
        "info_count",
        "risk_score",
    )
    values = [scan_dict.get(field) for field in fields]
    with _db_lock, _connect() as connection:
        connection.execute(
            f"INSERT OR REPLACE INTO scans ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
            values,
        )


def update_scan_status(scan_id, status, counts=None):
    counts = counts or {}
    completed_at = (
        datetime.now(timezone.utc).isoformat()
        if status in {"completed", "failed", "stopped"}
        else None
    )
    with _db_lock, _connect() as connection:
        connection.execute(
            """
            UPDATE scans SET status=?, completed_at=COALESCE(?, completed_at),
                total_findings=?, critical_count=?, high_count=?, medium_count=?,
                low_count=?, info_count=?, risk_score=?
            WHERE id=?
            """,
            (
                status,
                completed_at,
                counts.get("total_findings", 0),
                counts.get("critical_count", 0),
                counts.get("high_count", 0),
                counts.get("medium_count", 0),
                counts.get("low_count", 0),
                counts.get("info_count", 0),
                counts.get("risk_score", 0),
                scan_id,
            ),
        )


def insert_finding(finding_dict):
    fields = (
        "id",
        "scan_id",
        "title",
        "severity",
        "cvss_score",
        "description",
        "evidence",
        "remediation",
        "owasp",
        "mitre",
        "scanner",
        "url",
        "timestamp",
        "false_positive",
    )
    values = [finding_dict.get(field) for field in fields]
    values[-1] = int(bool(values[-1]))
    with _db_lock, _connect() as connection:
        connection.execute(
            f"INSERT OR REPLACE INTO findings ({','.join(fields)}) VALUES ({','.join('?' for _ in fields)})",
            values,
        )


def _one(query, params=()):
    with _db_lock, _connect() as connection:
        row = connection.execute(query, params).fetchone()
    return dict(row) if row else None


def _all(query, params=()):
    with _db_lock, _connect() as connection:
        rows = connection.execute(query, params).fetchall()
    return [dict(row) for row in rows]


def get_scan_by_id(scan_id):
    return _one("SELECT * FROM scans WHERE id=?", (scan_id,))


def get_all_scans(limit=50):
    return _all("SELECT * FROM scans ORDER BY started_at DESC LIMIT ?", (int(limit),))


def get_finding_by_id(finding_id):
    return _one("SELECT * FROM findings WHERE id=?", (finding_id,))


def get_findings_by_scan(scan_id):
    return _all(
        """
        SELECT * FROM findings WHERE scan_id=?
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END, cvss_score DESC
        """,
        (scan_id,),
    )


def get_all_findings(severity=None, scanner=None, limit=100, scan_id=None):
    clauses, params = [], []
    if severity:
        clauses.append("severity=?")
        params.append(severity.upper())
    if scanner:
        clauses.append("scanner=?")
        params.append(scanner.lower())
    if scan_id:
        clauses.append("scan_id=?")
        params.append(scan_id)
    where = f"WHERE {' AND '.join(clauses)}" if clauses else ""
    params.append(int(limit))
    return _all(
        f"SELECT * FROM findings {where} ORDER BY timestamp DESC LIMIT ?",
        tuple(params),
    )


def get_stats():
    scans = _all("SELECT * FROM scans")
    findings = _all("SELECT * FROM findings WHERE false_positive=0")
    severity = Counter(item["severity"] for item in findings)
    titles = Counter(item["title"] for item in findings)
    scanners = Counter(item["scanner"] for item in findings)
    owasp = Counter(item["owasp"] or "Unmapped" for item in findings)
    since = datetime.now(timezone.utc).date() - timedelta(days=29)
    daily = Counter()
    for item in findings:
        try:
            day = datetime.fromisoformat(item["timestamp"]).date()
            if day >= since:
                daily[day.isoformat()] += 1
        except (TypeError, ValueError):
            continue
    trend = []
    for offset in range(30):
        day = (since + timedelta(days=offset)).isoformat()
        trend.append({"date": day, "count": daily[day]})
    targets = _one("SELECT COUNT(DISTINCT target) AS count FROM scans")
    return {
        "total_scans": len(scans),
        "total_findings": len(findings),
        "critical_count": severity["CRITICAL"],
        "high_count": severity["HIGH"],
        "medium_count": severity["MEDIUM"],
        "low_count": severity["LOW"],
        "info_count": severity["INFO"],
        "top_vulnerability_types": [
            {"title": title, "count": count} for title, count in titles.most_common(10)
        ],
        "findings_by_scanner": [
            {"scanner": name, "count": count} for name, count in scanners.items()
        ],
        "findings_trend": trend,
        "owasp_breakdown": [
            {"category": category, "count": count} for category, count in owasp.items()
        ],
        "targets_scanned": targets["count"] if targets else 0,
    }


def get_targets():
    return _all("SELECT * FROM targets ORDER BY added_at DESC")


def get_target(target_id):
    return _one("SELECT * FROM targets WHERE id=?", (target_id,))


def upsert_target(url, monitor_enabled=True, interval="24h", alerts_enabled=True):
    now = datetime.now(timezone.utc).isoformat()
    unit = interval[-1].lower()
    amount = int(interval[:-1])
    seconds = amount * {"m": 60, "h": 3600, "d": 86400}[unit]
    next_run = (datetime.now(timezone.utc) + timedelta(seconds=seconds)).isoformat()
    target_id = str(uuid.uuid4())
    with _db_lock, _connect() as connection:
        existing = connection.execute("SELECT id FROM targets WHERE url=?", (url,)).fetchone()
        if existing:
            target_id = existing["id"]
            connection.execute(
                """
                UPDATE targets SET monitor_enabled=?, monitor_interval=?,
                    alerts_enabled=?, next_run=? WHERE id=?
                """,
                (
                    int(bool(monitor_enabled)),
                    interval,
                    int(bool(alerts_enabled)),
                    next_run,
                    target_id,
                ),
            )
        else:
            connection.execute(
                """
                INSERT INTO targets
                (id,url,added_at,last_scanned,total_scans,monitor_enabled,monitor_interval,
                 last_run,next_run,alerts_enabled)
                VALUES (?,?,?,?,?,?,?,?,?,?)
                """,
                (
                    target_id,
                    url,
                    now,
                    None,
                    0,
                    int(bool(monitor_enabled)),
                    interval,
                    None,
                    next_run,
                    int(bool(alerts_enabled)),
                ),
            )
    return get_target(target_id)


def update_target_scan(url):
    now = datetime.now(timezone.utc).isoformat()
    with _db_lock, _connect() as connection:
        connection.execute(
            """
            UPDATE targets SET last_scanned=?, last_run=?,
                total_scans=total_scans+1 WHERE url=?
            """,
            (now, now, url),
        )


def update_target_schedule(url, next_run):
    with _db_lock, _connect() as connection:
        connection.execute(
            "UPDATE targets SET next_run=? WHERE url=?",
            (next_run, url),
        )


def delete_target(target_id):
    with _db_lock, _connect() as connection:
        cursor = connection.execute("DELETE FROM targets WHERE id=?", (target_id,))
    return cursor.rowcount > 0


def mark_false_positive(finding_id):
    with _db_lock, _connect() as connection:
        connection.execute(
            """
            UPDATE findings SET false_positive =
              CASE false_positive WHEN 1 THEN 0 ELSE 1 END WHERE id=?
            """,
            (finding_id,),
        )
    return get_finding_by_id(finding_id)


def get_findings_for_diff(scan_id):
    return get_findings_by_scan(scan_id)


def insert_alert(scan_id, finding_id, alert_type, status):
    alert_id = str(uuid.uuid4())
    with _db_lock, _connect() as connection:
        connection.execute(
            """
            INSERT INTO alerts (id,scan_id,finding_id,alert_type,sent_at,status)
            VALUES (?,?,?,?,?,?)
            """,
            (
                alert_id,
                scan_id,
                finding_id,
                alert_type,
                datetime.now(timezone.utc).isoformat(),
                status,
            ),
        )
    return alert_id


def get_alerts(limit=100):
    return _all(
        """
        SELECT alerts.*, findings.title, findings.severity, scans.target
        FROM alerts
        LEFT JOIN findings ON findings.id=alerts.finding_id
        LEFT JOIN scans ON scans.id=alerts.scan_id
        ORDER BY sent_at DESC LIMIT ?
        """,
        (int(limit),),
    )


def insert_subdomain(subdomain_dict):
    item = dict(subdomain_dict)
    item.setdefault("id", str(uuid.uuid4()))
    fields = (
        "id", "scan_id", "subdomain", "ip", "status_code", "server_header",
        "redirect_url", "response_time", "discovered_by", "timestamp",
    )
    with _db_lock, _connect() as connection:
        connection.execute(
            f"INSERT OR REPLACE INTO subdomains ({','.join(fields)}) "
            f"VALUES ({','.join('?' for _ in fields)})",
            [item.get(field) for field in fields],
        )
    return item["id"]


def get_subdomains_by_scan(scan_id):
    return _all(
        "SELECT * FROM subdomains WHERE scan_id=? ORDER BY subdomain",
        (scan_id,),
    )


def insert_js_finding(js_finding_dict):
    item = dict(js_finding_dict)
    item.setdefault("id", str(uuid.uuid4()))
    fields = (
        "id", "scan_id", "js_file", "finding_type", "value", "severity",
        "line_approximate", "timestamp",
    )
    with _db_lock, _connect() as connection:
        connection.execute(
            f"INSERT OR REPLACE INTO js_findings ({','.join(fields)}) "
            f"VALUES ({','.join('?' for _ in fields)})",
            [item.get(field) for field in fields],
        )
    return item["id"]


def get_js_findings_by_scan(scan_id):
    return _all(
        """
        SELECT * FROM js_findings WHERE scan_id=?
        ORDER BY CASE severity WHEN 'CRITICAL' THEN 1 WHEN 'HIGH' THEN 2
          WHEN 'MEDIUM' THEN 3 WHEN 'LOW' THEN 4 ELSE 5 END
        """,
        (scan_id,),
    )


def insert_tech_fingerprint(fingerprint):
    item = dict(fingerprint)
    item.setdefault("id", str(uuid.uuid4()))
    fields = (
        "id", "scan_id", "target", "server", "language", "framework",
        "cms", "cdn", "waf", "interesting_paths", "timestamp",
    )
    with _db_lock, _connect() as connection:
        connection.execute(
            f"INSERT OR REPLACE INTO tech_fingerprints ({','.join(fields)}) "
            f"VALUES ({','.join('?' for _ in fields)})",
            [item.get(field) for field in fields],
        )
    return item["id"]


def get_tech_fingerprint(scan_id):
    return _one(
        "SELECT * FROM tech_fingerprints WHERE scan_id=? ORDER BY timestamp DESC LIMIT 1",
        (scan_id,),
    )


def insert_oob_callback(callback_dict):
    item = dict(callback_dict)
    item.setdefault("id", str(uuid.uuid4()))
    fields = (
        "id", "callback_type", "source_ip", "path", "headers", "body",
        "data", "timestamp",
    )
    with _db_lock, _connect() as connection:
        connection.execute(
            f"INSERT OR REPLACE INTO oob_callbacks ({','.join(fields)}) "
            f"VALUES ({','.join('?' for _ in fields)})",
            [item.get(field) for field in fields],
        )
    return item["id"]


def get_oob_callbacks(since=None):
    if since:
        return _all(
            "SELECT * FROM oob_callbacks WHERE timestamp>? ORDER BY timestamp DESC",
            (since,),
        )
    return _all("SELECT * FROM oob_callbacks ORDER BY timestamp DESC LIMIT 500")


def upsert_scope(program_name, in_scope, out_of_scope):
    import json

    now = datetime.now(timezone.utc).isoformat()
    scope_id = str(uuid.uuid4())
    with _db_lock, _connect() as connection:
        existing = connection.execute(
            "SELECT id FROM scope WHERE program_name=?",
            (program_name,),
        ).fetchone()
        if existing:
            scope_id = existing["id"]
            connection.execute(
                """
                UPDATE scope SET in_scope=?, out_of_scope=?, added_at=? WHERE id=?
                """,
                (json.dumps(in_scope), json.dumps(out_of_scope), now, scope_id),
            )
        else:
            connection.execute(
                """
                INSERT INTO scope (id,program_name,in_scope,out_of_scope,added_at)
                VALUES (?,?,?,?,?)
                """,
                (
                    scope_id,
                    program_name,
                    json.dumps(in_scope),
                    json.dumps(out_of_scope),
                    now,
                ),
            )
    return get_scope(program_name)


def get_scope(program_name):
    import json

    item = _one("SELECT * FROM scope WHERE program_name=?", (program_name,))
    if not item:
        return None
    for field in ("in_scope", "out_of_scope"):
        try:
            item[field] = json.loads(item[field] or "[]")
        except (TypeError, json.JSONDecodeError):
            item[field] = []
    return item
