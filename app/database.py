import sqlite3
from pathlib import Path
from typing import Any

DB_PATH = Path("data/soc.db")


def get_conn() -> sqlite3.Connection:
    DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    with get_conn() as conn:
        conn.executescript(
            """
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                ip TEXT,
                username TEXT,
                user_agent TEXT,
                method TEXT,
                path TEXT,
                status_code INTEGER,
                message TEXT,
                raw TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS alerts (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                severity TEXT NOT NULL,
                alert_type TEXT NOT NULL,
                ip TEXT,
                username TEXT,
                user_agent TEXT,
                details TEXT NOT NULL,
                log_id INTEGER,
                status TEXT NOT NULL DEFAULT 'new',
                assignee TEXT,
                resolution_note TEXT,
                occurrences INTEGER NOT NULL DEFAULT 1,
                updated_at TEXT,
                mitre_tactic TEXT,
                mitre_technique TEXT,
                asset_id INTEGER,
                explain_text TEXT,
                FOREIGN KEY(log_id) REFERENCES logs(id)
            );

            CREATE TABLE IF NOT EXISTS assets (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                criticality TEXT NOT NULL DEFAULT 'medium',
                ip_cidr TEXT,
                path_prefix TEXT,
                owner TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS suppressions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT,
                alert_type TEXT,
                path_pattern TEXT,
                reason TEXT,
                expires_at TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS incident_events (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                event_type TEXT NOT NULL,
                severity TEXT,
                alert_id INTEGER,
                ip TEXT,
                title TEXT NOT NULL,
                details TEXT,
                actor TEXT,
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            );

            CREATE TABLE IF NOT EXISTS saved_views (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                target TEXT NOT NULL DEFAULT 'both',
                query_dsl TEXT NOT NULL,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS cases (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                title TEXT NOT NULL,
                priority TEXT NOT NULL DEFAULT 'medium',
                status TEXT NOT NULL DEFAULT 'open',
                owner TEXT,
                description TEXT,
                due_at TEXT,
                opened_at TEXT NOT NULL,
                first_response_at TEXT,
                closed_at TEXT
            );

            CREATE TABLE IF NOT EXISTS case_alerts (
                case_id INTEGER NOT NULL,
                alert_id INTEGER NOT NULL,
                linked_at TEXT NOT NULL,
                PRIMARY KEY(case_id, alert_id),
                FOREIGN KEY(case_id) REFERENCES cases(id),
                FOREIGN KEY(alert_id) REFERENCES alerts(id)
            );

            CREATE TABLE IF NOT EXISTS case_actions (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                actor TEXT,
                action TEXT NOT NULL,
                details TEXT,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS case_comments (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                case_id INTEGER NOT NULL,
                ts TEXT NOT NULL,
                author TEXT,
                message TEXT NOT NULL,
                FOREIGN KEY(case_id) REFERENCES cases(id)
            );

            CREATE TABLE IF NOT EXISTS report_schedules (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                hour_utc INTEGER NOT NULL,
                minute_utc INTEGER NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                last_run_date TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS report_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                schedule_id INTEGER,
                ts TEXT NOT NULL,
                output_path TEXT NOT NULL,
                status TEXT NOT NULL,
                FOREIGN KEY(schedule_id) REFERENCES report_schedules(id)
            );

            CREATE TABLE IF NOT EXISTS ioc_watchlist (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ioc_type TEXT NOT NULL,
                ioc_value TEXT NOT NULL,
                severity_override TEXT NOT NULL DEFAULT 'high',
                enabled INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS policies (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                name TEXT NOT NULL,
                enabled INTEGER NOT NULL DEFAULT 1,
                condition_expr TEXT NOT NULL,
                action_type TEXT NOT NULL,
                action_payload TEXT,
                created_at TEXT NOT NULL
            );

            CREATE TABLE IF NOT EXISTS backup_runs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ts TEXT NOT NULL,
                backup_path TEXT NOT NULL,
                action TEXT NOT NULL,
                status TEXT NOT NULL,
                details TEXT
            );

            CREATE INDEX IF NOT EXISTS idx_logs_ts ON logs(ts);
            CREATE INDEX IF NOT EXISTS idx_logs_ip ON logs(ip);
            CREATE INDEX IF NOT EXISTS idx_alerts_ts ON alerts(ts);
            CREATE INDEX IF NOT EXISTS idx_alerts_type ON alerts(alert_type);
            CREATE INDEX IF NOT EXISTS idx_suppressions_expires ON suppressions(expires_at);
            CREATE INDEX IF NOT EXISTS idx_incident_events_ts ON incident_events(ts);
            CREATE INDEX IF NOT EXISTS idx_cases_status ON cases(status);
            CREATE INDEX IF NOT EXISTS idx_case_actions_case_id ON case_actions(case_id);
            CREATE INDEX IF NOT EXISTS idx_case_comments_case_id ON case_comments(case_id);
            CREATE INDEX IF NOT EXISTS idx_report_schedules_enabled ON report_schedules(enabled);
            CREATE INDEX IF NOT EXISTS idx_ioc_enabled ON ioc_watchlist(enabled);
            CREATE INDEX IF NOT EXISTS idx_policies_enabled ON policies(enabled);
            """
        )
        # Lightweight migrations for existing DB files.
        _ensure_column(conn, "alerts", "status", "TEXT NOT NULL DEFAULT 'new'")
        _ensure_column(conn, "alerts", "assignee", "TEXT")
        _ensure_column(conn, "alerts", "resolution_note", "TEXT")
        _ensure_column(conn, "alerts", "occurrences", "INTEGER NOT NULL DEFAULT 1")
        _ensure_column(conn, "alerts", "updated_at", "TEXT")
        _ensure_column(conn, "alerts", "mitre_tactic", "TEXT")
        _ensure_column(conn, "alerts", "mitre_technique", "TEXT")
        _ensure_column(conn, "alerts", "asset_id", "INTEGER")
        _ensure_column(conn, "alerts", "explain_text", "TEXT")


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, ddl: str) -> None:
    columns = {row["name"] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in columns:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {ddl}")
        conn.commit()


def fetch_all(query: str, params: tuple[Any, ...] = ()) -> list[dict[str, Any]]:
    with get_conn() as conn:
        rows = conn.execute(query, params).fetchall()
        return [dict(row) for row in rows]


def execute(query: str, params: tuple[Any, ...] = ()) -> int:
    with get_conn() as conn:
        cur = conn.execute(query, params)
        conn.commit()
        return int(cur.lastrowid or 0)


def execute_change(query: str, params: tuple[Any, ...] = ()) -> int:
    with get_conn() as conn:
        cur = conn.execute(query, params)
        conn.commit()
        return cur.rowcount
