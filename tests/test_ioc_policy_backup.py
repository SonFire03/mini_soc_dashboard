from pathlib import Path
from datetime import datetime, timedelta, timezone

from app.database import execute, init_db
from app.main import (
    create_backup,
    create_ioc,
    create_policy,
    delta_report_data,
    get_alerts,
    get_cases,
    list_backups,
    restore_backup,
    _store_logs,
)

DB_PATH = Path("data/soc.db")
BACKUPS_DIR = Path("data/backups")


def setup_function() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    for file in BACKUPS_DIR.glob("*.db"):
        file.unlink()
    execute("DELETE FROM backup_runs")


def test_ioc_watchlist_triggers_alert() -> None:
    create_ioc(
        {
            "ioc_type": "user_agent",
            "ioc_value": "evilscanner",
            "severity_override": "critical",
            "enabled": True,
        }
    )
    _store_logs(
        [
            '{"ts":"2026-04-22T10:00:00Z","ip":"198.51.100.8","method":"GET","path":"/","status_code":200,"user_agent":"evilscanner/1.0","message":"probe"}'
        ]
    )
    alerts = get_alerts(limit=200, alert_type="ioc-match")
    assert any(a["severity"] == "critical" for a in alerts["items"])


def test_policy_auto_creates_case() -> None:
    create_policy(
        {
            "name": "Auto case suspicious UA",
            "condition_expr": "alert_type==suspicious-user-agent",
            "action_type": "create_case",
            "action_payload": {"title": "Auto suspicious UA", "owner": "soc-auto", "priority": "high"},
            "enabled": True,
        }
    )
    _store_logs(
        [
            '{"ts":"2026-04-22T10:02:00Z","ip":"203.0.113.12","method":"GET","path":"/","status_code":200,"user_agent":"sqlmap/1.7","message":"scanner"}'
        ]
    )
    cases = get_cases()
    assert any(c["title"] == "Auto suspicious UA" for c in cases["items"])


def test_delta_and_backup_restore_cycle() -> None:
    now = datetime.now(timezone.utc)
    ts1 = (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    ts2 = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    _store_logs(
        [
            f'{{"ts":"{ts1}","ip":"203.0.113.21","method":"POST","path":"/login","status_code":401,"user_agent":"Mozilla/5.0","message":"failed"}}'
        ]
    )
    backup = create_backup()
    assert backup["status"] == "ok"
    _store_logs(
        [
            f'{{"ts":"{ts2}","ip":"203.0.113.21","method":"POST","path":"/login","status_code":401,"user_agent":"Mozilla/5.0","message":"failed-again"}}'
        ]
    )

    delta = delta_report_data(since_hours=48)
    assert delta["logs_ingested"] >= 2
    assert delta["alerts_created"] >= 1

    restored = restore_backup({})
    assert restored["status"] == "ok"
    backups = list_backups()
    assert backups["items"]
    assert backups["items"][0]["action"] == "restore"
