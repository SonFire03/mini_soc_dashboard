from pathlib import Path

from app.database import init_db
from app.main import _store_logs, get_alerts, get_logs, get_stats, playbook, update_alert

DB_PATH = Path("data/soc.db")


def setup_function() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()


def test_store_and_query_end_to_end() -> None:
    sample_lines = [
        '192.168.1.20 - - [22/Apr/2026:08:41:04 +0000] "POST /login HTTP/1.1" 401 231 "-" "Mozilla/5.0"',
        '192.168.1.20 - - [22/Apr/2026:08:42:01 +0000] "POST /login HTTP/1.1" 401 231 "-" "Mozilla/5.0"',
        '192.168.1.20 - - [22/Apr/2026:08:42:55 +0000] "POST /login HTTP/1.1" 401 231 "-" "Mozilla/5.0"',
        '192.168.1.20 - - [22/Apr/2026:08:44:12 +0000] "POST /login HTTP/1.1" 401 231 "-" "Mozilla/5.0"',
        '192.168.1.20 - - [22/Apr/2026:08:45:10 +0000] "POST /login HTTP/1.1" 401 231 "-" "Mozilla/5.0"',
        '{"ts":"2026-04-22T08:52:00Z","ip":"203.0.113.9","method":"GET","path":"/search?q=1 union select password","status_code":200,"user_agent":"sqlmap/1.7","message":"query suspicious"}',
    ]

    ingest_result = _store_logs(sample_lines)
    assert ingest_result["ingested"] == 6
    assert ingest_result["batch_alerts"] >= 1
    assert ingest_result["inserted_alerts"] >= 1

    alerts = get_alerts(limit=200, severity="high")
    assert len(alerts["items"]) >= 2

    alert_id = alerts["items"][0]["id"]
    updated = update_alert(alert_id, {"status": "investigating", "assignee": "soc-analyst"})
    assert updated["status"] == "investigating"
    assert updated["assignee"] == "soc-analyst"

    # Regression check: q filter must not crash on alerts/logs.
    alerts_q = get_alerts(limit=200, q="UNION")
    assert len(alerts_q["items"]) >= 1

    logs_q = get_logs(limit=200, q="login", ip="192.168.1.20", method="POST", status_code=401)
    assert len(logs_q["items"]) == 5

    low_alerts = get_alerts(limit=200, severity="low")
    assert any((item.get("occurrences") or 1) >= 1 for item in low_alerts["items"])

    stats = get_stats()
    assert stats["total_logs"] == 6
    assert stats["failed_logins"] >= 5
    assert "top_risky_ips" in stats

    pb = playbook("possible-bruteforce")
    assert len(pb["steps"]) >= 1
