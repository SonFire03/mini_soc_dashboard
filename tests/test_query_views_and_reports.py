from pathlib import Path

from app.database import execute, init_db
from app.main import (
    _store_logs,
    alert_context,
    alert_investigation,
    create_asset,
    create_case,
    create_ioc,
    create_saved_view,
    daily_report_data,
    get_alerts,
    get_logs,
    get_saved_views,
    link_case_alert,
)

DB_PATH = Path("data/soc.db")


def setup_function() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()


def test_query_dsl_filters_logs_and_alerts() -> None:
    _store_logs(
        [
            '192.0.2.10 - - [22/Apr/2026:08:41:04 +0000] "POST /login HTTP/1.1" 401 231 "-" "Mozilla/5.0"',
            '192.0.2.10 - - [22/Apr/2026:08:42:04 +0000] "GET /admin HTTP/1.1" 403 231 "-" "curl/8.0"',
        ]
    )

    logs = get_logs(dsl="ip:192.0.2.10 method:POST code:401", limit=200)
    assert len(logs["items"]) == 1

    alerts = get_alerts(dsl="ip:192.0.2.10 type:admin-access-denied severity:medium", limit=200)
    assert len(alerts["items"]) >= 1


def test_saved_views_crud() -> None:
    view = create_saved_view({"name": "Brute watch", "target": "alerts", "query_dsl": "severity:high type:possible-bruteforce"})
    assert view["name"] == "Brute watch"

    listed = get_saved_views()
    assert any(v["id"] == view["id"] for v in listed["items"])

    execute("DELETE FROM saved_views WHERE id = ?", (view["id"],))
    listed_after = get_saved_views()
    assert all(v["id"] != view["id"] for v in listed_after["items"])


def test_alert_context_and_report() -> None:
    _store_logs(
        [
            '{"ts":"2026-04-22T08:52:00Z","ip":"203.0.113.9","method":"GET","path":"/search?q=1 union select","status_code":200,"user_agent":"sqlmap/1.7","message":"query suspicious"}'
        ]
    )
    alerts = get_alerts(limit=200)
    assert alerts["items"]
    alert_id = alerts["items"][0]["id"]

    ctx = alert_context(alert_id)
    assert ctx["alert"]["id"] == alert_id
    assert isinstance(ctx["playbook"], list)
    assert isinstance(ctx["related_logs"], list)

    report = daily_report_data()
    assert "stats" in report
    assert "latest_alerts" in report


def test_alert_investigation_aggregates_asset_case_and_ioc_context() -> None:
    create_asset(
        {
            "name": "Admin Portal",
            "criticality": "critical",
            "path_prefix": "/search",
            "owner": "secops",
        }
    )
    create_ioc(
        {
            "ioc_type": "user_agent",
            "ioc_value": "sqlmap",
            "severity_override": "critical",
            "enabled": True,
        }
    )
    _store_logs(
        [
            '{"ts":"2026-04-22T08:52:00Z","ip":"203.0.113.9","method":"GET","path":"/search?q=1 union select","status_code":200,"user_agent":"sqlmap/1.7","message":"query suspicious"}'
        ]
    )

    alert = next(item for item in get_alerts(limit=200)["items"] if item["alert_type"] == "injection-or-traversal")
    case = create_case({"title": "Investigate suspicious search", "priority": "high", "owner": "soc-analyst"})
    link_case_alert(case["id"], alert["id"])
    execute(
        "INSERT INTO incident_events(ts, event_type, severity, alert_id, ip, title, details, actor) VALUES(?, ?, ?, ?, ?, ?, ?, ?)",
        (
            "2026-04-22T08:53:00+00:00",
            "manual_note",
            "medium",
            alert["id"],
            "203.0.113.9",
            "Analyst note",
            "Pivoted to related logs",
            "analyst",
        ),
    )

    investigation = alert_investigation(alert["id"])
    assert investigation["alert"]["id"] == alert["id"]
    assert investigation["asset"]["name"] == "Admin Portal"
    assert investigation["linked_cases"][0]["id"] == case["id"]
    assert investigation["ioc_matches"][0]["ioc_value"] == "sqlmap"
    assert investigation["summary"]["related_logs_count"] >= 1
    assert investigation["summary"]["related_events_count"] >= 1
