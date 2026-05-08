from pathlib import Path

from app.database import execute, init_db
from app.main import _store_logs, create_asset, create_suppression, get_alerts, incidents_timeline

DB_PATH = Path("data/soc.db")


def setup_function() -> None:
    init_db()
    execute("DELETE FROM incident_events")
    execute("DELETE FROM suppressions")
    execute("DELETE FROM alerts")
    execute("DELETE FROM logs")
    execute("DELETE FROM assets")


def test_asset_mapping_and_mitre_on_alerts() -> None:
    asset = create_asset(
        {
            "name": "Admin Portal",
            "criticality": "critical",
            "path_prefix": "/admin",
            "owner": "secops",
        }
    )
    assert asset["name"] == "Admin Portal"

    _store_logs([
        '198.51.100.10 - - [22/Apr/2026:08:49:10 +0000] "GET /admin HTTP/1.1" 403 114 "-" "curl/8.0"'
    ])

    alerts = get_alerts(limit=200, severity="medium")
    assert len(alerts["items"]) >= 1
    admin_alert = next(a for a in alerts["items"] if a["alert_type"] == "admin-access-denied")
    assert admin_alert["asset_name"] == "Admin Portal"
    assert admin_alert["mitre_technique"] == "T1087"


def test_suppression_blocks_alert_creation() -> None:
    create_suppression(
        {
            "ip": "203.0.113.9",
            "alert_type": "suspicious-user-agent",
            "ttl_minutes": 60,
            "reason": "known scanner in lab",
        }
    )

    _store_logs([
        '{"ts":"2026-04-22T08:52:00Z","ip":"203.0.113.9","method":"GET","path":"/","status_code":200,"user_agent":"sqlmap/1.7","message":"test"}'
    ])

    alerts = get_alerts(limit=200, alert_type="suspicious-user-agent")
    assert len(alerts["items"]) == 0


def test_incident_timeline_receives_events() -> None:
    _store_logs([
        '{"ts":"2026-04-22T08:52:00Z","ip":"203.0.113.9","method":"GET","path":"/search?q=1 union select","status_code":200,"user_agent":"sqlmap/1.7","message":"query suspicious"}'
    ])
    events = incidents_timeline(limit=200)
    assert len(events["items"]) >= 1
    assert any(e["event_type"] == "alert_created" for e in events["items"])
