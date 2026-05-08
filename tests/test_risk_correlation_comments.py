from datetime import UTC, datetime, timedelta
from pathlib import Path

from app.database import init_db
from app.main import (
    _store_logs,
    create_case,
    create_case_comment,
    delete_case_comment,
    get_alerts,
    get_case_comments,
    risk_entities,
)

DB_PATH = Path("data/soc.db")


def setup_function() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()


def test_correlation_engine_creates_chain_alert() -> None:
    _store_logs(
        [
            '{"ts":"2026-04-22T11:00:00Z","ip":"203.0.113.44","method":"POST","path":"/login","status_code":401,"user_agent":"Mozilla/5.0","message":"bad creds"}',
            '{"ts":"2026-04-22T11:01:00Z","ip":"203.0.113.44","method":"GET","path":"/search?q=1 union select","status_code":200,"user_agent":"sqlmap/1.7","message":"probe"}',
            '{"ts":"2026-04-22T11:02:00Z","ip":"203.0.113.44","method":"GET","path":"/admin","status_code":403,"user_agent":"curl/8.0","message":"forbidden"}',
        ]
    )
    alerts = get_alerts(limit=300, alert_type="correlated-attack-chain")
    assert any(a["ip"] == "203.0.113.44" for a in alerts["items"])


def test_risk_entities_exposes_top_scores() -> None:
    now = datetime.now(UTC)
    ts1 = (now - timedelta(minutes=2)).isoformat().replace("+00:00", "Z")
    ts2 = (now - timedelta(minutes=1)).isoformat().replace("+00:00", "Z")
    _store_logs(
        [
            f'{{"ts":"{ts1}","ip":"203.0.113.50","method":"GET","path":"/search?q=union+select","status_code":200,"user_agent":"sqlmap/1.7","message":"probe"}}',
            f'{{"ts":"{ts2}","ip":"203.0.113.50","method":"POST","path":"/login","status_code":401,"user_agent":"Mozilla/5.0","message":"failed"}}',
        ]
    )
    risk = risk_entities(since_hours=48)
    assert risk["top_ips"]
    assert any(item["entity"] == "203.0.113.50" for item in risk["top_ips"])


def test_case_comments_crud() -> None:
    case = create_case({"title": "Case comments test", "priority": "high", "owner": "soc"})
    comment = create_case_comment(case["id"], {"author": "analyst", "message": "initial triage"})
    assert comment["author"] == "analyst"

    listed = get_case_comments(case["id"])
    assert any(c["id"] == comment["id"] for c in listed["items"])

    deleted = delete_case_comment(case["id"], comment["id"])
    assert deleted["status"] == "ok"
