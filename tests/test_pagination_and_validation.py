from pathlib import Path

from app.database import init_db
from app.main import create_case, get_alerts, get_logs, _store_logs

DB_PATH = Path("data/soc.db")


def setup_function() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()


def test_logs_pagination_metadata() -> None:
    _store_logs(
        [
            '192.0.2.1 - - [22/Apr/2026:08:41:04 +0000] "POST /login HTTP/1.1" 401 231 "-" "Mozilla/5.0"',
            '192.0.2.2 - - [22/Apr/2026:08:42:04 +0000] "GET /admin HTTP/1.1" 403 231 "-" "curl/8.0"',
        ]
    )

    page = get_logs(limit=1, offset=0)
    assert page["total"] >= 2
    assert page["limit"] == 1
    assert page["offset"] == 0
    assert len(page["items"]) == 1


def test_alerts_pagination_metadata() -> None:
    _store_logs(
        [
            '{"ts":"2026-04-22T08:52:00Z","ip":"203.0.113.9","method":"GET","path":"/search?q=1 union select","status_code":200,"user_agent":"sqlmap/1.7","message":"query suspicious"}'
        ]
    )

    page = get_alerts(limit=1, offset=0)
    assert page["total"] >= 1
    assert page["limit"] == 1
    assert page["offset"] == 0


def test_create_case_validation_rejects_empty_title() -> None:
    bad = create_case({"title": "", "priority": "high"})
    assert getattr(bad, "status_code", 200) == 400
