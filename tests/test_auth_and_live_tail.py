import time
from pathlib import Path

import pytest
from starlette.requests import Request

from app.database import fetch_all, init_db
from app.main import (
    SESSION_COOKIE,
    SESSION_TOKEN,
    _is_authenticated,
    _validate_live_tail_path,
    start_live_tail,
    tail_manager,
)

DB_PATH = Path("data/soc.db")


@pytest.fixture(autouse=True)
def clean_db() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()
    tail_manager.stop()


def _make_request(cookie: str | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    if cookie:
        headers.append((b"cookie", cookie.encode("utf-8")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": "/",
        "raw_path": b"/",
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "root_path": "",
    }

    async def receive():
        return {"type": "http.request", "body": b"", "more_body": False}

    return Request(scope, receive)


def test_auth_cookie_validation() -> None:
    unauth = _make_request()
    assert _is_authenticated(unauth) is False

    auth = _make_request(f"{SESSION_COOKIE}={SESSION_TOKEN}")
    assert _is_authenticated(auth) is True


def test_live_tail_ingests_new_lines() -> None:
    tail_file = Path("/tmp/live_tail_test.log")
    tail_file.write_text("", encoding="utf-8")

    state = tail_manager.start(str(tail_file), from_start=True, interval_sec=0.2)
    assert state.running is True

    with tail_file.open("a", encoding="utf-8") as handle:
        handle.write(
            '198.51.100.40 - - [22/Apr/2026:10:41:04 +0000] "GET /admin HTTP/1.1" 403 231 "-" "curl/8.0"\n'
        )

    time.sleep(0.6)

    status = tail_manager.status()
    assert status.ingested_total >= 1

    alerts = fetch_all("SELECT alert_type FROM alerts")
    assert any(a["alert_type"] in {"admin-access-denied", "suspicious-user-agent"} for a in alerts)

    stopped = tail_manager.stop()
    assert stopped.running is False


def test_live_tail_invalid_path() -> None:
    with pytest.raises(ValueError):
        tail_manager.start("/tmp/does-not-exist.log")


def test_live_tail_endpoint_rejects_paths_outside_allowed_root() -> None:
    response = start_live_tail({"file_path": "/tmp/live_tail_test.log"})
    assert getattr(response, "status_code", 200) == 400


def test_live_tail_path_allows_data_directory_files() -> None:
    tail_file = Path("data/live_tail_allowed.log")
    tail_file.write_text("", encoding="utf-8")

    try:
        assert _validate_live_tail_path(str(tail_file)).endswith("data/live_tail_allowed.log")
    finally:
        tail_file.unlink(missing_ok=True)
