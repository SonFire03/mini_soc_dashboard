import asyncio
from pathlib import Path

from app.database import init_db
from app.main import (
    SESSION_COOKIE,
    SESSION_ROLE_COOKIE,
    SESSION_TOKEN,
    AuthMiddleware,
    _current_role,
    analytics_overview,
    health,
    settings,
)

DB_PATH = Path("data/soc.db")


def setup_function() -> None:
    if DB_PATH.exists():
        DB_PATH.unlink()
    init_db()


def _cookie_header(*pairs: tuple[str, str]) -> bytes:
    return "; ".join(f"{k}={v}" for k, v in pairs).encode("utf-8")


def _scope(path: str, cookie_header: bytes | None = None) -> dict:
    headers: list[tuple[bytes, bytes]] = []
    if cookie_header:
        headers.append((b"cookie", cookie_header))
    return {
        "type": "http",
        "http_version": "1.1",
        "method": "GET",
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": b"",
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "root_path": "",
    }


async def _receive() -> dict:
    return {"type": "http.request", "body": b"", "more_body": False}


def test_current_role_defaults_to_admin() -> None:
    from starlette.requests import Request

    request = Request(_scope("/api/alerts"), _receive)
    assert _current_role(request) == "admin"


def test_current_role_invalid_cookie_falls_back_to_admin() -> None:
    from starlette.requests import Request

    cookie = _cookie_header((SESSION_ROLE_COOKIE, "invalid-role"))
    request = Request(_scope("/api/alerts", cookie), _receive)
    assert _current_role(request) == "admin"


def test_analyst_forbidden_on_admin_path() -> None:
    called = {"next": False}
    sent: list[dict] = []
    async def send(event: dict) -> None:
        sent.append(event)

    async def next_app(scope, receive, send):
        called["next"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AuthMiddleware(next_app)
    cookie = _cookie_header((SESSION_COOKIE, SESSION_TOKEN), (SESSION_ROLE_COOKIE, "analyst"))
    asyncio.run(middleware(_scope("/api/admin/backups", cookie), _receive, send))
    assert called["next"] is False
    assert any(event.get("status") == 403 for event in sent if event.get("type") == "http.response.start")


def test_admin_allowed_on_admin_path() -> None:
    called = {"next": False}
    sent: list[dict] = []
    async def send(event: dict) -> None:
        sent.append(event)

    async def next_app(scope, receive, send):
        called["next"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AuthMiddleware(next_app)
    cookie = _cookie_header((SESSION_COOKIE, SESSION_TOKEN), (SESSION_ROLE_COOKIE, "admin"))
    asyncio.run(middleware(_scope("/api/admin/backups", cookie), _receive, send))
    assert called["next"] is True
    assert any(event.get("status") == 200 for event in sent if event.get("type") == "http.response.start")


def test_unauthenticated_api_returns_401() -> None:
    called = {"next": False}
    sent: list[dict] = []

    async def send(event: dict) -> None:
        sent.append(event)

    async def next_app(scope, receive, send):
        called["next"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AuthMiddleware(next_app)
    asyncio.run(middleware(_scope("/api/alerts"), _receive, send))
    assert called["next"] is False
    assert any(event.get("status") == 401 for event in sent if event.get("type") == "http.response.start")


def test_unauthenticated_web_redirects_to_login() -> None:
    called = {"next": False}
    sent: list[dict] = []

    async def send(event: dict) -> None:
        sent.append(event)

    async def next_app(scope, receive, send):
        called["next"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AuthMiddleware(next_app)
    asyncio.run(middleware(_scope("/"), _receive, send))
    assert called["next"] is False
    assert any(event.get("status") == 307 for event in sent if event.get("type") == "http.response.start")


def test_public_path_bypasses_auth_middleware() -> None:
    called = {"next": False}
    sent: list[dict] = []

    async def send(event: dict) -> None:
        sent.append(event)

    async def next_app(scope, receive, send):
        called["next"] = True
        await send({"type": "http.response.start", "status": 200, "headers": []})
        await send({"type": "http.response.body", "body": b"ok"})

    middleware = AuthMiddleware(next_app)
    asyncio.run(middleware(_scope("/login"), _receive, send))
    assert called["next"] is True
    assert any(event.get("status") == 200 for event in sent if event.get("type") == "http.response.start")


def test_settings_exposes_app_version() -> None:
    current = settings()
    assert "app_version" in current
    assert isinstance(current["app_version"], str)
    assert "security_warnings" in current
    assert isinstance(current["security_warnings"], list)
    assert current["live_tail_restricted"] is True


def test_health_exposes_version() -> None:
    status = health()
    assert status["status"] == "ok"
    assert isinstance(status["version"], str)


def test_analytics_overview_shape() -> None:
    overview = analytics_overview(window_hours=24)
    assert "severity_distribution" in overview
    assert "top_alert_types" in overview
    assert "top_source_ips" in overview
