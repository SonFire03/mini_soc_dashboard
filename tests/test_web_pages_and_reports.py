import asyncio
from pathlib import Path
from urllib.parse import urlencode

import pytest
from starlette.requests import Request

from app.database import init_db
from app.runtime import (
    AUTH_PASSWORD,
    AUTH_USER,
    SESSION_COOKIE,
    SESSION_ROLE_COOKIE,
    SESSION_TOKEN,
    admin_page,
    daily_report_page,
    investigations_page,
    login,
    login_page,
    logout,
    operations_page,
    overview_page,
    reports_page,
    wallboard,
)

DB_PATH = Path("data/soc.db")


@pytest.fixture(autouse=True)
def clean_db() -> None:
    init_db()


def _request(path: str, method: str = "GET", query_string: str = "", form_data: dict[str, str] | None = None) -> Request:
    headers: list[tuple[bytes, bytes]] = []
    body = b""
    if form_data is not None:
        body = urlencode(form_data).encode("utf-8")
        headers.append((b"content-type", b"application/x-www-form-urlencoded"))
        headers.append((b"content-length", str(len(body)).encode("utf-8")))

    scope = {
        "type": "http",
        "http_version": "1.1",
        "method": method,
        "scheme": "http",
        "path": path,
        "raw_path": path.encode("utf-8"),
        "query_string": query_string.encode("utf-8"),
        "headers": headers,
        "client": ("127.0.0.1", 12345),
        "server": ("test", 80),
        "root_path": "",
    }

    sent = {"done": False}

    async def receive() -> dict:
        if sent["done"]:
            return {"type": "http.request", "body": b"", "more_body": False}
        sent["done"] = True
        return {"type": "http.request", "body": body, "more_body": False}

    return Request(scope, receive)


def _render_text(response) -> str:
    template = getattr(response, "template", None)
    context = getattr(response, "context", None)
    if template is not None and context is not None:
        return template.render(context)
    return response.body.decode("utf-8")


def test_login_page_renders_language_selector() -> None:
    response = login_page(_request("/login"))
    body = _render_text(response)
    assert response.status_code == 200
    assert 'data-language-select' in body
    assert '<form method="post" action="/login"' in body


def test_login_rejects_invalid_credentials() -> None:
    response = asyncio.run(login(_request("/login", method="POST", form_data={"username": "bad", "password": "bad"})))
    body = _render_text(response)
    assert response.status_code == 401
    assert "Invalid credentials" in body


def test_login_sets_session_and_role_cookies() -> None:
    response = asyncio.run(
        login(_request("/login", method="POST", form_data={"username": AUTH_USER, "password": AUTH_PASSWORD}))
    )
    cookies = response.headers.getlist("set-cookie")
    assert response.status_code == 303
    assert response.headers["location"] == "/overview"
    assert any(cookie.startswith(f"{SESSION_COOKIE}={SESSION_TOKEN}") for cookie in cookies)
    assert any(cookie.startswith(f"{SESSION_ROLE_COOKIE}=admin") for cookie in cookies)


def test_logout_redirects_and_clears_cookies() -> None:
    response = logout()
    cookies = response.headers.getlist("set-cookie")
    assert response.status_code == 303
    assert response.headers["location"] == "/login"
    assert any(cookie.startswith(f"{SESSION_COOKIE}=") for cookie in cookies)
    assert any(cookie.startswith(f"{SESSION_ROLE_COOKIE}=") for cookie in cookies)


@pytest.mark.parametrize(
    ("builder", "marker"),
    [
        (overview_page, "page-overview"),
        (investigations_page, "page-investigations"),
        (operations_page, "page-operations"),
        (reports_page, "page-reports"),
        (admin_page, "page-admin"),
    ],
)
def test_dashboard_pages_render_expected_page_marker(builder, marker: str) -> None:
    response = builder(_request("/"))
    body = _render_text(response)
    assert response.status_code == 200
    assert marker in body
    assert "Mini SOC Dashboard" in body


def test_wallboard_renders_wallboard_layout() -> None:
    response = wallboard(_request("/wallboard"))
    body = _render_text(response)
    assert response.status_code == 200
    assert 'class="wallboard page-overview"' in body


@pytest.mark.parametrize(
    ("lang", "expected"),
    [
        ("en", "Daily SOC Report"),
        ("fr", "Rapport SOC quotidien"),
        ("ja", "日次SOCレポート"),
    ],
)
def test_daily_report_page_supports_language_query_param(lang: str, expected: str) -> None:
    response = daily_report_page(_request("/reports/daily", query_string=f"lang={lang}"))
    body = response.body.decode("utf-8")
    assert response.status_code == 200
    assert expected in body
