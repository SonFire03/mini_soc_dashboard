from app.detector import (
    detect_bruteforce,
    detect_error_spike,
    detect_login_success_after_failures,
    detect_single,
)
from app.parser import normalize_log


def test_normalize_json_log():
    log = normalize_log('{"ts":"2026-04-22T08:00:00Z","ip":"1.2.3.4","path":"/login","status_code":401}')
    assert log["ip"] == "1.2.3.4"
    assert log["status_code"] == 401


def test_detect_single_suspicious_ua():
    alerts = detect_single(
        {
            "path": "/",
            "message": "",
            "user_agent": "sqlmap/1.0",
            "status_code": 200,
        }
    )
    assert any(a["alert_type"] == "suspicious-user-agent" for a in alerts)


def test_detect_bruteforce():
    logs = [
        {"ip": "9.9.9.9", "path": "/login", "status_code": 401, "ts": "2026-04-22T08:00:00+00:00"},
        {"ip": "9.9.9.9", "path": "/login", "status_code": 401, "ts": "2026-04-22T08:01:00+00:00"},
        {"ip": "9.9.9.9", "path": "/login", "status_code": 401, "ts": "2026-04-22T08:02:00+00:00"},
        {"ip": "9.9.9.9", "path": "/login", "status_code": 401, "ts": "2026-04-22T08:03:00+00:00"},
        {"ip": "9.9.9.9", "path": "/login", "status_code": 401, "ts": "2026-04-22T08:04:00+00:00"},
    ]
    alerts = detect_bruteforce(logs)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "possible-bruteforce"


def test_detect_single_failed_login_attempt():
    alerts = detect_single(
        {
            "path": "/login",
            "message": "",
            "user_agent": "Mozilla/5.0",
            "status_code": 401,
        }
    )
    assert any(a["alert_type"] == "failed-login-attempt" for a in alerts)


def test_detect_login_success_after_failures():
    logs = [
        {"ip": "4.4.4.4", "path": "/login", "status_code": 401, "ts": "2026-04-22T08:00:00+00:00"},
        {"ip": "4.4.4.4", "path": "/login", "status_code": 401, "ts": "2026-04-22T08:01:00+00:00"},
        {"ip": "4.4.4.4", "path": "/login", "status_code": 403, "ts": "2026-04-22T08:02:00+00:00"},
        {"ip": "4.4.4.4", "path": "/login", "status_code": 200, "ts": "2026-04-22T08:03:00+00:00"},
    ]
    alerts = detect_login_success_after_failures(logs)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "possible-account-compromise"


def test_detect_error_spike():
    logs = []
    for i in range(7):
        logs.append(
            {
                "ip": "8.8.8.8",
                "path": "/api/data",
                "status_code": 500,
                "ts": f"2026-04-22T08:0{i % 5}:00+00:00",
            }
        )
    alerts = detect_error_spike(logs)
    assert len(alerts) == 1
    assert alerts[0]["alert_type"] == "error-spike-5xx"
