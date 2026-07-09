from __future__ import annotations

import asyncio
import csv
import hashlib
import io
import ipaddress
import json
import logging
import os
import re
import shutil
import threading
import time
from collections import Counter
from collections.abc import Sequence
from contextlib import asynccontextmanager
from datetime import UTC, datetime, timedelta
from pathlib import Path
from typing import Any, TypeVar

from fastapi import FastAPI, File, Query, Request, UploadFile, WebSocket, WebSocketDisconnect
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from fastapi.templating import Jinja2Templates
from pydantic import BaseModel, ValidationError
from starlette.types import ASGIApp, Receive, Scope, Send

from app.database import DB_PATH, execute, execute_change, fetch_all, init_db
from app.detector import (
    detect_bruteforce,
    detect_error_spike,
    detect_login_success_after_failures,
    detect_single,
)
from app.notifier import maybe_notify_alert
from app.parser import normalize_log
from app.playbook import get_playbook
from app.schemas import (
    AlertUpdatePayload,
    AssetCreatePayload,
    CaseCommentCreatePayload,
    CaseCreatePayload,
    CaseUpdatePayload,
    IngestJsonPayload,
    IocCreatePayload,
    IocUpdatePayload,
    LiveTailStartPayload,
    PolicyCreatePayload,
    PolicyUpdatePayload,
    ReportScheduleCreatePayload,
    ReportScheduleUpdatePayload,
    RestoreBackupPayload,
    SavedViewCreatePayload,
    SuppressionCreatePayload,
)
from app.tailer import LiveTailManager

AUTH_USER = os.getenv("SOC_DASHBOARD_USERNAME", "Change_me")
AUTH_PASSWORD = os.getenv("SOC_DASHBOARD_PASSWORD", "Change_me")
AUTH_SECRET = os.getenv("SOC_DASHBOARD_SECRET", "soc-dev-secret")
APP_VERSION = os.getenv("SOC_DASHBOARD_VERSION", "1.4.0")
INGEST_API_KEY = os.getenv("SOC_INGEST_API_KEY", "")
SESSION_COOKIE = "soc_session"
SESSION_ROLE_COOKIE = "soc_role"
SESSION_TOKEN = hashlib.sha256(f"{AUTH_USER}:{AUTH_PASSWORD}:{AUTH_SECRET}".encode()).hexdigest()
REPORTS_DIR = Path("data/reports")
BACKUPS_DIR = Path("data/backups")
LIVE_TAIL_ROOT = Path(os.getenv("SOC_LIVE_TAIL_ROOT", "data"))
MITRE_MAP: dict[str, tuple[str, str]] = {
    "failed-login-attempt": ("Credential Access", "T1110"),
    "possible-bruteforce": ("Credential Access", "T1110"),
    "possible-account-compromise": ("Persistence", "T1078"),
    "injection-or-traversal": ("Initial Access", "T1190"),
    "suspicious-user-agent": ("Reconnaissance", "T1595"),
    "admin-access-denied": ("Discovery", "T1087"),
    "error-spike-5xx": ("Impact", "T1499"),
}
_live_events: list[dict[str, Any]] = []
_live_events_lock = threading.Lock()
_event_seq = 0
_scheduler_thread: threading.Thread | None = None
_scheduler_stop = threading.Event()
_last_housekeeping_epoch = 0.0
_metrics: Counter[str] = Counter()
_ingest_hits: dict[str, list[float]] = {}
_ingest_lock = threading.Lock()
logger = logging.getLogger("soc_dashboard")
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(logging.Formatter("%(asctime)s %(levelname)s %(name)s %(message)s"))
    logger.addHandler(handler)
logger.setLevel(logging.INFO)
TModel = TypeVar("TModel", bound=BaseModel)
OPTIONAL_UPLOAD_FILE = File(default=None)


def startup() -> None:
    init_db()
    REPORTS_DIR.mkdir(parents=True, exist_ok=True)
    BACKUPS_DIR.mkdir(parents=True, exist_ok=True)
    _ensure_default_policies()
    _run_retention_housekeeping()
    _start_scheduler()


def shutdown() -> None:
    _stop_scheduler()


@asynccontextmanager
async def lifespan(_: FastAPI):
    startup()
    try:
        yield
    finally:
        shutdown()


templates = Jinja2Templates(directory="app/templates")


def _is_authenticated(request: Request) -> bool:
    return request.cookies.get(SESSION_COOKIE) == SESSION_TOKEN


def _current_role(request: Request) -> str:
    role = str(request.cookies.get(SESSION_ROLE_COOKIE) or "admin").strip().lower()
    return role if role in {"admin", "analyst"} else "admin"


def _ingest_key_valid(request: Request) -> bool:
    if not INGEST_API_KEY:
        return True
    header_key = request.headers.get("x-api-key") or ""
    return header_key == INGEST_API_KEY


def _env_bool(name: str, default: bool = False) -> bool:
    raw = os.getenv(name)
    if raw is None:
        return default
    return raw.strip().lower() in {"1", "true", "yes", "on"}


def _secure_cookies() -> bool:
    return _env_bool("SOC_COOKIE_SECURE", _env_bool("SOC_DASHBOARD_PRODUCTION", False))


def _security_warnings() -> list[str]:
    warnings: list[str] = []
    if AUTH_USER == "Change_me" or AUTH_PASSWORD == "Change_me":
        warnings.append("default_credentials")
    if AUTH_SECRET == "soc-dev-secret":
        warnings.append("default_secret")
    if not INGEST_API_KEY:
        warnings.append("ingest_api_key_disabled")
    if not _secure_cookies():
        warnings.append("secure_cookies_disabled")
    if _env_bool("SOC_LIVE_TAIL_ALLOW_ANY", False):
        warnings.append("live_tail_unrestricted")
    return warnings


def _inc_metric(name: str, value: int = 1) -> None:
    _metrics[name] += value


def _validate_payload(payload: Any, model_cls: type[TModel]) -> tuple[TModel | None, JSONResponse | None]:
    if isinstance(payload, model_cls):
        return payload, None
    try:
        return model_cls.model_validate(payload), None
    except ValidationError as exc:
        return None, JSONResponse({"detail": exc.errors()}, status_code=400)


def _ingest_rate_limited(request: Request) -> bool:
    max_per_minute = int(os.getenv("SOC_INGEST_RATE_LIMIT_PER_MIN", "120"))
    if max_per_minute <= 0:
        return False
    ip = request.client.host if request.client else "unknown"
    now = time.time()
    cutoff = now - 60
    with _ingest_lock:
        samples = _ingest_hits.setdefault(ip, [])
        samples[:] = [ts for ts in samples if ts >= cutoff]
        if len(samples) >= max_per_minute:
            _inc_metric("ingest_rate_limited_total")
            return True
        samples.append(now)
    return False


def _paginate(
    *,
    base_select: str,
    base_count: str,
    where: str,
    params: tuple[Any, ...],
    limit: int,
    offset: int,
    order_by: str,
) -> dict[str, Any]:
    total = int(fetch_all(f"{base_count} {where}", params)[0]["total"])
    rows = fetch_all(
        f"{base_select} {where} ORDER BY {order_by} LIMIT ? OFFSET ?",
        params + (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


class AuthMiddleware:
    def __init__(self, app_: ASGIApp):
        self.app = app_

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http":
            await self.app(scope, receive, send)
            return

        request = Request(scope, receive=receive)
        path = request.url.path
        public_paths = ("/login", "/api/health")
        if path.startswith("/static") or path in public_paths:
            await self.app(scope, receive, send)
            return

        if _is_authenticated(request):
            if path.startswith("/api/") and _current_role(request) == "analyst":
                admin_only_prefixes = ("/api/admin/", "/api/policies")
                if path.startswith(admin_only_prefixes):
                    forbidden_response = JSONResponse({"detail": "Forbidden for current role"}, status_code=403)
                    await forbidden_response(scope, receive, send)
                    return
            await self.app(scope, receive, send)
            return

        response: Response
        if path.startswith("/api/"):
            response = JSONResponse({"detail": "Unauthorized"}, status_code=401)
        else:
            response = RedirectResponse("/login", status_code=307)
        await response(scope, receive, send)




def login_page(request: Request, error: str | None = None):
    return templates.TemplateResponse(request, "login.html", {"error": error})


def _render_dashboard_page(request: Request, page: str, wallboard: bool = False):
    return templates.TemplateResponse(request, "index.html", {"wallboard": wallboard, "page": page})


async def login(request: Request):
    form = await request.form()
    username = str(form.get("username") or "")
    password = str(form.get("password") or "")
    if username != AUTH_USER or password != AUTH_PASSWORD:
        return templates.TemplateResponse(
            request,
            "login.html",
            {"error": "Invalid credentials"},
            status_code=401,
        )

    response = RedirectResponse("/overview", status_code=303)
    cookie_secure = _secure_cookies()
    response.set_cookie(SESSION_COOKIE, SESSION_TOKEN, httponly=True, samesite="strict", secure=cookie_secure)
    response.set_cookie(
        SESSION_ROLE_COOKIE,
        os.getenv("SOC_DASHBOARD_ROLE", "admin"),
        httponly=True,
        samesite="strict",
        secure=cookie_secure,
    )
    return response


def logout():
    response = RedirectResponse("/login", status_code=303)
    cookie_secure = _secure_cookies()
    response.delete_cookie(SESSION_COOKIE, secure=cookie_secure, httponly=True, samesite="strict")
    response.delete_cookie(SESSION_ROLE_COOKIE, secure=cookie_secure, httponly=True, samesite="strict")
    return response


def index(request: Request, wallboard: int = 0):
    return _render_dashboard_page(request, "overview", bool(wallboard))


def overview_page(request: Request):
    return _render_dashboard_page(request, "overview")


def investigations_page(request: Request):
    return _render_dashboard_page(request, "investigations")


def operations_page(request: Request):
    return _render_dashboard_page(request, "operations")


def reports_page(request: Request):
    return _render_dashboard_page(request, "reports")


def admin_page(request: Request):
    return _render_dashboard_page(request, "admin")


def wallboard(request: Request):
    return _render_dashboard_page(request, "overview", True)


def health():
    return {"status": "ok", "version": APP_VERSION}


async def ingest_logs(
    request: Request,
    file: UploadFile | None = OPTIONAL_UPLOAD_FILE,
):
    _inc_metric("ingest_requests_total")
    if _ingest_rate_limited(request):
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
    if not _ingest_key_valid(request):
        _inc_metric("ingest_auth_rejected_total")
        return JSONResponse({"detail": "Invalid API key"}, status_code=401)
    lines: list[str | dict[str, Any]] = []

    if file is not None:
        content_bytes = await file.read()
        max_bytes = int(os.getenv("SOC_INGEST_MAX_BYTES", str(5 * 1024 * 1024)))
        if len(content_bytes) > max_bytes:
            _inc_metric("ingest_payload_rejected_total")
            return JSONResponse({"detail": f"file too large (max={max_bytes} bytes)"}, status_code=413)
        content = content_bytes.decode("utf-8", errors="ignore")
        lines.extend([line for line in content.splitlines() if line.strip()])

    result = _store_logs(lines)
    _inc_metric("ingest_lines_total", int(result.get("ingested", 0)))
    _inc_metric("ingest_alerts_total", int(result.get("inserted_alerts", 0)))
    return result


def ingest_json(request: Request, payload: dict[str, list[str | dict[str, Any]]]):
    _inc_metric("ingest_requests_total")
    if _ingest_rate_limited(request):
        return JSONResponse({"detail": "rate limit exceeded"}, status_code=429)
    if not _ingest_key_valid(request):
        _inc_metric("ingest_auth_rejected_total")
        return JSONResponse({"detail": "Invalid API key"}, status_code=401)
    parsed, error = _validate_payload(payload, IngestJsonPayload)
    if error:
        return error
    assert parsed is not None
    lines = parsed.lines
    result = _store_logs(lines)
    _inc_metric("ingest_lines_total", int(result.get("ingested", 0)))
    _inc_metric("ingest_alerts_total", int(result.get("inserted_alerts", 0)))
    return result


def _store_logs(lines: Sequence[str | dict[str, Any]]) -> dict[str, int]:
    normalized_logs: list[dict[str, Any]] = []
    inserted_alerts = 0
    _cleanup_expired_suppressions()
    ioc_rows = _get_enabled_iocs()
    for line in lines:
        log = normalize_log(line)
        normalized_logs.append(log)
        log_id = execute(
            """
            INSERT INTO logs(ts, ip, username, user_agent, method, path, status_code, message, raw)
            VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                log["ts"],
                log["ip"],
                log["username"],
                log["user_agent"],
                log["method"],
                log["path"],
                log["status_code"],
                log["message"],
                log["raw"],
            ),
        )

        for alert in detect_single(log):
            inserted = _insert_alert(
                ts=log["ts"],
                severity=alert["severity"],
                alert_type=alert["alert_type"],
                ip=log["ip"],
                username=log["username"],
                user_agent=log["user_agent"],
                details=alert["details"],
                log_id=log_id,
                path=log.get("path"),
                explain=alert.get("explain"),
            )
            if inserted:
                inserted_alerts += 1

        for alert in _detect_ioc_matches(log, ioc_rows):
            inserted = _insert_alert(
                ts=log["ts"],
                severity=alert["severity"],
                alert_type=alert["alert_type"],
                ip=log["ip"],
                username=log["username"],
                user_agent=log["user_agent"],
                details=alert["details"],
                log_id=log_id,
                path=log.get("path"),
                explain=alert.get("explain"),
            )
            if inserted:
                inserted_alerts += 1

    batch_alerts = (
        detect_bruteforce(normalized_logs)
        + detect_login_success_after_failures(normalized_logs)
        + detect_error_spike(normalized_logs)
    )
    for alert in batch_alerts:
        inserted = _insert_alert(
            ts=alert["ts"],
            severity=alert["severity"],
            alert_type=alert["alert_type"],
            ip=alert["ip"],
            username=None,
            user_agent=None,
            details=alert["details"],
            log_id=None,
            path=None,
            explain=alert.get("explain"),
        )
        if inserted:
            inserted_alerts += 1

    return {
        "ingested": len(normalized_logs),
        "batch_alerts": len(batch_alerts),
        "inserted_alerts": inserted_alerts,
    }


def _insert_alert(
    ts: str,
    severity: str,
    alert_type: str,
    ip: str | None,
    username: str | None,
    user_agent: str | None,
    details: str,
    log_id: int | None,
    path: str | None,
    explain: str | None = None,
) -> bool:
    if _is_suppressed(ip=ip, alert_type=alert_type, path=path):
        return False

    mitre_tactic, mitre_technique = _mitre_for_alert_type(alert_type)
    asset = _find_asset_for_alert(ip=ip, path=path)
    asset_id = asset["id"] if asset else None

    existing = fetch_all(
        """
        SELECT id, ts, occurrences
        FROM alerts
        WHERE alert_type = ?
          AND COALESCE(ip, '') = COALESCE(?, '')
          AND details = ?
        ORDER BY ts DESC
        LIMIT 1
        """,
        (alert_type, ip, details),
    )

    if existing:
        latest = existing[0]
        try:
            current = datetime.fromisoformat(ts.replace("Z", "+00:00"))
            previous = datetime.fromisoformat(str(latest["ts"]).replace("Z", "+00:00"))
            if abs((current - previous).total_seconds()) <= 300:
                execute_change(
                    """
                    UPDATE alerts
                    SET occurrences = COALESCE(occurrences, 1) + 1, updated_at = ?
                    WHERE id = ?
                    """,
                    (ts, latest["id"]),
                )
                return False
        except ValueError:
            pass

    alert_id = execute(
        """
        INSERT INTO alerts(ts, severity, alert_type, ip, username, user_agent, details, log_id, status, updated_at, mitre_tactic, mitre_technique, asset_id, explain_text)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?, 'new', ?, ?, ?, ?, ?)
        """,
        (ts, severity, alert_type, ip, username, user_agent, details, log_id, ts, mitre_tactic, mitre_technique, asset_id, explain or _default_explain(alert_type, details)),
    )
    _record_incident_event(
        event_type="alert_created",
        severity=severity,
        alert_id=alert_id,
        ip=ip,
        title=f"Alert created: {alert_type}",
        details=details,
        actor="system",
        ts=ts,
    )
    maybe_notify_alert(
        {
            "ts": ts,
            "severity": severity,
            "alert_type": alert_type,
            "ip": ip,
            "details": details,
            "asset_id": asset_id,
            "mitre_tactic": mitre_tactic,
            "mitre_technique": mitre_technique,
        }
    )
    _apply_policies(
        {
            "id": alert_id,
            "ts": ts,
            "severity": severity,
            "alert_type": alert_type,
            "ip": ip,
            "details": details,
        }
    )
    if ip and alert_type != "correlated-attack-chain":
        _run_correlation_for_ip(ts=ts, ip=ip)
    return True


def _default_explain(alert_type: str, details: str) -> str:
    return f"Rule `{alert_type}` matched. Evidence: {details}"


def _risk_weight(alert_type: str, severity: str) -> int:
    base = {
        "possible-account-compromise": 8,
        "possible-bruteforce": 5,
        "injection-or-traversal": 5,
        "error-spike-5xx": 4,
        "admin-access-denied": 3,
        "suspicious-user-agent": 2,
        "failed-login-attempt": 1,
        "ioc-match": 6,
        "correlated-attack-chain": 10,
    }.get(alert_type, 1)
    severity_bonus = {"critical": 4, "high": 2, "medium": 1}.get(severity, 0)
    return base + severity_bonus


def _run_correlation_for_ip(ts: str, ip: str) -> None:
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        dt = datetime.now(UTC)
    start = (dt - timedelta(minutes=20)).isoformat()
    rows = fetch_all(
        """
        SELECT alert_type, severity
        FROM alerts
        WHERE ip = ? AND ts >= ?
        ORDER BY ts DESC
        LIMIT 200
        """,
        (ip, start),
    )
    types = {str(r.get("alert_type") or "") for r in rows}
    if len(types) < 3:
        return
    interesting = {"possible-bruteforce", "possible-account-compromise", "injection-or-traversal", "suspicious-user-agent", "ioc-match"}
    matched = sorted(types.intersection(interesting))
    if len(matched) < 2:
        return
    details = f"Correlated chain for IP {ip}: {', '.join(matched)} in <=20m"
    severity = "critical" if "possible-account-compromise" in matched else "high"
    _insert_alert(
        ts=ts,
        severity=severity,
        alert_type="correlated-attack-chain",
        ip=ip,
        username=None,
        user_agent=None,
        details=details,
        log_id=None,
        path=None,
        explain="Correlation engine matched a multi-step attack pattern for same source IP.",
    )


def _get_enabled_iocs() -> list[dict[str, Any]]:
    return fetch_all(
        """
        SELECT id, ioc_type, ioc_value, severity_override
        FROM ioc_watchlist
        WHERE enabled = 1
        """
    )


def _detect_ioc_matches(log: dict[str, Any], ioc_rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    ip = str(log.get("ip") or "")
    path = str(log.get("path") or "")
    ua = str(log.get("user_agent") or "")
    message = str(log.get("message") or "")
    for row in ioc_rows:
        ioc_type = str(row.get("ioc_type") or "").lower()
        value = str(row.get("ioc_value") or "").strip()
        sev = str(row.get("severity_override") or "high").lower()
        if not value:
            continue
        matched = False
        if ioc_type == "ip":
            matched = ip == value
        elif ioc_type == "path":
            matched = value.lower() in path.lower()
        elif ioc_type == "user_agent":
            matched = value.lower() in ua.lower()
        elif ioc_type == "text":
            matched = value.lower() in message.lower() or value.lower() in path.lower()
        if matched:
            out.append(
                {
                    "severity": sev,
                    "alert_type": "ioc-match",
                    "details": f"IOC match ({ioc_type}): {value}",
                    "explain": f"Watchlist IOC type={ioc_type} value={value} matched current log.",
                }
            )
    return out


def _condition_matches(condition: str, alert: dict[str, Any], stats: dict[str, Any]) -> bool:
    # Very small DSL: key==value combined by AND.
    # Supported keys: severity, alert_type, ip, open_alerts, high_alerts, compromise_count.
    if not condition:
        return False
    clauses = [c.strip() for c in condition.split("AND") if c.strip()]
    for clause in clauses:
        if "==" not in clause:
            return False
        key, raw_value = [part.strip() for part in clause.split("==", 1)]
        value = raw_value.strip().strip('"').strip("'")
        if key in {"open_alerts", "high_alerts", "compromise_count"}:
            actual = str(stats.get(key))
        else:
            actual = str(alert.get(key) or "")
        if actual != value:
            return False
    return True


def _policy_stats() -> dict[str, int]:
    return {
        "open_alerts": int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE status IN ('new', 'investigating')")[0]["c"]),
        "high_alerts": int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE severity = 'high'")[0]["c"]),
        "compromise_count": int(
            fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE alert_type = 'possible-account-compromise'")[0]["c"]
        ),
    }


def _apply_policies(alert: dict[str, Any]) -> None:
    rows = fetch_all(
        """
        SELECT id, name, condition_expr, action_type, action_payload
        FROM policies
        WHERE enabled = 1
        """
    )
    if not rows:
        return
    stats = _policy_stats()
    for row in rows:
        condition = str(row.get("condition_expr") or "")
        if not _condition_matches(condition, alert, stats):
            continue
        action_type = str(row.get("action_type") or "")
        payload_raw = str(row.get("action_payload") or "{}")
        try:
            payload = json.loads(payload_raw) if payload_raw else {}
        except json.JSONDecodeError:
            payload = {}
        if action_type == "create_case":
            title = str(payload.get("title") or f"Auto case: {alert.get('alert_type')}")
            owner = str(payload.get("owner") or "soc-auto")
            priority = str(payload.get("priority") or "high")
            case = create_case({"title": title, "owner": owner, "priority": priority})
            if isinstance(case, dict) and case.get("id"):
                link_case_alert(int(case["id"]), int(alert["id"]))
        elif action_type == "escalate_alert":
            update_alert(int(alert["id"]), {"status": "investigating", "assignee": str(payload.get("assignee") or "soc-escalation")})
        elif action_type == "notify_only":
            _publish_live_event("policy_notify", {"policy": row.get("name"), "alert_id": alert.get("id")})


def _publish_live_event(event_type: str, payload: dict[str, Any]) -> None:
    global _event_seq
    with _live_events_lock:
        _event_seq += 1
        _live_events.append(
            {
                "seq": _event_seq,
                "ts": datetime.now(UTC).isoformat(),
                "event_type": event_type,
                "payload": payload,
            }
        )
        if len(_live_events) > 2000:
            del _live_events[:500]


_REPORT_I18N: dict[str, dict[str, str]] = {
    "en": {
        "title": "Daily SOC Report",
        "generated": "Generated at",
        "total_logs": "Total Logs",
        "total_alerts": "Total Alerts",
        "high_alerts": "High Alerts",
        "open_alerts": "Open Alerts",
        "critical_open_assets": "Critical Assets Open",
        "latest_alerts": "Latest Alerts",
        "time": "Time",
        "severity": "Severity",
        "type": "Type",
        "status": "Status",
        "details": "Details",
    },
    "fr": {
        "title": "Rapport SOC quotidien",
        "generated": "Généré à",
        "total_logs": "Logs totales",
        "total_alerts": "Alertes totales",
        "high_alerts": "Alertes élevées",
        "open_alerts": "Alertes ouvertes",
        "critical_open_assets": "Actifs critiques ouverts",
        "latest_alerts": "Dernières alertes",
        "time": "Heure",
        "severity": "Sévérité",
        "type": "Type",
        "status": "Statut",
        "details": "Détails",
    },
    "de": {"title": "Täglicher SOC-Bericht", "generated": "Erstellt am", "total_logs": "Logs gesamt", "total_alerts": "Alarme gesamt", "high_alerts": "Hohe Alarme", "open_alerts": "Offene Alarme", "critical_open_assets": "Offene kritische Assets", "latest_alerts": "Neueste Alarme", "time": "Zeit", "severity": "Schweregrad", "type": "Typ", "status": "Status", "details": "Details"},
    "es": {"title": "Informe SOC diario", "generated": "Generado a las", "total_logs": "Logs totales", "total_alerts": "Alertas totales", "high_alerts": "Alertas altas", "open_alerts": "Alertas abiertas", "critical_open_assets": "Activos críticos abiertos", "latest_alerts": "Últimas alertas", "time": "Hora", "severity": "Severidad", "type": "Tipo", "status": "Estado", "details": "Detalles"},
    "ja": {"title": "日次SOCレポート", "generated": "生成日時", "total_logs": "総ログ数", "total_alerts": "総アラート数", "high_alerts": "高重大度アラート", "open_alerts": "未解決アラート", "critical_open_assets": "対応中の重要資産", "latest_alerts": "最新アラート", "time": "時刻", "severity": "重大度", "type": "種別", "status": "状態", "details": "詳細"},
    "zh": {"title": "每日 SOC 报告", "generated": "生成时间", "total_logs": "日志总数", "total_alerts": "告警总数", "high_alerts": "高危告警", "open_alerts": "未关闭告警", "critical_open_assets": "关键资产开放数", "latest_alerts": "最新告警", "time": "时间", "severity": "严重级别", "type": "类型", "status": "状态", "details": "详情"},
    "hi": {"title": "दैनिक SOC रिपोर्ट", "generated": "जनरेट किया गया", "total_logs": "कुल लॉग", "total_alerts": "कुल अलर्ट", "high_alerts": "उच्च अलर्ट", "open_alerts": "खुले अलर्ट", "critical_open_assets": "खुले महत्वपूर्ण एसेट", "latest_alerts": "नवीनतम अलर्ट", "time": "समय", "severity": "गंभीरता", "type": "प्रकार", "status": "स्थिति", "details": "विवरण"},
    "ar": {"title": "تقرير SOC اليومي", "generated": "تم الإنشاء في", "total_logs": "إجمالي السجلات", "total_alerts": "إجمالي التنبيهات", "high_alerts": "التنبيهات العالية", "open_alerts": "التنبيهات المفتوحة", "critical_open_assets": "الأصول الحرجة المفتوحة", "latest_alerts": "أحدث التنبيهات", "time": "الوقت", "severity": "الخطورة", "type": "النوع", "status": "الحالة", "details": "التفاصيل"},
    "ru": {"title": "Ежедневный SOC-отчет", "generated": "Сформировано", "total_logs": "Всего логов", "total_alerts": "Всего алертов", "high_alerts": "Высокие алерты", "open_alerts": "Открытые алерты", "critical_open_assets": "Открытые критичные активы", "latest_alerts": "Последние алерты", "time": "Время", "severity": "Критичность", "type": "Тип", "status": "Статус", "details": "Детали"},
}


def _render_daily_report_html(report: dict[str, Any], lang: str = "en") -> str:
    labels = _REPORT_I18N.get(lang, _REPORT_I18N["en"])
    s = report["stats"]
    alert_rows = "".join(
        f"<tr><td>{a['ts']}</td><td>{a['severity']}</td><td>{a['alert_type']}</td><td>{a.get('ip') or '-'}</td><td>{a.get('status') or '-'}</td><td>{a.get('occurrences') or 1}</td><td>{a.get('details') or '-'}</td></tr>"
        for a in report["latest_alerts"][:50]
    )
    return f"""
    <!doctype html>
    <html lang="{lang}"><head><meta charset="utf-8"/><title>{labels['title']}</title>
    <style>
      body {{ font-family: Arial, sans-serif; margin: 24px; color: #0f2235; }}
      h1 {{ margin: 0 0 8px; }} .meta {{ color: #4c6278; margin-bottom: 18px; }}
      .kpi {{ display: inline-block; margin: 6px 14px 6px 0; padding: 10px 12px; border: 1px solid #d2dde8; border-radius: 8px; }}
      table {{ width: 100%; border-collapse: collapse; margin-top: 10px; font-size: 13px; }}
      th,td {{ border: 1px solid #d6e1eb; padding: 6px; text-align: left; vertical-align: top; }}
      th {{ background: #eef4fa; }}
      @media print {{ body {{ margin: 8mm; }} }}
    </style></head><body>
      <h1>{labels['title']}</h1>
      <div class="meta">{labels['generated']} {report['generated_at']}</div>
      <div class="kpi"><strong>{labels['total_logs']}:</strong> {s['total_logs']}</div>
      <div class="kpi"><strong>{labels['total_alerts']}:</strong> {s['total_alerts']}</div>
      <div class="kpi"><strong>{labels['high_alerts']}:</strong> {s['high_alerts']}</div>
      <div class="kpi"><strong>{labels['open_alerts']}:</strong> {s['open_alerts']}</div>
      <div class="kpi"><strong>{labels['critical_open_assets']}:</strong> {s.get('critical_open_assets', 0)}</div>
      <h2>{labels['latest_alerts']}</h2>
      <table>
        <thead><tr><th>{labels['time']}</th><th>{labels['severity']}</th><th>{labels['type']}</th><th>IP</th><th>{labels['status']}</th><th>Occ</th><th>{labels['details']}</th></tr></thead>
        <tbody>{alert_rows}</tbody>
      </table>
    </body></html>
    """


def _run_scheduled_report(schedule_id: int) -> dict[str, Any]:
    report = daily_report_data()
    timestamp = datetime.now(UTC).strftime("%Y%m%d-%H%M%S")
    output_path = REPORTS_DIR / f"daily-report-{schedule_id}-{timestamp}.html"
    html = _render_daily_report_html(report)
    output_path.write_text(html, encoding="utf-8")
    execute(
        """
        INSERT INTO report_runs(schedule_id, ts, output_path, status)
        VALUES(?, ?, ?, 'ok')
        """,
        (schedule_id, datetime.now(UTC).isoformat(), str(output_path)),
    )
    _publish_live_event(
        "report_generated",
        {"schedule_id": schedule_id, "output_path": str(output_path)},
    )
    return {"output_path": str(output_path)}


def _scheduler_loop() -> None:
    global _last_housekeeping_epoch
    while not _scheduler_stop.is_set():
        try:
            _auto_escalate_stale_alerts()
            now_epoch = time.time()
            if now_epoch - _last_housekeeping_epoch > 300:
                _run_retention_housekeeping()
                _last_housekeeping_epoch = now_epoch
            now = datetime.now(UTC)
            rows = fetch_all(
                """
                SELECT id, hour_utc, minute_utc, enabled, last_run_date
                FROM report_schedules
                WHERE enabled = 1
                """
            )
            today = now.strftime("%Y-%m-%d")
            for row in rows:
                if int(row["hour_utc"]) == now.hour and int(row["minute_utc"]) == now.minute:
                    if row.get("last_run_date") == today:
                        continue
                    schedule_id = int(row["id"])
                    try:
                        _run_scheduled_report(schedule_id)
                        execute_change(
                            "UPDATE report_schedules SET last_run_date = ? WHERE id = ?",
                            (today, schedule_id),
                        )
                    except Exception as exc:
                        logger.exception("scheduler.report_failed schedule_id=%s error=%s", schedule_id, exc)
                        _inc_metric("scheduler_report_failed_total")
                        execute(
                            """
                            INSERT INTO report_runs(schedule_id, ts, output_path, status)
                            VALUES(?, ?, ?, 'failed')
                            """,
                            (schedule_id, datetime.now(UTC).isoformat(), ""),
                        )
        except Exception as exc:
            logger.exception("scheduler.loop_error error=%s", exc)
            _inc_metric("scheduler_errors_total")
        time.sleep(20)


def _auto_escalate_stale_alerts() -> None:
    threshold_minutes = int(os.getenv("SOC_ESCALATE_MINUTES", "20"))
    assignee = os.getenv("SOC_ESCALATE_ASSIGNEE", "soc-escalation")
    now = datetime.now(UTC)
    rows = fetch_all(
        """
        SELECT id, ts, severity, status
        FROM alerts
        WHERE status = 'new' AND severity IN ('high', 'critical')
        """
    )
    for row in rows:
        try:
            ts = datetime.fromisoformat(str(row["ts"]).replace("Z", "+00:00"))
        except ValueError:
            continue
        if (now - ts).total_seconds() < threshold_minutes * 60:
            continue
        update_alert(int(row["id"]), {"status": "investigating", "assignee": assignee})
        _publish_live_event("alert_escalated", {"alert_id": row["id"], "assignee": assignee})


def _ensure_default_policies() -> None:
    rows = fetch_all("SELECT id FROM policies")
    if rows:
        return
    now = datetime.now(UTC).isoformat()
    execute(
        """
        INSERT INTO policies(name, enabled, condition_expr, action_type, action_payload, created_at)
        VALUES(?, 1, ?, ?, ?, ?)
        """,
        (
            "Auto case on compromise",
            "alert_type==possible-account-compromise",
            "create_case",
            json.dumps({"title": "Auto: possible account compromise", "owner": "soc-auto", "priority": "critical"}),
            now,
        ),
    )


def _safe_backup_name(name: str) -> str:
    return Path(name).name


def _record_backup_run(action: str, status: str, backup_path: str, details: str | None = None) -> None:
    execute(
        """
        INSERT INTO backup_runs(ts, backup_path, action, status, details)
        VALUES(?, ?, ?, ?, ?)
        """,
        (datetime.now(UTC).isoformat(), backup_path, action, status, details),
    )


def _validate_live_tail_path(file_path: str) -> str:
    candidate = Path(file_path).expanduser().resolve()
    if _env_bool("SOC_LIVE_TAIL_ALLOW_ANY", False):
        return str(candidate)

    allowed_root = LIVE_TAIL_ROOT.expanduser().resolve()
    try:
        candidate.relative_to(allowed_root)
    except ValueError as exc:
        raise ValueError(f"Live tail path must be under {allowed_root}") from exc
    return str(candidate)


def _run_retention_housekeeping() -> None:
    now = datetime.now(UTC)
    logs_days = int(os.getenv("SOC_RETENTION_LOGS_DAYS", "30"))
    alerts_days = int(os.getenv("SOC_RETENTION_ALERTS_DAYS", "90"))
    events_days = int(os.getenv("SOC_RETENTION_EVENTS_DAYS", "90"))
    reports_days = int(os.getenv("SOC_RETENTION_REPORTS_DAYS", "30"))
    backups_days = int(os.getenv("SOC_RETENTION_BACKUPS_DAYS", "30"))

    logs_before = (now - timedelta(days=logs_days)).isoformat()
    alerts_before = (now - timedelta(days=alerts_days)).isoformat()
    events_before = (now - timedelta(days=events_days)).isoformat()
    reports_before = (now - timedelta(days=reports_days)).isoformat()
    backups_before = (now - timedelta(days=backups_days)).isoformat()

    deleted_logs = execute_change("DELETE FROM logs WHERE ts < ?", (logs_before,))
    deleted_alerts = execute_change("DELETE FROM alerts WHERE ts < ?", (alerts_before,))
    deleted_events = execute_change("DELETE FROM incident_events WHERE ts < ?", (events_before,))
    deleted_report_runs = execute_change("DELETE FROM report_runs WHERE ts < ?", (reports_before,))
    deleted_backup_rows = execute_change("DELETE FROM backup_runs WHERE ts < ?", (backups_before,))

    removed_reports = 0
    report_cutoff = now - timedelta(days=reports_days)
    if REPORTS_DIR.exists():
        for path in REPORTS_DIR.glob("*.html"):
            try:
                if datetime.fromtimestamp(path.stat().st_mtime, tz=UTC) < report_cutoff:
                    path.unlink(missing_ok=True)
                    removed_reports += 1
            except OSError:
                continue

    removed_backups = 0
    backup_cutoff = now - timedelta(days=backups_days)
    if BACKUPS_DIR.exists():
        for path in BACKUPS_DIR.glob("*.db"):
            try:
                if datetime.fromtimestamp(path.stat().st_mtime, tz=UTC) < backup_cutoff:
                    path.unlink(missing_ok=True)
                    removed_backups += 1
            except OSError:
                continue

    if any([deleted_logs, deleted_alerts, deleted_events, deleted_report_runs, deleted_backup_rows, removed_reports, removed_backups]):
        logger.info(
            "housekeeping.deleted logs=%s alerts=%s events=%s report_runs=%s backup_runs=%s report_files=%s backup_files=%s",
            deleted_logs,
            deleted_alerts,
            deleted_events,
            deleted_report_runs,
            deleted_backup_rows,
            removed_reports,
            removed_backups,
        )


def _parse_policy_payload(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    text = str(raw or "").strip()
    if not text:
        return {}
    try:
        value = json.loads(text)
    except json.JSONDecodeError:
        return {}
    return value if isinstance(value, dict) else {}


def _start_scheduler() -> None:
    global _scheduler_thread
    if _scheduler_thread and _scheduler_thread.is_alive():
        return
    _scheduler_stop.clear()
    _scheduler_thread = threading.Thread(target=_scheduler_loop, daemon=True)
    _scheduler_thread.start()


def _stop_scheduler() -> None:
    _scheduler_stop.set()


def _mitre_for_alert_type(alert_type: str) -> tuple[str | None, str | None]:
    return MITRE_MAP.get(alert_type, (None, None))


def _cleanup_expired_suppressions() -> None:
    now_iso = datetime.now(UTC).isoformat()
    execute_change("DELETE FROM suppressions WHERE expires_at <= ?", (now_iso,))


def _is_suppressed(ip: str | None, alert_type: str, path: str | None) -> bool:
    now_iso = datetime.now(UTC).isoformat()
    rows = fetch_all(
        """
        SELECT ip, alert_type, path_pattern
        FROM suppressions
        WHERE expires_at > ?
        """,
        (now_iso,),
    )
    ip_value = ip or ""
    path_value = (path or "").lower()
    for row in rows:
        row_ip = str(row.get("ip") or "")
        row_type = str(row.get("alert_type") or "")
        row_path_pattern = str(row.get("path_pattern") or "").lower()
        ip_match = not row_ip or row_ip == ip_value
        type_match = not row_type or row_type == alert_type
        path_match = not row_path_pattern or row_path_pattern in path_value
        if ip_match and type_match and path_match:
            return True
    return False


def _find_asset_for_alert(ip: str | None, path: str | None) -> dict[str, Any] | None:
    assets = fetch_all("SELECT id, ip_cidr, path_prefix FROM assets")
    ip_value = ip or ""
    path_value = (path or "").lower()
    for asset in assets:
        ip_cidr = (asset.get("ip_cidr") or "").strip()
        path_prefix = (asset.get("path_prefix") or "").strip().lower()

        ip_match = False
        path_match = False

        if ip_cidr:
            try:
                if "/" in ip_cidr:
                    ip_match = bool(ip_value) and ipaddress.ip_address(ip_value) in ipaddress.ip_network(ip_cidr, strict=False)
                else:
                    ip_match = ip_value == ip_cidr
            except ValueError:
                ip_match = False
        if path_prefix:
            path_match = bool(path_value) and path_value.startswith(path_prefix)

        if (ip_cidr and ip_match) or (path_prefix and path_match):
            return asset
    return None


def _record_incident_event(
    event_type: str,
    severity: str | None,
    alert_id: int | None,
    ip: str | None,
    title: str,
    details: str | None,
    actor: str,
    ts: str | None = None,
) -> None:
    event_ts = ts or datetime.now(UTC).isoformat()
    execute(
        """
        INSERT INTO incident_events(ts, event_type, severity, alert_id, ip, title, details, actor)
        VALUES(?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (event_ts, event_type, severity, alert_id, ip, title, details, actor),
    )
    _publish_live_event(
        "incident_event",
        {
            "event_type": event_type,
            "severity": severity,
            "alert_id": alert_id,
            "ip": ip,
            "title": title,
            "actor": actor,
            "ts": event_ts,
        },
    )


tail_manager = LiveTailManager(store_logs_fn=lambda lines: _store_logs(lines))


def _parse_query_dsl(dsl: str | None) -> dict[str, str]:
    if not dsl:
        return {}
    # Format: key:value key2:\"multi words\"
    tokens = re.findall(r'([a-zA-Z_]+):("[^"]+"|\S+)', dsl)
    out: dict[str, str] = {}
    for key, raw_value in tokens:
        value = raw_value.strip().strip('"')
        if value:
            out[key.lower()] = value
    return out


def _pick(explicit: Any, parsed: dict[str, str], keys: list[str]) -> Any:
    if explicit is not None and explicit != "":
        return explicit
    for key in keys:
        if key in parsed:
            return parsed[key]
    return explicit


def _build_where(
    searchable_columns: list[str],
    ip: str | None,
    user_agent: str | None,
    username: str | None,
    q: str | None,
    start: str | None,
    end: str | None,
    extra: dict[str, str] | None = None,
):
    clauses: list[str] = []
    params: list[Any] = []

    if ip:
        clauses.append("ip = ?")
        params.append(ip)
    if user_agent:
        clauses.append("COALESCE(user_agent, '') LIKE ?")
        params.append(f"%{user_agent}%")
    if username:
        clauses.append("username = ?")
        params.append(username)
    if q and searchable_columns:
        query_clauses = [f"COALESCE({column}, '') LIKE ?" for column in searchable_columns]
        clauses.append("(" + " OR ".join(query_clauses) + ")")
        params.extend([f"%{q}%"] * len(searchable_columns))
    if start:
        clauses.append("ts >= ?")
        params.append(start)
    if end:
        clauses.append("ts <= ?")
        params.append(end)

    if extra:
        for key, value in extra.items():
            clauses.append(f"{key} = ?")
            params.append(value)

    where = " WHERE " + " AND ".join(clauses) if clauses else ""
    return where, tuple(params)


def get_logs(
    limit: int = 200,
    offset: int = 0,
    ip: str | None = None,
    user_agent: str | None = None,
    username: str | None = None,
    method: str | None = None,
    status_code: int | None = None,
    q: str | None = None,
    dsl: str | None = None,
    start: str | None = None,
    end: str | None = None,
):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    parsed = _parse_query_dsl(dsl)
    ip = _pick(ip, parsed, ["ip"])
    user_agent = _pick(user_agent, parsed, ["ua", "user_agent"])
    username = _pick(username, parsed, ["user", "username"])
    method = _pick(method, parsed, ["method"])
    q = _pick(q, parsed, ["q", "text", "search"])
    start = _pick(start, parsed, ["start", "from"])
    end = _pick(end, parsed, ["end", "to"])
    if status_code is None:
        code_val = _pick(None, parsed, ["code", "status", "status_code"])
        if code_val is not None:
            try:
                status_code = int(str(code_val))
            except ValueError:
                status_code = None

    extra: dict[str, str] = {}
    if method:
        extra["method"] = method.upper()
    if status_code is not None:
        extra["status_code"] = str(status_code)

    where, params = _build_where(
        searchable_columns=["message", "path", "raw"],
        ip=ip,
        user_agent=user_agent,
        username=username,
        q=q,
        start=start,
        end=end,
        extra=extra,
    )
    return _paginate(
        base_select="""
        SELECT id, ts, ip, username, user_agent, method, path, status_code, message
        FROM logs
        """,
        base_count="SELECT COUNT(*) AS total FROM logs",
        where=where,
        params=params,
        limit=limit,
        offset=offset,
        order_by="ts DESC",
    )


def get_alerts(
    limit: int = 200,
    offset: int = 0,
    severity: str | None = None,
    alert_type: str | None = None,
    status: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    username: str | None = None,
    q: str | None = None,
    dsl: str | None = None,
    start: str | None = None,
    end: str | None = None,
):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    parsed = _parse_query_dsl(dsl)
    severity = _pick(severity, parsed, ["severity", "sev"])
    alert_type = _pick(alert_type, parsed, ["type", "alert_type"])
    status = _pick(status, parsed, ["state", "status"])
    ip = _pick(ip, parsed, ["ip"])
    user_agent = _pick(user_agent, parsed, ["ua", "user_agent"])
    username = _pick(username, parsed, ["user", "username"])
    q = _pick(q, parsed, ["q", "text", "search"])
    start = _pick(start, parsed, ["start", "from"])
    end = _pick(end, parsed, ["end", "to"])

    extra: dict[str, str] = {}
    if severity:
        extra["severity"] = severity
    if alert_type:
        extra["alert_type"] = alert_type
    if status:
        extra["status"] = status

    where, params = _build_where(
        searchable_columns=["details", "alert_type"],
        ip=ip,
        user_agent=user_agent,
        username=username,
        q=q,
        start=start,
        end=end,
        extra=extra,
    )
    page = _paginate(
        base_select="""
        SELECT id, ts, severity, alert_type, ip, username, user_agent, details, status, assignee, resolution_note, occurrences, updated_at, mitre_tactic, mitre_technique, asset_id, explain_text
        FROM alerts
        """,
        base_count="SELECT COUNT(*) AS total FROM alerts",
        where=where,
        params=params,
        limit=limit,
        offset=offset,
        order_by="ts DESC",
    )
    rows = page["items"]
    asset_ids = [row["asset_id"] for row in rows if row.get("asset_id")]
    assets_by_id: dict[int, dict[str, Any]] = {}
    if asset_ids:
        placeholders = ",".join("?" for _ in asset_ids)
        assets = fetch_all(f"SELECT id, name, criticality, owner FROM assets WHERE id IN ({placeholders})", tuple(asset_ids))
        assets_by_id = {int(a["id"]): a for a in assets}
    for row in rows:
        asset = assets_by_id.get(int(row["asset_id"])) if row.get("asset_id") else None
        row["asset_name"] = asset.get("name") if asset else None
        row["asset_criticality"] = asset.get("criticality") if asset else None
    return page


def get_stats():
    total_logs = int(fetch_all("SELECT COUNT(*) AS c FROM logs")[0]["c"])
    total_alerts = int(fetch_all("SELECT COUNT(*) AS c FROM alerts")[0]["c"])
    high_alerts = int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE severity = 'high'")[0]["c"])
    failed_logins = int(
        fetch_all(
            """
            SELECT COUNT(*) AS c
            FROM logs
            WHERE status_code IN (401, 403)
              AND LOWER(COALESCE(path, '')) LIKE '%login%'
            """
        )[0]["c"]
    )
    failed_login_alerts = int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE alert_type = 'failed-login-attempt'")[0]["c"])
    failed_logins = max(failed_logins, failed_login_alerts)
    bruteforce_count = int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE alert_type = 'possible-bruteforce'")[0]["c"])
    compromise_count = int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE alert_type = 'possible-account-compromise'")[0]["c"])
    unique_ips = int(fetch_all("SELECT COUNT(DISTINCT ip) AS c FROM logs WHERE ip IS NOT NULL AND ip != ''")[0]["c"])
    http_5xx = int(fetch_all("SELECT COUNT(*) AS c FROM logs WHERE status_code >= 500")[0]["c"])
    open_alerts = int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE status IN ('new', 'investigating')")[0]["c"])
    resolved_alerts = int(fetch_all("SELECT COUNT(*) AS c FROM alerts WHERE status = 'resolved'")[0]["c"])
    critical_open_assets = int(
        fetch_all(
            """
            SELECT COUNT(*) AS c
            FROM alerts a
            LEFT JOIN assets s ON s.id = a.asset_id
            WHERE s.criticality = 'critical'
              AND a.status IN ('new', 'investigating')
            """
        )[0]["c"]
    )

    top_ips_rows = fetch_all(
        """
        SELECT COALESCE(ip, 'unknown') AS entity, COUNT(*) AS c
        FROM logs
        GROUP BY entity
        ORDER BY c DESC
        LIMIT 8
        """
    )
    top_ua_rows = fetch_all(
        """
        SELECT COALESCE(user_agent, 'unknown') AS entity, COUNT(*) AS c
        FROM logs
        GROUP BY entity
        ORDER BY c DESC
        LIMIT 8
        """
    )
    timeline_rows = fetch_all(
        """
        SELECT SUBSTR(ts, 1, 13) || ':00' AS bucket, COUNT(*) AS c
        FROM logs
        GROUP BY bucket
        ORDER BY bucket ASC
        """
    )

    risk_counter: Counter[str] = Counter()
    risk_rows = fetch_all("SELECT COALESCE(ip, 'unknown') AS ip, alert_type, severity FROM alerts")
    for row in risk_rows:
        risk_counter[str(row.get("ip") or "unknown")] += _risk_weight(
            str(row.get("alert_type") or ""),
            str(row.get("severity") or ""),
        )

    return {
        "total_logs": total_logs,
        "total_alerts": total_alerts,
        "high_alerts": high_alerts,
        "failed_logins": failed_logins,
        "bruteforce_count": bruteforce_count,
        "compromise_count": compromise_count,
        "unique_ips": unique_ips,
        "http_5xx": http_5xx,
        "open_alerts": open_alerts,
        "resolved_alerts": resolved_alerts,
        "critical_open_assets": critical_open_assets,
        "top_ips": [(row["entity"], int(row["c"])) for row in top_ips_rows],
        "top_user_agents": [(row["entity"], int(row["c"])) for row in top_ua_rows],
        "top_risky_ips": risk_counter.most_common(8),
        "timeline": [(row["bucket"], int(row["c"])) for row in timeline_rows],
    }


def update_alert(alert_id: int, payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, AlertUpdatePayload)
    if error:
        return error
    status = parsed.status if parsed else None
    assignee = parsed.assignee if parsed else None
    resolution_note = parsed.resolution_note if parsed else None

    exists = fetch_all("SELECT id FROM alerts WHERE id = ?", (alert_id,))
    if not exists:
        return JSONResponse({"detail": "Alert not found"}, status_code=404)

    fields: list[str] = []
    params: list[Any] = []

    if status is not None:
        status_str = str(status)
        fields.append("status = ?")
        params.append(status_str)
    if assignee is not None:
        fields.append("assignee = ?")
        params.append(str(assignee)[:120] or None)
    if resolution_note is not None:
        fields.append("resolution_note = ?")
        params.append(str(resolution_note)[:1000] or None)

    fields.append("updated_at = ?")
    params.append(datetime.now(UTC).isoformat())
    params.append(alert_id)

    execute_change(f"UPDATE alerts SET {', '.join(fields)} WHERE id = ?", tuple(params))
    row = fetch_all(
        """
        SELECT id, ts, severity, alert_type, ip, username, user_agent, details, status, assignee, resolution_note, occurrences, updated_at, mitre_tactic, mitre_technique, asset_id, explain_text
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,),
    )[0]
    _record_incident_event(
        event_type="alert_updated",
        severity=row.get("severity"),
        alert_id=alert_id,
        ip=row.get("ip"),
        title=f"Alert updated: {row.get('alert_type')}",
        details=f"status={row.get('status')} assignee={row.get('assignee')}",
        actor="analyst",
    )
    return row


def risk_entities(since_hours: int = Query(default=24, ge=1, le=24 * 30)):
    now = datetime.now(UTC)
    since = (now - timedelta(hours=since_hours)).isoformat()
    previous = (now - timedelta(hours=since_hours * 2)).isoformat()
    rows = fetch_all(
        """
        SELECT ts, ip, username, asset_id, alert_type, severity
        FROM alerts
        WHERE ts >= ?
        """,
        (previous,),
    )
    assets = fetch_all("SELECT id, name FROM assets")
    asset_by_id = {int(a["id"]): str(a.get("name") or f"asset-{a['id']}") for a in assets}

    current_ip: Counter[str] = Counter()
    current_user: Counter[str] = Counter()
    current_asset: Counter[str] = Counter()
    previous_ip: Counter[str] = Counter()
    previous_user: Counter[str] = Counter()
    previous_asset: Counter[str] = Counter()

    for row in rows:
        ts = str(row.get("ts") or "")
        weight = _risk_weight(str(row.get("alert_type") or ""), str(row.get("severity") or ""))
        ip = str(row.get("ip") or "unknown")
        user = str(row.get("username") or "unknown")
        asset_name = asset_by_id.get(int(row["asset_id"]), "unmapped") if row.get("asset_id") else "unmapped"
        if ts >= since:
            current_ip[ip] += weight
            current_user[user] += weight
            current_asset[asset_name] += weight
        else:
            previous_ip[ip] += weight
            previous_user[user] += weight
            previous_asset[asset_name] += weight

    def _build(items: list[tuple[str, int]], previous_counter: Counter, limit: int = 10) -> list[dict[str, Any]]:
        out: list[dict[str, Any]] = []
        for key, score in items[:limit]:
            prev = int(previous_counter.get(key, 0))
            out.append({"entity": key, "score": score, "previous_score": prev, "delta": score - prev})
        return out

    return {
        "generated_at": now.isoformat(),
        "since_hours": since_hours,
        "top_ips": _build(current_ip.most_common(), previous_ip),
        "top_users": _build(current_user.most_common(), previous_user),
        "top_assets": _build(current_asset.most_common(), previous_asset),
    }


def analytics_overview(window_hours: int = Query(default=24, ge=1, le=24 * 30)):
    since = (datetime.now(UTC) - timedelta(hours=window_hours)).isoformat()
    rows = fetch_all(
        """
        SELECT severity, alert_type, COALESCE(ip, 'unknown') AS ip, mitre_tactic, mitre_technique
        FROM alerts
        WHERE ts >= ?
        """,
        (since,),
    )
    severity_counter: Counter[str] = Counter()
    alert_type_counter: Counter[str] = Counter()
    ip_counter: Counter[str] = Counter()
    mitre_counter: Counter[str] = Counter()
    for row in rows:
        severity = str(row.get("severity") or "unknown").lower()
        alert_type = str(row.get("alert_type") or "unknown")
        ip = str(row.get("ip") or "unknown")
        mitre_tactic = str(row.get("mitre_tactic") or "").strip()
        mitre_technique = str(row.get("mitre_technique") or "").strip()
        severity_counter[severity] += 1
        alert_type_counter[alert_type] += 1
        ip_counter[ip] += 1
        if mitre_tactic or mitre_technique:
            mitre_counter[f"{mitre_tactic}::{mitre_technique}"] += 1

    return {
        "window_hours": window_hours,
        "alert_count": len(rows),
        "severity_distribution": dict(sorted(severity_counter.items())),
        "top_alert_types": [{"alert_type": name, "count": count} for name, count in alert_type_counter.most_common(8)],
        "top_source_ips": [{"ip": ip, "count": count} for ip, count in ip_counter.most_common(8)],
        "mitre_coverage": [
            {
                "mitre_tactic": key.split("::", 1)[0],
                "mitre_technique": key.split("::", 1)[1],
                "count": count,
            }
            for key, count in mitre_counter.most_common(8)
        ],
    }


def playbook(alert_type: str):
    return {"alert_type": alert_type, "steps": get_playbook(alert_type)}


def settings():
    return {
        "app_version": APP_VERSION,
        "webhook_enabled": bool(os.getenv("SOC_WEBHOOK_URL", "").strip()),
        "webhook_min_severity": os.getenv("SOC_WEBHOOK_MIN_SEVERITY", "high"),
        "ingest_api_key_enabled": bool(INGEST_API_KEY),
        "secure_cookies_enabled": _secure_cookies(),
        "live_tail_root": str(LIVE_TAIL_ROOT.expanduser().resolve()),
        "live_tail_restricted": not _env_bool("SOC_LIVE_TAIL_ALLOW_ANY", False),
        "security_warnings": _security_warnings(),
    }


def metrics():
    lines = [
        "# HELP soc_dashboard_events_total Internal event counters",
        "# TYPE soc_dashboard_events_total counter",
    ]
    for key, value in sorted(_metrics.items()):
        lines.append(f'soc_dashboard_events_total{{name="{key}"}} {int(value)}')
    return Response("\n".join(lines) + "\n", media_type="text/plain; version=0.0.4")


async def websocket_live(ws: WebSocket):
    if ws.cookies.get(SESSION_COOKIE) != SESSION_TOKEN:
        await ws.close(code=1008)
        _inc_metric("ws_auth_rejected_total")
        return

    await ws.accept()
    _inc_metric("ws_connections_total")
    cursor = 0
    try:
        while True:
            with _live_events_lock:
                if cursor < len(_live_events):
                    batch = _live_events[cursor:]
                    cursor = len(_live_events)
                else:
                    batch = []
            if batch:
                for event in batch[-50:]:
                    await ws.send_json(event)
            await ws.send_json({"event_type": "heartbeat", "ts": datetime.now(UTC).isoformat()})
            await asyncio.sleep(2)
    except WebSocketDisconnect:
        return
    except Exception as exc:
        logger.exception("websocket.live_error error=%s", exc)
        _inc_metric("ws_errors_total")
        try:
            await ws.close()
        except Exception:
            pass


def get_cases(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM cases")[0]["total"])
    rows = fetch_all(
        """
        SELECT c.id, c.title, c.priority, c.status, c.owner, c.description, c.due_at, c.opened_at, c.first_response_at, c.closed_at,
               COUNT(ca.alert_id) AS alert_count
        FROM cases c
        LEFT JOIN case_alerts ca ON ca.case_id = c.id
        GROUP BY c.id
        ORDER BY c.opened_at DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_case(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, CaseCreatePayload)
    if error:
        return error
    assert parsed is not None
    title = str(parsed.title).strip()
    priority = str(parsed.priority).strip().lower()
    status = str(parsed.status).strip().lower()
    owner = str(parsed.owner or "").strip() or None
    description = str(parsed.description or "").strip() or None
    due_at = str(parsed.due_at or "").strip() or None
    now = datetime.now(UTC).isoformat()
    case_id = execute(
        """
        INSERT INTO cases(title, priority, status, owner, description, due_at, opened_at)
        VALUES(?, ?, ?, ?, ?, ?, ?)
        """,
        (title, priority, status, owner, description, due_at, now),
    )
    execute(
        """
        INSERT INTO case_actions(case_id, ts, actor, action, details)
        VALUES(?, ?, ?, 'case_created', ?)
        """,
        (case_id, now, owner or "system", description or ""),
    )
    _publish_live_event("case_created", {"case_id": case_id, "title": title, "priority": priority})
    row = fetch_all(
        """
        SELECT id, title, priority, status, owner, description, due_at, opened_at, first_response_at, closed_at
        FROM cases WHERE id = ?
        """,
        (case_id,),
    )[0]
    return row


def update_case(case_id: int, payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, CaseUpdatePayload)
    if error:
        return error
    assert parsed is not None
    rows = fetch_all("SELECT id, status, owner FROM cases WHERE id = ?", (case_id,))
    if not rows:
        return JSONResponse({"detail": "Case not found"}, status_code=404)
    current = rows[0]

    fields: list[str] = []
    params: list[Any] = []
    status = parsed.status if parsed else None
    owner = parsed.owner if parsed else None
    title = parsed.title if parsed else None
    priority = parsed.priority if parsed else None
    description = parsed.description if parsed else None
    due_at = parsed.due_at if parsed else None

    if status is not None:
        status_str = str(status).strip().lower()
        fields.append("status = ?")
        params.append(status_str)
        if status_str == "investigating" and not current.get("first_response_at"):
            fields.append("first_response_at = ?")
            params.append(datetime.now(UTC).isoformat())
        if status_str == "closed":
            fields.append("closed_at = ?")
            params.append(datetime.now(UTC).isoformat())
    if owner is not None:
        fields.append("owner = ?")
        params.append(str(owner).strip() or None)
    if title is not None:
        fields.append("title = ?")
        params.append(str(title).strip())
    if priority is not None:
        p = str(priority).strip().lower()
        fields.append("priority = ?")
        params.append(p)
    if description is not None:
        fields.append("description = ?")
        params.append(str(description).strip() or None)
    if due_at is not None:
        fields.append("due_at = ?")
        params.append(str(due_at).strip() or None)

    if fields:
        params.append(case_id)
        execute_change(f"UPDATE cases SET {', '.join(fields)} WHERE id = ?", tuple(params))
        execute(
            """
            INSERT INTO case_actions(case_id, ts, actor, action, details)
            VALUES(?, ?, ?, 'case_updated', ?)
            """,
            (case_id, datetime.now(UTC).isoformat(), str(parsed.actor or "analyst"), str(payload)),
        )
        _publish_live_event("case_updated", {"case_id": case_id, "changes": payload})

    row = fetch_all(
        """
        SELECT id, title, priority, status, owner, description, due_at, opened_at, first_response_at, closed_at
        FROM cases WHERE id = ?
        """,
        (case_id,),
    )[0]
    return row


def link_case_alert(case_id: int, alert_id: int):
    case_exists = fetch_all("SELECT id FROM cases WHERE id = ?", (case_id,))
    alert_exists = fetch_all("SELECT id FROM alerts WHERE id = ?", (alert_id,))
    if not case_exists or not alert_exists:
        return JSONResponse({"detail": "Case or alert not found"}, status_code=404)
    linked_at = datetime.now(UTC).isoformat()
    execute(
        """
        INSERT OR IGNORE INTO case_alerts(case_id, alert_id, linked_at)
        VALUES(?, ?, ?)
        """,
        (case_id, alert_id, linked_at),
    )
    execute(
        """
        INSERT INTO case_actions(case_id, ts, actor, action, details)
        VALUES(?, ?, 'analyst', 'alert_linked', ?)
        """,
        (case_id, linked_at, f"alert_id={alert_id}"),
    )
    _publish_live_event("case_alert_linked", {"case_id": case_id, "alert_id": alert_id})
    return {"status": "ok"}


def unlink_case_alert(case_id: int, alert_id: int):
    execute_change("DELETE FROM case_alerts WHERE case_id = ? AND alert_id = ?", (case_id, alert_id))
    execute(
        """
        INSERT INTO case_actions(case_id, ts, actor, action, details)
        VALUES(?, ?, 'analyst', 'alert_unlinked', ?)
        """,
        (case_id, datetime.now(UTC).isoformat(), f"alert_id={alert_id}"),
    )
    _publish_live_event("case_alert_unlinked", {"case_id": case_id, "alert_id": alert_id})
    return {"status": "ok"}


def case_detail(case_id: int):
    rows = fetch_all(
        """
        SELECT id, title, priority, status, owner, description, due_at, opened_at, first_response_at, closed_at
        FROM cases WHERE id = ?
        """,
        (case_id,),
    )
    if not rows:
        return JSONResponse({"detail": "Case not found"}, status_code=404)
    case = rows[0]
    alerts = fetch_all(
        """
        SELECT a.id, a.ts, a.severity, a.alert_type, a.ip, a.status
        FROM alerts a
        JOIN case_alerts ca ON ca.alert_id = a.id
        WHERE ca.case_id = ?
        ORDER BY a.ts DESC
        """,
        (case_id,),
    )
    actions = fetch_all(
        """
        SELECT id, ts, actor, action, details
        FROM case_actions
        WHERE case_id = ?
        ORDER BY ts DESC
        LIMIT 200
        """,
        (case_id,),
    )
    comments = fetch_all(
        """
        SELECT id, ts, author, message
        FROM case_comments
        WHERE case_id = ?
        ORDER BY ts DESC
        LIMIT 200
        """,
        (case_id,),
    )
    return {"case": case, "alerts": alerts, "actions": actions, "comments": comments}


def get_case_comments(case_id: int, limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    case_exists = fetch_all("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not case_exists:
        return JSONResponse({"detail": "Case not found"}, status_code=404)
    total = int(fetch_all("SELECT COUNT(*) AS total FROM case_comments WHERE case_id = ?", (case_id,))[0]["total"])
    rows = fetch_all(
        """
        SELECT id, ts, author, message
        FROM case_comments
        WHERE case_id = ?
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
        """,
        (case_id, limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_case_comment(case_id: int, payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, CaseCommentCreatePayload)
    if error:
        return error
    assert parsed is not None
    case_exists = fetch_all("SELECT id FROM cases WHERE id = ?", (case_id,))
    if not case_exists:
        return JSONResponse({"detail": "Case not found"}, status_code=404)
    message = str(parsed.message).strip()
    author = str(parsed.author or "analyst").strip()[:120]
    ts = datetime.now(UTC).isoformat()
    comment_id = execute(
        """
        INSERT INTO case_comments(case_id, ts, author, message)
        VALUES(?, ?, ?, ?)
        """,
        (case_id, ts, author or "analyst", message[:2000]),
    )
    execute(
        """
        INSERT INTO case_actions(case_id, ts, actor, action, details)
        VALUES(?, ?, ?, 'comment_added', ?)
        """,
        (case_id, ts, author or "analyst", message[:200]),
    )
    _publish_live_event("case_comment_added", {"case_id": case_id, "comment_id": comment_id})
    return fetch_all("SELECT id, ts, author, message FROM case_comments WHERE id = ?", (comment_id,))[0]


def delete_case_comment(case_id: int, comment_id: int):
    count = execute_change("DELETE FROM case_comments WHERE id = ? AND case_id = ?", (comment_id, case_id))
    if count == 0:
        return JSONResponse({"detail": "Comment not found"}, status_code=404)
    execute(
        """
        INSERT INTO case_actions(case_id, ts, actor, action, details)
        VALUES(?, ?, 'analyst', 'comment_deleted', ?)
        """,
        (case_id, datetime.now(UTC).isoformat(), f"comment_id={comment_id}"),
    )
    _publish_live_event("case_comment_deleted", {"case_id": case_id, "comment_id": comment_id})
    return {"status": "ok"}


def sla_metrics():
    alerts = fetch_all("SELECT ts, status, severity, updated_at FROM alerts")
    cases = fetch_all("SELECT opened_at, first_response_at, closed_at, priority FROM cases")

    def minutes_between(start: str | None, end: str | None) -> float | None:
        if not start or not end:
            return None
        try:
            s = datetime.fromisoformat(start.replace("Z", "+00:00"))
            e = datetime.fromisoformat(end.replace("Z", "+00:00"))
            return max(0.0, (e - s).total_seconds() / 60.0)
        except ValueError:
            return None

    mtta_values: list[float] = []
    mttr_values: list[float] = []
    for c in cases:
        mtta = minutes_between(c.get("opened_at"), c.get("first_response_at"))
        mttr = minutes_between(c.get("opened_at"), c.get("closed_at"))
        if mtta is not None:
            mtta_values.append(mtta)
        if mttr is not None:
            mttr_values.append(mttr)

    open_high = sum(1 for a in alerts if a.get("status") in ("new", "investigating") and a.get("severity") == "high")
    return {
        "cases_total": len(cases),
        "alerts_total": len(alerts),
        "mtta_minutes_avg": round(sum(mtta_values) / len(mtta_values), 2) if mtta_values else None,
        "mttr_minutes_avg": round(sum(mttr_values) / len(mttr_values), 2) if mttr_values else None,
        "open_high_alerts": open_high,
    }


def get_saved_views(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM saved_views")[0]["total"])
    rows = fetch_all(
        """
        SELECT id, name, target, query_dsl, created_at
        FROM saved_views
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_saved_view(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, SavedViewCreatePayload)
    if error:
        return error
    assert parsed is not None
    name = str(parsed.name).strip()
    target = str(parsed.target).strip().lower()
    query_dsl = str(parsed.query_dsl).strip()
    created_at = datetime.now(UTC).isoformat()
    view_id = execute(
        """
        INSERT INTO saved_views(name, target, query_dsl, created_at)
        VALUES(?, ?, ?, ?)
        """,
        (name, target, query_dsl, created_at),
    )
    row = fetch_all("SELECT id, name, target, query_dsl, created_at FROM saved_views WHERE id = ?", (view_id,))[0]
    return row


def delete_saved_view(view_id: int):
    count = execute_change("DELETE FROM saved_views WHERE id = ?", (view_id,))
    if count == 0:
        return JSONResponse({"detail": "Saved view not found"}, status_code=404)
    return {"status": "ok"}


def _build_alert_investigation(alert_id: int) -> dict[str, Any] | JSONResponse:
    rows = fetch_all(
        """
        SELECT id, ts, severity, alert_type, ip, username, user_agent, details, log_id, status, assignee, resolution_note, occurrences, updated_at, mitre_tactic, mitre_technique, asset_id, explain_text
        FROM alerts
        WHERE id = ?
        """,
        (alert_id,),
    )
    if not rows:
        return JSONResponse({"detail": "Alert not found"}, status_code=404)

    alert = rows[0]
    asset = None
    if alert.get("asset_id"):
        asset_rows = fetch_all(
            """
            SELECT id, name, criticality, ip_cidr, path_prefix, owner, created_at
            FROM assets
            WHERE id = ?
            """,
            (alert["asset_id"],),
        )
        asset = asset_rows[0] if asset_rows else None
    if asset:
        alert["asset_name"] = asset.get("name")
        alert["asset_criticality"] = asset.get("criticality")
        alert["asset_owner"] = asset.get("owner")

    ts = str(alert["ts"])
    ip = alert.get("ip")
    log_id = alert.get("log_id")
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        dt = datetime.now(UTC)
    start_ts = (dt - timedelta(minutes=30)).isoformat()
    end_ts = (dt + timedelta(minutes=30)).isoformat()

    related_logs = fetch_all(
        """
        SELECT id, ts, ip, username, user_agent, method, path, status_code, message, raw
        FROM logs
        WHERE ((? IS NOT NULL AND id = ?) OR (? IS NULL OR ip = ?))
          AND ts BETWEEN ? AND ?
        ORDER BY ts DESC
        LIMIT 120
        """,
        (log_id, log_id, ip, ip, start_ts, end_ts),
    )
    related_events = fetch_all(
        """
        SELECT id, ts, event_type, severity, alert_id, ip, title, details, actor
        FROM incident_events
        WHERE (alert_id = ? OR (? IS NOT NULL AND ip = ?))
        ORDER BY ts DESC
        LIMIT 120
        """,
        (alert_id, ip, ip),
    )
    linked_cases = fetch_all(
        """
        SELECT c.id, c.title, c.priority, c.status, c.owner, c.description, c.due_at, c.opened_at, c.first_response_at, c.closed_at,
               ca.linked_at,
               (SELECT COUNT(*) FROM case_comments cc WHERE cc.case_id = c.id) AS comment_count,
               (SELECT COUNT(*) FROM case_actions act WHERE act.case_id = c.id) AS action_count
        FROM cases c
        JOIN case_alerts ca ON ca.case_id = c.id
        WHERE ca.alert_id = ?
        ORDER BY ca.linked_at DESC
        """,
        (alert_id,),
    )

    ioc_rows = _get_enabled_iocs()
    matched_iocs: dict[tuple[int, str, str], dict[str, Any]] = {}
    for log in related_logs:
        log_payload = {
            "ip": log.get("ip"),
            "path": log.get("path"),
            "user_agent": log.get("user_agent"),
            "message": log.get("message"),
        }
        for match in _detect_ioc_matches(log_payload, ioc_rows):
            details = str(match.get("details") or "")
            for row in ioc_rows:
                marker = f"IOC match ({row.get('ioc_type')}): {row.get('ioc_value')}"
                if details != marker:
                    continue
                key = (int(row["id"]), str(row["ioc_type"]), str(row["ioc_value"]))
                entry = matched_iocs.setdefault(
                    key,
                    {
                        "id": int(row["id"]),
                        "ioc_type": str(row["ioc_type"]),
                        "ioc_value": str(row["ioc_value"]),
                        "severity_override": str(row.get("severity_override") or "high"),
                        "matched_log_ids": [],
                        "matched_count": 0,
                    },
                )
                if log.get("id") not in entry["matched_log_ids"]:
                    entry["matched_log_ids"].append(log.get("id"))
                entry["matched_count"] += 1
                break

    ioc_matches = list(matched_iocs.values())
    return {
        "alert": alert,
        "asset": asset,
        "playbook": get_playbook(str(alert["alert_type"])),
        "related_logs": related_logs,
        "related_events": related_events,
        "linked_cases": linked_cases,
        "ioc_matches": ioc_matches,
        "summary": {
            "window_start": start_ts,
            "window_end": end_ts,
            "related_logs_count": len(related_logs),
            "related_events_count": len(related_events),
            "linked_cases_count": len(linked_cases),
            "ioc_matches_count": len(ioc_matches),
        },
    }


def alert_context(alert_id: int):
    investigation = _build_alert_investigation(alert_id)
    if isinstance(investigation, JSONResponse):
        return investigation
    return {
        "alert": investigation["alert"],
        "playbook": investigation["playbook"],
        "related_logs": investigation["related_logs"],
        "related_events": investigation["related_events"],
    }


def alert_investigation(alert_id: int):
    return _build_alert_investigation(alert_id)


def daily_report_data():
    stats = get_stats()
    latest_alerts = fetch_all(
        """
        SELECT ts, severity, alert_type, ip, details, status, occurrences
        FROM alerts
        ORDER BY ts DESC
        LIMIT 50
        """
    )
    top_open = fetch_all(
        """
        SELECT id, ts, severity, alert_type, ip, status, assignee
        FROM alerts
        WHERE status IN ('new','investigating')
        ORDER BY ts DESC
        LIMIT 20
        """
    )
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "stats": stats,
        "latest_alerts": latest_alerts,
        "top_open_alerts": top_open,
    }


def daily_report_page(request: Request):
    report = daily_report_data()
    lang = str(request.query_params.get("lang") or "en")
    return HTMLResponse(_render_daily_report_html(report, lang))


def report_schedules(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM report_schedules")[0]["total"])
    rows = fetch_all(
        """
        SELECT id, name, hour_utc, minute_utc, enabled, last_run_date, created_at
        FROM report_schedules
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_report_schedule(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, ReportScheduleCreatePayload)
    if error:
        return error
    assert parsed is not None
    name = str(parsed.name or "").strip() or f"schedule-{int(time.time())}"
    hour_utc = int(parsed.hour_utc)
    minute_utc = int(parsed.minute_utc)
    enabled = 1 if bool(parsed.enabled) else 0
    created_at = datetime.now(UTC).isoformat()
    schedule_id = execute(
        """
        INSERT INTO report_schedules(name, hour_utc, minute_utc, enabled, created_at)
        VALUES(?, ?, ?, ?, ?)
        """,
        (name, hour_utc, minute_utc, enabled, created_at),
    )
    row = fetch_all(
        """
        SELECT id, name, hour_utc, minute_utc, enabled, last_run_date, created_at
        FROM report_schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )[0]
    return row


def update_report_schedule(schedule_id: int, payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, ReportScheduleUpdatePayload)
    if error:
        return error
    assert parsed is not None
    rows = fetch_all("SELECT id FROM report_schedules WHERE id = ?", (schedule_id,))
    if not rows:
        return JSONResponse({"detail": "schedule not found"}, status_code=404)
    fields: list[str] = []
    params: list[Any] = []
    if parsed.name is not None:
        fields.append("name = ?")
        params.append(str(parsed.name or "").strip())
    if parsed.hour_utc is not None:
        hour = int(parsed.hour_utc)
        fields.append("hour_utc = ?")
        params.append(hour)
    if parsed.minute_utc is not None:
        minute = int(parsed.minute_utc)
        fields.append("minute_utc = ?")
        params.append(minute)
    if parsed.enabled is not None:
        fields.append("enabled = ?")
        params.append(1 if bool(parsed.enabled) else 0)
    if fields:
        params.append(schedule_id)
        execute_change(f"UPDATE report_schedules SET {', '.join(fields)} WHERE id = ?", tuple(params))
    row = fetch_all(
        """
        SELECT id, name, hour_utc, minute_utc, enabled, last_run_date, created_at
        FROM report_schedules
        WHERE id = ?
        """,
        (schedule_id,),
    )[0]
    return row


def delete_report_schedule(schedule_id: int):
    count = execute_change("DELETE FROM report_schedules WHERE id = ?", (schedule_id,))
    if count == 0:
        return JSONResponse({"detail": "schedule not found"}, status_code=404)
    return {"status": "ok"}


def run_report_schedule_now(schedule_id: int):
    rows = fetch_all("SELECT id FROM report_schedules WHERE id = ?", (schedule_id,))
    if not rows:
        return JSONResponse({"detail": "schedule not found"}, status_code=404)
    result = _run_scheduled_report(schedule_id)
    execute_change(
        "UPDATE report_schedules SET last_run_date = ? WHERE id = ?",
        (datetime.now(UTC).strftime("%Y-%m-%d"), schedule_id),
    )
    return {"status": "ok", **result}


def report_runs(limit: int = 100, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM report_runs")[0]["total"])
    rows = fetch_all(
        """
        SELECT id, schedule_id, ts, output_path, status
        FROM report_runs
        ORDER BY ts DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def delta_report_data(since_hours: int = Query(default=24, ge=1, le=24 * 30)):
    since_dt = datetime.now(UTC) - timedelta(hours=since_hours)
    since_iso = since_dt.isoformat()
    logs_count = fetch_all("SELECT COUNT(*) AS c FROM logs WHERE ts >= ?", (since_iso,))[0]["c"]
    alerts = fetch_all(
        """
        SELECT id, ts, severity, alert_type, ip, status, details
        FROM alerts
        WHERE ts >= ?
        ORDER BY ts DESC
        LIMIT 200
        """,
        (since_iso,),
    )
    severity_counter = Counter(str(a.get("severity") or "unknown") for a in alerts)
    type_counter = Counter(str(a.get("alert_type") or "unknown") for a in alerts)
    ip_counter = Counter(str(a.get("ip") or "unknown") for a in alerts if a.get("ip"))
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "since_hours": since_hours,
        "since_ts": since_iso,
        "logs_ingested": logs_count,
        "alerts_created": len(alerts),
        "open_alerts": sum(1 for a in alerts if a.get("status") in ("new", "investigating")),
        "critical_alerts": sum(1 for a in alerts if a.get("severity") == "critical"),
        "high_alerts": sum(1 for a in alerts if a.get("severity") == "high"),
        "by_severity": severity_counter.most_common(),
        "by_type": type_counter.most_common(10),
        "top_ips": ip_counter.most_common(10),
        "latest_alerts": alerts[:20],
    }


def get_iocs(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM ioc_watchlist")[0]["total"])
    rows = fetch_all(
        """
        SELECT id, ioc_type, ioc_value, severity_override, enabled, created_at
        FROM ioc_watchlist
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_ioc(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, IocCreatePayload)
    if error:
        return error
    assert parsed is not None
    ioc_type = str(parsed.ioc_type).strip().lower()
    ioc_value = str(parsed.ioc_value).strip()
    severity = str(parsed.severity_override).strip().lower()
    enabled = 1 if bool(parsed.enabled) else 0
    created_at = datetime.now(UTC).isoformat()
    ioc_id = execute(
        """
        INSERT INTO ioc_watchlist(ioc_type, ioc_value, severity_override, enabled, created_at)
        VALUES(?, ?, ?, ?, ?)
        """,
        (ioc_type, ioc_value, severity, enabled, created_at),
    )
    return fetch_all(
        "SELECT id, ioc_type, ioc_value, severity_override, enabled, created_at FROM ioc_watchlist WHERE id = ?",
        (ioc_id,),
    )[0]


def update_ioc(ioc_id: int, payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, IocUpdatePayload)
    if error:
        return error
    assert parsed is not None
    rows = fetch_all("SELECT id FROM ioc_watchlist WHERE id = ?", (ioc_id,))
    if not rows:
        return JSONResponse({"detail": "IOC not found"}, status_code=404)
    fields: list[str] = []
    params: list[Any] = []
    if parsed.ioc_type is not None:
        ioc_type = str(parsed.ioc_type).strip().lower()
        fields.append("ioc_type = ?")
        params.append(ioc_type)
    if parsed.ioc_value is not None:
        ioc_value = str(parsed.ioc_value).strip()
        fields.append("ioc_value = ?")
        params.append(ioc_value)
    if parsed.severity_override is not None:
        severity = str(parsed.severity_override).strip().lower()
        fields.append("severity_override = ?")
        params.append(severity)
    if parsed.enabled is not None:
        fields.append("enabled = ?")
        params.append(1 if bool(parsed.enabled) else 0)
    if fields:
        params.append(ioc_id)
        execute_change(f"UPDATE ioc_watchlist SET {', '.join(fields)} WHERE id = ?", tuple(params))
    return fetch_all(
        "SELECT id, ioc_type, ioc_value, severity_override, enabled, created_at FROM ioc_watchlist WHERE id = ?",
        (ioc_id,),
    )[0]


def delete_ioc(ioc_id: int):
    count = execute_change("DELETE FROM ioc_watchlist WHERE id = ?", (ioc_id,))
    if count == 0:
        return JSONResponse({"detail": "IOC not found"}, status_code=404)
    return {"status": "ok"}


def get_policies(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM policies")[0]["total"])
    rows = fetch_all(
        """
        SELECT id, name, enabled, condition_expr, action_type, action_payload, created_at
        FROM policies
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    for row in rows:
        row["action_payload_obj"] = _parse_policy_payload(row.get("action_payload"))
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_policy(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, PolicyCreatePayload)
    if error:
        return error
    assert parsed is not None
    name = str(parsed.name).strip()
    condition_expr = str(parsed.condition_expr).strip()
    action_type = str(parsed.action_type).strip()
    action_payload_obj = _parse_policy_payload(parsed.action_payload)
    enabled = 1 if bool(parsed.enabled) else 0
    created_at = datetime.now(UTC).isoformat()
    policy_id = execute(
        """
        INSERT INTO policies(name, enabled, condition_expr, action_type, action_payload, created_at)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (name, enabled, condition_expr, action_type, json.dumps(action_payload_obj), created_at),
    )
    row = fetch_all(
        """
        SELECT id, name, enabled, condition_expr, action_type, action_payload, created_at
        FROM policies
        WHERE id = ?
        """,
        (policy_id,),
    )[0]
    row["action_payload_obj"] = _parse_policy_payload(row.get("action_payload"))
    return row


def update_policy(policy_id: int, payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, PolicyUpdatePayload)
    if error:
        return error
    assert parsed is not None
    rows = fetch_all("SELECT id FROM policies WHERE id = ?", (policy_id,))
    if not rows:
        return JSONResponse({"detail": "Policy not found"}, status_code=404)
    fields: list[str] = []
    params: list[Any] = []
    if parsed.name is not None:
        name = str(parsed.name).strip()
        fields.append("name = ?")
        params.append(name)
    if parsed.condition_expr is not None:
        condition_expr = str(parsed.condition_expr).strip()
        fields.append("condition_expr = ?")
        params.append(condition_expr)
    if parsed.action_type is not None:
        action_type = str(parsed.action_type).strip()
        fields.append("action_type = ?")
        params.append(action_type)
    if parsed.action_payload is not None:
        fields.append("action_payload = ?")
        params.append(json.dumps(_parse_policy_payload(parsed.action_payload)))
    if parsed.enabled is not None:
        fields.append("enabled = ?")
        params.append(1 if bool(parsed.enabled) else 0)
    if fields:
        params.append(policy_id)
        execute_change(f"UPDATE policies SET {', '.join(fields)} WHERE id = ?", tuple(params))
    row = fetch_all(
        """
        SELECT id, name, enabled, condition_expr, action_type, action_payload, created_at
        FROM policies
        WHERE id = ?
        """,
        (policy_id,),
    )[0]
    row["action_payload_obj"] = _parse_policy_payload(row.get("action_payload"))
    return row


def delete_policy(policy_id: int):
    count = execute_change("DELETE FROM policies WHERE id = ?", (policy_id,))
    if count == 0:
        return JSONResponse({"detail": "Policy not found"}, status_code=404)
    return {"status": "ok"}


def get_assets(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM assets")[0]["total"])
    rows = fetch_all(
        "SELECT id, name, criticality, ip_cidr, path_prefix, owner, created_at FROM assets ORDER BY id DESC LIMIT ? OFFSET ?",
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_asset(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, AssetCreatePayload)
    if error:
        return error
    assert parsed is not None
    name = str(parsed.name).strip()
    criticality = str(parsed.criticality).strip().lower()
    ip_cidr = str(parsed.ip_cidr or "").strip() or None
    path_prefix = str(parsed.path_prefix or "").strip() or None
    owner = str(parsed.owner or "").strip() or None
    if not ip_cidr and not path_prefix:
        return JSONResponse({"detail": "ip_cidr or path_prefix is required"}, status_code=400)
    if ip_cidr:
        try:
            if "/" in ip_cidr:
                ipaddress.ip_network(ip_cidr, strict=False)
            else:
                ipaddress.ip_address(ip_cidr)
        except ValueError:
            return JSONResponse({"detail": "invalid ip_cidr"}, status_code=400)

    created_at = datetime.now(UTC).isoformat()
    asset_id = execute(
        """
        INSERT INTO assets(name, criticality, ip_cidr, path_prefix, owner, created_at)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (name, criticality, ip_cidr, path_prefix, owner, created_at),
    )
    row = fetch_all("SELECT id, name, criticality, ip_cidr, path_prefix, owner, created_at FROM assets WHERE id = ?", (asset_id,))[0]
    return row


def delete_asset(asset_id: int):
    count = execute_change("DELETE FROM assets WHERE id = ?", (asset_id,))
    if count == 0:
        return JSONResponse({"detail": "Asset not found"}, status_code=404)
    return {"status": "ok"}


def get_suppressions(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    _cleanup_expired_suppressions()
    total = int(fetch_all("SELECT COUNT(*) AS total FROM suppressions")[0]["total"])
    rows = fetch_all(
        """
        SELECT id, ip, alert_type, path_pattern, reason, expires_at, created_at
        FROM suppressions
        ORDER BY expires_at ASC
        LIMIT ? OFFSET ?
        """
        ,
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_suppression(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, SuppressionCreatePayload)
    if error:
        return error
    assert parsed is not None
    ip = str(parsed.ip or "").strip() or None
    alert_type = str(parsed.alert_type or "").strip() or None
    path_pattern = str(parsed.path_pattern or "").strip() or None
    reason = str(parsed.reason or "").strip() or "manual suppression"
    ttl_minutes = int(parsed.ttl_minutes)
    if not ip and not alert_type and not path_pattern:
        return JSONResponse({"detail": "at least one condition is required"}, status_code=400)
    expires_at = (datetime.now(UTC) + timedelta(minutes=ttl_minutes)).isoformat()
    created_at = datetime.now(UTC).isoformat()
    suppression_id = execute(
        """
        INSERT INTO suppressions(ip, alert_type, path_pattern, reason, expires_at, created_at)
        VALUES(?, ?, ?, ?, ?, ?)
        """,
        (ip, alert_type, path_pattern, reason, expires_at, created_at),
    )
    row = fetch_all(
        """
        SELECT id, ip, alert_type, path_pattern, reason, expires_at, created_at
        FROM suppressions
        WHERE id = ?
        """,
        (suppression_id,),
    )[0]
    return row


def delete_suppression(suppression_id: int):
    count = execute_change("DELETE FROM suppressions WHERE id = ?", (suppression_id,))
    if count == 0:
        return JSONResponse({"detail": "Suppression not found"}, status_code=404)
    return {"status": "ok"}


def incidents_timeline(
    limit: int = 200,
    offset: int = 0,
    ip: str | None = None,
):
    limit = max(1, min(int(limit), 2000))
    offset = max(0, int(offset))
    if ip:
        total = int(fetch_all("SELECT COUNT(*) AS total FROM incident_events WHERE ip = ?", (ip,))[0]["total"])
    else:
        total = int(fetch_all("SELECT COUNT(*) AS total FROM incident_events")[0]["total"])
    if ip:
        rows = fetch_all(
            """
            SELECT id, ts, event_type, severity, alert_id, ip, title, details, actor
            FROM incident_events
            WHERE ip = ?
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
            """,
            (ip, limit, offset),
        )
    else:
        rows = fetch_all(
            """
            SELECT id, ts, event_type, severity, alert_id, ip, title, details, actor
            FROM incident_events
            ORDER BY ts DESC
            LIMIT ? OFFSET ?
            """,
            (limit, offset),
        )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def list_backups(limit: int = 200, offset: int = 0):
    limit = max(1, min(int(limit), 1000))
    offset = max(0, int(offset))
    total = int(fetch_all("SELECT COUNT(*) AS total FROM backup_runs")[0]["total"])
    rows = fetch_all(
        """
        SELECT id, ts, backup_path, action, status, details
        FROM backup_runs
        ORDER BY id DESC
        LIMIT ? OFFSET ?
        """,
        (limit, offset),
    )
    return {"items": rows, "total": total, "limit": limit, "offset": offset}


def create_backup():
    ts = datetime.now(UTC)
    filename = f"soc-{ts.strftime('%Y%m%d-%H%M%S')}.db"
    out_path = BACKUPS_DIR / filename
    try:
        shutil.copy2(DB_PATH, out_path)
        _record_backup_run("backup", "ok", str(out_path), "manual backup")
        _publish_live_event("backup_created", {"path": str(out_path)})
        _inc_metric("backup_success_total")
        return {"status": "ok", "backup_path": str(out_path)}
    except Exception as exc:
        logger.exception("backup.failed path=%s error=%s", out_path, exc)
        _inc_metric("backup_failed_total")
        _record_backup_run("backup", "failed", str(out_path), str(exc))
        return JSONResponse({"detail": f"backup failed: {exc}"}, status_code=500)


def restore_backup(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, RestoreBackupPayload)
    if error:
        return error
    assert parsed is not None
    requested = str(parsed.backup_name or "").strip()
    if not requested:
        rows = fetch_all(
            """
            SELECT backup_path
            FROM backup_runs
            WHERE action = 'backup' AND status = 'ok'
            ORDER BY id DESC
            LIMIT 1
            """
        )
        if not rows:
            return JSONResponse({"detail": "no valid backup found"}, status_code=404)
        source = Path(str(rows[0]["backup_path"]))
    else:
        source = BACKUPS_DIR / _safe_backup_name(requested)
    if not source.exists():
        return JSONResponse({"detail": "backup not found"}, status_code=404)

    ts = datetime.now(UTC)
    pre_restore_snapshot = BACKUPS_DIR / f"pre-restore-{ts.strftime('%Y%m%d-%H%M%S')}.db"
    try:
        if DB_PATH.exists():
            shutil.copy2(DB_PATH, pre_restore_snapshot)
        shutil.copy2(source, DB_PATH)
        _record_backup_run("restore", "ok", str(source), f"restored from {source.name}")
        _publish_live_event("backup_restored", {"source": str(source)})
        _inc_metric("restore_success_total")
        return {
            "status": "ok",
            "restored_from": str(source),
            "previous_snapshot": str(pre_restore_snapshot) if pre_restore_snapshot.exists() else None,
        }
    except Exception as exc:
        logger.exception("restore.failed source=%s error=%s", source, exc)
        _inc_metric("restore_failed_total")
        _record_backup_run("restore", "failed", str(source), str(exc))
        return JSONResponse({"detail": f"restore failed: {exc}"}, status_code=500)


def reset_data():
    execute("DELETE FROM alerts")
    execute("DELETE FROM logs")
    execute("DELETE FROM incident_events")
    execute("DELETE FROM case_alerts")
    execute("DELETE FROM case_actions")
    execute("DELETE FROM case_comments")
    execute("DELETE FROM cases")
    _publish_live_event("admin_reset", {"status": "ok"})
    return {"status": "ok"}


def _rows_to_csv(rows: list[dict[str, Any]], columns: list[str]) -> str:
    buf = io.StringIO()
    writer = csv.DictWriter(buf, fieldnames=columns)
    writer.writeheader()
    for row in rows:
        writer.writerow({col: row.get(col) for col in columns})
    return buf.getvalue()


def export_logs_csv(limit: int = Query(default=2000, le=10000)):
    rows = fetch_all(
        """
        SELECT ts, ip, username, user_agent, method, path, status_code, message
        FROM logs
        ORDER BY ts DESC
        LIMIT ?
        """,
        (limit,),
    )
    csv_content = _rows_to_csv(rows, ["ts", "ip", "username", "user_agent", "method", "path", "status_code", "message"])
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc_logs.csv"'},
    )


def export_alerts_csv(limit: int = Query(default=2000, le=10000)):
    rows = fetch_all(
        """
        SELECT ts, severity, alert_type, ip, username, user_agent, details, explain_text, status, assignee
        FROM alerts
        ORDER BY ts DESC
        LIMIT ?
        """,
        (limit,),
    )
    csv_content = _rows_to_csv(rows, ["ts", "severity", "alert_type", "ip", "username", "user_agent", "details", "explain_text", "status", "assignee"])
    return Response(
        content=csv_content,
        media_type="text/csv",
        headers={"Content-Disposition": 'attachment; filename="soc_alerts.csv"'},
    )


def start_live_tail(payload: dict[str, Any]):
    parsed, error = _validate_payload(payload, LiveTailStartPayload)
    if error:
        return error
    assert parsed is not None
    try:
        file_path = _validate_live_tail_path(str(parsed.file_path).strip())
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    from_start = bool(parsed.from_start)
    interval_sec = float(parsed.interval_sec)
    try:
        state = tail_manager.start(file_path=file_path, from_start=from_start, interval_sec=interval_sec)
    except ValueError as exc:
        return JSONResponse({"detail": str(exc)}, status_code=400)
    return state.__dict__


def stop_live_tail():
    state = tail_manager.stop()
    return state.__dict__


def live_tail_status():
    return tail_manager.status().__dict__
