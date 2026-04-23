from __future__ import annotations

from collections import defaultdict
from datetime import datetime, timedelta
from typing import Any, Callable

from app.rules import load_rules

SingleRule = Callable[[dict[str, Any], dict[str, Any]], list[dict[str, Any]]]
BatchRule = Callable[[list[dict[str, Any]], dict[str, Any]], list[dict[str, Any]]]

_SINGLE_RULES: list[SingleRule] = []
_BATCH_RULES: list[BatchRule] = []


def register_single_rule(rule: SingleRule) -> SingleRule:
    _SINGLE_RULES.append(rule)
    return rule


def register_batch_rule(rule: BatchRule) -> BatchRule:
    _BATCH_RULES.append(rule)
    return rule


def _to_dt(ts: str) -> datetime:
    return datetime.fromisoformat(ts.replace("Z", "+00:00"))


@register_single_rule
def _rule_suspicious_payload(log: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    suspicious_patterns = tuple(str(v).lower() for v in rules.get("suspicious_patterns", []))
    path = (log.get("path") or "").lower()
    msg = (log.get("message") or "").lower()
    if any(token in path or token in msg for token in suspicious_patterns):
        return [
            {
                "severity": "high",
                "alert_type": "injection-or-traversal",
                "details": f"Suspicious payload detected in path/message: {log.get('path') or log.get('message')}",
                "explain": "Matched payload signatures from suspicious_patterns against path/message.",
            }
        ]
    return []


@register_single_rule
def _rule_suspicious_ua(log: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    suspicious_uas = tuple(str(v).lower() for v in rules.get("suspicious_user_agents", []))
    ua = (log.get("user_agent") or "").lower()
    if any(token in ua for token in suspicious_uas):
        return [
            {
                "severity": "medium",
                "alert_type": "suspicious-user-agent",
                "details": f"Known scanner/bot user-agent: {log.get('user_agent')}",
                "explain": "User-agent matched configured suspicious_user_agents signatures.",
            }
        ]
    return []


@register_single_rule
def _rule_admin_access_denied(log: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    admin_paths = tuple(str(v).lower() for v in rules.get("admin_paths", []))
    path = (log.get("path") or "").lower()
    status = int(log.get("status_code") or 0)
    if any(path.startswith(admin_path) for admin_path in admin_paths) and status in (401, 403):
        return [
            {
                "severity": "medium",
                "alert_type": "admin-access-denied",
                "details": f"Denied access on admin endpoint {log.get('path')}",
                "explain": "Request hit protected admin path and returned authorization failure.",
            }
        ]
    return []


@register_single_rule
def _rule_failed_login(log: dict[str, Any], rules: dict[str, Any]) -> list[dict[str, Any]]:
    failed_markers = tuple(str(v).lower() for v in rules.get("failed_login_markers", []))
    path = (log.get("path") or "").lower()
    status = int(log.get("status_code") or 0)
    if any(marker in path for marker in failed_markers) and status in (401, 403):
        return [
            {
                "severity": "low",
                "alert_type": "failed-login-attempt",
                "details": f"Failed login attempt on {log.get('path')}",
                "explain": "Login marker detected in path with auth failure status code.",
            }
        ]
    return []


def detect_single(log: dict[str, Any]) -> list[dict[str, Any]]:
    rules = load_rules()
    alerts: list[dict[str, Any]] = []
    for rule in _SINGLE_RULES:
        alerts.extend(rule(log, rules))
    return alerts


@register_batch_rule
def _rule_bruteforce(logs: list[dict[str, Any]], rules: dict[str, Any]) -> list[dict[str, Any]]:
    brute_cfg = rules.get("thresholds", {}).get("bruteforce", {})
    attempts_threshold = int(brute_cfg.get("attempts", 5))
    window_minutes = int(brute_cfg.get("window_minutes", 10))
    failed_markers = tuple(str(v).lower() for v in rules.get("failed_login_markers", []))

    failures: dict[str, list[datetime]] = defaultdict(list)
    alerts: list[dict[str, Any]] = []

    for log in logs:
        ip = log.get("ip") or "unknown"
        path = (log.get("path") or "").lower()
        status = int(log.get("status_code") or 0)

        if any(marker in path for marker in failed_markers) and status in (401, 403):
            failures[ip].append(_to_dt(log["ts"]))

    for ip, times in failures.items():
        times.sort()
        for i in range(len(times)):
            window_end = times[i] + timedelta(minutes=window_minutes)
            count = sum(1 for t in times[i:] if t <= window_end)
            if count >= attempts_threshold:
                alerts.append(
                    {
                        "ts": times[i].isoformat(),
                        "severity": "high",
                        "alert_type": "possible-bruteforce",
                        "ip": ip,
                        "details": f"{count} failed login attempts in {window_minutes} minutes",
                        "explain": f"Threshold reached: attempts>={attempts_threshold} within {window_minutes} minutes.",
                    }
                )
                break

    return alerts


@register_batch_rule
def _rule_login_success_after_failures(logs: list[dict[str, Any]], rules: dict[str, Any]) -> list[dict[str, Any]]:
    cfg = rules.get("thresholds", {}).get("login_success_after_failures", {})
    failed_threshold = int(cfg.get("failed_attempts", 3))
    window_minutes = int(cfg.get("window_minutes", 10))
    failed_markers = tuple(str(v).lower() for v in rules.get("failed_login_markers", []))

    events_by_ip: dict[str, list[tuple[datetime, int, str]]] = defaultdict(list)
    alerts: list[dict[str, Any]] = []

    for log in logs:
        ip = log.get("ip") or "unknown"
        path = (log.get("path") or "").lower()
        status = int(log.get("status_code") or 0)
        if not any(marker in path for marker in failed_markers):
            continue
        events_by_ip[ip].append((_to_dt(log["ts"]), status, path))

    for ip, events in events_by_ip.items():
        events.sort(key=lambda item: item[0])
        for idx, (ts, status, path) in enumerate(events):
            if status not in (200, 201, 204):
                continue
            window_start = ts - timedelta(minutes=window_minutes)
            failed_before_success = sum(
                1
                for t_prev, s_prev, _ in events[:idx]
                if t_prev >= window_start and s_prev in (401, 403)
            )
            if failed_before_success >= failed_threshold:
                alerts.append(
                    {
                        "ts": ts.isoformat(),
                        "severity": "high",
                        "alert_type": "possible-account-compromise",
                        "ip": ip,
                        "details": f"Successful login after {failed_before_success} failed attempts in {window_minutes} minutes ({path})",
                        "explain": f"Success after >= {failed_threshold} failures in {window_minutes} minute window.",
                    }
                )
                break

    return alerts


@register_batch_rule
def _rule_error_spike(logs: list[dict[str, Any]], rules: dict[str, Any]) -> list[dict[str, Any]]:
    cfg = rules.get("thresholds", {}).get("error_spike_5xx", {})
    errors_threshold = int(cfg.get("errors", 7))
    window_minutes = int(cfg.get("window_minutes", 5))

    spikes: dict[str, list[datetime]] = defaultdict(list)
    alerts: list[dict[str, Any]] = []
    for log in logs:
        status = int(log.get("status_code") or 0)
        if status < 500:
            continue
        ip = log.get("ip") or "unknown"
        spikes[ip].append(_to_dt(log["ts"]))

    for ip, times in spikes.items():
        times.sort()
        for i, ts in enumerate(times):
            window_end = ts + timedelta(minutes=window_minutes)
            count = sum(1 for t in times[i:] if t <= window_end)
            if count >= errors_threshold:
                alerts.append(
                    {
                        "ts": ts.isoformat(),
                        "severity": "medium",
                        "alert_type": "error-spike-5xx",
                        "ip": ip,
                        "details": f"{count} server errors from same IP in {window_minutes} minutes",
                        "explain": f"5xx errors from same IP exceeded threshold {errors_threshold} in {window_minutes} minutes.",
                    }
                )
                break

    return alerts


def _run_batch_rule(name: str, logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    rules = load_rules()
    registry: dict[str, BatchRule] = {
        "detect_bruteforce": _rule_bruteforce,
        "detect_login_success_after_failures": _rule_login_success_after_failures,
        "detect_error_spike": _rule_error_spike,
    }
    return registry[name](logs, rules)


def detect_bruteforce(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _run_batch_rule("detect_bruteforce", logs)


def detect_login_success_after_failures(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _run_batch_rule("detect_login_success_after_failures", logs)


def detect_error_spike(logs: list[dict[str, Any]]) -> list[dict[str, Any]]:
    return _run_batch_rule("detect_error_spike", logs)
