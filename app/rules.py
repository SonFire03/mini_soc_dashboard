from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

_RULES_PATH = Path("config/rules.yaml")
_DEFAULT_RULES: dict[str, Any] = {
    "suspicious_user_agents": ["sqlmap", "nikto", "nmap", "dirbuster", "masscan", "curl/"],
    "suspicious_patterns": ["union select", "or 1=1", "../", "<script", "xp_cmdshell"],
    "admin_paths": ["/admin"],
    "failed_login_markers": ["login", "signin", "auth"],
    "thresholds": {
        "bruteforce": {"attempts": 5, "window_minutes": 10},
        "login_success_after_failures": {"failed_attempts": 3, "window_minutes": 10},
        "error_spike_5xx": {"errors": 7, "window_minutes": 5},
    },
}

_cached_rules: dict[str, Any] | None = None
_cached_mtime: float | None = None


def _deep_merge(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_merge(out[key], value)
        else:
            out[key] = value
    return out


def load_rules() -> dict[str, Any]:
    global _cached_rules, _cached_mtime

    if not _RULES_PATH.exists():
        return _DEFAULT_RULES

    mtime = _RULES_PATH.stat().st_mtime
    if _cached_rules is not None and _cached_mtime == mtime:
        return _cached_rules

    with _RULES_PATH.open("r", encoding="utf-8") as handle:
        loaded = yaml.safe_load(handle) or {}

    if not isinstance(loaded, dict):
        loaded = {}

    _cached_rules = _deep_merge(_DEFAULT_RULES, loaded)
    _cached_mtime = mtime
    return _cached_rules
