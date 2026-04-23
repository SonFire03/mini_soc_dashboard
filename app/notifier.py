from __future__ import annotations

import json
import os
from typing import Any
from urllib import request

_SEVERITY_ORDER = {"low": 1, "medium": 2, "high": 3}


def maybe_notify_alert(alert: dict[str, Any]) -> None:
    webhook_url = os.getenv("SOC_WEBHOOK_URL", "").strip()
    if not webhook_url:
        return

    min_level = os.getenv("SOC_WEBHOOK_MIN_SEVERITY", "high").strip().lower()
    min_rank = _SEVERITY_ORDER.get(min_level, 3)
    current_rank = _SEVERITY_ORDER.get(str(alert.get("severity", "low")).lower(), 1)
    if current_rank < min_rank:
        return

    payload = {
        "event": "soc_alert",
        "severity": alert.get("severity"),
        "alert_type": alert.get("alert_type"),
        "ip": alert.get("ip"),
        "details": alert.get("details"),
        "ts": alert.get("ts"),
    }

    data = json.dumps(payload).encode("utf-8")
    req = request.Request(
        webhook_url,
        data=data,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    try:
        request.urlopen(req, timeout=1.5)
    except Exception:
        # Notifications should never break ingestion flow.
        return
