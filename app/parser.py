from __future__ import annotations

import json
import re
from datetime import UTC, datetime
from typing import Any

# Basic Apache/Nginx-like combined log parser.
LOG_RE = re.compile(
    r'(?P<ip>\S+) \S+ \S+ \[(?P<ts>[^\]]+)\] "(?P<method>\S+) (?P<path>[^\s]+) [^"]+" (?P<status>\d{3}) \S+ "[^"]*" "(?P<ua>[^"]*)"'
)


def parse_ts(raw_ts: str | None = None) -> str:
    if not raw_ts:
        return datetime.now(UTC).isoformat()
    try:
        dt = datetime.fromisoformat(raw_ts.replace("Z", "+00:00"))
        return dt.isoformat()
    except ValueError:
        try:
            dt = datetime.strptime(raw_ts, "%d/%b/%Y:%H:%M:%S %z")
            return dt.isoformat()
        except ValueError:
            return datetime.now(UTC).isoformat()


def normalize_log(item: str | dict[str, Any]) -> dict[str, Any]:
    if isinstance(item, dict):
        return {
            "ts": parse_ts(item.get("ts")),
            "ip": item.get("ip"),
            "username": item.get("username"),
            "user_agent": item.get("user_agent"),
            "method": item.get("method"),
            "path": item.get("path"),
            "status_code": int(item.get("status_code") or 0),
            "message": item.get("message"),
            "raw": json.dumps(item, ensure_ascii=True),
        }

    line = item.strip()
    if not line:
        raise ValueError("Empty line")

    try:
        payload = json.loads(line)
        return normalize_log(payload)
    except json.JSONDecodeError:
        pass

    match = LOG_RE.match(line)
    if match:
        data = match.groupdict()
        return {
            "ts": parse_ts(data.get("ts")),
            "ip": data.get("ip"),
            "username": None,
            "user_agent": data.get("ua"),
            "method": data.get("method"),
            "path": data.get("path"),
            "status_code": int(data.get("status") or 0),
            "message": None,
            "raw": line,
        }

    return {
        "ts": parse_ts(),
        "ip": None,
        "username": None,
        "user_agent": None,
        "method": None,
        "path": None,
        "status_code": 0,
        "message": line,
        "raw": line,
    }
