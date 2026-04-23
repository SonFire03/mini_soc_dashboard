from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field


class IngestJsonPayload(BaseModel):
    lines: list[str | dict[str, Any]] = Field(default_factory=list)


class AlertUpdatePayload(BaseModel):
    status: Literal["new", "investigating", "resolved", "false-positive"] | None = None
    assignee: str | None = Field(default=None, max_length=120)
    resolution_note: str | None = Field(default=None, max_length=1000)


class CaseCreatePayload(BaseModel):
    title: str = Field(min_length=1, max_length=240)
    priority: Literal["low", "medium", "high", "critical"] = "medium"
    status: Literal["open", "investigating", "closed"] = "open"
    owner: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    due_at: str | None = None


class CaseUpdatePayload(BaseModel):
    title: str | None = Field(default=None, min_length=1, max_length=240)
    priority: Literal["low", "medium", "high", "critical"] | None = None
    status: Literal["open", "investigating", "closed"] | None = None
    owner: str | None = Field(default=None, max_length=120)
    description: str | None = Field(default=None, max_length=2000)
    due_at: str | None = None
    actor: str | None = Field(default=None, max_length=120)


class CaseCommentCreatePayload(BaseModel):
    author: str = Field(default="analyst", max_length=120)
    message: str = Field(min_length=1, max_length=2000)


class SavedViewCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    target: Literal["logs", "alerts", "both"] = "both"
    query_dsl: str = Field(min_length=1, max_length=1000)


class ReportScheduleCreatePayload(BaseModel):
    name: str | None = Field(default=None, max_length=200)
    hour_utc: int = Field(ge=0, le=23)
    minute_utc: int = Field(ge=0, le=59)
    enabled: bool = True


class ReportScheduleUpdatePayload(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    hour_utc: int | None = Field(default=None, ge=0, le=23)
    minute_utc: int | None = Field(default=None, ge=0, le=59)
    enabled: bool | None = None


class IocCreatePayload(BaseModel):
    ioc_type: Literal["ip", "path", "user_agent", "text"]
    ioc_value: str = Field(min_length=1, max_length=500)
    severity_override: Literal["low", "medium", "high", "critical"] = "high"
    enabled: bool = True


class IocUpdatePayload(BaseModel):
    ioc_type: Literal["ip", "path", "user_agent", "text"] | None = None
    ioc_value: str | None = Field(default=None, min_length=1, max_length=500)
    severity_override: Literal["low", "medium", "high", "critical"] | None = None
    enabled: bool | None = None


class PolicyCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    condition_expr: str = Field(min_length=1, max_length=500)
    action_type: Literal["create_case", "escalate_alert", "notify_only"]
    action_payload: dict[str, Any] | None = None
    enabled: bool = True


class PolicyUpdatePayload(BaseModel):
    name: str | None = Field(default=None, min_length=1, max_length=200)
    condition_expr: str | None = Field(default=None, min_length=1, max_length=500)
    action_type: Literal["create_case", "escalate_alert", "notify_only"] | None = None
    action_payload: dict[str, Any] | None = None
    enabled: bool | None = None


class AssetCreatePayload(BaseModel):
    name: str = Field(min_length=1, max_length=200)
    criticality: Literal["low", "medium", "high", "critical"] = "medium"
    ip_cidr: str | None = Field(default=None, max_length=100)
    path_prefix: str | None = Field(default=None, max_length=400)
    owner: str | None = Field(default=None, max_length=120)


class SuppressionCreatePayload(BaseModel):
    ip: str | None = Field(default=None, max_length=64)
    alert_type: str | None = Field(default=None, max_length=120)
    path_pattern: str | None = Field(default=None, max_length=400)
    reason: str = Field(default="manual suppression", max_length=240)
    ttl_minutes: int = Field(default=60, gt=0, le=60 * 24 * 365)


class RestoreBackupPayload(BaseModel):
    backup_name: str | None = Field(default=None, max_length=300)


class LiveTailStartPayload(BaseModel):
    file_path: str = Field(min_length=1, max_length=2000)
    from_start: bool = False
    interval_sec: float = Field(default=1.0, ge=0.2, le=30.0)
