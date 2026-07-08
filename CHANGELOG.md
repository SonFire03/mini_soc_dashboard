# Changelog

All notable changes to this project are documented in this file.

## [1.4.0] - 2026-07-08

### Added
- Security posture metadata in `GET /api/settings`, including cookie security, live-tail restriction, and configuration warnings.
- `SOC_COOKIE_SECURE` and `SOC_DASHBOARD_PRODUCTION` controls for secure cookies.
- `SOC_LIVE_TAIL_ROOT` and `SOC_LIVE_TAIL_ALLOW_ANY` controls for live-tail file access.

### Updated
- Default demo credentials are now consistently `Change_me` / `Change_me`.
- Logout clears both session and role cookies.
- Live tail API rejects paths outside the configured root by default.

## [1.3.1] - 2026-05-08

### Added
- RBAC baseline in auth middleware:
  - `analyst` role is forbidden on sensitive endpoints (`/api/admin/*`, `/api/policies*`).
- OpenAPI examples for:
  - `POST /api/logs/ingest-json`
  - `GET /api/alerts` (`dsl` query sample)
  - `POST /api/cases`
- New tests for RBAC middleware and metadata endpoints.

### Updated
- CI quality gate raised to `66%` coverage.
- README updated with a "What Changed Since v1.3.0" section.

## [1.3.0] - 2026-05-08

### Added
- New aggregated SOC analytics endpoint: `GET /api/analytics/overview?window_hours=24`.
- Version exposure through:
  - `GET /api/health` (`version` field),
  - `GET /api/settings` (`app_version` field).
- Integration test coverage for analytics overview payload.

### Updated
- README refreshed to include release info and analytics endpoint.
