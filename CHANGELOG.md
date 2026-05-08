# Changelog

All notable changes to this project are documented in this file.

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
