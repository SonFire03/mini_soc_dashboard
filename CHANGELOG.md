# Changelog

All notable changes to this project are documented in this file.

## [1.3.0] - 2026-05-08

### Added
- New aggregated SOC analytics endpoint: `GET /api/analytics/overview?window_hours=24`.
- Version exposure through:
  - `GET /api/health` (`version` field),
  - `GET /api/settings` (`app_version` field).
- Integration test coverage for analytics overview payload.

### Updated
- README refreshed to include release info and analytics endpoint.
