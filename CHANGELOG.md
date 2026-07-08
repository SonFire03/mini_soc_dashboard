# Changelog

All notable changes to this project are documented in this file.

## [1.5.0] - 2026-07-09

### Added
- Multi-page dashboard navigation with dedicated `Overview`, `Investigations`, `Operations`, `Reports`, and `Admin` views.
- Route modules under `app/routes/` for auth, logs, alerts, cases, reports, and admin domains.
- Unified investigation endpoint: `GET /api/alerts/{id}/investigation`.
- Frontend i18n layer with language selector and flags for:
  - English
  - French
  - German
  - Spanish
  - Japanese
  - Mandarin Chinese
  - Hindi
  - Arabic
  - Russian
- Localized daily report rendering via `GET /reports/daily?lang=...`.
- Additional regression coverage for aggregated investigation context.

### Updated
- `app/main.py` now focuses on FastAPI assembly and runtime re-exports.
- Core application logic moved into `app/runtime.py`.
- Investigation workspace now centralizes alert, asset, case, IOC, event, and related-log context in one panel.
- Operations page layout reorganized to avoid an oversized single-page dashboard and improve tool discoverability.
- Login and dashboard UI now support persistent client-side language switching, including RTL layout support for Arabic.
- README updated to document the new architecture, navigation model, multilingual UI, and localized reporting.

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
