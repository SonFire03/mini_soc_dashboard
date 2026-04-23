# Mini SOC Dashboard

Mini dashboard SOC web: ingestion de logs, détection d'événements suspects, alertes, statistiques, timeline et filtres de recherche.

## Stack

- Backend: FastAPI
- Storage: SQLite (`data/soc.db`)
- Frontend: HTML/CSS/JS
- Conteneurisation: Docker

## Tout connecter en local

```bash
make connect
```

`make connect` installe les deps puis choisit automatiquement un port libre entre `8000` et `8005`.
Puis ouvre l'URL affichee dans le terminal et importe `data/sample.log`.
Connexion par defaut: `admin / admin123`.

Pour changer les identifiants:

```bash
SOC_DASHBOARD_USERNAME=socadmin SOC_DASHBOARD_PASSWORD='strong-pass' make run
```

Pour activer notifications webhook:

```bash
SOC_WEBHOOK_URL='https://example.webhook' SOC_WEBHOOK_MIN_SEVERITY=high make run
```

Si tu veux imposer un port:

```bash
make run PORT=8010
```

## Commandes utiles

```bash
make test       # tests unitaires + intégration API
make docker-up  # exécution via Docker
make docker-down
alembic upgrade head  # migrations DB versionnées
```

## API principale

- `GET /api/health`
- `POST /api/logs/ingest` (upload log file)
- `POST /api/logs/ingest-json` (JSON lines direct)
- `GET /api/logs?q=&ip=&method=&status_code=&user_agent=&start=&end=`
- `GET /api/logs?...&limit=200&offset=0` (pagination standard)
- `GET /api/logs?dsl=ip:1.2.3.4 method:POST code:401`
- `GET /api/alerts?severity=&alert_type=&q=&ip=`
- `GET /api/alerts?...&limit=200&offset=0` (pagination standard)
- `GET /api/alerts?dsl=severity:high type:possible-bruteforce`
- `PATCH /api/alerts/{id}` (status/assignee/note)
- `GET /api/alerts/{id}/context` (drill-down logs/events/playbook)
- `GET /api/stats`
- `GET /api/risk/entities?since_hours=24`
- `GET /api/sla`
- `GET /api/incidents/timeline`
- `POST /api/live-tail/start`
- `POST /api/live-tail/stop`
- `GET /api/live-tail/status`
- `POST /api/admin/reset` (purge logs + alerts)
- `GET /api/export/logs.csv`
- `GET /api/export/alerts.csv`
- `GET /api/playbook/{alert_type}`
- `GET /api/settings`
- `GET /api/metrics` (format Prometheus text)
- `GET/POST/DELETE /api/assets`
- `GET/POST/DELETE /api/suppressions`
- `GET/POST/DELETE /api/saved-views`
- `GET /api/reports/daily`
- `GET /reports/daily` (print-ready HTML report)
- `GET/POST/PATCH/DELETE /api/reports/schedules`
- `POST /api/reports/schedules/{id}/run`
- `GET /api/reports/runs`
- `GET/POST/PATCH /api/cases`
- `POST/DELETE /api/cases/{case_id}/alerts/{alert_id}`
- `GET /api/cases/{case_id}`
- `GET/POST /api/cases/{case_id}/comments`
- `DELETE /api/cases/{case_id}/comments/{comment_id}`
- `GET/POST/PATCH/DELETE /api/iocs` (IOC watchlist)
- `GET/POST/PATCH/DELETE /api/policies` (policy engine)
- `GET /api/reports/delta?since_hours=24`
- `GET /api/admin/backups`
- `POST /api/admin/backup`
- `POST /api/admin/restore` (`{"backup_name":"soc-YYYYMMDD-HHMMSS.db"}` or latest if empty)
- `WS /ws/live` (heartbeat + events)
- `GET /wallboard` (mode mur SOC)

## Detections incluses

- `failed-login-attempt`
- `possible-bruteforce`
- `possible-account-compromise` (login reussi apres echecs)
- `error-spike-5xx`
- `injection-or-traversal`
- `suspicious-user-agent`
- `admin-access-denied`

## Règles configurables

Le moteur charge `config/rules.yaml` à chaud:
- user-agents et patterns suspects
- chemins admin et marqueurs login
- seuils bruteforce / compromission / spike 5xx

Tu peux modifier ce fichier sans toucher au code.

## Fonctions SOC avancées

- Mapping MITRE ATT&CK par alerte (tactique + technique).
- Inventory d'assets avec criticite (`low/medium/high/critical`), matching par IP/CIDR ou `path_prefix`.
- Suppression rules avec expiration (`ttl_minutes`) pour réduire le bruit.
- Incident timeline unifiee (creation et mise a jour d'alertes).
- Deduplication d'alertes proche-temps via compteur `occurrences`.
- Query DSL (`key:value`) pour hunts rapides.
- Saved views pour memoriser des recherches SOC frequentes.
- Drill-down d'alerte avec explainability (`explain_text`) + contexte.
- Rapport journalier HTML imprimable (PDF-ready via navigateur).
- Case management (multi-alertes, owner, priorite, actions).
- Metriques SLA (MTTA / MTTR moyens).
- Scheduler de rapports journaliers avec execution automatique UTC.
- WebSocket live updates (events cases/alerts/reports/reset).
- IOC watchlist (IP/path/user-agent/text) avec severite override.
- Policy engine (condition DSL simple `key==value AND ...`) avec actions auto-case/escalade/notif.
- Auto-escalation des alertes `high/critical` non traitees apres un seuil configurable.
- Backup/restore SQLite avec historique d'operations.
- Rétention auto (logs/alertes/events/reports/backups) configurable via variables `SOC_RETENTION_*`.
- Protection ingestion: rate limit (`SOC_INGEST_RATE_LIMIT_PER_MIN`) et limite taille payload (`SOC_INGEST_MAX_BYTES`).
- Delta report pour suivre l'evolution des alertes sur une fenetre temporelle.
- Correlation engine (chaine d'attaque multi-signaux sur une IP).
- Risk radar (scores IP/user/asset + delta sur fenetre precedente).
- Commentaires de case pour le suivi analyste.
- Option de securisation ingestion via `SOC_INGEST_API_KEY` (`X-API-Key`).
- Wallboard mode (vue ecran SOC epuree).
