# Repository Guidelines

## Project Structure & Module Organization
The project is a FastAPI-based mini SOC dashboard.
- `app/main.py`: API routes, ingestion flow, filtering, and stats endpoints.
- `app/parser.py`: log normalization from JSON lines or Apache/Nginx-like lines.
- `app/detector.py`: security detection rules (scanner UA, injection/traversal, brute-force).
- `app/database.py`: SQLite schema and query helpers (`data/soc.db`).
- `app/templates/` and `app/static/`: frontend UI (HTML/CSS/JS).
- `tests/`: parser/detector unit tests.
- `data/sample.log`: sample dataset for manual demo.

## Build, Test, and Development Commands
- `pip install -r requirements.txt`: install runtime and test dependencies.
- `uvicorn app.main:app --reload`: run dashboard locally on `:8000`.
- `pytest -q`: run unit tests.
- `docker compose up --build`: build and run in container.

## Coding Style & Naming Conventions
- Use Python 3.11+, 4-space indentation, and type hints for new Python code.
- Keep modules focused: parsing in `parser.py`, detection in `detector.py`, persistence in `database.py`.
- Prefer snake_case for functions/variables and clear alert names (e.g. `possible-bruteforce`).
- Keep frontend JavaScript framework-free unless explicitly migrating to React.

## Testing Guidelines
- Framework: `pytest`.
- Test files should be named `test_*.py`; test functions should start with `test_`.
- Cover parser edge cases and detection logic for regressions.
- Before PRs, run `pytest -q` and a quick manual UI check by importing `data/sample.log`.

## Commit & Pull Request Guidelines
- Follow concise, imperative commit messages (e.g. `add brute-force detection rule`).
- Scope commits by concern: backend rules, frontend UX, docs, tests.
- PRs should include:
- short summary of behavior changes,
- testing evidence (`pytest` output and manual checks),
- screenshots/GIFs for UI changes,
- linked issue/task when available.

## Security & Configuration Tips
- Do not commit real production logs with sensitive data.
- Use anonymized sample logs for demos/tests.
- If exposing publicly, place the app behind auth and HTTPS.
