# Contributing

Thanks for contributing to `mini_soc_dashboard`.

## Development Setup

Requirements:
- Python 3.11+
- `pip`
- optional: Docker

Local setup:

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt
alembic upgrade head
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000
```

You can also use:

```bash
make setup
make run
```

## Project Structure

- `app/main.py`: FastAPI app assembly
- `app/runtime.py`: core application logic
- `app/routes/`: route modules by domain
- `app/parser.py`: log normalization
- `app/detector.py`: detection rules
- `app/database.py`: SQLite access
- `app/templates/` and `app/static/`: UI
- `tests/`: regression coverage

## Coding Guidelines

- Target Python `3.11+`.
- Use type hints for new Python code.
- Keep functions and modules scoped by concern.
- Follow existing naming and routing conventions.
- Prefer extending current patterns over introducing a new abstraction style.
- Keep frontend JavaScript framework-free unless the project explicitly changes direction.

## Tests and Checks

Run before opening a pull request:

```bash
make lint
make typecheck
make test
```

If your change affects database schema:

```bash
make migrate
```

If your change affects the UI, also do a quick manual check in the browser after importing `data/sample.log`.

## Pull Requests

A good pull request should include:
- a short summary of the change,
- why the change is needed,
- testing evidence,
- screenshots for UI changes,
- any migration or operational note if relevant.

Keep pull requests focused. Avoid mixing refactors, UI changes, and backend behavior changes unless they are part of the same delivery.

## Commit Messages

Use short imperative commit messages, for example:
- `add multilingual dashboard support`
- `harden live tail path validation`
- `refactor routes into modules`

## Security

- Do not commit real production logs.
- Do not commit secrets, tokens, or credentials.
- Use anonymized samples for reproduction.
- Follow [SECURITY.md](SECURITY.md) for vulnerability reporting.
