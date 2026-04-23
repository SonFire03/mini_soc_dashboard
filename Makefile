PYTHON=.venv/bin/python
PIP=.venv/bin/pip
PORT?=8000
HOST?=0.0.0.0

setup:
	python3 -m venv .venv
	$(PIP) install -r requirements.txt

run:
	$(PYTHON) -m uvicorn app.main:app --reload --host $(HOST) --port $(PORT)

connect: setup
	@for p in 8000 8001 8002 8003 8004 8005; do \
		if ! lsof -i :$$p >/dev/null 2>&1; then \
			echo "Mini SOC Dashboard running on http://localhost:$$p"; \
			$(PYTHON) -m uvicorn app.main:app --reload --host $(HOST) --port $$p; \
			exit 0; \
		fi; \
	done; \
	echo "No free port in 8000-8005. Use: make run PORT=<port>"; \
	exit 1

test:
	$(PYTHON) -m pytest -q

lint:
	$(PYTHON) -m ruff check .

typecheck:
	$(PYTHON) -m mypy app

migrate:
	$(PYTHON) -m alembic upgrade head

docker-up:
	docker compose up --build

docker-down:
	docker compose down
