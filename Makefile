.PHONY: help install test test-cov lint clean lab-up lab-down smoke

PYTHON ?= python3
VENV   ?= .venv

help:
	@echo "Targets:"
	@echo "  install    create venv and install dev deps"
	@echo "  test       run pytest"
	@echo "  test-cov   run pytest with coverage"
	@echo "  lab-up     start isolated lab (docker compose)"
	@echo "  lab-down   stop lab"
	@echo "  smoke      run a single mocked end-to-end shannon run"
	@echo "  fetch      download all paper resources (target apps, tools, ground truth)"
	@echo "  fetch-dry  dry-run of fetch — show what would be downloaded"
	@echo "  clean      remove venv and caches"

install:
	$(PYTHON) -m venv $(VENV)
	$(VENV)/bin/pip install -U pip
	$(VENV)/bin/pip install -e ".[dev]"

test:
	$(VENV)/bin/pytest

test-cov:
	$(VENV)/bin/pytest --cov=lab --cov=payloads --cov-report=term-missing

lab-up:
	docker compose -f lab/docker-compose.yml up -d

lab-down:
	docker compose -f lab/docker-compose.yml down -v

smoke:
	$(VENV)/bin/python -m lab.shannon_runner.runner --mock --target juice-shop --out results/smoke.jsonl

fetch:
	$(VENV)/bin/python -m data.fetch

fetch-dry:
	$(VENV)/bin/python -m data.fetch --dry-run

clean:
	rm -rf $(VENV) .pytest_cache .coverage htmlcov **/__pycache__
