.PHONY: install dev lint format check test clean scan list-usb honeypot stream logs

PYTHON ?= python
VENV := .venv
BIN := $(VENV)/bin

# Setup
install: $(VENV)/pyvenv.cfg

$(VENV)/pyvenv.cfg: pyproject.toml
	$(PYTHON) -m venv $(VENV)
	$(BIN)/pip install -e .
	@touch $@

dev: $(VENV)/pyvenv.cfg
	$(BIN)/pip install -e ".[dev]"

# Linting & formatting
lint:
	$(BIN)/ruff check defender/ main.py

format:
	$(BIN)/ruff format defender/ main.py
	$(BIN)/ruff check --fix defender/ main.py

check: lint
	$(BIN)/ruff format --check defender/ main.py

# Tests
test:
	$(BIN)/pytest tests/ -v

# Bluetooth Defender commands
scan: install
	$(BIN)/python main.py scan $(ARGS)

list-usb: install
	$(BIN)/python main.py list-usb

honeypot: install
	$(BIN)/python main.py honeypot $(ARGS)

stream: install
	$(BIN)/python main.py stream $(ARGS)

logs: install
	$(BIN)/python main.py logs

# Cleanup
clean:
	rm -rf $(VENV) *.egg-info dist build __pycache__ .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
