.PHONY: help install dev lint format check test clean scan list-usb set-usb honeypot stream logs

PYTHON ?= python
VENV := .venv
BIN := $(VENV)/bin

# Default target
help:
	@echo "Usage: make <target> [ARGS='...']"
	@echo ""
	@echo "Setup"
	@echo "  install       Create venv and install dependencies"
	@echo "  dev           Install with dev deps (ruff, pytest)"
	@echo ""
	@echo "Code quality"
	@echo "  lint          Run ruff linter"
	@echo "  format        Auto-format and fix lint issues"
	@echo "  check         Check formatting + lint (CI-friendly)"
	@echo "  test          Run pytest"
	@echo ""
	@echo "Commands"
	@echo "  scan          Scan for nearby Bluetooth devices"
	@echo "  list-usb      List available USB Bluetooth dongles"
	@echo "  set-usb       Save default USB dongle (ARGS='2357:0604'), omit to clear"
	@echo "  honeypot      Run the honeypot"
	@echo "  stream        Stream bytes to a target"
	@echo "  logs          View log summaries"
	@echo ""
	@echo "Other"
	@echo "  clean         Remove venv, caches, build artifacts"

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

set-usb: install
	$(BIN)/python main.py set-usb $(ARGS)

honeypot: install
	$(BIN)/python main.py honeypot $(ARGS)

stream: install
	$(BIN)/python main.py stream $(ARGS)

logs: install
	$(BIN)/python main.py logs $(ARGS)

# Cleanup
clean:
	rm -rf $(VENV) *.egg-info dist build __pycache__ .ruff_cache .pytest_cache
	find . -type d -name __pycache__ -exec rm -rf {} + 2>/dev/null || true
