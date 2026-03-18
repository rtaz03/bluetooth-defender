# Bluetooth Defender

## Project Overview

A Python CLI toolkit for defending against unauthorized Bluetooth connections. Three tools: scanner (diagnostics), honeypot (trap + logging), and streamer (byte-streaming deterrent).

## Design Doc

See `docs/brainstorming/2026-03-18-bluetooth-defender.md` for the full design.

## Tech Stack

- Python 3.11+
- `bumble` — Google's BT stack for Classic Bluetooth (honeypot, streamer)
- `bleak` — BLE scanning
- `rich` — terminal UI
- `ruff` — linting and formatting
- `pytest` + `pytest-asyncio` — testing

## Setup

```bash
make install    # Create venv and install deps
make dev        # Install with dev deps (ruff, pytest)
```

## Project Structure

```
defender/          # Main package
  scanner.py       # Passive scanning & defense recommendations
  honeypot.py      # Fake BT device that logs connection attempts
  streamer.py      # Byte-streaming deterrent
  utils/           # Shared helpers (logging, BT helpers)
main.py            # CLI entrypoint: python main.py scan|honeypot|stream|logs
logs/              # JSONL logs from all tools (gitignored)
```

## Make Targets

```bash
make install     # Create venv, install deps
make dev         # Install with dev deps (ruff, pytest)
make lint        # Run ruff linter
make format      # Auto-format and fix lint issues
make check       # Check formatting + lint (CI-friendly)
make test        # Run pytest
make scan        # Run scanner (pass ARGS="--known-devices devices.json")
make honeypot    # Run honeypot (pass ARGS="--name 'Speaker' --retaliate")
make stream      # Run streamer (pass ARGS="AA:BB:CC:DD:EE:FF --mode l2cap")
make logs        # View log summaries (all tools)
make clean       # Remove venv, caches, build artifacts
```

## Commands

```bash
python main.py scan --known-devices devices.json
python main.py honeypot --name "Speaker Name" [--retaliate --mode l2cap]
python main.py stream <MAC> --mode <l2cap|a2dp_garbage|spp> --pattern <random|zeros|hex> --duration <seconds>
python main.py logs [--tool honeypot|scanner|streamer] [--mac AA:BB:CC:DD:EE:FF] [--date 2026-03-18] [--raw] [--last N]
```

## Linting & Formatting

Uses `ruff` with these rule sets: E, W, F, I (isort), B (bugbear), UP (pyupgrade), SIM, TCH. Config in `pyproject.toml`. Run `make format` before committing.

## Hardware Requirement

The honeypot and streamer require a USB Bluetooth dongle (CSR8510 or similar) for HCI transport. The built-in Mac Bluetooth adapter only works with the scanner via `bleak`.

## Commits

Use [Conventional Commits](https://www.conventionalcommits.org/): one-liner, no body, no co-author. Examples:
- `feat: add honeypot auto-retaliation mode`
- `fix: handle missing USB dongle gracefully`
- `docs: update setup instructions`
- `chore: add ruff to dev deps`

## Conventions

- Structured JSONL logging for all tools — one JSON object per line in `logs/`
- Known devices stored in `devices.json` at repo root (copy `devices.example.json`)
- Streamer refuses to target MACs in the known-devices list when invoked via `--retaliate`
- All Bluetooth code is async (bumble + bleak are both asyncio-based)
