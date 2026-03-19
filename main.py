"""Thin shim for running bt-defender without installing (dev only)."""

from defender.cli import cli

if __name__ == "__main__":
    cli()
