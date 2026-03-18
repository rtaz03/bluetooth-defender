# Bluetooth Defender

A Python CLI toolkit for defending against unauthorized Bluetooth connections. Three tools: a passive scanner for diagnostics, a honeypot that traps and logs connection attempts, and a byte streamer for active deterrence.

## Setup

```bash
make install    # Create venv and install deps
make dev        # Install with dev deps (ruff, pytest)
```

## Usage

### Scanner

Passively scan for nearby Bluetooth devices and flag unknowns.

```bash
python main.py scan --known-devices devices.json --duration 15
```

### Honeypot

Emulate a fake Bluetooth device (e.g. a speaker) and log every connection attempt. Optionally auto-retaliate with one or more modes.

```bash
python main.py honeypot --name "Living Room Speaker"
python main.py honeypot --name "Car Stereo" --retaliate --known-devices devices.json
python main.py honeypot --name "Kitchen Speaker" --retaliate --mode a2dp_garbage,pairing_loop,avctp
```

The default retaliation is `a2dp_garbage,pairing_loop`.

### Streamer

Stream garbage bytes to a target Bluetooth device. Supports comma-separated modes to run concurrently.

```bash
python main.py stream AA:BB:CC:DD:EE:FF --mode l2cap --pattern random --duration 30
python main.py stream AA:BB:CC:DD:EE:FF --mode a2dp_garbage,avctp --duration 15
python main.py stream AA:BB:CC:DD:EE:FF --mode pairing_loop
```

### Retaliation Modes

| Mode | Type | Description |
|------|------|-------------|
| `l2cap` | Connection | Raw L2CAP byte flood on a dynamic PSM |
| `spp` | Connection | RFCOMM/Serial Port Profile data flood |
| `a2dp_garbage` | Connection | Malformed SBC audio frames over AVDTP |
| `avctp` | Connection | Fake AV/C media control commands (play/pause/volume) |
| `sdp_spam` | Connection | Oversized malformed SDP response PDUs |
| `pairing_loop` | Device | Repeated pair/abort cycles forcing auth dialogs |
| `name_spoof` | Device | Rotate advertised name to pollute device scans |

Connection modes require an active Bluetooth connection. Device modes operate at the adapter level and can run without one. Multiple modes can be combined with commas.

### Log Viewer

View aggregated summaries or raw event logs from all tools. Logs are stored as JSONL in `logs/`.

```bash
python main.py logs                                  # summaries for all tools
python main.py logs --tool honeypot                  # honeypot summary only
python main.py logs --mac AA:BB:CC:DD:EE:FF          # filter by MAC address
python main.py logs --date 2026-03-18 --tool scanner # scanner logs from a specific date
python main.py logs --raw --last 20                  # last 20 raw events, chronological
```

| Flag | Description |
|------|-------------|
| `--tool/-t` | Filter by tool: `honeypot`, `scanner`, `streamer` |
| `--mac/-m` | Filter events by MAC address |
| `--date/-d` | Filter by date (`YYYY-MM-DD`) |
| `--raw/-r` | Show raw chronological event table |
| `--last/-n` | Show only the last N events (with `--raw`) |

## Hardware

The honeypot and streamer require a USB Bluetooth dongle (CSR8510 or similar) for HCI transport. The built-in Mac Bluetooth adapter only works with the scanner via `bleak`.

## Development

```bash
make lint      # Run ruff linter
make format    # Auto-format and fix lint issues
make check     # Check formatting + lint (CI-friendly)
make test      # Run pytest
make clean     # Remove venv, caches, build artifacts
```

## Known Devices

Copy `devices.example.json` to `devices.json` and add your trusted devices. The streamer refuses to target listed MACs when invoked via `--retaliate`, and the scanner uses the list to flag unknowns.
