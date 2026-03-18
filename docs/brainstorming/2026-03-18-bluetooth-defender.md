# Bluetooth Defender — Design

**Date:** 2026-03-18
**Problem:** Neighbor hijacks open Bluetooth devices (speaker, piano) by connecting to them while they're in discoverable/pairing mode and playing audio.

## Project Structure

Three standalone tools sharing a common utility layer:

```
bluetooth-defender/
├── defender/
│   ├── __init__.py
│   ├── scanner.py          # Passive BT scanning & defense recommendations
│   ├── honeypot.py         # Fake BT device that logs all connection activity
│   ├── streamer.py         # Byte-streaming deterrent tool
│   └── utils/
│       ├── __init__.py
│       ├── logging.py      # Structured JSON logging (shared by all tools)
│       └── bt_helpers.py   # Common Bluetooth helpers (RSSI, device class parsing)
├── logs/                   # Output directory for honeypot logs
├── requirements.txt        # bumble, bleak, rich
└── main.py                 # CLI entrypoint: python main.py scan|honeypot|stream
```

### Dependencies

- **`bumble`** — Google's full BT stack for low-level Classic BT control (honeypot, streamer)
- **`bleak`** — BLE scanning (scanner covers both protocols)
- **`rich`** — Terminal output for real-time monitoring

## Component 1: Scanner

Diagnostic tool — "what's exposed right now?"

1. Scans for nearby discoverable Bluetooth devices (Classic via `bumble` inquiry, BLE via `bleak`)
2. Identifies your own devices from a known-devices config file
3. Flags suspicious activity — generic-named devices that could be spoofs, unknown devices with strong RSSI
4. Outputs a defense report:
   - Which of your devices are discoverable (with fix recommendations)
   - Unknown nearby devices ranked by signal strength
   - Actionable recommendations

**Usage:**
```bash
python main.py scan --known-devices devices.json
```

**devices.json format:**
```json
[
  {"name": "Piano", "mac": "AA:BB:CC:DD:EE:FF"},
  {"name": "Speaker", "mac": "11:22:33:44:55:66"}
]
```

## Component 2: Honeypot

Fake Bluetooth device that acts as a trap, logging full forensics on anyone who connects.

1. Advertises as a fake speaker (configurable name, e.g. "JBL Flip 7") with correct device class bits for audio
2. Accepts all connection attempts — no PIN, no authentication
3. Registers SDP services — advertises A2DP Sink and SPP profiles
4. Logs everything:
   - Timestamp
   - Attacker MAC address and device name
   - Device class (phone, laptop, tablet, etc.)
   - RSSI (signal strength for distance estimation)
   - SDP service discovery probes
   - L2CAP connection details (PSM, channel, duration)
   - Raw protocol events from `bumble`
5. Writes structured JSON logs to `logs/honeypot_YYYY-MM-DD.json`
6. Real-time terminal display via `rich` — live table of active connections, rolling event log, per-MAC connection counts

**Usage:**
```bash
python main.py honeypot --name "Living Room Speaker" --device-class audio_sink
```

## Component 3: Streamer (Byte-Streaming Deterrent)

Sends garbage data back to connecting devices over L2CAP or SPP.

1. Triggered by honeypot connections (optional `--retaliate` flag) or used standalone
2. Streaming modes:
   - **L2CAP raw** — continuous stream of random bytes. Some audio devices will interpret as garbled noise
   - **A2DP garbage** — malformed A2DP/SBC audio frames. Produces harsh static or forces disconnect
   - **SPP flood** — floods Serial Port Profile channel with data
3. Configurable parameters:
   - Byte pattern: random, zeros, repeating, or custom hex
   - Packet size and interval
   - Duration or unlimited
4. Logs all sent data — timestamps, bytes sent, connection state changes, time to remote disconnect
5. Safety: refuses to target any MAC in known-devices list when invoked from `--retaliate` mode

**Usage:**
```bash
# Experiment with your own speaker
python main.py stream --target AA:BB:CC:DD:EE:FF --mode l2cap --pattern random --duration 10

# Auto-respond to honeypot connections
python main.py honeypot --name "Living Room Speaker" --retaliate --mode a2dp_garbage
```

## Typical Workflow

1. **Scan** to see what's exposed, fix discoverable devices
2. **Deploy honeypot** as decoy with retaliation enabled
3. **Review logs** to confirm attacker identity (MAC, device name, RSSI proximity)

```bash
python main.py scan --known-devices devices.json
python main.py honeypot --name "Kitchen Speaker" --retaliate --mode l2cap
python main.py logs --summary
```

## macOS Considerations

- `bumble` on macOS requires a **USB Bluetooth dongle** (CSR8510 or similar, ~$10) for HCI transport. The built-in Mac Bluetooth is locked down by CoreBluetooth.
- The scanner can use the built-in adapter via `bleak`.
- README will document specific dongle recommendations.

## Scope Boundaries

- CLI only, no GUI
- No persistent daemon mode — run it, ctrl-C to stop
- No network/cloud logging — local JSON files only
