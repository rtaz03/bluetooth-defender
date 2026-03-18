# Retaliation Modes Expansion — Design

**Date:** 2026-03-18

## Problem

The streamer currently has 3 retaliation modes (l2cap, spp, a2dp_garbage). We want to add 4 more modes and support running multiple modes concurrently as a combo.

## Mode Categories

### Connection-based (require an active connection)

Signature: `async def stream_xxx(connection, device, pattern, packet_size, interval, duration) -> dict`

| Mode | PSM/Channel | Payload | Default Interval | Default Packet Size |
|------|-------------|---------|------------------|-------------------|
| `l2cap` (existing) | 0x1001 (dynamic) | Configurable pattern | 10ms | 672B |
| `spp` (existing) | RFCOMM ch 1 | Configurable pattern | 10ms | 512B |
| `a2dp_garbage` (existing) | 0x0019 (AVDTP) | SBC sync + garbage | 5ms | 672B |
| `avctp` (new) | 0x0017 (AVCTP) | Valid AV/C opcodes + garbage operands | 10ms | 64B |
| `sdp_spam` (new) | 0x0001 (SDP) | Oversized malformed SDP response PDUs | 50ms | 1024B |

### Device-level (no connection required)

Signature: `async def device_xxx(device, target_mac, duration) -> dict`

| Mode | Mechanism | Interval |
|------|-----------|----------|
| `pairing_loop` (new) | Repeated pair/abort cycles to target MAC | 1-2s between cycles |
| `name_spoof` (new) | Rotate device name from pool of ~20 plausible names, toggle discoverable | 5-10s |

All modes return: `{"bytes_sent": int, "packets_sent": int, "errors": int, "duration": float}`

## Registries

```python
STREAM_MODES = {"l2cap", "spp", "a2dp_garbage", "avctp", "sdp_spam"}
DEVICE_MODES = {"pairing_loop", "name_spoof"}
ALL_MODES = STREAM_MODES | DEVICE_MODES
```

## Combo Support

`--mode` accepts comma-separated values: `--mode a2dp_garbage,pairing_loop`

Honeypot `on_connection` splits the mode string, classifies each as connection-based or device-level, and fires all concurrently via `asyncio.create_task`.

## Default Changes

- Honeypot `--mode` default: `a2dp_garbage,pairing_loop`
- Standalone `stream` command default: stays `l2cap`

## CLI Changes

- Drop `choices=` from argparse for `--mode` (comma-separated values break it)
- Validate modes manually after parsing
- Standalone `stream` with device-level modes skips connection step

## New Mode Details

### avctp

- Opens L2CAP on AVCTP PSM (0x0017)
- Sends randomized AV/C frames: valid opcodes (0x44 play, 0x46 pause, 0x48 stop) with corrupted operands
- Targets media control layer — can trigger phantom volume/playback changes

### sdp_spam

- Opens L2CAP on SDP PSM (0x0001)
- Sends oversized malformed SDP response PDUs with deeply nested data elements
- Exhausts remote SDP parser memory/CPU during service discovery

### pairing_loop

- Drops existing connection first
- Loop: initiate pairing to target MAC -> wait for start -> abort -> 1-2s delay -> repeat
- Forces pairing dialogs / auth requests on target device

### name_spoof

- Pool of ~20 plausible device names (JBL, Sony, Bose speakers/headphones)
- Every 5-10s: change device.name, toggle discoverable off/on
- Pollutes attacker's scan results with phantom devices
