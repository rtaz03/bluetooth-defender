"""Bluetooth Defender — CLI entrypoint."""

import argparse
import asyncio
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()
BT_DEFENDER_DIR = Path.home() / ".bt-defender"
LOGS_DIR = BT_DEFENDER_DIR / "logs"
CONFIG_FILE = BT_DEFENDER_DIR / "config.json"


def _load_config() -> dict:
    if CONFIG_FILE.exists():
        try:
            return json.loads(CONFIG_FILE.read_text())
        except (json.JSONDecodeError, OSError):
            pass
    return {}


def _save_config(config: dict) -> None:
    BT_DEFENDER_DIR.mkdir(parents=True, exist_ok=True)
    CONFIG_FILE.write_text(json.dumps(config, indent=2))


def cmd_scan(args):
    from defender.scanner import run

    try:
        asyncio.run(
            run(
                known_devices_path=args.known_devices,
                duration=args.duration,
                usb_transport=args.usb,
            )
        )
    except KeyboardInterrupt:
        pass


def cmd_list_usb(args):
    from defender.scanner import list_usb_dongles

    list_usb_dongles()


def cmd_set_usb(args):
    config = _load_config()
    if args.transport is None:
        config.pop("usb", None)
        _save_config(config)
        console.print("[green]USB dongle preference cleared.[/green]")
    else:
        config["usb"] = args.transport
        _save_config(config)
        console.print(f"[green]Default USB dongle set to:[/green] {args.transport}")
        console.print(f"[dim]Saved to {CONFIG_FILE}[/dim]")


def cmd_honeypot(args):
    from defender.honeypot import run

    try:
        asyncio.run(
            run(
                name=args.name,
                device_class=args.device_class,
                retaliate=args.retaliate,
                retaliate_mode=args.mode,
                known_devices_path=args.known_devices,
                usb_transport=args.usb,
            )
        )
    except KeyboardInterrupt:
        pass


def cmd_stream(args):
    from defender.streamer import run

    try:
        asyncio.run(
            run(
                target=args.target,
                mode=args.mode,
                pattern=args.pattern,
                packet_size=args.packet_size,
                interval=args.interval,
                duration=args.duration,
                known_devices_path=args.known_devices,
                usb_transport=args.usb,
            )
        )
    except KeyboardInterrupt:
        pass


def _load_events(tool_filter=None, mac_filter=None, date_filter=None):
    """Load and filter JSONL log events. Returns (events, log_file_count)."""
    if not LOGS_DIR.exists():
        return [], 0

    tools = [tool_filter] if tool_filter else ["honeypot", "scanner", "streamer"]
    log_files = []
    for tool in tools:
        pattern = f"{tool}_*.jsonl"
        if date_filter:
            pattern = f"{tool}_{date_filter}.jsonl"
        log_files.extend(sorted(LOGS_DIR.glob(pattern)))

    events = []
    for log_file in log_files:
        with open(log_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if mac_filter:
                    mac = event.get("data", {}).get("mac", "")
                    target = event.get("data", {}).get("target", "")
                    if mac_filter.upper() not in (mac.upper(), target.upper()):
                        continue
                events.append(event)

    return events, len(log_files)


def _rssi_trend_label(readings: list[int]) -> str:
    """Describe RSSI trend from a list of readings over time."""
    if len(readings) < 2:
        return "—"
    first_half = readings[: len(readings) // 2]
    second_half = readings[len(readings) // 2 :]
    avg_first = sum(first_half) / len(first_half)
    avg_second = sum(second_half) / len(second_half)
    diff = avg_second - avg_first
    if diff > 5:
        return "[bold red]approaching[/bold red]"
    if diff < -5:
        return "[green]moving away[/green]"
    return "[dim]stable[/dim]"


def _show_honeypot_summary(events):
    """Display honeypot events as an aggregated connection table."""
    connections_by_mac: dict[str, dict] = {}
    for event in events:
        data = event.get("data", {})
        mac = data.get("mac")
        if not mac:
            continue
        if mac not in connections_by_mac:
            connections_by_mac[mac] = {
                "mac": mac,
                "names": set(),
                "first_seen": event.get("timestamp", ""),
                "last_seen": event.get("timestamp", ""),
                "connection_count": 0,
                "retaliations": 0,
                "rssi_readings": [],
                "last_distance": "—",
            }
        entry = connections_by_mac[mac]
        name = data.get("device_name")
        if name:
            entry["names"].add(name)
        entry["last_seen"] = event.get("timestamp", entry["last_seen"])
        if event["message"] == "connection":
            entry["connection_count"] += 1
            rssi = data.get("rssi")
            if rssi is not None:
                entry["rssi_readings"].append(rssi)
            distance = data.get("distance")
            if distance:
                entry["last_distance"] = distance
        if event["message"] == "retaliate_start":
            entry["retaliations"] += 1

    if not connections_by_mac:
        console.print("[yellow]No honeypot connection events found.[/yellow]")
        return

    table = Table(title="Honeypot — Connections by Device")
    table.add_column("MAC Address")
    table.add_column("Device Names")
    table.add_column("Connections", justify="right")
    table.add_column("RSSI (last)", justify="right")
    table.add_column("Distance", justify="center")
    table.add_column("Trend")
    table.add_column("Retaliations", justify="right")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    for _mac, entry in sorted(
        connections_by_mac.items(),
        key=lambda x: x[1]["connection_count"],
        reverse=True,
    ):
        readings = entry["rssi_readings"]
        last_rssi = f"{readings[-1]} dBm" if readings else "—"
        trend = _rssi_trend_label(readings)

        table.add_row(
            entry["mac"],
            ", ".join(entry["names"]) or "Unknown",
            str(entry["connection_count"]),
            last_rssi,
            entry["last_distance"],
            trend,
            str(entry["retaliations"]),
            entry["first_seen"][:19],
            entry["last_seen"][:19],
        )
    console.print(table)


def _show_scanner_summary(events):
    """Display scanner events as a discovered-devices table."""
    devices_by_mac: dict[str, dict] = {}
    for event in events:
        data = event.get("data", {})
        mac = data.get("mac") or data.get("address")
        if not mac:
            continue
        if mac not in devices_by_mac:
            devices_by_mac[mac] = {
                "mac": mac,
                "name": data.get("name", "Unknown"),
                "rssi": data.get("rssi"),
                "known": data.get("known", False),
                "scan_count": 0,
                "last_seen": event.get("timestamp", ""),
            }
        entry = devices_by_mac[mac]
        entry["scan_count"] += 1
        entry["last_seen"] = event.get("timestamp", entry["last_seen"])
        if data.get("rssi") is not None:
            entry["rssi"] = data["rssi"]

    if not devices_by_mac:
        console.print("[yellow]No scanner events found.[/yellow]")
        return

    table = Table(title="Scanner — Discovered Devices")
    table.add_column("MAC Address")
    table.add_column("Name")
    table.add_column("RSSI", justify="right")
    table.add_column("Known", justify="center")
    table.add_column("Times Seen", justify="right")
    table.add_column("Last Seen")

    for _mac, entry in sorted(
        devices_by_mac.items(),
        key=lambda x: x[1]["scan_count"],
        reverse=True,
    ):
        rssi = str(entry["rssi"]) if entry["rssi"] is not None else "—"
        known = "[green]Yes[/green]" if entry["known"] else "[red]No[/red]"
        table.add_row(
            entry["mac"],
            entry["name"],
            rssi,
            known,
            str(entry["scan_count"]),
            entry["last_seen"][:19],
        )
    console.print(table)


MODE_IMPACT = {
    "l2cap": "Baseband saturation — device lag, UI freezes, forced disconnects",
    "spp": "Serial flood — application-layer crashes on devices with open SPP",
    "a2dp_garbage": "Audio decoder corruption — loud static, glitches, decoder crash/reboot",
    "avctp": "Phantom media controls — unexpected play/pause/volume, UI confusion",
    "sdp_spam": "SDP parser exhaustion — slow service discovery, memory pressure",
    "pairing_loop": "Auth dialog spam — repeated pairing prompts, BT stack exhaustion",
    "name_spoof": "Scan pollution — phantom devices flooding attacker's device list",
}


def _estimate_impact(mode: str, packets: int, bytes_sent: int, errors: int) -> str:
    """Estimate what the target is likely experiencing based on mode and stats."""
    if errors > 0 and packets == 0:
        return "[yellow]Target rejected connection — may have blocked us[/yellow]"

    if mode in ("pairing_loop", "name_spoof"):
        if packets == 0:
            return "[yellow]No cycles completed — target may be out of range[/yellow]"
        if packets < 3:
            return "[yellow]Mild annoyance — a few prompts/phantom devices[/yellow]"
        if packets < 10:
            return "[bold yellow]Moderate disruption — repeated prompts piling up[/bold yellow]"
        return "[bold red]Heavy disruption — BT stack under sustained pressure[/bold red]"

    if packets == 0:
        return "[yellow]No data sent — channel may have been rejected[/yellow]"

    if mode == "a2dp_garbage":
        if packets > 100:
            return "[bold red]Sustained audio corruption — static/glitches, likely decoder crash[/bold red]"
        return "[yellow]Brief audio disruption — garbled output[/yellow]"
    if mode == "avctp":
        if packets > 50:
            return "[bold red]Media control chaos — phantom commands flooding device[/bold red]"
        return "[yellow]Sporadic phantom media commands[/yellow]"
    if mode == "sdp_spam":
        if bytes_sent > 50_000:
            return "[bold red]SDP parser under heavy load — discovery likely stalled[/bold red]"
        return "[yellow]Light SDP pressure — discovery slowed[/yellow]"

    # l2cap / spp
    if bytes_sent > 100_000:
        return "[bold red]Heavy bandwidth saturation — device likely lagging[/bold red]"
    if bytes_sent > 10_000:
        return "[bold yellow]Moderate pressure — some performance degradation[/bold yellow]"
    return "[yellow]Light pressure — device may not notice yet[/yellow]"


def _show_streamer_summary(events):
    """Display streamer events as a session table with impact estimates."""
    sessions: list[dict] = []
    current: dict | None = None
    for event in events:
        msg = event.get("message", "")
        data = event.get("data", {})
        if msg == "stream_start":
            current = {
                "mac": data.get("mac", "Unknown"),
                "mode": data.get("mode", "—"),
                "pattern": data.get("pattern", "—"),
                "started": event.get("timestamp", ""),
                "packets": 0,
                "bytes": 0,
                "errors": 0,
            }
        elif msg == "stream_complete" and current:
            current["packets"] = data.get("packets_sent", 0)
            current["bytes"] = data.get("bytes_sent", 0)
            current["errors"] = data.get("errors", 0)
            sessions.append(current)
            current = None
        elif msg.endswith("_error") and current:
            current["errors"] += 1

    if not sessions:
        console.print("[yellow]No streamer sessions found.[/yellow]")
        return

    table = Table(title="Streamer — Sessions")
    table.add_column("Target MAC")
    table.add_column("Mode")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Likely Target Impact")
    table.add_column("Started")

    for s in sessions:
        impact = _estimate_impact(s["mode"], s["packets"], s["bytes"], s["errors"])
        table.add_row(
            s["mac"],
            s["mode"],
            str(s["packets"]),
            str(s["bytes"]),
            impact,
            s["started"][:19],
        )
    console.print(table)

    # Print mode reference after the table
    console.print("\n[bold underline]Mode Effects Reference[/bold underline]")
    for mode, desc in MODE_IMPACT.items():
        console.print(f"  [bold]{mode}[/bold]: {desc}")


def _show_raw_events(events, limit):
    """Display raw event log as a chronological table."""
    if not events:
        console.print("[yellow]No events found.[/yellow]")
        return

    events.sort(key=lambda e: e.get("timestamp", ""))
    if limit:
        events = events[-limit:]

    table = Table(title="Event Log")
    table.add_column("Timestamp")
    table.add_column("Tool")
    table.add_column("Level")
    table.add_column("Message")
    table.add_column("Details")

    for event in events:
        data = event.get("data", {})
        details = ", ".join(f"{k}={v}" for k, v in data.items()) if data else "—"
        table.add_row(
            event.get("timestamp", "")[:19],
            event.get("tool", "—"),
            event.get("level", "—"),
            event.get("message", "—"),
            details,
        )
    console.print(table)


def cmd_logs(args):
    """View log summaries, optionally filtered by tool, MAC, or date."""
    events, file_count = _load_events(
        tool_filter=args.tool,
        mac_filter=args.mac,
        date_filter=args.date,
    )

    if not events:
        console.print("[yellow]No log events found.[/yellow]")
        return

    console.print(f"\n[dim]Log files: {file_count} | Total events: {len(events)}[/dim]\n")

    if args.raw:
        _show_raw_events(events, args.last)
        return

    # When filtering to a specific tool, show only that summary
    if args.tool:
        {
            "honeypot": _show_honeypot_summary,
            "scanner": _show_scanner_summary,
            "streamer": _show_streamer_summary,
        }[args.tool](events)
        return

    # Show all tool summaries
    by_tool: dict[str, list] = {}
    for event in events:
        tool = event.get("tool", "unknown")
        by_tool.setdefault(tool, []).append(event)

    if "honeypot" in by_tool:
        _show_honeypot_summary(by_tool["honeypot"])
        console.print()
    if "scanner" in by_tool:
        _show_scanner_summary(by_tool["scanner"])
        console.print()
    if "streamer" in by_tool:
        _show_streamer_summary(by_tool["streamer"])


def cli():
    parser = argparse.ArgumentParser(
        prog="bt-defender",
        description="Bluetooth Defender — defend against unauthorized BT connections",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    # scan
    scan_parser = subparsers.add_parser("scan", help="Scan for nearby Bluetooth devices")
    scan_parser.add_argument(
        "--known-devices",
        "-k",
        type=str,
        default=None,
        help="Path to known devices JSON file",
    )
    scan_parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=10.0,
        help="Scan duration in seconds (default: 10)",
    )
    scan_parser.add_argument(
        "--usb",
        "-u",
        type=str,
        default=None,
        help="USB dongle transport: index (0, 1), vendor:product hex (2357:0604), or 'none' to skip classic scan",
    )
    scan_parser.set_defaults(func=cmd_scan)

    # list-usb
    list_usb_parser = subparsers.add_parser(
        "list-usb", help="List USB Bluetooth dongles available for classic scanning"
    )
    list_usb_parser.set_defaults(func=cmd_list_usb)

    # set-usb
    set_usb_parser = subparsers.add_parser(
        "set-usb",
        help="Save a default USB dongle so --usb is not needed on every command",
    )
    set_usb_parser.add_argument(
        "transport",
        type=str,
        nargs="?",
        default=None,
        help="Dongle to save as default: index (0, 1), vendor:product hex (2357:0604), or omit to clear",
    )
    set_usb_parser.set_defaults(func=cmd_set_usb)

    # honeypot
    hp_parser = subparsers.add_parser("honeypot", help="Run a fake Bluetooth device honeypot")
    hp_parser.add_argument(
        "--name",
        "-n",
        type=str,
        default="Living Room Speaker",
        help="Advertised device name (default: 'Living Room Speaker')",
    )
    hp_parser.add_argument(
        "--device-class",
        "-c",
        type=str,
        default="audio_sink",
        choices=[
            "audio_sink",
            "headset",
            "headphones",
            "portable_audio",
            "car_audio",
            "hifi",
            "keyboard",
            "generic",
        ],
        help="Device class to emulate (default: audio_sink)",
    )
    hp_parser.add_argument(
        "--retaliate",
        "-r",
        action="store_true",
        help="Auto-stream garbage to connecting devices",
    )
    hp_parser.add_argument(
        "--mode",
        "-m",
        type=str,
        default="a2dp_garbage,pairing_loop",
        help=(
            "Retaliation mode(s), comma-separated "
            "(default: a2dp_garbage,pairing_loop). "
            "Options: l2cap, spp, a2dp_garbage, avctp, sdp_spam, pairing_loop, name_spoof"
        ),
    )
    hp_parser.add_argument(
        "--known-devices",
        "-k",
        type=str,
        default=None,
        help="Path to known devices JSON (protected from retaliation)",
    )
    hp_parser.add_argument(
        "--usb",
        "-u",
        type=str,
        default=None,
        help="USB dongle transport: index (0, 1) or vendor:product hex (2357:0604). Run list-usb to find values.",
    )
    hp_parser.set_defaults(func=cmd_honeypot)

    # stream
    stream_parser = subparsers.add_parser("stream", help="Stream bytes to a Bluetooth device")
    stream_parser.add_argument(
        "target",
        type=str,
        help="Target MAC address (e.g. AA:BB:CC:DD:EE:FF)",
    )
    stream_parser.add_argument(
        "--mode",
        "-m",
        type=str,
        default="l2cap",
        help=(
            "Streaming mode(s), comma-separated (default: l2cap). "
            "Options: l2cap, spp, a2dp_garbage, avctp, sdp_spam, pairing_loop, name_spoof"
        ),
    )
    stream_parser.add_argument(
        "--pattern",
        "-p",
        type=str,
        default="random",
        help="Byte pattern: random, zeros, or hex like 0xDEADBEEF (default: random)",
    )
    stream_parser.add_argument(
        "--packet-size",
        "-s",
        type=int,
        default=672,
        help="Packet size in bytes (default: 672)",
    )
    stream_parser.add_argument(
        "--interval",
        "-i",
        type=float,
        default=0.01,
        help="Interval between packets in seconds (default: 0.01)",
    )
    stream_parser.add_argument(
        "--duration",
        "-d",
        type=float,
        default=10.0,
        help="Duration in seconds, 0 for unlimited (default: 10)",
    )
    stream_parser.add_argument(
        "--known-devices",
        "-k",
        type=str,
        default=None,
        help="Path to known devices JSON (refuses to target listed MACs)",
    )
    stream_parser.add_argument(
        "--usb",
        "-u",
        type=str,
        default=None,
        help="USB dongle transport: index (0, 1) or vendor:product hex (2357:0604). Run list-usb to find values.",
    )
    stream_parser.set_defaults(func=cmd_stream)

    # logs
    logs_parser = subparsers.add_parser("logs", help="View log summaries")
    logs_parser.add_argument(
        "--tool",
        "-t",
        type=str,
        choices=["honeypot", "scanner", "streamer"],
        default=None,
        help="Filter by tool (default: show all)",
    )
    logs_parser.add_argument(
        "--mac",
        "-m",
        type=str,
        default=None,
        help="Filter by MAC address",
    )
    logs_parser.add_argument(
        "--date",
        "-d",
        type=str,
        default=None,
        help="Filter by date (YYYY-MM-DD)",
    )
    logs_parser.add_argument(
        "--raw",
        "-r",
        action="store_true",
        help="Show raw chronological event log instead of summaries",
    )
    logs_parser.add_argument(
        "--last",
        "-n",
        type=int,
        default=None,
        help="Show only the last N events (use with --raw)",
    )
    logs_parser.set_defaults(func=cmd_logs)

    args = parser.parse_args()

    # Auto-apply saved USB dongle preference when --usb not explicitly passed
    if getattr(args, "usb", None) is None:
        saved_usb = _load_config().get("usb")
        if saved_usb:
            args.usb = saved_usb

    # Convert duration=0 to None (unlimited) for streamer
    if hasattr(args, "duration") and args.duration == 0:
        args.duration = None

    args.func(args)
