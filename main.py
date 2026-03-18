"""Bluetooth Defender — CLI entrypoint."""

import argparse
import asyncio
import json
from pathlib import Path

from rich.console import Console
from rich.table import Table

console = Console()
LOGS_DIR = Path(__file__).parent / "logs"


def cmd_scan(args):
    from defender.scanner import run

    asyncio.run(
        run(
            known_devices_path=args.known_devices,
            duration=args.duration,
        )
    )


def cmd_honeypot(args):
    from defender.honeypot import run

    asyncio.run(
        run(
            name=args.name,
            device_class=args.device_class,
            retaliate=args.retaliate,
            retaliate_mode=args.mode,
            known_devices_path=args.known_devices,
        )
    )


def cmd_stream(args):
    from defender.streamer import run

    asyncio.run(
        run(
            target=args.target,
            mode=args.mode,
            pattern=args.pattern,
            packet_size=args.packet_size,
            interval=args.interval,
            duration=args.duration,
            known_devices_path=args.known_devices,
        )
    )


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
            }
        entry = connections_by_mac[mac]
        name = data.get("device_name")
        if name:
            entry["names"].add(name)
        entry["last_seen"] = event.get("timestamp", entry["last_seen"])
        if event["message"] == "connection":
            entry["connection_count"] += 1
        if event["message"] == "retaliate_start":
            entry["retaliations"] += 1

    if not connections_by_mac:
        console.print("[yellow]No honeypot connection events found.[/yellow]")
        return

    table = Table(title="Honeypot — Connections by Device")
    table.add_column("MAC Address")
    table.add_column("Device Names")
    table.add_column("Connections", justify="right")
    table.add_column("Retaliations", justify="right")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    for _mac, entry in sorted(
        connections_by_mac.items(),
        key=lambda x: x[1]["connection_count"],
        reverse=True,
    ):
        table.add_row(
            entry["mac"],
            ", ".join(entry["names"]) or "Unknown",
            str(entry["connection_count"]),
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


def _show_streamer_summary(events):
    """Display streamer events as a session table."""
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
                "errors": [],
            }
        elif msg == "stream_complete" and current:
            current["packets"] = data.get("packets_sent", 0)
            current["bytes"] = data.get("bytes_sent", 0)
            sessions.append(current)
            current = None
        elif msg.endswith("_error") and current:
            current["errors"].append(data.get("error", msg))

    if not sessions:
        console.print("[yellow]No streamer sessions found.[/yellow]")
        return

    table = Table(title="Streamer — Sessions")
    table.add_column("Target MAC")
    table.add_column("Mode")
    table.add_column("Pattern")
    table.add_column("Packets", justify="right")
    table.add_column("Bytes", justify="right")
    table.add_column("Errors", justify="right")
    table.add_column("Started")

    for s in sessions:
        table.add_row(
            s["mac"],
            s["mode"],
            s["pattern"],
            str(s["packets"]),
            str(s["bytes"]),
            str(len(s["errors"])),
            s["started"][:19],
        )
    console.print(table)


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
    scan_parser.set_defaults(func=cmd_scan)

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
        default="l2cap",
        choices=["l2cap", "spp", "a2dp_garbage"],
        help="Retaliation stream mode (default: l2cap)",
    )
    hp_parser.add_argument(
        "--known-devices",
        "-k",
        type=str,
        default=None,
        help="Path to known devices JSON (protected from retaliation)",
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
        choices=["l2cap", "spp", "a2dp_garbage"],
        help="Streaming mode (default: l2cap)",
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

    # Convert duration=0 to None (unlimited) for streamer
    if hasattr(args, "duration") and args.duration == 0:
        args.duration = None

    args.func(args)


if __name__ == "__main__":
    cli()
