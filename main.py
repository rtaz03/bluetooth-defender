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


def cmd_logs(args):
    """Show a summary of honeypot logs."""
    if not LOGS_DIR.exists():
        console.print("[yellow]No logs directory found.[/yellow]")
        return

    log_files = sorted(LOGS_DIR.glob("honeypot_*.jsonl"))
    if not log_files:
        console.print("[yellow]No honeypot logs found.[/yellow]")
        return

    # Aggregate connection data across all log files
    connections_by_mac: dict[str, dict] = {}
    total_events = 0

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

                total_events += 1
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
                        "events": [],
                    }

                entry = connections_by_mac[mac]
                name = data.get("device_name")
                if name:
                    entry["names"].add(name)
                entry["last_seen"] = event.get("timestamp", entry["last_seen"])
                if event.get("data", {}).get("mac") and event["message"] == "connection":
                    entry["connection_count"] += 1
                entry["events"].append(event["message"])

    if not connections_by_mac:
        console.print("[yellow]No connection events found in logs.[/yellow]")
        return

    console.print("\n[bold underline]Honeypot Log Summary[/bold underline]")
    console.print(f"[dim]Log files: {len(log_files)} | Total events: {total_events}[/dim]\n")

    table = Table()
    table.add_column("MAC Address")
    table.add_column("Device Names")
    table.add_column("Connections")
    table.add_column("First Seen")
    table.add_column("Last Seen")

    for mac, entry in sorted(
        connections_by_mac.items(),
        key=lambda x: x[1]["connection_count"],
        reverse=True,
    ):
        table.add_row(
            mac,
            ", ".join(entry["names"]) or "Unknown",
            str(entry["connection_count"]),
            entry["first_seen"][:19],
            entry["last_seen"][:19],
        )

    console.print(table)


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
    logs_parser = subparsers.add_parser("logs", help="View honeypot log summary")
    logs_parser.set_defaults(func=cmd_logs)

    args = parser.parse_args()

    # Convert duration=0 to None (unlimited) for streamer
    if hasattr(args, "duration") and args.duration == 0:
        args.duration = None

    args.func(args)


if __name__ == "__main__":
    cli()
