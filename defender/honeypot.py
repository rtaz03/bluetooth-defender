"""Bluetooth honeypot — fake device that logs all connection attempts with full forensics."""

import asyncio
from datetime import UTC, datetime

from bumble.core import (
    BT_L2CAP_PROTOCOL_ID,
    BT_RFCOMM_PROTOCOL_ID,
)
from bumble.device import Device
from bumble.host import Host
from bumble.sdp import (
    SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
    SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
    SDP_PUBLIC_BROWSE_ROOT,
    SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
    SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
    DataElement,
    ServiceAttribute,
)
from rich.console import Console
from rich.live import Live
from rich.table import Table

from defender.utils.bt_helpers import (
    DEVICE_CLASSES,
    find_usb_transport,
    normalize_mac,
    rssi_to_distance_estimate,
)
from defender.utils.logging import get_logger, log_event

console = Console()
logger = get_logger("honeypot")

# Well-known UUIDs
A2DP_SINK_UUID = 0x110B
SPP_UUID = 0x1101
L2CAP_PSM_AVDTP = 0x0019


class HoneypotState:
    """Tracks active connections and event history for the live display."""

    def __init__(self):
        self.connections: dict[str, dict] = {}
        self.events: list[dict] = []
        self.connection_counts: dict[str, int] = {}

    def add_connection(self, mac: str, info: dict) -> None:
        self.connections[mac] = info
        self.connection_counts[mac] = self.connection_counts.get(mac, 0) + 1

    def remove_connection(self, mac: str) -> None:
        self.connections.pop(mac, None)

    def add_event(self, event: dict) -> None:
        self.events.append(event)
        # Keep last 50 events for display
        if len(self.events) > 50:
            self.events = self.events[-50:]


def build_live_display(state: HoneypotState) -> Table:
    """Build the rich table for live terminal display."""
    grid = Table(title="Bluetooth Honeypot", expand=True)
    grid.add_column("Active Connections", ratio=1)
    grid.add_column("Recent Events", ratio=2)

    # Active connections sub-table
    conn_table = Table(show_header=True)
    conn_table.add_column("MAC")
    conn_table.add_column("Name")
    conn_table.add_column("RSSI")
    conn_table.add_column("Distance")
    conn_table.add_column("Since")
    conn_table.add_column("Count")
    for mac, info in state.connections.items():
        rssi = info.get("rssi")
        rssi_str = f"{rssi} dBm" if rssi is not None else "?"
        conn_table.add_row(
            mac,
            info.get("name", "?"),
            rssi_str,
            info.get("distance", "?"),
            info.get("connected_at", "?"),
            str(state.connection_counts.get(mac, 0)),
        )
    if not state.connections:
        conn_table.add_row("[dim]Waiting for connections...[/dim]", "", "", "", "", "")

    # Recent events sub-table
    event_table = Table(show_header=True)
    event_table.add_column("Time")
    event_table.add_column("Event")
    event_table.add_column("Details")
    for event in state.events[-15:]:
        event_table.add_row(
            event.get("time", ""),
            event.get("type", ""),
            event.get("details", ""),
        )
    if not state.events:
        event_table.add_row("[dim]No events yet[/dim]", "", "")

    grid.add_row(conn_table, event_table)
    return grid


def make_a2dp_sink_record(handle: int) -> list[ServiceAttribute]:
    """Build an SDP service record for A2DP Audio Sink."""
    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(handle),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(A2DP_SINK_UUID)]),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_L2CAP_PROTOCOL_ID),
                            DataElement.unsigned_integer_16(L2CAP_PSM_AVDTP),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
        ),
    ]


def make_spp_record(handle: int, rfcomm_channel: int = 1) -> list[ServiceAttribute]:
    """Build an SDP service record for Serial Port Profile."""
    return [
        ServiceAttribute(
            SDP_SERVICE_RECORD_HANDLE_ATTRIBUTE_ID,
            DataElement.unsigned_integer_32(handle),
        ),
        ServiceAttribute(
            SDP_SERVICE_CLASS_ID_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SPP_UUID)]),
        ),
        ServiceAttribute(
            SDP_PROTOCOL_DESCRIPTOR_LIST_ATTRIBUTE_ID,
            DataElement.sequence(
                [
                    DataElement.sequence([DataElement.uuid(BT_L2CAP_PROTOCOL_ID)]),
                    DataElement.sequence(
                        [
                            DataElement.uuid(BT_RFCOMM_PROTOCOL_ID),
                            DataElement.unsigned_integer_8(rfcomm_channel),
                        ]
                    ),
                ]
            ),
        ),
        ServiceAttribute(
            SDP_BROWSE_GROUP_LIST_ATTRIBUTE_ID,
            DataElement.sequence([DataElement.uuid(SDP_PUBLIC_BROWSE_ROOT)]),
        ),
    ]


async def run(
    name: str = "Living Room Speaker",
    device_class: str = "audio_sink",
    retaliate: bool = False,
    retaliate_mode: str = "l2cap",
    known_devices_path: str | None = None,
) -> None:
    """Run the Bluetooth honeypot."""
    from defender.utils.bt_helpers import load_known_devices

    known = load_known_devices(known_devices_path) if known_devices_path else []
    known_macs = {d["mac"] for d in known}

    cod = DEVICE_CLASSES.get(device_class, DEVICE_CLASSES["audio_sink"])

    console.print(f"[bold green]Starting honeypot as '{name}'[/bold green]")
    console.print(f"[dim]Device class: {device_class} (0x{cod:06X})[/dim]")
    console.print(f"[dim]Retaliate: {retaliate} (mode: {retaliate_mode})[/dim]")
    console.print()

    # Open USB transport
    transport = await find_usb_transport()

    # Configure device
    host = Host()
    host.hci_source = transport.source
    host.hci_sink = transport.sink

    device = Device(name=name, host=host)
    device.class_of_device = cod

    # Register SDP services
    device.sdp_service_records = {
        0x00010001: make_a2dp_sink_record(0x00010001),
        0x00010002: make_spp_record(0x00010002),
    }

    await device.power_on()

    # Make discoverable and connectable
    await device.set_discoverable(True)
    await device.set_connectable(True)

    state = HoneypotState()

    @device.on("connection")
    async def on_connection(connection):
        mac = normalize_mac(str(connection.peer_address))
        now = datetime.now(UTC)
        time_short = now.strftime("%H:%M:%S")

        rssi = getattr(connection, "rssi", None)
        distance = rssi_to_distance_estimate(rssi) if rssi is not None else "unknown"

        info = {
            "mac": mac,
            "name": connection.peer_name or "Unknown",
            "connected_at": time_short,
            "transport": str(connection.transport),
            "rssi": rssi,
            "distance": distance,
        }

        state.add_connection(mac, info)
        state.add_event(
            {
                "time": time_short,
                "type": "CONNECT",
                "details": f"{mac} ({info['name']}) RSSI: {rssi} ({distance})",
            }
        )

        log_data = {
            "mac": mac,
            "device_name": info["name"],
            "rssi": rssi,
            "distance": distance,
            "transport": str(connection.transport),
            "handle": connection.handle,
        }
        log_event(logger, "honeypot", "connection", **log_data)

        console.print(
            f"[bold red]CONNECTION from {mac} ({info['name']})[/bold red] "
            f"[dim]RSSI: {rssi} dBm — {distance}[/dim]"
        )

        # Retaliate if enabled
        if retaliate and mac not in known_macs:
            from defender.streamer import (
                DEVICE_MODES,
                STREAM_MODES,
                device_mode_to_target,
                stream_to_connection,
            )

            modes = [m.strip() for m in retaliate_mode.split(",") if m.strip()]
            state.add_event(
                {
                    "time": time_short,
                    "type": "RETALIATE",
                    "details": f"Modes: {', '.join(modes)} -> {mac}",
                }
            )
            log_event(
                logger,
                "honeypot",
                "retaliate_start",
                mac=mac,
                modes=modes,
            )

            try:
                for mode in modes:
                    if mode in STREAM_MODES:
                        asyncio.create_task(stream_to_connection(connection, device, mode=mode))
                    elif mode in DEVICE_MODES:
                        asyncio.create_task(device_mode_to_target(device, mac, mode=mode))
            except Exception as e:
                log_event(logger, "honeypot", "retaliate_error", mac=mac, error=str(e))

        @connection.on("disconnection")
        def on_disconnection(reason):
            state.remove_connection(mac)
            state.add_event(
                {
                    "time": datetime.now(UTC).strftime("%H:%M:%S"),
                    "type": "DISCONNECT",
                    "details": f"{mac} (reason: {reason})",
                }
            )
            log_event(
                logger,
                "honeypot",
                "disconnection",
                mac=mac,
                reason=str(reason),
            )

    console.print("[bold green]Honeypot is live. Press Ctrl+C to stop.[/bold green]\n")

    # Keep running with live display
    try:
        with Live(build_live_display(state), console=console, refresh_per_second=2) as live:
            while True:
                live.update(build_live_display(state))
                await asyncio.sleep(0.5)
    except (KeyboardInterrupt, asyncio.CancelledError):
        console.print("\n[yellow]Shutting down honeypot...[/yellow]")
    finally:
        await device.power_off()
        transport.close()
