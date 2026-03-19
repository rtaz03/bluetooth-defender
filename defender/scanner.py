"""Passive Bluetooth scanning and defense recommendations."""

import asyncio
import contextlib

from bleak import BleakScanner
from rich.console import Console
from rich.table import Table

from defender.utils.bt_helpers import (
    load_known_devices,
    normalize_mac,
    rssi_to_distance_estimate,
)
from defender.utils.logging import get_logger, log_event

console = Console()
logger = get_logger("scanner")


async def ble_scan(duration: float = 10.0) -> list[dict]:
    """Scan for BLE devices using bleak (works with built-in Mac adapter)."""
    console.print(f"[bold blue]Scanning BLE devices for {duration}s...[/bold blue]")
    devices = await BleakScanner.discover(timeout=duration, return_adv=True)

    results = []
    for device, adv_data in devices.values():
        results.append(
            {
                "mac": normalize_mac(device.address),
                "name": device.name or adv_data.local_name or "Unknown",
                "rssi": adv_data.rssi,
                "protocol": "BLE",
                "manufacturer_data": {
                    str(k): v.hex() for k, v in (adv_data.manufacturer_data or {}).items()
                },
                "service_uuids": adv_data.service_uuids or [],
            }
        )
    return results


def list_usb_dongles() -> None:
    """Print a table of USB Bluetooth HCI devices visible to bumble."""
    try:
        import usb1
    except ImportError:
        console.print("[red]usb1 not installed[/red]")
        return

    # USB class/subclass/protocol for Bluetooth HCI (fixed by USB spec)
    BT_HCI = (0xE0, 0x01, 0x01)

    context = usb1.USBContext()
    context.open()

    table = Table(title="USB Bluetooth Dongles")
    table.add_column("Index", justify="right")
    table.add_column("Vendor:Product")
    table.add_column("Name")
    table.add_column("Bus-Port")
    table.add_column("--usb value")

    index = 0
    for device in context.getDeviceIterator(skip_on_error=True):
        vid = device.getVendorID()
        pid = device.getProductID()
        dev_class = device.getDeviceClass()
        dev_sub = device.getDeviceSubClass()
        dev_proto = device.getDeviceProtocol()

        is_bt = (dev_class, dev_sub, dev_proto) == BT_HCI
        if not is_bt and dev_class == 0x00:
            for cfg in device:
                for iface in cfg:
                    for setting in iface:
                        if (
                            setting.getClass(),
                            setting.getSubClass(),
                            setting.getProtocol(),
                        ) == BT_HCI:
                            is_bt = True
                            break

        if not is_bt:
            device.close()
            continue

        try:
            name = device.getProduct()
        except usb1.USBError:
            name = "Unknown"

        bus = device.getBusNumber()
        port = ".".join(map(str, device.getPortNumberList()))
        table.add_row(
            str(index),
            f"{vid:04X}:{pid:04X}",
            name or "Unknown",
            f"{bus}-{port}",
            f"{vid:04X}:{pid:04X}",
        )
        index += 1
        device.close()

    context.close()

    if index == 0:
        console.print("[yellow]No USB Bluetooth HCI devices found.[/yellow]")
    else:
        console.print(table)
        console.print(
            "[dim]Use the [bold]--usb value[/bold] column with: python main.py scan --usb <value>[/dim]"
        )


async def classic_scan(duration: float = 10.0, usb_transport: str | None = None) -> list[dict]:
    """Scan for Classic BT devices using bumble (requires USB dongle)."""
    results = []
    transport = None
    try:
        from bumble.device import Device
        from bumble.host import Host
        from bumble.transport import open_transport

        if usb_transport is not None:
            transport_spec = f"usb:{usb_transport}"
            transport = await asyncio.wait_for(open_transport(transport_spec), timeout=5.0)
        else:
            for usb_index in range(4):
                try:
                    transport = await asyncio.wait_for(
                        open_transport(f"usb:{usb_index}"), timeout=3.0
                    )
                    break
                except Exception:
                    continue
            if transport is None:
                raise RuntimeError("no USB Bluetooth dongle found (tried usb:0–3)")

        host = Host()
        host.hci_source = transport.source
        host.hci_sink = transport.sink
        device = Device(host=host)
        await asyncio.wait_for(device.power_on(), timeout=10.0)

        console.print(f"[bold blue]Scanning Classic BT devices for {duration}s...[/bold blue]")

        found_devices = []

        @device.on("inquiry_result")
        def on_inquiry_result(address, class_of_device, data, rssi):
            from defender.utils.bt_helpers import parse_device_class

            name = (
                data.get(0x09, data.get(0x08, b"")).decode("utf-8", errors="replace") or "Unknown"
            )
            found_devices.append(
                {
                    "mac": str(address),
                    "name": name,
                    "rssi": rssi,
                    "protocol": "Classic",
                    "class_of_device": parse_device_class(class_of_device),
                }
            )

        await device.start_inquiry(duration=duration)
        await asyncio.sleep(duration + 1)
        await device.power_off()
        results = found_devices

    except Exception as e:
        console.print(f"[yellow]Classic BT scan skipped (USB dongle not available): {e}[/yellow]")
    finally:
        if transport is not None:
            with contextlib.suppress(Exception):
                transport.close()

    return results


def analyze_results(devices: list[dict], known_devices: list[dict]) -> dict:
    """Analyze scan results and generate defense recommendations."""
    known_macs = {d["mac"] for d in known_devices}
    known_names = {d["name"].lower() for d in known_devices}

    own_discoverable = []
    suspicious = []
    unknown_nearby = []

    for device in devices:
        mac = device["mac"]
        name = device.get("name", "Unknown")
        rssi = device.get("rssi", -100)

        if mac in known_macs:
            own_discoverable.append(device)
        elif name.lower() in known_names:
            # Same name as a known device but different MAC — possible spoof
            device["warning"] = "POSSIBLE SPOOF — name matches your device but MAC differs"
            suspicious.append(device)
        elif rssi > -70:
            unknown_nearby.append(device)

    # Sort unknown by signal strength (strongest first)
    unknown_nearby.sort(key=lambda d: d.get("rssi", -100), reverse=True)

    return {
        "own_discoverable": own_discoverable,
        "suspicious": suspicious,
        "unknown_nearby": unknown_nearby,
    }


def print_report(analysis: dict, all_devices: list[dict]) -> None:
    """Print a defense report to the console."""
    console.print()
    console.print("[bold underline]Bluetooth Defense Report[/bold underline]")
    console.print()

    # Your discoverable devices
    if analysis["own_discoverable"]:
        console.print("[bold red]YOUR DEVICES THAT ARE DISCOVERABLE:[/bold red]")
        table = Table()
        table.add_column("Name")
        table.add_column("MAC")
        table.add_column("Protocol")
        table.add_column("Recommendation")
        for d in analysis["own_discoverable"]:
            table.add_row(
                d["name"],
                d["mac"],
                d.get("protocol", "?"),
                "Pair and disable discovery mode",
            )
        console.print(table)
        console.print()
    else:
        console.print("[green]None of your known devices are currently discoverable.[/green]\n")

    # Suspicious devices
    if analysis["suspicious"]:
        console.print("[bold red]SUSPICIOUS DEVICES (possible spoofs):[/bold red]")
        table = Table()
        table.add_column("Name")
        table.add_column("MAC")
        table.add_column("RSSI")
        table.add_column("Warning")
        for d in analysis["suspicious"]:
            table.add_row(
                d["name"],
                d["mac"],
                str(d.get("rssi", "?")),
                d.get("warning", ""),
            )
        console.print(table)
        console.print()

    # Unknown nearby
    if analysis["unknown_nearby"]:
        console.print("[bold yellow]UNKNOWN NEARBY DEVICES (strong signal):[/bold yellow]")
        table = Table()
        table.add_column("Name")
        table.add_column("MAC")
        table.add_column("RSSI")
        table.add_column("Distance")
        table.add_column("Protocol")
        for d in analysis["unknown_nearby"]:
            table.add_row(
                d["name"],
                d["mac"],
                str(d.get("rssi", "?")),
                rssi_to_distance_estimate(d.get("rssi", -100)),
                d.get("protocol", "?"),
            )
        console.print(table)
        console.print()

    console.print(f"[dim]Total devices found: {len(all_devices)}[/dim]")


async def run(
    known_devices_path: str | None = None,
    duration: float = 10.0,
    usb_transport: str | None = None,
) -> None:
    """Run the scanner."""
    known = load_known_devices(known_devices_path) if known_devices_path else []

    if usb_transport and usb_transport.lower() == "none":
        ble_results = await ble_scan(duration)
        classic_results = []
    else:
        # Run BLE and Classic scans concurrently
        ble_results, classic_results = await asyncio.gather(
            ble_scan(duration),
            classic_scan(duration, usb_transport=usb_transport),
        )

    all_devices = ble_results + classic_results

    for device in all_devices:
        log_event(logger, "scanner", "device_found", **device)

    analysis = analyze_results(all_devices, known)
    print_report(analysis, all_devices)

    # Print recommendations
    console.print()
    console.print("[bold underline]Recommendations:[/bold underline]")
    if analysis["own_discoverable"]:
        console.print("  1. Disable discoverable mode on your devices when not actively pairing")
    if analysis["unknown_nearby"]:
        console.print(
            "  2. Run the honeypot to identify who is connecting: "
            "[bold]python main.py honeypot --name 'Kitchen Speaker'[/bold]"
        )
    if not analysis["own_discoverable"] and not analysis["suspicious"]:
        console.print("  [green]Your Bluetooth exposure looks clean.[/green]")
