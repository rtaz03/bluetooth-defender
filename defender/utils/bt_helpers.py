"""Common Bluetooth helpers — device class parsing, RSSI formatting, transport discovery."""

import asyncio
import json
import re
import sys
from pathlib import Path

# Class of Device (CoD) constants
# Format: Major Service Class (bits 13-23) | Major Device Class (bits 8-12) | Minor (bits 2-7)
DEVICE_CLASSES = {
    "audio_sink": 0x240404,  # Audio+Rendering, Audio/Video, Loudspeaker
    "headset": 0x200404,  # Audio, Audio/Video, Wearable Headset
    "headphones": 0x200418,  # Audio, Audio/Video, Headphones
    "portable_audio": 0x200414,  # Audio, Audio/Video, Portable Audio
    "car_audio": 0x200420,  # Audio, Audio/Video, Car Audio
    "hifi": 0x200428,  # Audio, Audio/Video, HiFi Audio
    "keyboard": 0x002540,  # Peripheral, Keyboard
    "generic": 0x1F00,  # Uncategorized
}

MAJOR_DEVICE_CLASSES = {
    0: "Miscellaneous",
    1: "Computer",
    2: "Phone",
    3: "LAN/Network Access Point",
    4: "Audio/Video",
    5: "Peripheral",
    6: "Imaging",
    7: "Wearable",
    8: "Toy",
    9: "Health",
}

MAJOR_SERVICE_CLASSES = {
    13: "Limited Discoverable",
    16: "Positioning",
    17: "Networking",
    18: "Rendering",
    19: "Capturing",
    20: "Object Transfer",
    21: "Audio",
    22: "Telephony",
    23: "Information",
}


def parse_device_class(cod: int) -> dict:
    """Parse a Class of Device integer into human-readable components."""
    minor = (cod >> 2) & 0x3F
    major = (cod >> 8) & 0x1F
    services = []
    for bit, name in MAJOR_SERVICE_CLASSES.items():
        if cod & (1 << bit):
            services.append(name)

    return {
        "raw": f"0x{cod:06X}",
        "major_class": MAJOR_DEVICE_CLASSES.get(major, f"Unknown ({major})"),
        "minor_class": minor,
        "services": services,
    }


def rssi_to_distance_estimate(rssi: int) -> str:
    """Rough distance estimate from RSSI (very approximate)."""
    if rssi >= -40:
        return "very close (<1m)"
    elif rssi >= -55:
        return "close (1-3m)"
    elif rssi >= -70:
        return "nearby (3-10m)"
    elif rssi >= -85:
        return "far (10-20m)"
    else:
        return "very far (>20m)"


def validate_mac(mac: str) -> bool:
    """Check if a string looks like a valid MAC address."""
    return bool(re.match(r"^([0-9A-Fa-f]{2}:){5}[0-9A-Fa-f]{2}$", mac))


def normalize_mac(mac: str) -> str:
    """Normalize MAC address to uppercase with colons."""
    return mac.upper().strip()


def load_known_devices(path: str | Path) -> list[dict]:
    """Load known devices from a JSON file."""
    path = Path(path)
    if not path.exists():
        print(f"Known devices file not found: {path}", file=sys.stderr)
        return []
    with open(path) as f:
        devices = json.load(f)
    for d in devices:
        d["mac"] = normalize_mac(d["mac"])
    return devices


async def find_usb_transport(transport_spec: str | None = None):
    """Try to open a bumble USB HCI transport. Returns transport or exits with help.

    transport_spec: bumble USB spec (e.g. '2357:0604', '1'). If None, probes usb:0–3.
    """
    try:
        from bumble.transport import open_transport

        if transport_spec is not None:
            return await asyncio.wait_for(open_transport(f"usb:{transport_spec}"), timeout=5.0)

        for index in range(4):
            try:
                return await asyncio.wait_for(open_transport(f"usb:{index}"), timeout=3.0)
            except Exception:
                continue

        raise RuntimeError("no USB Bluetooth dongle found (tried usb:0–3)")
    except Exception as e:
        print(
            f"Failed to open USB Bluetooth adapter: {e}\n\n"
            "The honeypot and streamer require a USB Bluetooth dongle.\n"
            "Run 'python main.py list-usb' to see available dongles,\n"
            "then pass the value with --usb (e.g. --usb 2357:0604).",
            file=sys.stderr,
        )
        sys.exit(1)
