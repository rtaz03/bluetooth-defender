"""Common Bluetooth helpers — device class parsing, RSSI formatting, transport discovery."""

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


async def find_usb_transport():
    """Try to open a bumble USB HCI transport. Returns (hci_source, hci_sink) or exits with help."""
    try:
        from bumble.transport import open_transport

        transport = await open_transport("usb:0")
        return transport
    except Exception as e:
        print(
            f"Failed to open USB Bluetooth adapter: {e}\n\n"
            "The honeypot and streamer require a USB Bluetooth dongle (e.g. CSR8510).\n"
            "The built-in Mac Bluetooth adapter is locked down by CoreBluetooth.\n\n"
            "1. Plug in a USB BT dongle\n"
            "2. Make sure no other driver is claiming it\n"
            "3. Try again",
            file=sys.stderr,
        )
        sys.exit(1)
