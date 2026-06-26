from __future__ import annotations

import ipaddress
import json
import platform
import socket
import subprocess
from dataclasses import asdict, dataclass


VIRTUAL_HINTS = (
    "virtual",
    "vmware",
    "virtualbox",
    "hyper-v",
    "docker",
    "wsl",
    "loopback",
    "bluetooth",
    "npcap",
    "tap",
    "tunnel",
)


@dataclass(slots=True)
class NetworkInterface:
    name: str
    address: str
    prefix_length: int
    network: str
    gateway: str | None = None
    description: str | None = None
    recommended: bool = False
    virtual: bool = False

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


def discover_interfaces() -> list[NetworkInterface]:
    interfaces = _discover_windows_interfaces() if platform.system().lower() == "windows" else []
    if not interfaces:
        interfaces = _discover_default_interface()

    interfaces = _dedupe_interfaces(interfaces)
    _mark_recommended(interfaces)
    return interfaces


def recommended_network() -> str | None:
    interfaces = discover_interfaces()
    if not interfaces:
        return None
    for item in interfaces:
        if item.recommended:
            return item.network
    return interfaces[0].network


def _discover_windows_interfaces() -> list[NetworkInterface]:
    command = (
        "Get-NetIPConfiguration | "
        "Where-Object { $_.IPv4Address -ne $null } | "
        "ForEach-Object { [PSCustomObject]@{ "
        "Name=$_.InterfaceAlias; "
        "Description=$_.InterfaceDescription; "
        "Address=$_.IPv4Address.IPAddress; "
        "PrefixLength=$_.IPv4Address.PrefixLength; "
        "Gateway=($_.IPv4DefaultGateway | Select-Object -ExpandProperty NextHop -First 1) "
        "} } | ConvertTo-Json -Depth 4 -Compress"
    )
    try:
        result = subprocess.run(
            ["powershell", "-NoProfile", "-Command", command],
            capture_output=True,
            text=True,
            timeout=4,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []

    if result.returncode != 0 or not result.stdout.strip():
        return []

    try:
        data = json.loads(result.stdout)
    except json.JSONDecodeError:
        return []

    rows = data if isinstance(data, list) else [data]
    interfaces: list[NetworkInterface] = []
    for row in rows:
        if not isinstance(row, dict):
            continue
        address = row.get("Address")
        prefix = row.get("PrefixLength")
        if isinstance(address, list):
            address = address[0] if address else None
        if isinstance(prefix, list):
            prefix = prefix[0] if prefix else None
        item = _build_interface(
            name=str(row.get("Name") or "Network"),
            address=str(address or ""),
            prefix_length=_safe_int(prefix, 24),
            gateway=str(row.get("Gateway") or "") or None,
            description=str(row.get("Description") or "") or None,
        )
        if item is not None:
            interfaces.append(item)
    return interfaces


def _discover_default_interface() -> list[NetworkInterface]:
    address = _default_route_address()
    if not address:
        return []
    item = _build_interface("Default network", address, 24, None, "Default route")
    return [item] if item else []


def _default_route_address() -> str | None:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        sock.connect(("8.8.8.8", 80))
        return sock.getsockname()[0]
    except OSError:
        try:
            return socket.gethostbyname(socket.gethostname())
        except OSError:
            return None
    finally:
        sock.close()


def _build_interface(
    name: str,
    address: str,
    prefix_length: int,
    gateway: str | None,
    description: str | None,
) -> NetworkInterface | None:
    try:
        ip = ipaddress.ip_address(address)
    except ValueError:
        return None
    if ip.version != 4 or ip.is_loopback or ip.is_link_local or ip.is_unspecified:
        return None

    prefix_length = max(1, min(32, prefix_length))
    network = ipaddress.ip_network(f"{address}/{prefix_length}", strict=False)
    label = f"{name} {description or ''}".lower()
    virtual = any(hint in label for hint in VIRTUAL_HINTS)
    return NetworkInterface(
        name=name,
        address=address,
        prefix_length=prefix_length,
        network=str(network),
        gateway=gateway,
        description=description,
        virtual=virtual,
    )


def _dedupe_interfaces(interfaces: list[NetworkInterface]) -> list[NetworkInterface]:
    seen: set[tuple[str, str]] = set()
    result: list[NetworkInterface] = []
    for item in interfaces:
        key = (item.address, item.network)
        if key in seen:
            continue
        seen.add(key)
        result.append(item)
    return result


def _mark_recommended(interfaces: list[NetworkInterface]) -> None:
    if not interfaces:
        return

    def score(item: NetworkInterface) -> tuple[int, int, int]:
        private = ipaddress.ip_address(item.address).is_private
        gateway = bool(item.gateway)
        reasonable_size = 16 <= item.prefix_length <= 30
        return (int(private) + int(gateway) + int(reasonable_size) - int(item.virtual) * 2, item.prefix_length, int(gateway))

    best = max(interfaces, key=score)
    best.recommended = True


def _safe_int(value: object, default: int) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default
