import asyncio
import platform
import re


async def read_arp_table() -> dict[str, str]:
    if platform.system().lower() == "windows":
        return await _read_arp_windows()
    return await _read_arp_linux()


async def _read_arp_windows() -> dict[str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "arp", "-a",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
    except (OSError, asyncio.TimeoutError):
        return {}

    table: dict[str, str] = {}
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        match = re.match(
            r"\s*(\d+\.\d+\.\d+\.\d+)\s+([0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2}[-:][0-9a-fA-F]{2})",
            line,
        )
        if match:
            ip = match.group(1)
            mac = _normalize_mac(match.group(2))
            if mac and not mac.startswith("ff:ff:ff") and not mac.startswith("01:00:5e"):
                table[ip] = mac
    return table


async def _read_arp_linux() -> dict[str, str]:
    try:
        proc = await asyncio.create_subprocess_exec(
            "ip", "neigh",
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.DEVNULL,
        )
        stdout, _ = await asyncio.wait_for(proc.communicate(), timeout=5)
    except (OSError, asyncio.TimeoutError):
        return {}

    table: dict[str, str] = {}
    for line in stdout.decode("utf-8", errors="replace").splitlines():
        match = re.match(
            r"(\d+\.\d+\.\d+\.\d+)\s+.*\s+lladdr\s+([0-9a-fA-F:]{17})",
            line,
        )
        if match:
            ip = match.group(1)
            mac = _normalize_mac(match.group(2))
            if mac and not mac.startswith("ff:ff:ff") and not mac.startswith("01:00:5e"):
                table[ip] = mac
    return table


def _normalize_mac(raw: str) -> str:
    return raw.replace("-", ":").lower()
