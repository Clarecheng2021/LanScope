import asyncio
import ipaddress
import socket
from collections.abc import Iterable


def expand_targets(values: list[str], max_hosts: int | None = None) -> list[str]:
    hosts: list[str] = []
    seen: set[str] = set()

    for value in values:
        item = value.strip()
        if not item:
            continue
        try:
            network = ipaddress.ip_network(item, strict=False)
        except ValueError:
            candidates = [item]
        else:
            candidates = _network_candidates(network)

        for candidate in candidates:
            if candidate in seen:
                continue
            if max_hosts is not None and len(hosts) + 1 > max_hosts:
                raise ValueError(f"target expansion exceeded limit of {max_hosts} hosts")
            hosts.append(candidate)
            seen.add(candidate)

    if not hosts:
        raise ValueError("at least one target is required")
    return hosts


def _network_candidates(network: ipaddress.IPv4Network | ipaddress.IPv6Network) -> Iterable[str]:
    if network.num_addresses == 1:
        return (str(network.network_address),)
    return (str(host) for host in network.hosts())


async def resolve_host(host: str) -> str:
    loop = asyncio.get_running_loop()
    try:
        results = await loop.getaddrinfo(host, None, family=socket.AF_INET, type=socket.SOCK_STREAM)
        if results:
            return results[0][4][0]
        return host
    except OSError:
        return host


async def reverse_lookup(address: str) -> str | None:
    loop = asyncio.get_running_loop()
    try:
        host, _ = await loop.getnameinfo((address, 0), socket.NI_NAMEREQD)
        return host
    except OSError:
        return None
