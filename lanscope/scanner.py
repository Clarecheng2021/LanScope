import asyncio
from collections.abc import Callable

from .arp import read_arp_table
from .models import Asset, Service
from .oui import lookup_vendor
from .probe import can_attempt_tcp, ping_host, scan_port
from .targets import resolve_host, reverse_lookup

DEFAULT_DISCOVERY_PORTS = [22, 80, 443, 445, 3389, 8080]


async def scan_assets(
    hosts: list[str],
    ports: list[int],
    timeout: float,
    concurrency: int,
    skip_ping: bool,
    on_progress: Callable[[int, int], None] | None = None,
    on_result: Callable[[Asset], None] | None = None,
    discover_hosts: bool = False,
    discovery_ports: list[int] | None = None,
    host_concurrency: int | None = None,
    global_concurrency: int | None = None,
    per_host_concurrency: int | None = None,
    cancel_event=None,
    on_port_scanned: Callable[[], None] | None = None,
) -> list[Asset]:
    host_limit = host_concurrency if host_concurrency is not None else concurrency
    global_limit = global_concurrency if global_concurrency is not None else concurrency
    per_host_limit = per_host_concurrency if per_host_concurrency is not None else min(64, max(1, global_limit))
    discovery_ports = discovery_ports or DEFAULT_DISCOVERY_PORTS

    initial_arp_table = await read_arp_table()
    if discover_hosts:
        discovered = await discover_live_hosts(
            hosts=hosts,
            timeout=timeout,
            concurrency=host_limit,
            skip_ping=skip_ping,
            discovery_ports=discovery_ports,
            arp_table=initial_arp_table,
        )
        hosts = [asset.host for asset in discovered]

    host_sem = asyncio.Semaphore(host_limit)
    conn_sem = asyncio.Semaphore(global_limit)
    total = len(hosts)
    completed = 0

    async def run_host(host: str) -> Asset | None:
        nonlocal completed
        if cancel_event and cancel_event.is_set():
            return None
        async with host_sem:
            result = await _scan_host(host, ports, timeout, skip_ping, conn_sem, per_host_limit, cancel_event, on_port_scanned)
        _enrich_asset(result, initial_arp_table)
        completed += 1
        if on_result:
            on_result(result)
        if on_progress:
            on_progress(completed, total)
        return result

    assets = [a for a in await asyncio.gather(*(run_host(host) for host in hosts)) if a is not None]

    arp_table = {**initial_arp_table, **await read_arp_table()}
    for asset in assets:
        _enrich_asset(asset, arp_table)

    return assets


async def _scan_host(
    host: str,
    ports: list[int],
    timeout: float,
    skip_ping: bool,
    conn_sem: asyncio.Semaphore,
    per_host_concurrency: int,
    cancel_event=None,
    on_port_scanned=None,
) -> Asset:
    address = await resolve_host(host)

    if skip_ping:
        reachable = False
    else:
        reachable = await ping_host(address, timeout)
        if not reachable and not await can_attempt_tcp(address):
            return Asset(host=host, address=address, hostname=None, reachable=False)

    services = await _scan_ports(address, ports, timeout, conn_sem, per_host_concurrency, cancel_event, on_port_scanned)
    hostname = await reverse_lookup(address)
    return Asset(
        host=host,
        address=address,
        hostname=hostname,
        reachable=reachable or bool(services),
        services=services,
    )


async def _scan_ports(
    host: str,
    ports: list[int],
    timeout: float,
    conn_sem: asyncio.Semaphore,
    per_host_concurrency: int,
    cancel_event=None,
    on_port_scanned=None,
) -> list[Service]:
    found: list[Service] = []
    iterator = iter(ports)
    iterator_lock = asyncio.Lock()

    async def next_port() -> int | None:
        async with iterator_lock:
            try:
                return next(iterator)
            except StopIteration:
                return None

    async def worker() -> None:
        while True:
            if cancel_event and cancel_event.is_set():
                return
            port = await next_port()
            if port is None:
                return
            async with conn_sem:
                service = await scan_port(host, port, timeout)
            if on_port_scanned:
                on_port_scanned()
            if service is not None:
                found.append(service)

    worker_count = min(len(ports), max(1, per_host_concurrency))
    await asyncio.gather(*(worker() for _ in range(worker_count)))
    return sorted(found, key=lambda s: s.port)


async def discover_live_hosts(
    hosts: list[str],
    timeout: float,
    concurrency: int,
    skip_ping: bool,
    discovery_ports: list[int],
    arp_table: dict[str, str] | None = None,
) -> list[Asset]:
    arp_table = arp_table if arp_table is not None else await read_arp_table()
    sem = asyncio.Semaphore(concurrency)

    async def discover(host: str) -> Asset | None:
        async with sem:
            address = await resolve_host(host)
            mac = arp_table.get(address)
            reachable = bool(mac)
            if not reachable and not skip_ping:
                reachable = await ping_host(address, timeout)
            if not reachable:
                reachable = await _tcp_ping(address, discovery_ports, timeout)
            if not reachable and not mac:
                return None
            hostname = await reverse_lookup(address)
            asset = Asset(host=host, address=address, hostname=hostname, reachable=True)
            _enrich_asset(asset, arp_table)
            return asset

    found = await asyncio.gather(*(discover(host) for host in hosts))
    return [asset for asset in found if asset is not None]


async def _tcp_ping(host: str, ports: list[int], timeout: float) -> bool:
    async def try_port(port: int) -> bool:
        writer = None
        try:
            _, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
            return True
        except (OSError, asyncio.TimeoutError):
            return False
        finally:
            if writer is not None:
                writer.close()
                try:
                    await writer.wait_closed()
                except OSError:
                    pass

    tasks = [asyncio.create_task(try_port(port)) for port in ports]
    try:
        for task in asyncio.as_completed(tasks):
            if await task:
                for pending in tasks:
                    if not pending.done():
                        pending.cancel()
                return True
        return False
    finally:
        await asyncio.gather(*tasks, return_exceptions=True)


def _enrich_asset(asset: Asset, arp_table: dict[str, str]) -> None:
    mac = arp_table.get(asset.address)
    if not mac:
        return
    asset.mac = mac
    asset.vendor = lookup_vendor(mac)
    asset.reachable = True
