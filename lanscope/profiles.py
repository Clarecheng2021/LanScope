from __future__ import annotations

from dataclasses import dataclass


QUICK_PORTS = "22,80,443,445,3389,8080"
DISCOVERY_PORTS = "22,80,443,445,3389,8080"


@dataclass(frozen=True, slots=True)
class ScanProfile:
    name: str
    ports: str
    timeout: float
    host_concurrency: int
    global_concurrency: int
    per_host_concurrency: int
    discover_hosts: bool
    skip_ping: bool
    max_hosts: int


PROFILES: dict[str, ScanProfile] = {
    "quick": ScanProfile(
        name="quick",
        ports=QUICK_PORTS,
        timeout=0.5,
        host_concurrency=128,
        global_concurrency=300,
        per_host_concurrency=32,
        discover_hosts=True,
        skip_ping=True,
        max_hosts=4096,
    ),
    "normal": ScanProfile(
        name="normal",
        ports="top100",
        timeout=0.7,
        host_concurrency=128,
        global_concurrency=500,
        per_host_concurrency=64,
        discover_hosts=True,
        skip_ping=True,
        max_hosts=4096,
    ),
    "full": ScanProfile(
        name="full",
        ports="full",
        timeout=0.35,
        host_concurrency=64,
        global_concurrency=1000,
        per_host_concurrency=128,
        discover_hosts=True,
        skip_ping=True,
        max_hosts=4096,
    ),
    "deep": ScanProfile(
        name="deep",
        ports="full",
        timeout=0.7,
        host_concurrency=64,
        global_concurrency=700,
        per_host_concurrency=96,
        discover_hosts=True,
        skip_ping=False,
        max_hosts=4096,
    ),
}


def get_profile(name: str) -> ScanProfile:
    try:
        return PROFILES[name]
    except KeyError as exc:
        raise ValueError(f"unknown scan mode: {name}") from exc
