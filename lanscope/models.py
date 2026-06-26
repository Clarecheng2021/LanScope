from dataclasses import asdict, dataclass, field


@dataclass(slots=True)
class HttpInfo:
    scheme: str
    status: int | None = None
    title: str | None = None
    server: str | None = None
    location: str | None = None
    error: str | None = None

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


@dataclass(slots=True)
class Service:
    port: int
    protocol: str = "tcp"
    state: str = "open"
    service: str | None = None
    banner: str | None = None
    http: HttpInfo | None = None

    def to_dict(self) -> dict[str, object]:
        data = asdict(self)
        if self.http is not None:
            data["http"] = self.http.to_dict()
        return data


@dataclass(slots=True)
class Asset:
    host: str
    address: str
    reachable: bool
    hostname: str | None = None
    mac: str | None = None
    vendor: str | None = None
    services: list[Service] = field(default_factory=list)

    def to_dict(self) -> dict[str, object]:
        return {
            "host": self.host,
            "address": self.address,
            "hostname": self.hostname,
            "mac": self.mac,
            "vendor": self.vendor,
            "reachable": self.reachable,
            "services": [service.to_dict() for service in self.services],
        }
