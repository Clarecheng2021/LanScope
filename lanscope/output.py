import csv
import json
import sys
from pathlib import Path
from typing import TextIO

from .models import Asset


def write_output(assets: list[Asset], fmt: str, output: str | None) -> None:
    stream: TextIO
    if output:
        path = Path(output)
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("w", encoding="utf-8", newline="") as file:
            _write(assets, fmt, file)
        return

    stream = sys.stdout
    _write(assets, fmt, stream)


def _write(assets: list[Asset], fmt: str, stream: TextIO) -> None:
    if fmt == "json":
        json.dump([asset.to_dict() for asset in assets], stream, ensure_ascii=False, indent=2)
        stream.write("\n")
    elif fmt == "csv":
        _write_csv(assets, stream)
    else:
        stream.write(render_table(assets))
        stream.write("\n")


def _write_csv(assets: list[Asset], stream: TextIO) -> None:
    writer = csv.DictWriter(
        stream,
        fieldnames=[
            "host",
            "address",
            "hostname",
            "mac",
            "vendor",
            "reachable",
            "port",
            "protocol",
            "service",
            "banner",
            "http_scheme",
            "http_status",
            "http_title",
            "http_server",
            "http_location",
        ],
    )
    writer.writeheader()
    for asset in assets:
        base = {
            "host": asset.host,
            "address": asset.address,
            "hostname": asset.hostname or "",
            "mac": asset.mac or "",
            "vendor": asset.vendor or "",
            "reachable": asset.reachable,
        }
        if not asset.services:
            writer.writerow(base)
            continue
        for service in asset.services:
            writer.writerow(
                {
                    **base,
                    "port": service.port,
                    "protocol": service.protocol,
                    "service": service.service or "",
                    "banner": service.banner or "",
                    "http_scheme": service.http.scheme if service.http else "",
                    "http_status": service.http.status if service.http else "",
                    "http_title": service.http.title if service.http else "",
                    "http_server": service.http.server if service.http else "",
                    "http_location": service.http.location if service.http else "",
                }
            )


def render_table(assets: list[Asset]) -> str:
    rows = [["HOST", "ADDRESS", "MAC", "VENDOR", "UP", "PORT", "SERVICE", "HTTP", "TITLE/BANNER"]]
    for asset in assets:
        mac = asset.mac or "-"
        vendor = asset.vendor or "-"
        if not asset.services:
            rows.append([asset.host, asset.address, mac, vendor, _yes_no(asset.reachable), "-", "-", "-", "-"])
            continue
        for service in asset.services:
            http_status = str(service.http.status) if service.http and service.http.status else "-"
            title = service.http.title if service.http and service.http.title else service.banner or "-"
            rows.append(
                [
                    asset.host,
                    asset.address,
                    mac,
                    vendor,
                    _yes_no(asset.reachable),
                    str(service.port),
                    service.service or "-",
                    http_status,
                    title,
                ]
            )
    widths = [max(len(str(row[index])) for row in rows) for index in range(len(rows[0]))]
    lines = []
    for index, row in enumerate(rows):
        lines.append("  ".join(str(cell).ljust(widths[cell_index]) for cell_index, cell in enumerate(row)))
        if index == 0:
            lines.append("  ".join("-" * width for width in widths))
    return "\n".join(lines)


def _yes_no(value: bool) -> str:
    return "yes" if value else "no"
