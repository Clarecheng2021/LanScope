import asyncio
import platform
import re
import socket
import ssl
from html import unescape
from urllib.parse import urlsplit

from .models import HttpInfo, Service

HTTP_PORTS = {80, 8000, 8008, 8080, 8081, 8888}
HTTPS_PORTS = {443, 8443}

SERVICE_NAMES = {
    21: "ftp",
    22: "ssh",
    23: "telnet",
    25: "smtp",
    53: "dns",
    80: "http",
    110: "pop3",
    135: "msrpc",
    139: "netbios-ssn",
    143: "imap",
    389: "ldap",
    443: "https",
    445: "smb",
    465: "smtps",
    587: "submission",
    636: "ldaps",
    993: "imaps",
    995: "pop3s",
    1433: "mssql",
    1521: "oracle",
    2049: "nfs",
    2375: "docker",
    2376: "docker-tls",
    3306: "mysql",
    3389: "rdp",
    5432: "postgresql",
    5900: "vnc",
    6379: "redis",
    8080: "http-alt",
    8443: "https-alt",
    9200: "elasticsearch",
    11211: "memcached",
    27017: "mongodb",
}


async def ping_host(host: str, timeout: float) -> bool:
    count_arg = "-n" if platform.system().lower() == "windows" else "-c"
    timeout_arg = "-w" if platform.system().lower() == "windows" else "-W"
    timeout_value = str(max(1, int(timeout * 1000))) if count_arg == "-n" else str(max(1, int(timeout)))

    try:
        process = await asyncio.create_subprocess_exec(
            "ping",
            count_arg,
            "1",
            timeout_arg,
            timeout_value,
            host,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        return await asyncio.wait_for(process.wait(), timeout=timeout + 2) == 0
    except asyncio.TimeoutError:
        try:
            process.kill()
        except ProcessLookupError:
            pass
        await process.wait()
        return False
    except OSError:
        return False


async def scan_port(host: str, port: int, timeout: float) -> Service | None:
    if port in HTTP_PORTS:
        return await _scan_http_port(host, port, "http", timeout)
    if port in HTTPS_PORTS:
        return await _scan_http_port(host, port, "https", timeout)

    try:
        reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)
    except (OSError, asyncio.TimeoutError):
        return None

    service = Service(port=port, service=SERVICE_NAMES.get(port))
    banner = await _read_banner(reader, writer, timeout)
    if banner:
        service.banner = banner
    await _close_writer(writer)
    return service


async def _scan_http_port(host: str, port: int, scheme: str, timeout: float) -> Service | None:
    http = await probe_http(host, port, scheme, timeout)
    if http.error and http.status is None:
        return None
    service = Service(port=port, service=SERVICE_NAMES.get(port, scheme))
    service.http = http
    if http.server:
        service.banner = http.server
    return service


async def probe_http(host: str, port: int, scheme: str, timeout: float) -> HttpInfo:
    info = HttpInfo(scheme=scheme)
    if "\r" in host or "\n" in host:
        info.error = "invalid hostname"
        return info
    writer = None
    try:
        if scheme == "https":
            context = ssl.create_default_context()
            context.check_hostname = False
            context.verify_mode = ssl.CERT_NONE
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection(host, port, ssl=context, server_hostname=host),
                timeout=timeout,
            )
        else:
            reader, writer = await asyncio.wait_for(asyncio.open_connection(host, port), timeout=timeout)

        request = (
            f"GET / HTTP/1.1\r\n"
            f"Host: {host}\r\n"
            "User-Agent: LanScope/0.1\r\n"
            "Accept: text/html,*/*;q=0.8\r\n"
            "Connection: close\r\n\r\n"
        )
        writer.write(request.encode("latin-1", errors="replace"))
        await asyncio.wait_for(writer.drain(), timeout=timeout)
        raw = await asyncio.wait_for(reader.read(65536), timeout=timeout)
    except (OSError, asyncio.TimeoutError, ssl.SSLError) as exc:
        info.error = str(exc)
        return info
    finally:
        if writer is not None:
            await _close_writer(writer)

    text = raw.decode("utf-8", errors="replace")
    header_text, _, body = text.partition("\r\n\r\n")
    headers = _parse_headers(header_text)
    info.status = _parse_status(header_text)
    info.server = headers.get("server")
    info.location = _normalize_location(headers.get("location"), scheme, host, port)
    info.title = _extract_title(body)
    return info


async def _read_banner(reader: asyncio.StreamReader, writer: asyncio.StreamWriter, timeout: float) -> str | None:
    try:
        data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 0.8))
    except (OSError, asyncio.TimeoutError):
        data = b""

    if not data:
        try:
            writer.write(b"\r\n")
            await asyncio.wait_for(writer.drain(), timeout=min(timeout, 0.8))
            data = await asyncio.wait_for(reader.read(256), timeout=min(timeout, 0.8))
        except (OSError, asyncio.TimeoutError):
            data = b""

    banner = data.decode("utf-8", errors="replace").strip()
    return re.sub(r"\s+", " ", banner)[:160] if banner else None


def _parse_headers(header_text: str) -> dict[str, str]:
    headers: dict[str, str] = {}
    for line in header_text.splitlines()[1:]:
        name, sep, value = line.partition(":")
        if sep:
            headers[name.strip().lower()] = value.strip()
    return headers


def _parse_status(header_text: str) -> int | None:
    first_line = header_text.splitlines()[0] if header_text else ""
    match = re.match(r"HTTP/\S+\s+(\d{3})", first_line)
    return int(match.group(1)) if match else None


def _extract_title(body: str) -> str | None:
    match = re.search(r"<title[^>]*>(.*?)</title>", body, flags=re.IGNORECASE | re.DOTALL)
    if not match:
        return None
    title = re.sub(r"\s+", " ", unescape(match.group(1))).strip()
    return title[:120] if title else None


def _normalize_location(location: str | None, scheme: str, host: str, port: int) -> str | None:
    if not location:
        return None
    if urlsplit(location).scheme:
        return location
    default_port = 443 if scheme == "https" else 80
    netloc = host if port == default_port else f"{host}:{port}"
    return f"{scheme}://{netloc}{location}"


async def _close_writer(writer: asyncio.StreamWriter) -> None:
    writer.close()
    try:
        await writer.wait_closed()
    except OSError:
        pass


async def can_attempt_tcp(host: str) -> bool:
    loop = asyncio.get_running_loop()
    try:
        await loop.getaddrinfo(host, None)
    except OSError:
        return False
    return True
