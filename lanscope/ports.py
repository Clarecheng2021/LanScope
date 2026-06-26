COMMON_PORTS = [
    21,
    22,
    23,
    25,
    53,
    80,
    110,
    123,
    135,
    139,
    143,
    161,
    389,
    443,
    445,
    465,
    587,
    636,
    993,
    995,
    1433,
    1521,
    2049,
    2375,
    2376,
    3306,
    3389,
    5432,
    5900,
    6379,
    8000,
    8080,
    8443,
    9200,
    9300,
    11211,
    27017,
]

TOP_100_PORTS = [
    7,
    9,
    13,
    21,
    22,
    23,
    25,
    26,
    37,
    53,
    79,
    80,
    81,
    88,
    106,
    110,
    111,
    113,
    119,
    135,
    139,
    143,
    144,
    179,
    199,
    389,
    427,
    443,
    444,
    445,
    465,
    513,
    514,
    515,
    543,
    544,
    548,
    554,
    587,
    631,
    646,
    873,
    990,
    993,
    995,
    1025,
    1026,
    1027,
    1028,
    1029,
    1110,
    1433,
    1720,
    1723,
    1755,
    1900,
    2000,
    2001,
    2049,
    2121,
    2717,
    3000,
    3128,
    3306,
    3389,
    3986,
    4899,
    5000,
    5009,
    5051,
    5060,
    5101,
    5190,
    5357,
    5432,
    5631,
    5666,
    5800,
    5900,
    6000,
    6001,
    6646,
    7070,
    8000,
    8008,
    8009,
    8080,
    8081,
    8443,
    8888,
    9100,
    9999,
    10000,
    32768,
    49152,
    49153,
    49154,
    49155,
    49156,
    49157,
]


def parse_ports(value: str) -> list[int]:
    lowered = value.strip().lower()
    if lowered == "common":
        return COMMON_PORTS.copy()
    if lowered == "top100":
        return TOP_100_PORTS.copy()
    if lowered in {"full", "all"}:
        return list(range(1, 65536))

    ports: set[int] = set()
    for part in value.split(","):
        token = part.strip()
        if not token:
            continue
        if "-" in token:
            start_text, end_text = token.split("-", 1)
            start = _parse_port(start_text)
            end = _parse_port(end_text)
            if start > end:
                raise ValueError(f"invalid port range: {token}")
            ports.update(range(start, end + 1))
        else:
            ports.add(_parse_port(token))
    if not ports:
        raise ValueError("at least one port is required")
    return sorted(ports)


def _parse_port(value: str) -> int:
    try:
        port = int(value)
    except ValueError as exc:
        raise ValueError(f"invalid port: {value}") from exc
    if port < 1 or port > 65535:
        raise ValueError(f"port out of range: {port}")
    return port
