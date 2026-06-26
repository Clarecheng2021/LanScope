import argparse
import asyncio
import sys

from . import __version__
from .output import write_output
from .ports import parse_ports
from .profiles import DISCOVERY_PORTS, get_profile
from .scanner import scan_assets
from .targets import expand_targets

EXAMPLES = """\
examples:
  python -m lanscope 192.168.1.0/24
  python -m lanscope 192.168.1.0/24 --mode full
  python -m lanscope 10.0.0.1 10.0.0.2 --ports 22,80,443
  python -m lanscope 172.16.0.0/24 --ports top100 --format json --output scan.json
  python -m lanscope --interactive
"""


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="python -m lanscope",
        description="Discover internal network assets and exposed TCP services.",
        epilog=EXAMPLES,
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    parser.add_argument("targets", nargs="*", help="IP, CIDR range, or hostname to scan")
    parser.add_argument(
        "--mode",
        choices=["custom", "quick", "normal", "full", "deep"],
        default="custom",
        help="scan profile: quick, normal, full, deep, or custom (default: custom)",
    )
    parser.add_argument(
        "--ports",
        default="common",
        help="port set: common, top100, full, or custom list (e.g. 22,80,443,8000-8010)",
    )
    parser.add_argument("--timeout", type=float, default=1.5, help="per-connection timeout in seconds (default: 1.5)")
    parser.add_argument("--concurrency", type=int, default=128, help="legacy concurrency value used when specific concurrency options are omitted")
    parser.add_argument("--host-concurrency", type=int, help="maximum concurrent hosts")
    parser.add_argument("--global-concurrency", type=int, help="maximum concurrent TCP connections across the whole scan")
    parser.add_argument("--per-host-concurrency", type=int, help="maximum concurrent TCP connections per host")
    parser.add_argument("--max-hosts", type=int, default=4096, help="refuse CIDR expansion above this count (default: 4096)")
    parser.add_argument("--skip-ping", action="store_true", help="skip ICMP ping, scan all targets directly")
    parser.add_argument("--discover-hosts", action="store_true", help="discover live hosts before port scanning")
    parser.add_argument("--no-discover-hosts", action="store_true", help="disable profile host discovery")
    parser.add_argument("--discovery-ports", default=DISCOVERY_PORTS, help="TCP ports used for host discovery")
    parser.add_argument("--format", choices=["table", "json", "csv"], default="table", help="output format (default: table)")
    parser.add_argument("--output", help="write output to file instead of stdout")
    parser.add_argument("--quiet", action="store_true", help="suppress progress display")
    parser.add_argument("--interactive", action="store_true", help="guided interactive mode for entering scan parameters")
    parser.add_argument("--version", action="version", version=f"LanScope {__version__}")
    return parser


def _interactive_prompt() -> dict:
    print("LanScope Interactive Scanner")
    print("=" * 35)
    print()

    target = input("  Target (IP, CIDR, or hostname): ").strip()
    if not target:
        print("Error: at least one target is required.", file=sys.stderr)
        raise SystemExit(1)
    targets = target.replace(",", " ").split()

    print()
    print("  Port presets:  common = 38 common ports")
    print("                 top100 = top 100 TCP ports")
    print("                 or enter a custom list, e.g. 22,80,443,8000-8010")
    ports = input("  Ports [common]: ").strip() or "common"

    print()
    timeout_raw = input("  Timeout in seconds [1.5]: ").strip()
    try:
        timeout = float(timeout_raw) if timeout_raw else 1.5
    except ValueError:
        print(f"Error: invalid timeout value: {timeout_raw}", file=sys.stderr)
        raise SystemExit(1)

    skip_ping_raw = input("  Skip ping check? (y/N): ").strip().lower()
    skip_ping = skip_ping_raw in ("y", "yes")

    print()
    fmt_raw = input("  Output format (table/json/csv) [table]: ").strip().lower()
    fmt = fmt_raw if fmt_raw in ("table", "json", "csv") else "table"

    output = input("  Output file (leave empty for stdout): ").strip() or None

    print()
    return {
        "targets": targets,
        "ports": ports,
        "timeout": timeout,
        "skip_ping": skip_ping,
        "format": fmt,
        "output": output,
    }


def _progress_callback(completed: int, total: int) -> None:
    width = 30
    filled = int(width * completed / total) if total else width
    bar = "#" * filled + "-" * (width - filled)
    pct = completed * 100 // total if total else 100
    sys.stderr.write(f"\r  [{bar}] {completed}/{total} hosts ({pct}%)")
    sys.stderr.flush()
    if completed == total:
        sys.stderr.write("\n")


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    raw_argv = sys.argv[1:] if argv is None else argv
    args = parser.parse_args(raw_argv)
    ports_overridden = "--ports" in raw_argv
    timeout_overridden = "--timeout" in raw_argv
    skip_ping_overridden = "--skip-ping" in raw_argv
    max_hosts_overridden = "--max-hosts" in raw_argv

    profile = get_profile(args.mode) if args.mode != "custom" else None

    if args.interactive or not args.targets:
        if not args.targets and not args.interactive and not sys.stdin.isatty():
            parser.error("no targets specified (use --interactive for guided mode)")
        try:
            params = _interactive_prompt()
        except (EOFError, KeyboardInterrupt):
            print("\nAborted.", file=sys.stderr)
            return 130
        targets = params["targets"]
        ports_str = params["ports"]
        timeout = params["timeout"]
        skip_ping = params["skip_ping"]
        fmt = params["format"]
        output = params["output"]
    else:
        targets = args.targets
        ports_str = args.ports
        timeout = args.timeout
        skip_ping = args.skip_ping
        fmt = args.format
        output = args.output

    if profile is not None:
        if not ports_overridden:
            ports_str = profile.ports
        if not timeout_overridden:
            timeout = profile.timeout
        if not skip_ping_overridden:
            skip_ping = profile.skip_ping
        if not max_hosts_overridden:
            args.max_hosts = profile.max_hosts

    try:
        ports = parse_ports(ports_str)
        discovery_ports = parse_ports(args.discovery_ports)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    try:
        hosts = expand_targets(targets, max_hosts=args.max_hosts)
    except ValueError as exc:
        print(f"Error: {exc}", file=sys.stderr)
        return 1

    if timeout <= 0:
        print("Error: --timeout must be greater than 0", file=sys.stderr)
        return 1
    if args.concurrency <= 0:
        print("Error: --concurrency must be greater than 0", file=sys.stderr)
        return 1
    host_concurrency = args.host_concurrency or (profile.host_concurrency if profile else args.concurrency)
    global_concurrency = args.global_concurrency or (profile.global_concurrency if profile else args.concurrency)
    per_host_concurrency = args.per_host_concurrency or (profile.per_host_concurrency if profile else min(64, global_concurrency))
    discover_hosts = args.discover_hosts or bool(profile and profile.discover_hosts)
    if args.no_discover_hosts:
        discover_hosts = False

    if host_concurrency <= 0:
        print("Error: --host-concurrency must be greater than 0", file=sys.stderr)
        return 1
    if global_concurrency <= 0:
        print("Error: --global-concurrency must be greater than 0", file=sys.stderr)
        return 1
    if per_host_concurrency <= 0:
        print("Error: --per-host-concurrency must be greater than 0", file=sys.stderr)
        return 1

    show_progress = not args.quiet and sys.stderr.isatty()
    progress = _progress_callback if show_progress else None

    if show_progress:
        mode_text = args.mode if args.mode != "custom" else "custom"
        discovery_text = "with host discovery" if discover_hosts else "without host discovery"
        sys.stderr.write(
            f"  Scanning {len(hosts)} target(s), {len(ports)} port(s), mode={mode_text}, {discovery_text}...\n"
        )

    try:
        assets = asyncio.run(
            scan_assets(
                hosts=hosts,
                ports=ports,
                timeout=timeout,
                concurrency=args.concurrency,
                skip_ping=skip_ping,
                on_progress=progress,
                discover_hosts=discover_hosts,
                discovery_ports=discovery_ports,
                host_concurrency=host_concurrency,
                global_concurrency=global_concurrency,
                per_host_concurrency=per_host_concurrency,
            )
        )
    except KeyboardInterrupt:
        print("\nScan interrupted.", file=sys.stderr)
        return 130

    write_output(assets, fmt, output)
    return 0
