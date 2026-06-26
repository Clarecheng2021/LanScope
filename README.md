# LanScope

LanScope is a lightweight asset discovery scanner for internal networks.

It discovers reachable hosts, scans selected TCP ports, collects basic service
metadata, and exports results as table, JSON, or CSV.

## Features

- Scan single IPs, CIDR ranges, and hostnames
- TCP connect port scanning with configurable concurrency
- Optional ICMP-style reachability check through OS `ping`
- HTTP/HTTPS probing for status code, title, server, and redirect location
- JSON, CSV, and terminal table output
- No third-party runtime dependencies

## Quick Start

```powershell
python -m lanscope 192.168.1.0/24
```

Scan common ports:

```powershell
python -m lanscope 192.168.1.0/24 --ports common
```

Run an nmap-style full TCP port scan against discovered live hosts:

```powershell
python -m lanscope 192.168.1.0/24 --mode full
```

Scan custom ports and save JSON:

```powershell
python -m lanscope 10.0.0.5 10.0.0.8 --ports 22,80,443,8080 --format json --output scan.json
```

Save CSV:

```powershell
python -m lanscope 192.168.1.0/28 --ports top100 --format csv --output assets.csv
```

Start the local web console:

```powershell
python -m lanscope.web
```

Then open:

```text
http://127.0.0.1:8765
```

The web console can discover the current LAN automatically and run a quick scan
without requiring you to look up your local IP address manually.

## Usage

```text
python -m lanscope TARGET [TARGET ...] [options]

Targets:
  192.168.1.10          Single IP
  192.168.1.0/24        CIDR network
  intranet.local        Hostname

Options:
  --mode MODE           Scan profile: quick, normal, full, deep, or custom
  --ports PORTS         Port set: common, top100, or comma/range list
  --timeout SECONDS     Per-connection timeout
  --host-concurrency N  Maximum concurrent hosts
  --global-concurrency N Maximum concurrent TCP connections
  --per-host-concurrency N Maximum concurrent TCP connections per host
  --discover-hosts      Discover live hosts before port scanning
  --skip-ping           Do not run pre-scan ping checks
  --format FORMAT       table, json, or csv
  --output PATH         Write results to a file
```

## Scan Modes

LanScope includes nmap-style scan profiles:

- `quick`: host discovery + high-value ports such as `22,80,443,445,3389,8080`
- `normal`: host discovery + `top100`
- `full`: host discovery + all TCP ports `1-65535`
- `deep`: full TCP scan with a more conservative timeout and ICMP ping enabled
- `custom`: use `--ports` and your own timing options

For large ranges, prefer:

```powershell
python -m lanscope 192.168.1.0/24 --mode full
```

Instead of scanning every host blindly, `full` first discovers live hosts with
ARP cache, optional ping, and TCP discovery ports, then scans all TCP ports only
on discovered hosts. The port scanner uses streaming workers, so it does not
create `hosts * 65535` tasks at once.

Tune timing when needed:

```powershell
python -m lanscope 192.168.1.0/24 --mode full --global-concurrency 800 --per-host-concurrency 100 --timeout 0.4
```

## Web Console

```powershell
python -m lanscope.web --host 127.0.0.1 --port 8765
```

The web console provides:

- Local network interface discovery
- Recommended current LAN CIDR, such as `192.168.1.0/24`
- One-click quick scan for the current LAN
- Custom target and port scanning
- Scan task progress and JSON result view

Quick scan defaults to:

```text
22,80,443,445,3389,8080
```

## Notes

Only scan networks and systems you own or are authorized to assess.
