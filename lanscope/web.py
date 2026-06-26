from __future__ import annotations

import argparse
import asyncio
import io
import json
import threading
import time
import uuid
from dataclasses import dataclass, field
from http import HTTPStatus
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from . import __version__
from .models import Asset
from .network import discover_interfaces, recommended_network
from .output import _write_csv
from .ports import parse_ports
from .profiles import DISCOVERY_PORTS, QUICK_PORTS, get_profile
from .scanner import scan_assets
from .targets import expand_targets

MAX_BODY = 64 * 1024


@dataclass(slots=True)
class ScanTask:
    id: str
    target: str
    mode: str
    ports: str
    timeout: float
    concurrency: int
    host_concurrency: int
    global_concurrency: int
    per_host_concurrency: int
    discover_hosts: bool
    discovery_ports: str
    skip_ping: bool
    max_hosts: int
    status: str = "queued"
    created_at: float = field(default_factory=time.time)
    started_at: float | None = None
    finished_at: float | None = None
    completed_hosts: int = 0
    total_hosts: int = 0
    error: str | None = None
    assets: list[Asset] = field(default_factory=list)
    cancel_event: threading.Event = field(default_factory=threading.Event)
    scanned_ports: int = 0
    total_ports: int = 0

    def to_dict(self, include_assets: bool = False) -> dict[str, Any]:
        data: dict[str, Any] = {
            "id": self.id,
            "target": self.target,
            "mode": self.mode,
            "ports": self.ports,
            "timeout": self.timeout,
            "concurrency": self.concurrency,
            "host_concurrency": self.host_concurrency,
            "global_concurrency": self.global_concurrency,
            "per_host_concurrency": self.per_host_concurrency,
            "discover_hosts": self.discover_hosts,
            "discovery_ports": self.discovery_ports,
            "skip_ping": self.skip_ping,
            "max_hosts": self.max_hosts,
            "status": self.status,
            "created_at": self.created_at,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "completed_hosts": self.completed_hosts,
            "total_hosts": self.total_hosts,
            "error": self.error,
            "open_services": sum(len(asset.services) for asset in self.assets),
            "reachable_hosts": sum(1 for asset in self.assets if asset.reachable),
            "scanned_ports": self.scanned_ports,
            "total_ports": self.total_ports,
        }
        if include_assets:
            data["assets"] = [asset.to_dict() for asset in self.assets]
        return data


class TaskStore:
    def __init__(self) -> None:
        self._tasks: dict[str, ScanTask] = {}
        self._lock = threading.Lock()

    def add(self, task: ScanTask) -> None:
        with self._lock:
            self._tasks[task.id] = task

    def get(self, task_id: str) -> ScanTask | None:
        with self._lock:
            return self._tasks.get(task_id)

    def list(self) -> list[ScanTask]:
        with self._lock:
            return sorted(self._tasks.values(), key=lambda task: task.created_at, reverse=True)

    def update_progress(self, task_id: str, completed: int, total: int) -> None:
        with self._lock:
            task = self._tasks.get(task_id)
            if task:
                task.completed_hosts = completed
                task.total_hosts = total

    def remove(self, task_id: str) -> bool:
        with self._lock:
            return self._tasks.pop(task_id, None) is not None


STORE = TaskStore()


def _optional_int(value: object) -> int | None:
    if value in (None, ""):
        return None
    return int(value)


def _optional_bool(value: object) -> bool | None:
    if value is None:
        return None
    if isinstance(value, bool):
        return value
    if isinstance(value, str):
        return value.strip().lower() in {"1", "true", "yes", "y", "on"}
    return bool(value)


def _optional_str(value: object) -> str | None:
    if value in (None, ""):
        return None
    return str(value)


def create_scan(
    target: str,
    mode: str = "quick",
    ports: str | None = None,
    timeout: float | None = None,
    concurrency: int = 128,
    host_concurrency: int | None = None,
    global_concurrency: int | None = None,
    per_host_concurrency: int | None = None,
    discover_hosts: bool | None = None,
    discovery_ports: str = DISCOVERY_PORTS,
    skip_ping: bool | None = None,
    max_hosts: int | None = None,
) -> ScanTask:
    profile = get_profile(mode) if mode != "custom" else None
    if profile is not None:
        ports = ports if ports is not None else profile.ports
        timeout = timeout if timeout is not None else profile.timeout
        host_concurrency = host_concurrency or profile.host_concurrency
        global_concurrency = global_concurrency or profile.global_concurrency
        per_host_concurrency = per_host_concurrency or profile.per_host_concurrency
        skip_ping = profile.skip_ping if skip_ping is None else skip_ping
        max_hosts = max_hosts or profile.max_hosts
        discover_hosts = profile.discover_hosts if discover_hosts is None else discover_hosts
    ports = ports or QUICK_PORTS
    timeout = timeout if timeout is not None else 0.7
    skip_ping = bool(skip_ping) if skip_ping is not None else True
    max_hosts = max_hosts or 4096
    host_concurrency = host_concurrency or concurrency
    global_concurrency = global_concurrency or concurrency
    per_host_concurrency = per_host_concurrency or min(64, global_concurrency)
    discover_hosts = bool(discover_hosts)

    task = ScanTask(
        id=uuid.uuid4().hex[:12],
        target=target,
        mode=mode,
        ports=ports,
        timeout=timeout,
        concurrency=concurrency,
        host_concurrency=host_concurrency,
        global_concurrency=global_concurrency,
        per_host_concurrency=per_host_concurrency,
        discover_hosts=discover_hosts,
        discovery_ports=discovery_ports,
        skip_ping=skip_ping,
        max_hosts=max_hosts,
    )
    STORE.add(task)
    thread = threading.Thread(target=_run_scan_task, args=(task.id,), daemon=True)
    thread.start()
    return task


def _run_scan_task(task_id: str) -> None:
    task = STORE.get(task_id)
    if task is None:
        return
    task.status = "running"
    task.started_at = time.time()
    try:
        ports = parse_ports(task.ports)
        discovery_ports = parse_ports(task.discovery_ports)
        hosts = expand_targets(task.target.replace(",", " ").split(), max_hosts=task.max_hosts)
        task.total_hosts = len(hosts)
        task.total_ports = len(hosts) * len(ports)

        def progress(completed: int, total: int) -> None:
            STORE.update_progress(task.id, completed, total)
            task.total_ports = total * len(ports)

        def on_result(asset: Asset) -> None:
            task.assets.append(asset)

        def on_port_done() -> None:
            task.scanned_ports += 1

        asyncio.run(
            scan_assets(
                hosts=hosts,
                ports=ports,
                timeout=task.timeout,
                concurrency=task.concurrency,
                skip_ping=task.skip_ping,
                on_progress=progress,
                on_result=on_result,
                discover_hosts=task.discover_hosts,
                discovery_ports=discovery_ports,
                host_concurrency=task.host_concurrency,
                global_concurrency=task.global_concurrency,
                per_host_concurrency=task.per_host_concurrency,
                cancel_event=task.cancel_event,
                on_port_scanned=on_port_done,
            )
        )
        task.status = "cancelled" if task.cancel_event.is_set() else "done"
    except Exception as exc:
        task.error = str(exc)
        task.status = "failed"
    finally:
        task.finished_at = time.time()


class LanScopeHandler(BaseHTTPRequestHandler):
    server_version = f"LanScopeWeb/{__version__}"
    api_token: str | None = None

    def _check_auth(self) -> bool:
        if not self.api_token:
            return True
        auth = self.headers.get("Authorization", "")
        return auth == f"Bearer {self.api_token}"

    def do_GET(self) -> None:
        route = urlparse(self.path)
        if route.path == "/":
            html = INDEX_HTML.replace("{{API_TOKEN}}", self.api_token or "")
            self._send_html(html)
        elif route.path == "/api/interfaces":
            interfaces = [item.to_dict() for item in discover_interfaces()]
            self._send_json({"interfaces": interfaces, "recommended": next((i for i in interfaces if i["recommended"]), None)})
        elif route.path == "/api/scans":
            self._send_json({"tasks": [task.to_dict() for task in STORE.list()]})
        elif route.path.startswith("/api/scans/") and route.path.endswith("/csv"):
            task_id = route.path.split("/")[-2]
            task = STORE.get(task_id)
            if not task:
                self._send_json({"error": "scan task not found"}, HTTPStatus.NOT_FOUND)
                return
            if task.status not in ("done", "cancelled"):
                self._send_json({"error": "scan not finished yet"}, HTTPStatus.BAD_REQUEST)
                return
            self._send_csv(task)
        elif route.path.startswith("/api/scans/") and route.path.endswith("/json"):
            task_id = route.path.split("/")[-2]
            task = STORE.get(task_id)
            if not task:
                self._send_json({"error": "scan task not found"}, HTTPStatus.NOT_FOUND)
                return
            if task.status not in ("done", "cancelled"):
                self._send_json({"error": "scan not finished yet"}, HTTPStatus.BAD_REQUEST)
                return
            self._send_json_download(task)
        elif route.path.startswith("/api/scans/"):
            task_id = route.path.rsplit("/", 1)[-1]
            task = STORE.get(task_id)
            if not task:
                self._send_json({"error": "scan task not found"}, HTTPStatus.NOT_FOUND)
                return
            self._send_json(task.to_dict(include_assets=True))
        else:
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_POST(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        route = urlparse(self.path)
        if route.path.startswith("/api/scans/") and route.path.endswith("/cancel"):
            task_id = route.path.split("/")[-2]
            task = STORE.get(task_id)
            if not task:
                self._send_json({"error": "scan task not found"}, HTTPStatus.NOT_FOUND)
                return
            if task.status != "running":
                self._send_json({"error": "scan is not running"}, HTTPStatus.BAD_REQUEST)
                return
            task.cancel_event.set()
            self._send_json(task.to_dict())
        elif route.path == "/api/scans/quick":
            target = recommended_network()
            if not target:
                self._send_json({"error": "no usable local network interface found"}, HTTPStatus.BAD_REQUEST)
                return
            params = self._read_json()
            task = create_scan(
                target=target,
                mode=str(params.get("mode") or "quick"),
                ports=_optional_str(params.get("ports")),
                timeout=float(params.get("timeout") or 0.7),
                concurrency=int(params.get("concurrency") or 128),
                host_concurrency=_optional_int(params.get("host_concurrency")),
                global_concurrency=_optional_int(params.get("global_concurrency")),
                per_host_concurrency=_optional_int(params.get("per_host_concurrency")),
                discover_hosts=_optional_bool(params.get("discover_hosts")),
                discovery_ports=str(params.get("discovery_ports") or DISCOVERY_PORTS),
                skip_ping=bool(params.get("skip_ping", True)),
                max_hosts=int(params.get("max_hosts") or 4096),
            )
            self._send_json(task.to_dict(), HTTPStatus.CREATED)
        elif route.path == "/api/scans":
            params = self._read_json()
            target = str(params.get("target") or "").strip()
            if not target:
                self._send_json({"error": "target is required"}, HTTPStatus.BAD_REQUEST)
                return
            task = create_scan(
                target=target,
                mode=str(params.get("mode") or "custom"),
                ports=_optional_str(params.get("ports")),
                timeout=float(params.get("timeout") or 0.7),
                concurrency=int(params.get("concurrency") or 128),
                host_concurrency=_optional_int(params.get("host_concurrency")),
                global_concurrency=_optional_int(params.get("global_concurrency")),
                per_host_concurrency=_optional_int(params.get("per_host_concurrency")),
                discover_hosts=_optional_bool(params.get("discover_hosts")),
                discovery_ports=str(params.get("discovery_ports") or DISCOVERY_PORTS),
                skip_ping=bool(params.get("skip_ping", True)),
                max_hosts=int(params.get("max_hosts") or 4096),
            )
            self._send_json(task.to_dict(), HTTPStatus.CREATED)
        else:
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def do_DELETE(self) -> None:
        if not self._check_auth():
            self._send_json({"error": "unauthorized"}, HTTPStatus.UNAUTHORIZED)
            return
        route = urlparse(self.path)
        if route.path.startswith("/api/scans/"):
            task_id = route.path.rsplit("/", 1)[-1]
            task = STORE.get(task_id)
            if not task:
                self._send_json({"error": "scan task not found"}, HTTPStatus.NOT_FOUND)
                return
            if task.status == "running":
                task.cancel_event.set()
            STORE.remove(task_id)
            self._send_json({"ok": True})
        else:
            self._send_json({"error": "not found"}, HTTPStatus.NOT_FOUND)

    def log_message(self, fmt: str, *args: object) -> None:
        return

    def _read_json(self) -> dict[str, Any]:
        length = int(self.headers.get("Content-Length") or 0)
        if length <= 0:
            return {}
        if length > MAX_BODY:
            return {}
        raw = self.rfile.read(length).decode("utf-8")
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {}
        except json.JSONDecodeError:
            return {}

    def _send_json(self, payload: dict[str, Any], status: HTTPStatus = HTTPStatus.OK) -> None:
        raw = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_html(self, html: str) -> None:
        raw = html.encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_csv(self, task: ScanTask) -> None:
        buf = io.StringIO()
        _write_csv(task.assets, buf)
        raw = buf.getvalue().encode("utf-8-sig")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "text/csv; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="lanscope-{task.id}.csv"')
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)

    def _send_json_download(self, task: ScanTask) -> None:
        data = task.to_dict(include_assets=True)
        raw = json.dumps(data, ensure_ascii=False, indent=2).encode("utf-8")
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Disposition", f'attachment; filename="lanscope-{task.id}.json"')
        self.send_header("Content-Length", str(len(raw)))
        self.end_headers()
        self.wfile.write(raw)


def run(host: str, port: int, token: str | None = None) -> None:
    LanScopeHandler.api_token = token
    server = ThreadingHTTPServer((host, port), LanScopeHandler)
    try:
        print(f"LanScope Web Console: http://{host}:{port}", flush=True)
        if token:
            print(f"API Token: {token}", flush=True)
    except OSError:
        pass
    server.serve_forever()


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run the LanScope web console.")
    parser.add_argument("--host", default="127.0.0.1", help="bind address, default: 127.0.0.1")
    parser.add_argument("--port", type=int, default=8765, help="bind port, default: 8765")
    parser.add_argument("--token", default=None, help="API token for mutating requests (POST/DELETE). Auto-generated when --host is not 127.0.0.1 if not specified.")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    token = args.token
    if not token and args.host not in ("127.0.0.1", "localhost", "::1"):
        token = uuid.uuid4().hex
    try:
        run(args.host, args.port, token=token)
    except KeyboardInterrupt:
        print("\nLanScope Web Console stopped.")
        return 130
    return 0


INDEX_HTML = r"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>LanScope 控制台</title>
  <style>
    :root { color-scheme: light; --bg:#f6f8fb; --panel:#ffffff; --text:#17202a; --muted:#64748b; --line:#d8e0ea; --blue:#2563eb; --green:#11845b; --red:#b42318; --orange:#c2410c; }
    * { box-sizing: border-box; }
    body { margin:0; font-family: "Microsoft YaHei", "Segoe UI", Arial, sans-serif; background:var(--bg); color:var(--text); }
    header { height:64px; display:flex; align-items:center; justify-content:space-between; padding:0 28px; background:#172033; color:white; }
    h1 { margin:0; font-size:22px; letter-spacing:0; }
    main { max-width:1180px; margin:24px auto 48px; padding:0 20px; display:grid; gap:18px; }
    section { background:var(--panel); border:1px solid var(--line); border-radius:8px; padding:18px; }
    h2 { margin:0 0 14px; font-size:17px; }
    .grid { display:grid; grid-template-columns: repeat(3, minmax(0,1fr)); gap:12px; }
    .iface { border:1px solid var(--line); border-radius:8px; padding:12px; background:#fbfdff; cursor:pointer; transition:border-color .15s; }
    .iface:hover { border-color:var(--blue); }
    .iface strong { display:block; margin-bottom:6px; font-size:15px; }
    .muted { color:var(--muted); font-size:13px; }
    .badge { display:inline-block; padding:2px 8px; border-radius:999px; font-size:12px; background:#e8f1ff; color:#1d4ed8; margin-left:8px; }
    .row { display:flex; gap:10px; flex-wrap:wrap; align-items:end; }
    label { display:grid; gap:5px; font-size:13px; color:#334155; }
    label.check { display:flex; align-items:center; gap:6px; cursor:pointer; }
    label.check input { width:auto; height:auto; min-width:auto; }
    input, select { height:36px; border:1px solid var(--line); border-radius:6px; padding:0 10px; min-width:140px; background:white; }
    input[type=search] { min-width:200px; }
    button { height:36px; border:0; border-radius:6px; padding:0 14px; background:var(--blue); color:white; cursor:pointer; font-weight:600; font-size:13px; }
    button.secondary { background:#334155; }
    button.danger { background:var(--red); }
    button.warn { background:var(--orange); }
    button:disabled { opacity:.55; cursor:not-allowed; }
    table { width:100%; border-collapse:collapse; font-size:13px; }
    th, td { border-bottom:1px solid var(--line); padding:9px 8px; text-align:left; vertical-align:top; }
    th { color:#475569; font-weight:700; background:#f8fafc; position:sticky; top:0; cursor:pointer; user-select:none; }
    th:hover { color:var(--blue); }
    pre { margin:0; max-height:360px; overflow:auto; background:#0f172a; color:#dbeafe; border-radius:8px; padding:14px; font-size:12px; line-height:1.45; }
    #detail { display:grid; gap:12px; }
    #detail pre { white-space:pre-wrap; }
    .summary { display:grid; grid-template-columns: repeat(5, minmax(0, 1fr)); gap:10px; }
    .metric { border:1px solid var(--line); border-radius:8px; padding:10px; background:#fbfdff; }
    .metric b { display:block; font-size:20px; margin-bottom:4px; }
    .selected { background:#eff6ff; }
    .status-done { color:var(--green); font-weight:700; }
    .status-failed { color:var(--red); font-weight:700; }
    .status-cancelled { color:var(--orange); font-weight:700; }
    .status-running { color:var(--blue); font-weight:700; }
    .progress-bar { width:100%; height:6px; background:#e2e8f0; border-radius:3px; overflow:hidden; }
    .progress-bar-fill { height:100%; background:var(--blue); border-radius:3px; transition:width .3s; }
    .advanced-toggle { font-size:13px; color:var(--blue); cursor:pointer; border:none; background:none; padding:0; font-weight:600; }
    .advanced-toggle:hover { text-decoration:underline; }
    .advanced { display:none; margin-top:12px; padding-top:12px; border-top:1px solid var(--line); }
    .advanced.open { display:block; }
    .port-stats { display:flex; gap:8px; flex-wrap:wrap; margin-top:8px; }
    .port-tag { display:inline-flex; align-items:center; gap:4px; padding:3px 10px; background:#f1f5f9; border:1px solid var(--line); border-radius:999px; font-size:12px; }
    .port-tag b { color:var(--blue); }
    .toolbar { display:flex; gap:10px; align-items:center; flex-wrap:wrap; margin:8px 0; }
    .scan-params { display:grid; grid-template-columns: repeat(auto-fill, minmax(180px, 1fr)); gap:6px; font-size:12px; color:var(--muted); padding:8px 12px; background:#f8fafc; border:1px solid var(--line); border-radius:6px; }
    .scan-params span { white-space:nowrap; }
    .results-wrap { max-height:520px; overflow:auto; border:1px solid var(--line); border-radius:6px; }
    .results-wrap table { margin:0; }
    @media (max-width: 760px) { .grid, .summary { grid-template-columns:1fr 1fr; } header { padding:0 16px; } }
  </style>
</head>
<body>
  <header>
    <h1>LanScope 控制台</h1>
    <span>资产发现与快速扫描</span>
  </header>
  <main>
    <section>
      <h2>本地局域网发现</h2>
      <div id="interfaces" class="grid"></div>
    </section>

    <section>
      <h2>快速扫描</h2>
      <div class="row">
        <label>扫描模式
          <select id="quickMode">
            <option value="quick" selected>quick</option>
            <option value="normal">normal</option>
            <option value="full">full</option>
            <option value="deep">deep</option>
          </select>
        </label>
        <label>快速端口
          <input id="quickPorts" value="22,80,443,445,3389,8080" />
        </label>
        <label>超时秒数
          <input id="quickTimeout" type="number" step="0.1" value="0.7" />
        </label>
        <label class="check">
          <input type="checkbox" id="quickDiscoverHosts" checked /> 主机发现
        </label>
        <button id="quickBtn">一键扫描当前局域网</button>
      </div>
    </section>

    <section>
      <h2>自定义扫描</h2>
      <div class="row">
        <label>扫描模式
          <select id="mode">
            <option value="custom" selected>custom</option>
            <option value="quick">quick</option>
            <option value="normal">normal</option>
            <option value="full">full</option>
            <option value="deep">deep</option>
          </select>
        </label>
        <label>目标
          <input id="target" placeholder="192.168.1.0/24 或 192.168.1.10" />
        </label>
        <label>端口
          <input id="ports" value="common" />
        </label>
        <label>超时秒数
          <input id="timeout" type="number" step="0.1" value="0.7" />
        </label>
        <button id="customBtn" class="secondary">开始扫描</button>
      </div>
      <button class="advanced-toggle" onclick="document.getElementById('advOpts').classList.toggle('open')">▶ 高级选项</button>
      <div id="advOpts" class="advanced">
        <div class="row">
          <label>主机并发
            <input id="hostConc" type="number" value="128" min="1" />
          </label>
          <label>全局并发
            <input id="globalConc" type="number" value="500" min="1" />
          </label>
          <label>单主机并发
            <input id="perHostConc" type="number" value="64" min="1" />
          </label>
          <label>最大主机数
            <input id="maxHosts" type="number" value="4096" min="1" />
          </label>
          <label>发现端口
            <input id="discoveryPorts" value="22,80,443,445,3389,8080" />
          </label>
          <label class="check">
            <input type="checkbox" id="discoverHosts" checked /> 主机发现
          </label>
          <label class="check">
            <input type="checkbox" id="skipPing" checked /> 跳过 Ping
          </label>
        </div>
      </div>
    </section>

    <section>
      <h2>扫描任务</h2>
      <table>
        <thead><tr><th>任务</th><th>目标</th><th>模式</th><th>状态</th><th>进度</th><th>发现</th><th>操作</th></tr></thead>
        <tbody id="tasks"></tbody>
      </table>
    </section>

    <section>
      <h2>任务详情</h2>
      <div id="detail"><pre>选择一个任务查看结果。</pre></div>
    </section>
  </main>
  <script>
    const $ = (id) => document.getElementById(id);
    const API_TOKEN = '{{API_TOKEN}}';
    let selectedTaskId = null;
    let sortCol = null, sortAsc = true;
    let _lastDetailKey = null;

    function apiHeaders() {
      const h = {'Content-Type': 'application/json'};
      if (API_TOKEN) h['Authorization'] = `Bearer ${API_TOKEN}`;
      return h;
    }

    async function api(path, options = {}) {
      const res = await fetch(path, { headers: apiHeaders(), ...options });
      const data = await res.json();
      if (!res.ok) throw new Error(data.error || '请求失败');
      return data;
    }

    async function loadInterfaces() {
      const data = await api('/api/interfaces');
      const box = $('interfaces');
      box.innerHTML = '';
      if (!data.interfaces.length) {
        box.innerHTML = '<div class="muted">没有发现可用的局域网网卡。</div>';
        return;
      }
      for (const item of data.interfaces) {
        const div = document.createElement('div');
        div.className = 'iface';
        div.innerHTML = `
          <strong>${esc(item.name)}${item.recommended ? '<span class="badge">推荐</span>' : ''}</strong>
          <div>地址：${esc(item.address)}/${item.prefix_length}</div>
          <div>网段：${esc(item.network)}</div>
          <div>网关：${esc(item.gateway || '-')}</div>
          <div class="muted">${esc(item.description || '')}${item.virtual ? ' · 虚拟网卡' : ''}</div>
        `;
        div.onclick = () => { $('target').value = item.network; };
        box.appendChild(div);
      }
    }

    async function startQuick() {
      $('quickBtn').disabled = true;
      try {
        const task = await api('/api/scans/quick', {
          method: 'POST',
          body: JSON.stringify({
            mode: $('quickMode').value,
            ports: $('quickMode').value === 'quick' ? $('quickPorts').value : null,
            timeout: Number($('quickTimeout').value || 0.7),
            discover_hosts: $('quickDiscoverHosts').checked,
            skip_ping: true,
            max_hosts: 4096
          })
        });
        await showTask(task.id);
      } catch (err) {
        alert(err.message);
      } finally {
        $('quickBtn').disabled = false;
      }
    }

    async function startCustom() {
      const target = $('target').value.trim();
      if (!target) { alert('请输入扫描目标'); return; }
      const body = {
        target,
        mode: $('mode').value,
        ports: $('ports').value || 'common',
        timeout: Number($('timeout').value || 0.7),
        host_concurrency: Number($('hostConc').value) || null,
        global_concurrency: Number($('globalConc').value) || null,
        per_host_concurrency: Number($('perHostConc').value) || null,
        discover_hosts: $('discoverHosts').checked,
        discovery_ports: $('discoveryPorts').value,
        skip_ping: $('skipPing').checked,
        max_hosts: Number($('maxHosts').value) || 4096,
      };
      const task = await api('/api/scans', { method: 'POST', body: JSON.stringify(body) });
      await showTask(task.id);
    }

    async function cancelScan(id) {
      try { await api(`/api/scans/${id}/cancel`, { method: 'POST' }); } catch(e) { alert(e.message); }
      _lastDetailKey = null;
      loadTasks(); refreshDetail();
    }

    async function deleteScan(id) {
      if (!confirm('确定删除此任务？')) return;
      try { await fetch(`/api/scans/${id}`, { method: 'DELETE', headers: apiHeaders() }); } catch(e) {}
      if (selectedTaskId === id) { selectedTaskId = null; _lastDetailKey = null; $('detail').innerHTML = '<pre>选择一个任务查看结果。</pre>'; }
      loadTasks();
    }

    function elapsed(task) {
      const start = task.started_at;
      if (!start) return '-';
      const end = task.finished_at || (Date.now() / 1000);
      const s = Math.round(end - start);
      return s < 60 ? `${s}s` : `${Math.floor(s/60)}m${s%60}s`;
    }

    async function loadTasks() {
      const data = await api('/api/scans');
      const tbody = $('tasks');
      tbody.innerHTML = '';
      for (const task of data.tasks) {
        const progress = task.total_hosts ? `${task.completed_hosts}/${task.total_hosts}` : '-';
        const statusCls = `status-${task.status}`;
        const tr = document.createElement('tr');
        if (task.id === selectedTaskId) tr.className = 'selected';
        let actions = `<button class="secondary" onclick="showTask('${task.id}')">查看</button>`;
        if (task.status === 'running') actions += ` <button class="warn" onclick="cancelScan('${task.id}')">取消</button>`;
        if (task.status !== 'running') actions += ` <button class="danger" onclick="deleteScan('${task.id}')">删除</button>`;
        tr.innerHTML = `
          <td>${esc(task.id)}</td>
          <td>${esc(task.target)}<div class="muted">${esc(task.ports)}</div></td>
          <td>${esc(task.mode)}</td>
          <td><span class="${statusCls}">${esc(task.status)}</span><div class="muted">${elapsed(task)}</div></td>
          <td>${progress}</td>
          <td>${task.reachable_hosts} 主机 / ${task.open_services} 服务</td>
          <td>${actions}</td>
        `;
        tbody.appendChild(tr);
      }
    }

    async function showTask(id) {
      selectedTaskId = id;
      _lastDetailKey = null;
      $('detail').innerHTML = '<pre>正在加载任务详情...</pre>';
      $('detail').scrollIntoView({behavior: 'smooth', block: 'start'});
      await refreshDetail();
      await loadTasks();
    }

    async function refreshDetail() {
      if (!selectedTaskId) return;
      try {
        const data = await api(`/api/scans/${selectedTaskId}`);
        const key = [data.status, data.completed_hosts, data.total_hosts,
                     data.reachable_hosts, data.open_services, (data.assets||[]).length,
                     Math.floor(data.scanned_ports / 100)].join(',');
        if (key === _lastDetailKey) return;
        _lastDetailKey = key;
        const filterEl = $('resultFilter');
        const filterVal = filterEl ? filterEl.value : '';
        const hadFocus = filterEl && document.activeElement === filterEl;
        const wrap = document.querySelector('.results-wrap');
        const scrollTop = wrap ? wrap.scrollTop : 0;
        renderDetail(data);
        const newFilter = $('resultFilter');
        if (newFilter) {
          newFilter.value = filterVal;
          if (hadFocus) newFilter.focus();
          if (filterVal) filterResults();
        }
        const newWrap = document.querySelector('.results-wrap');
        if (newWrap) newWrap.scrollTop = scrollTop;
      } catch (err) {
        $('detail').innerHTML = `<pre>加载失败：${esc(err.message)}</pre>`;
      }
    }

    function portStats(assets) {
      const counts = {};
      for (const a of assets || []) {
        for (const s of a.services || []) {
          const label = s.service || String(s.port);
          counts[label] = (counts[label] || 0) + 1;
        }
      }
      return Object.entries(counts).sort((a,b) => b[1]-a[1]).slice(0, 15);
    }

    function renderDetail(task) {
      const pct = task.total_hosts ? Math.round(task.completed_hosts * 100 / task.total_hosts) : 0;
      const portPct = task.total_ports ? Math.round(task.scanned_ports * 100 / task.total_ports) : 0;
      const statusCls = `status-${task.status}`;

      let phaseHtml = '';
      if (task.status === 'running') {
        if (task.scanned_ports === 0 && task.completed_hosts === 0) {
          phaseHtml = task.discover_hosts
            ? '<div class="muted" style="margin:4px 0">正在发现存活主机...</div>'
            : '<div class="muted" style="margin:4px 0">正在准备扫描...</div>';
        }
      }

      const stats = portStats(task.assets);
      const statsHtml = stats.length
        ? `<div class="port-stats">${stats.map(([k,v]) => `<span class="port-tag"><b>${v}</b> ${esc(k)}</span>`).join('')}</div>`
        : '';

      const paramFields = [
        `模式: ${esc(task.mode)}`, `端口: ${esc(task.ports)}`, `超时: ${task.timeout}s`,
        `主机并发: ${task.host_concurrency}`, `全局并发: ${task.global_concurrency}`, `单主机并发: ${task.per_host_concurrency}`,
        `主机发现: ${task.discover_hosts ? '是' : '否'}`, `跳过Ping: ${task.skip_ping ? '是' : '否'}`,
      ];

      const exportBtns = (task.status === 'done' || task.status === 'cancelled')
        ? `<button onclick="window.location='/api/scans/${task.id}/csv'">导出 CSV</button> <button class="secondary" onclick="window.location='/api/scans/${task.id}/json'">导出 JSON</button>`
        : '';

      let rows = [];
      for (const asset of task.assets || []) {
        const mac = asset.mac || '-';
        const vendor = asset.vendor || '-';
        if (!asset.services || asset.services.length === 0) {
          rows.push({ip:asset.address, host:asset.hostname||'-', mac, vendor, port:'-', svc:'-', status:'-', title:'-'});
          continue;
        }
        for (const service of asset.services) {
          const http = service.http || {};
          const title = http.title || service.banner || '-';
          rows.push({ip:asset.address, host:asset.hostname||'-', mac, vendor, port:String(service.port), svc:service.service||'-', status:String(http.status||'-'), title});
        }
      }

      if (sortCol !== null) {
        const keys = ['ip','host','mac','vendor','port','svc','status','title'];
        const key = keys[sortCol];
        rows.sort((a,b) => {
          let va = a[key], vb = b[key];
          if (key === 'port') { va = parseInt(va)||99999; vb = parseInt(vb)||99999; return sortAsc ? va-vb : vb-va; }
          return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
        });
      }

      const allRows = rows;

      $('detail').innerHTML = `
        <div class="summary">
          <div class="metric"><span class="${statusCls}"><b>${esc(task.status)}</b></span><span>任务状态</span></div>
          <div class="metric"><b>${task.completed_hosts}/${task.total_hosts || 0}</b><span>主机进度</span>
            <div class="progress-bar"><div class="progress-bar-fill" style="width:${pct}%"></div></div>
          </div>
          <div class="metric"><b>${task.scanned_ports.toLocaleString()}/${(task.total_ports||0).toLocaleString()}</b><span>端口进度 (${portPct}%)</span>
            <div class="progress-bar"><div class="progress-bar-fill" style="width:${portPct}%"></div></div>
          </div>
          <div class="metric"><b>${task.reachable_hosts}</b><span>可达主机</span></div>
          <div class="metric"><b>${task.open_services}</b><span>开放服务</span></div>
        </div>
        ${phaseHtml}
        ${task.error ? `<pre>错误：${esc(task.error)}</pre>` : ''}
        <div class="scan-params">${paramFields.map(f => `<span>${f}</span>`).join('')}</div>
        ${statsHtml}
        <div class="toolbar">
          ${exportBtns}
          <input type="search" id="resultFilter" placeholder="搜索 IP / 端口 / 服务 / Banner ..." oninput="filterResults()" />
        </div>
        <div class="results-wrap">
          <table id="resultTable">
            <thead><tr>
              <th onclick="sortBy(0)">地址</th><th onclick="sortBy(1)">主机名</th><th onclick="sortBy(2)">MAC</th>
              <th onclick="sortBy(3)">厂商</th><th onclick="sortBy(4)">端口</th><th onclick="sortBy(5)">服务</th>
              <th onclick="sortBy(6)">HTTP</th><th onclick="sortBy(7)">标题/Banner</th>
            </tr></thead>
            <tbody id="resultBody"></tbody>
          </table>
        </div>
      `;

      window._allRows = allRows;
      renderRows(allRows);
    }

    function renderRows(rows) {
      const tbody = $('resultBody');
      if (!tbody) return;
      if (!rows.length) { tbody.innerHTML = '<tr><td colspan="8">暂无结果</td></tr>'; return; }
      tbody.innerHTML = rows.map(r => `<tr>
        <td>${esc(r.ip)}</td><td>${esc(r.host)}</td><td>${esc(r.mac)}</td><td>${esc(r.vendor)}</td>
        <td>${esc(r.port)}</td><td>${esc(r.svc)}</td><td>${esc(r.status)}</td><td>${esc(r.title)}</td>
      </tr>`).join('');
    }

    function filterResults() {
      const q = ($('resultFilter')?.value || '').toLowerCase();
      if (!window._allRows) return;
      if (!q) { renderRows(window._allRows); return; }
      renderRows(window._allRows.filter(r =>
        r.ip.toLowerCase().includes(q) || r.host.toLowerCase().includes(q) ||
        r.port.toLowerCase().includes(q) || r.svc.toLowerCase().includes(q) ||
        r.title.toLowerCase().includes(q) || r.mac.toLowerCase().includes(q) ||
        r.vendor.toLowerCase().includes(q)
      ));
    }

    function sortBy(col) {
      if (sortCol === col) { sortAsc = !sortAsc; } else { sortCol = col; sortAsc = true; }
      if (!window._allRows) return;
      const keys = ['ip','host','mac','vendor','port','svc','status','title'];
      const key = keys[col];
      window._allRows.sort((a,b) => {
        let va = a[key], vb = b[key];
        if (key === 'port') { va = parseInt(va)||99999; vb = parseInt(vb)||99999; return sortAsc ? va-vb : vb-va; }
        return sortAsc ? va.localeCompare(vb) : vb.localeCompare(va);
      });
      filterResults();
    }

    function esc(value) {
      return String(value ?? '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#039;');
    }

    $('quickBtn').onclick = startQuick;
    $('customBtn').onclick = startCustom;
    loadInterfaces().catch(err => alert(err.message));
    loadTasks();
    setInterval(() => { loadTasks(); refreshDetail(); }, 1000);
  </script>
</body>
</html>
"""


if __name__ == "__main__":
    raise SystemExit(main())
