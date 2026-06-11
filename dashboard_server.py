#!/usr/bin/env python3
"""Локальная веб-оболочка для scanner.py"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
import threading
import uuid
from dataclasses import dataclass
from datetime import datetime, timezone
from http import HTTPStatus
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlparse

HISTORY_LIMIT = 100


@dataclass(frozen=True)
class ServerConfig:
    host: str
    port: int
    scanner_script: Path
    reports_dir: Path
    static_dir: Path
    history_file: Path


def utc_now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Web Control Tower for Docker image filter")
    parser.add_argument("--host", default="127.0.0.1", help="Host for HTTP server")
    parser.add_argument("--port", type=int, default=8765, help="Port for HTTP server")
    parser.add_argument(
        "--reports-dir",
        type=Path,
        default=Path("reports/web"),
        help="Directory for web scan reports",
    )
    return parser.parse_args(argv)


def ensure_directories(config: ServerConfig) -> None:
    config.reports_dir.mkdir(parents=True, exist_ok=True)
    config.history_file.parent.mkdir(parents=True, exist_ok=True)
    if not config.history_file.exists():
        config.history_file.write_text("", encoding="utf-8")


def _safe_read_json(path: Path) -> dict[str, object]:
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}


def load_history(history_file: Path) -> list[dict[str, object]]:
    if not history_file.exists():
        return []
    rows: list[dict[str, object]] = []
    for line in history_file.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rows.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    return rows[-HISTORY_LIMIT:]


def append_history(history_file: Path, entry: dict[str, object]) -> None:
    with history_file.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(entry, ensure_ascii=False) + "\n")


def run_scan(config: ServerConfig, image: str) -> dict[str, object]:
    scan_id = uuid.uuid4().hex[:12]
    started_at = utc_now_iso()

    report_path = config.reports_dir / f"{scan_id}.json"
    guidance_path = config.reports_dir / f"{scan_id}.txt"

    cmd = [
        sys.executable,
        str(config.scanner_script),
        image,
        "--report",
        str(report_path),
        "--guidance",
        str(guidance_path),
    ]

    started_ts = datetime.now(timezone.utc)
    proc = subprocess.run(cmd, capture_output=True, text=True)
    finished_ts = datetime.now(timezone.utc)
    duration_ms = int((finished_ts - started_ts).total_seconds() * 1000)

    if proc.returncode == 0:
        status = "PASSED"
    elif proc.returncode == 1:
        status = "FAILED"
    else:
        status = "ERROR"

    payload = _safe_read_json(report_path) if report_path.exists() else {}
    critical_count = int(payload.get("critical_count", 0))
    warning_count = int(payload.get("warning_count", 0))
    findings = payload.get("findings", [])
    remediation = payload.get("remediation", {})

    entry = {
        "id": scan_id,
        "image": image,
        "status": status,
        "exit_code": proc.returncode,
        "started_at": started_at,
        "duration_ms": duration_ms,
        "critical_count": critical_count,
        "warning_count": warning_count,
        "stdout": proc.stdout.strip(),
        "stderr": proc.stderr.strip(),
        "report_path": str(report_path),
        "guidance_path": str(guidance_path) if guidance_path.exists() else "",
        "findings": findings if isinstance(findings, list) else [],
        "remediation": remediation if isinstance(remediation, dict) else {},
    }
    append_history(config.history_file, entry)
    return entry


class DashboardHandler(SimpleHTTPRequestHandler):
    config: ServerConfig
    state_lock = threading.Lock()
    scan_running = False

    def __init__(self, *args, directory: str | None = None, **kwargs) -> None:
        super().__init__(*args, directory=directory, **kwargs)

    def log_message(self, format: str, *args) -> None:
        return

    def _send_json(self, payload: dict[str, object], status: int = 200) -> None:
        body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _read_json_body(self) -> dict[str, object]:
        length = int(self.headers.get("Content-Length", "0"))
        if length <= 0:
            return {}
        try:
            raw = self.rfile.read(length).decode("utf-8")
            data = json.loads(raw)
        except (UnicodeDecodeError, json.JSONDecodeError):
            return {}
        return data if isinstance(data, dict) else {}

    def _path_parts(self) -> list[str]:
        parsed = urlparse(self.path)
        return [p for p in parsed.path.split("/") if p]

    def do_GET(self) -> None:
        parts = self._path_parts()
        if parts[:2] == ["api", "health"]:
            with self.state_lock:
                running = self.scan_running
            self._send_json({"ok": True, "scan_running": running, "now": utc_now_iso()})
            return

        if parts[:2] == ["api", "scans"] and len(parts) == 2:
            entries = list(reversed(load_history(self.config.history_file)))
            self._send_json({"items": entries})
            return

        if parts[:2] == ["api", "scans"] and len(parts) == 3:
            scan_id = parts[2]
            for item in reversed(load_history(self.config.history_file)):
                if item.get("id") == scan_id:
                    self._send_json({"item": item})
                    return
            self._send_json({"error": "scan not found"}, status=404)
            return

        super().do_GET()

    def do_POST(self) -> None:
        parts = self._path_parts()
        if parts[:2] != ["api", "scan"]:
            self._send_json({"error": "not found"}, status=404)
            return

        body = self._read_json_body()
        image = str(body.get("image", "")).strip()
        if not image:
            self._send_json({"error": "image is required"}, status=400)
            return

        with self.state_lock:
            if self.scan_running:
                self._send_json(
                    {"error": "scan already running"},
                    status=HTTPStatus.CONFLICT,
                )
                return
            self.scan_running = True

        try:
            item = run_scan(self.config, image)
        finally:
            with self.state_lock:
                self.scan_running = False

        self._send_json({"item": item}, status=201)


def build_config(args: argparse.Namespace) -> ServerConfig:
    root = Path(__file__).resolve().parent
    reports_dir = args.reports_dir if args.reports_dir.is_absolute() else root / args.reports_dir
    static_dir = root / "webui"
    return ServerConfig(
        host=args.host,
        port=args.port,
        scanner_script=root / "scanner.py",
        reports_dir=reports_dir,
        static_dir=static_dir,
        history_file=reports_dir / "history.jsonl",
    )


def main(argv: list[str] | None = None) -> int:
    args = parse_args(argv)
    config = build_config(args)
    ensure_directories(config)

    if not config.scanner_script.exists():
        print(f"ERROR: scanner not found: {config.scanner_script}", file=sys.stderr)
        return 2
    if not config.static_dir.exists():
        print(f"ERROR: static dir not found: {config.static_dir}", file=sys.stderr)
        return 2

    def handler(*h_args, **h_kwargs):
        DashboardHandler.config = config
        return DashboardHandler(
            *h_args,
            directory=str(config.static_dir),
            **h_kwargs,
        )

    server = ThreadingHTTPServer((config.host, config.port), handler)
    print(f"Control Tower started: http://{config.host}:{config.port}")
    print(f"Reports dir: {config.reports_dir}")
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
