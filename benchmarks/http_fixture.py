#!/usr/bin/env python3
"""Serve a deterministic loopback redirect and bounded response body."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import urlsplit


class FixtureServer(ThreadingHTTPServer):
    daemon_threads = True
    allow_reuse_address = False

    def __init__(self, address: tuple[str, int], body: bytes) -> None:
        super().__init__(address, FixtureHandler)
        self.fixture_body = body


class FixtureHandler(BaseHTTPRequestHandler):
    protocol_version = "HTTP/1.1"

    def do_GET(self) -> None:
        path = urlsplit(self.path).path
        if path == "/start":
            self.send_response(302)
            self.send_header("Location", "/body?token=fixture-secret")
            self.send_header("Content-Length", "0")
            self.send_header("Connection", "close")
            self.end_headers()
            return

        if path == "/body":
            body = self.server.fixture_body
            self.send_response(200)
            self.send_header("Content-Type", "application/octet-stream")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Connection", "close")
            self.end_headers()
            try:
                self.wfile.write(body)
            except (BrokenPipeError, ConnectionResetError):
                # The client intentionally stops at its configured body bound.
                pass
            return

        self.send_response(404)
        self.send_header("Content-Length", "0")
        self.send_header("Connection", "close")
        self.end_headers()

    def log_message(self, _format: str, *_args: object) -> None:
        return


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--port-file", required=True, type=Path)
    parser.add_argument("--body-bytes", type=int, default=65_536)
    return parser.parse_args()


def write_metadata(path: Path, server: FixtureServer, body: bytes) -> None:
    host, port = server.server_address
    metadata = {
        "schema_version": "hopwhy.http-fixture.v1",
        "topology": "single-process IPv4 loopback HTTP/1.1",
        "base_url": f"http://{host}:{port}",
        "routes": {
            "/start": "302 /body?token=fixture-secret",
            "/body": "200 bounded deterministic body",
        },
        "body_bytes": len(body),
        "body_sha256": hashlib.sha256(body).hexdigest(),
    }
    path.parent.mkdir(parents=True, exist_ok=True)
    temporary = path.with_name(f"{path.name}.{os.getpid()}.tmp")
    temporary.write_text(
        json.dumps(metadata, sort_keys=True, separators=(",", ":")) + "\n",
        encoding="utf-8",
    )
    os.replace(temporary, path)


def main() -> None:
    args = parse_args()
    if not 1 <= args.body_bytes <= 8 * 1024 * 1024:
        raise SystemExit("--body-bytes must be between 1 and 8388608")

    body = b"x" * args.body_bytes
    with FixtureServer(("127.0.0.1", 0), body) as server:
        write_metadata(args.port_file, server, body)
        try:
            server.serve_forever(poll_interval=0.1)
        except KeyboardInterrupt:
            pass


if __name__ == "__main__":
    main()
