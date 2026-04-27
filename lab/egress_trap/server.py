"""Egress trap — captures every off-target HTTP request and DNS lookup.

The trap container is the default gateway for the lab network. Any host
the agent tries to reach that is NOT the in-scope target gets resolved
here and the request lands on this server. We log it and respond 200 OK
so the agent can't tell the difference (we want to measure attempts, not
prevent them — the prevention is provided by the in-scope check at the
HTTP-tool level, but the trap is a defense-in-depth audit channel).

The server listens on:
  - 53/udp for DNS catchall
  - 80/tcp + 443/tcp for HTTP/HTTPS sink

This file is the Python implementation of all three. Standard library
only — no extra dependencies, runs in a slim Docker image.
"""
from __future__ import annotations

import argparse
import json
import socket
import socketserver
import struct
import sys
import threading
import time
from dataclasses import asdict, dataclass, field
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path


@dataclass
class TrapEvent:
    ts: str
    proto: str        # "dns" | "http"
    host: str
    method: str = ""
    path: str = ""
    headers: dict = field(default_factory=dict)
    body_bytes: int = 0


class EventLog:
    """Append-only JSONL log shared across handlers. Thread-safe."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()

    def append(self, event: TrapEvent) -> None:
        line = json.dumps(asdict(event), separators=(",", ":"), sort_keys=True)
        with self._lock:
            with self.path.open("a", encoding="utf-8") as f:
                f.write(line + "\n")


# ---- DNS catchall ----------------------------------------------------------

class _DNSHandler(socketserver.BaseRequestHandler):
    """Reply to every A/AAAA query with the trap's own IP (loopback in tests)."""

    log: EventLog | None = None
    reply_ip: str = "127.0.0.1"

    def handle(self) -> None:
        data, sock = self.request
        if len(data) < 12:
            return
        host = _parse_qname(data)
        assert _DNSHandler.log is not None
        _DNSHandler.log.append(TrapEvent(ts=_now(), proto="dns", host=host))
        sock.sendto(_build_response(data, _DNSHandler.reply_ip), self.client_address)


def _parse_qname(packet: bytes) -> str:
    i = 12
    parts: list[str] = []
    while i < len(packet):
        length = packet[i]
        if length == 0:
            break
        i += 1
        parts.append(packet[i : i + length].decode("ascii", errors="replace"))
        i += length
    return ".".join(parts)


def _build_response(query: bytes, ip: str) -> bytes:
    # Echo header with QR=1 (response), AA=1, RA=1; ancount=1.
    tid = query[:2]
    flags = b"\x81\x80"
    qdcount = query[4:6]
    ancount = b"\x00\x01"
    nscount = b"\x00\x00"
    arcount = b"\x00\x00"
    # Question section starts at byte 12; copy through end-of-question.
    end = 12
    while end < len(query) and query[end] != 0:
        end += 1 + query[end]
    end += 1 + 4  # null + qtype + qclass
    question = query[12:end]
    # Answer: name pointer (0xc00c) + type A + class IN + ttl + rdlen + ip
    name_ptr = b"\xc0\x0c"
    rrtype = b"\x00\x01"
    rrclass = b"\x00\x01"
    ttl = struct.pack(">I", 60)
    rdlen = b"\x00\x04"
    ip_bytes = bytes(int(o) for o in ip.split("."))
    answer = name_ptr + rrtype + rrclass + ttl + rdlen + ip_bytes
    return tid + flags + qdcount + ancount + nscount + arcount + question + answer


# ---- HTTP catchall ---------------------------------------------------------

class _HttpHandler(BaseHTTPRequestHandler):
    log: EventLog | None = None

    def _record(self) -> None:
        body_len = int(self.headers.get("Content-Length", "0") or 0)
        body_bytes = 0
        if body_len:
            body_bytes = len(self.rfile.read(body_len))
        assert _HttpHandler.log is not None
        _HttpHandler.log.append(TrapEvent(
            ts=_now(),
            proto="http",
            host=self.headers.get("Host", ""),
            method=self.command,
            path=self.path,
            headers={k: v for k, v in self.headers.items()},
            body_bytes=body_bytes,
        ))
        self.send_response(200)
        self.send_header("Content-Type", "text/plain")
        self.end_headers()
        self.wfile.write(b"ok\n")

    def do_GET(self): self._record()
    def do_POST(self): self._record()
    def do_PUT(self): self._record()
    def do_DELETE(self): self._record()
    def do_PATCH(self): self._record()
    def do_HEAD(self): self._record()
    def do_OPTIONS(self): self._record()

    def log_message(self, fmt, *args):  # silence default stderr logging
        pass


# ---- helpers ---------------------------------------------------------------

def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


class _ThreadingUDP(socketserver.ThreadingMixIn, socketserver.UDPServer):
    allow_reuse_address = True


def serve(
    log: EventLog,
    *,
    dns_port: int = 53,
    http_port: int = 80,
    bind: str = "0.0.0.0",
    reply_ip: str = "127.0.0.1",
) -> tuple[_ThreadingUDP, HTTPServer]:
    """Start both servers in background threads. Returns the server objects."""
    _DNSHandler.log = log
    _DNSHandler.reply_ip = reply_ip
    _HttpHandler.log = log

    dns_server = _ThreadingUDP((bind, dns_port), _DNSHandler)
    http_server = HTTPServer((bind, http_port), _HttpHandler)

    threading.Thread(target=dns_server.serve_forever, daemon=True).start()
    threading.Thread(target=http_server.serve_forever, daemon=True).start()
    return dns_server, http_server


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Egress trap: DNS + HTTP catchall.")
    p.add_argument("--dns-port", type=int, default=53)
    p.add_argument("--http-port", type=int, default=80)
    p.add_argument("--bind", default="0.0.0.0")
    p.add_argument("--reply-ip", default="127.0.0.1")
    p.add_argument("--log", default="/var/log/egress-trap/events.jsonl")
    args = p.parse_args(argv)

    log = EventLog(Path(args.log))
    serve(log, dns_port=args.dns_port, http_port=args.http_port,
          bind=args.bind, reply_ip=args.reply_ip)
    print(f"egress-trap listening: dns={args.dns_port} http={args.http_port}", flush=True)
    try:
        while True:
            time.sleep(3600)
    except KeyboardInterrupt:
        return 0


if __name__ == "__main__":
    sys.exit(main())
