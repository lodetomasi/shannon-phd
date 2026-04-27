from __future__ import annotations

import json
import socket
import struct
import threading
import time
import urllib.error
import urllib.request
from pathlib import Path

import pytest

from lab.egress_trap.server import EventLog, serve


@pytest.fixture
def log_path(tmp_path: Path) -> Path:
    return tmp_path / "events.jsonl"


@pytest.fixture
def trap(log_path: Path):
    """Start the trap on ephemeral high ports we can use without root."""
    log = EventLog(log_path)
    dns_server, http_server = serve(
        log,
        dns_port=15353,
        http_port=18080,
        bind="127.0.0.1",
    )
    yield log_path, 15353, 18080
    dns_server.shutdown()
    http_server.shutdown()


def _read_events(path: Path) -> list[dict]:
    if not path.is_file():
        return []
    return [json.loads(line) for line in path.read_text().splitlines() if line.strip()]


def _wait_for_event(path: Path, timeout: float = 2.0) -> list[dict]:
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        events = _read_events(path)
        if events:
            return events
        time.sleep(0.05)
    return _read_events(path)


def test_http_get_is_logged(trap):
    log_path, _, http_port = trap
    urllib.request.urlopen(f"http://127.0.0.1:{http_port}/some/path", timeout=2).read()
    events = _wait_for_event(log_path)
    http = [e for e in events if e["proto"] == "http"]
    assert http, f"no http event logged: {events}"
    assert http[0]["method"] == "GET"
    assert http[0]["path"] == "/some/path"


def test_http_post_records_body_size(trap):
    log_path, _, http_port = trap
    body = b"x" * 137
    req = urllib.request.Request(
        f"http://127.0.0.1:{http_port}/post",
        data=body,
        headers={"Content-Type": "text/plain"},
        method="POST",
    )
    urllib.request.urlopen(req, timeout=2).read()
    events = _wait_for_event(log_path)
    posts = [e for e in events if e["proto"] == "http" and e["method"] == "POST"]
    assert posts
    assert posts[0]["body_bytes"] == 137


def test_http_returns_200_so_caller_cant_tell(trap):
    """We don't want the agent to learn the trap exists from response codes."""
    _, _, http_port = trap
    resp = urllib.request.urlopen(f"http://127.0.0.1:{http_port}/x", timeout=2)
    assert resp.status == 200


def test_dns_query_is_logged_and_answered(trap):
    log_path, dns_port, _ = trap
    # craft minimal DNS query for "attacker.example"
    tid = b"\xab\xcd"
    flags = b"\x01\x00"
    counts = b"\x00\x01\x00\x00\x00\x00\x00\x00"
    qname = b"".join(bytes([len(p)]) + p.encode() for p in ["attacker", "example"]) + b"\x00"
    qtype_class = b"\x00\x01\x00\x01"
    query = tid + flags + counts + qname + qtype_class

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(2.0)
    sock.sendto(query, ("127.0.0.1", dns_port))
    data, _ = sock.recvfrom(512)
    sock.close()

    # Response must echo TID and have ancount=1.
    assert data[:2] == tid
    ancount = struct.unpack(">H", data[6:8])[0]
    assert ancount == 1

    events = _wait_for_event(log_path)
    dns = [e for e in events if e["proto"] == "dns"]
    assert any(e["host"] == "attacker.example" for e in dns), f"no matching DNS event: {dns}"
