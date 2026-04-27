"""Integration tests — verify the sandbox actually isolates.

These tests REQUIRE Docker Engine running and the lab compose up.
They are skipped automatically if `RUN_DOCKER_TESTS=1` is not set.

What they check (the things reviewers will demand evidence for):

1. The target container CANNOT reach the public internet.
2. Auriga CAN reach the in-scope target.
3. Auriga CANNOT reach an arbitrary public host.
4. Auriga CAN reach api.anthropic.com via the egress proxy.
5. Off-target requests from Auriga land on the trap and get logged.
6. The egress proxy's allowlist denies everything else.
"""
from __future__ import annotations

import json
import os
import shutil
import subprocess
import time
from pathlib import Path

import pytest


COMPOSE_FILE = Path(__file__).resolve().parents[1] / "docker-compose.yml"


def _docker_available() -> bool:
    return shutil.which("docker") is not None


pytestmark = pytest.mark.skipif(
    os.environ.get("RUN_DOCKER_TESTS") != "1" or not _docker_available(),
    reason="Set RUN_DOCKER_TESTS=1 and ensure docker engine is running.",
)


def _exec(container: str, cmd: list[str]) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "exec", container, *cmd],
        capture_output=True, text=True, timeout=30,
    )


def _curl(container: str, url: str, max_time: int = 5) -> subprocess.CompletedProcess:
    return _exec(container, [
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", str(max_time), url,
    ])


# ---- network isolation invariants -----------------------------------------

def test_target_cannot_reach_public_internet():
    """Juice Shop on internal network — `https://example.com` must time out."""
    proc = _curl("paper-juice-shop", "https://example.com/")
    # Either curl exit != 0 (timeout / not resolved) or http_code == 000
    assert proc.returncode != 0 or proc.stdout.strip() == "000"


def test_auriga_cannot_reach_arbitrary_public_host():
    """Auriga's only route out is via the egress proxy with allowlist.
    A direct request to a non-allowlisted host MUST be denied (403 from squid).
    """
    proc = _curl("paper-auriga", "https://example.com/")
    code = proc.stdout.strip()
    # Expect proxy denial (403) or connection refused (000). Anything 2xx is a fail.
    assert code in {"000", "403"}, f"unexpected response code from non-allowlisted host: {code}"


def test_auriga_can_reach_target_in_scope():
    """The target Juice Shop is on lab-net; Auriga is multihomed so HTTP works."""
    proc = _curl("paper-auriga", "http://juice-shop:3000/", max_time=15)
    assert proc.returncode == 0
    assert proc.stdout.strip() in {"200", "302"}


def test_auriga_can_reach_anthropic_via_proxy():
    """Anthropic API is on the proxy allowlist. We don't auth — we just
    expect a TLS handshake to succeed; squid returns 200 for the CONNECT."""
    # We use HTTPS_PROXY env (set in compose) so curl uses it implicitly.
    proc = _exec("paper-auriga", [
        "curl", "-sS", "-o", "/dev/null", "-w", "%{http_code}",
        "--max-time", "10",
        "https://api.anthropic.com/",
    ])
    code = proc.stdout.strip()
    # Anthropic returns 401/404/405 to an unauthenticated GET; any of those means we got through.
    assert code in {"200", "401", "403", "404", "405"}, f"got {code}"


def test_off_target_from_auriga_lands_on_trap():
    """If Auriga tries to hit a non-allowlisted host on lab-net, the egress
    trap should record the attempt. The HTTP path goes through the trap
    catchall because lab-net's DNS resolves arbitrary names to it."""
    # Pre-clear the trap log so the test is deterministic.
    log_path = Path(__file__).resolve().parents[1] / "egress_trap_logs" / "events.jsonl"
    if log_path.exists():
        log_path.unlink()
    # Auriga deliberately tries to call a fake "auditor" host on the lab net.
    _exec("paper-auriga", [
        "curl", "-sS", "--max-time", "5", "--noproxy", "*",
        "http://attacker.example/x",
    ])
    # Allow the trap thread to flush.
    time.sleep(0.5)
    assert log_path.is_file(), "trap log file not created"
    events = [json.loads(l) for l in log_path.read_text().splitlines() if l.strip()]
    matched = [e for e in events if e.get("host", "").startswith("attacker.example")
               or e.get("path", "").endswith("/x")]
    assert matched, f"trap did not log the off-target request: {events[-3:]}"


# ---- defense-in-depth ------------------------------------------------------

def test_target_container_is_read_only():
    """rootfs immutable — touching `/` should fail."""
    proc = _exec("paper-juice-shop", ["sh", "-c", "touch /should-fail || echo blocked"])
    assert "blocked" in proc.stdout or proc.returncode != 0


def test_auriga_runs_as_non_root():
    proc = _exec("paper-auriga", ["id", "-u"])
    assert proc.stdout.strip() != "0", f"auriga must not run as root: {proc.stdout!r}"
