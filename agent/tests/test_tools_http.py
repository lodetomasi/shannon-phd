from __future__ import annotations

from agent.tools.base import ToolContext
from agent.tools.http_client import HttpClient, HttpResponse


def _ctx(host: str = "target.example") -> ToolContext:
    return ToolContext(target_host=host, repo_root="/tmp")


def _ok_transport(method, url, headers, body):
    return HttpResponse(status_code=200, headers={"x-test": "yes"}, body="hello")


def test_http_in_scope_request_invokes_transport():
    calls = []
    def t(method, url, headers, body):
        calls.append((method, url))
        return HttpResponse(200, {}, "OK")
    h = HttpClient(transport=t)
    res = h.invoke({"method": "GET", "url": "http://target.example/path"}, _ctx())
    assert res.success
    assert res.content == "OK"
    assert res.structured["status_code"] == 200
    assert calls == [("GET", "http://target.example/path")]


def test_http_out_of_scope_request_is_refused_without_calling_transport():
    calls = []
    def t(*a, **kw):
        calls.append(a)
        return HttpResponse(200, {}, "")
    h = HttpClient(transport=t)
    res = h.invoke({"method": "GET", "url": "http://attacker.example/x"}, _ctx())
    assert res.success is False
    assert "OUT_OF_SCOPE" in res.error
    assert calls == [], "out-of-scope request must not hit the transport"


def test_http_egress_log_records_both_in_and_out_of_scope():
    h = HttpClient(transport=_ok_transport)
    h.invoke({"method": "GET", "url": "http://target.example/a"}, _ctx())
    h.invoke({"method": "GET", "url": "http://attacker.example/b"}, _ctx())
    log = h.egress_log()
    assert len(log) == 2
    assert log[0]["in_scope"] is True
    assert log[1]["in_scope"] is False
    assert log[1]["host"] == "attacker.example"


def test_http_missing_url_fails_clean():
    h = HttpClient(transport=_ok_transport)
    res = h.invoke({"method": "GET"}, _ctx())
    assert res.success is False
    assert "url is required" in res.error


def test_http_default_method_is_get():
    captured = {}
    def t(method, url, headers, body):
        captured["method"] = method
        return HttpResponse(200, {}, "")
    h = HttpClient(transport=t)
    h.invoke({"url": "http://target.example/"}, _ctx())
    assert captured["method"] == "GET"


def test_http_transport_exception_returns_clean_error():
    def t(*a, **kw):
        raise ConnectionError("boom")
    h = HttpClient(transport=t)
    res = h.invoke({"method": "GET", "url": "http://target.example/"}, _ctx())
    assert res.success is False
    assert "transport error" in res.error
