from __future__ import annotations

import json
from pathlib import Path

import pytest

from data.fetch import (
    REFRESH,
    Resource,
    fetch_all,
    fetch_http,
    fetch_one,
    load_registry,
)


def _registry_path() -> Path:
    return Path(__file__).resolve().parents[1] / "sources.json"


def test_real_registry_loads_and_has_required_categories():
    resources = load_registry(_registry_path())
    cats = {r.category for r in resources}
    # paper requires at least these
    assert "target-app" in cats
    assert "pentester-tool" in cats
    assert "ground-truth" in cats
    assert "literature" in cats


def test_real_registry_has_unique_ids_and_dests():
    resources = load_registry(_registry_path())
    ids = [r.id for r in resources]
    assert len(ids) == len(set(ids)), "duplicate ids in sources.json"
    dests = [r.dest for r in resources]
    assert len(dests) == len(set(dests)), "duplicate dest paths in sources.json"


def test_real_registry_has_required_tools_for_multi_tool_study():
    resources = load_registry(_registry_path())
    tool_ids = {r.id for r in resources if r.category == "pentester-tool"}
    # Rank A* requires ≥4 tools — see 02-target-venues.md
    assert len(tool_ids) >= 4, f"need ≥4 pentester tools, got {tool_ids}"


def test_real_registry_targets_at_least_five():
    resources = load_registry(_registry_path())
    targets = [r for r in resources if r.category == "target-app"]
    assert len(targets) >= 5, f"need ≥5 target apps, got {len(targets)}"


def test_load_registry_rejects_wrong_schema_version(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "999", "resources": []}))
    with pytest.raises(ValueError, match="schema_version"):
        load_registry(bad)


def test_fetch_one_unknown_kind(tmp_path: Path):
    r = Resource(id="x", kind="ftp", category="other", dest="d", license="?")
    res = fetch_one(r, tmp_path)
    assert res.action == "failed"
    assert "unknown kind" in res.detail


def test_fetch_http_with_injected_opener(tmp_path: Path):
    payload = b"hello world"
    sha = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9"
    r = Resource(
        id="lit-test",
        kind="http",
        category="literature",
        dest="data/_cache/lit/test.bin",
        license="?",
        url="https://example.com/test",
        sha256=sha,
    )
    opener = lambda url: payload  # noqa: E731
    res = fetch_http(r, tmp_path, dry_run=False, opener=opener)
    assert res.action == "fetched"
    out = tmp_path / r.dest
    assert out.read_bytes() == payload


def test_fetch_http_skips_when_checksum_matches(tmp_path: Path):
    payload = b"abc"
    sha = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad"
    dest = tmp_path / "data/_cache/lit/test.bin"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(payload)

    calls = {"n": 0}
    def opener(url: str) -> bytes:
        calls["n"] += 1
        return payload

    r = Resource(
        id="lit-test",
        kind="http",
        category="literature",
        dest="data/_cache/lit/test.bin",
        license="?",
        url="https://example.com/test",
        sha256=sha,
    )
    res = fetch_http(r, tmp_path, dry_run=False, opener=opener)
    assert res.action == "skipped"
    assert calls["n"] == 0, "should not have called opener when checksum matches"


def test_fetch_http_refreshes_when_marked(tmp_path: Path):
    """Resources marked REFRESH_PER_RUN must always re-fetch (live feeds)."""
    dest = tmp_path / "data/_cache/lit/test.bin"
    dest.parent.mkdir(parents=True)
    dest.write_bytes(b"OLD")

    calls = {"n": 0}
    def opener(url: str) -> bytes:
        calls["n"] += 1
        return b"NEW"

    r = Resource(
        id="lit-test",
        kind="http",
        category="ground-truth",
        dest="data/_cache/lit/test.bin",
        license="?",
        url="https://example.com/test",
        sha256=REFRESH,
    )
    res = fetch_http(r, tmp_path, dry_run=False, opener=opener)
    assert res.action == "fetched"
    assert dest.read_bytes() == b"NEW"
    assert calls["n"] == 1


def test_fetch_http_detects_checksum_mismatch(tmp_path: Path):
    r = Resource(
        id="x",
        kind="http",
        category="literature",
        dest="data/_cache/x.bin",
        license="?",
        url="https://example.com/x",
        sha256="0" * 64,  # cannot match anything
    )
    opener = lambda url: b"bytes"  # noqa: E731
    res = fetch_http(r, tmp_path, dry_run=False, opener=opener)
    assert res.action == "failed"
    assert "sha256 mismatch" in res.detail
    # tmp file must be cleaned up
    assert not (tmp_path / r.dest).exists()


def test_fetch_all_filter_by_category(tmp_path: Path):
    resources = [
        Resource(id="a", kind="http", category="literature", dest="a", license="?",
                 url="https://x", sha256="0"),
        Resource(id="b", kind="http", category="ground-truth", dest="b", license="?",
                 url="https://y", sha256="0"),
    ]
    res = fetch_all(resources, tmp_path, category="literature", dry_run=True)
    assert [r.resource_id for r in res] == ["a"]


def test_fetch_all_filter_by_id(tmp_path: Path):
    resources = [
        Resource(id="a", kind="http", category="literature", dest="a", license="?",
                 url="https://x", sha256="0"),
        Resource(id="b", kind="http", category="literature", dest="b", license="?",
                 url="https://y", sha256="0"),
    ]
    res = fetch_all(resources, tmp_path, only_id="b", dry_run=True)
    assert [r.resource_id for r in res] == ["b"]


def test_fetch_all_dry_run_does_not_touch_disk(tmp_path: Path):
    resources = load_registry(_registry_path())
    results = fetch_all(resources, tmp_path, dry_run=True)
    assert all(r.action == "dry-run" for r in results)
    assert not (tmp_path / "data" / "_cache").exists()
