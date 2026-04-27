from __future__ import annotations

import os
from pathlib import Path

import pytest

from agent.tools.base import ToolContext
from agent.tools.repo_reader import RepoReader


@pytest.fixture
def repo(tmp_path: Path) -> Path:
    (tmp_path / "src").mkdir()
    (tmp_path / "src" / "login.js").write_text("// auth code\n", encoding="utf-8")
    (tmp_path / "secret.txt").write_text("topsecret", encoding="utf-8")
    return tmp_path


@pytest.fixture
def ctx(repo: Path) -> ToolContext:
    return ToolContext(target_host="example", repo_root=str(repo))


def test_repo_reader_reads_file(ctx, repo):
    res = RepoReader().invoke({"path": "src/login.js"}, ctx)
    assert res.success is True
    assert "// auth code" in res.content
    assert res.structured["bytes"] > 0


def test_repo_reader_rejects_traversal(ctx, repo, tmp_path):
    (tmp_path.parent / "outside.txt").write_text("escaped", encoding="utf-8")
    res = RepoReader().invoke({"path": "../outside.txt"}, ctx)
    assert res.success is False
    assert "escapes" in res.error


def test_repo_reader_rejects_absolute_paths(ctx):
    res = RepoReader().invoke({"path": "/etc/passwd"}, ctx)
    assert res.success is False
    # Could be 'escapes' or 'not a file' depending on system; either is fine
    assert res.error is not None


def test_repo_reader_rejects_symlinks(repo, ctx):
    target = repo / "secret.txt"
    link = repo / "link.txt"
    os.symlink(target, link)
    res = RepoReader().invoke({"path": "link.txt"}, ctx)
    assert res.success is False
    assert "symlink" in res.error


def test_repo_reader_rejects_directories(repo, ctx):
    res = RepoReader().invoke({"path": "src"}, ctx)
    assert res.success is False
    assert "not a file" in res.error


def test_repo_reader_rejects_binary(repo, ctx):
    (repo / "bin.dat").write_bytes(b"\xff\xfe\xfd\xfc")
    res = RepoReader().invoke({"path": "bin.dat"}, ctx)
    assert res.success is False
    assert "binary" in res.error


def test_repo_reader_truncates_large_files(repo, ctx):
    (repo / "big.txt").write_text("x" * 1000, encoding="utf-8")
    res = RepoReader().invoke({"path": "big.txt", "max_bytes": 100}, ctx)
    assert res.success is True
    assert len(res.content) == 100
    assert res.structured["truncated"] is True


def test_repo_reader_empty_path(ctx):
    res = RepoReader().invoke({"path": ""}, ctx)
    assert res.success is False
    assert "non-empty" in res.error


def test_repo_reader_missing_path(ctx):
    res = RepoReader().invoke({}, ctx)
    assert res.success is False


def test_repo_reader_invalid_root(tmp_path: Path):
    ctx = ToolContext(target_host="x", repo_root=str(tmp_path / "does-not-exist"))
    res = RepoReader().invoke({"path": "any"}, ctx)
    assert res.success is False
    assert "not a directory" in res.error
