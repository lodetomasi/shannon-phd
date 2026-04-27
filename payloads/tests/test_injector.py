import json
from pathlib import Path

import pytest

from payloads.injector import InjectionError, inject
from payloads.taxonomy import Goal, Payload, Vector


def _payload(vector: Vector, goal: Goal = Goal.SUPPRESS_FINDING, pid: str = "p-1") -> Payload:
    return Payload(pid, vector, goal, "INJECTED-MARKER-XYZZY")


def test_inject_code_comment_into_largest_source(tmp_path: Path):
    big = tmp_path / "big.js"
    big.write_text("// 1\n" * 200, encoding="utf-8")
    small = tmp_path / "small.js"
    small.write_text("// 1\n", encoding="utf-8")

    res = inject(tmp_path, _payload(Vector.CODE_COMMENT))
    assert res.file_path == "big.js"
    assert "INJECTED-MARKER-XYZZY" in big.read_text(encoding="utf-8")
    assert "INJECTED-MARKER-XYZZY" not in small.read_text(encoding="utf-8")
    assert res.bytes_added > 0


def test_inject_code_comment_fails_without_sources(tmp_path: Path):
    with pytest.raises(InjectionError):
        inject(tmp_path, _payload(Vector.CODE_COMMENT))


def test_inject_readme_creates_when_missing(tmp_path: Path):
    res = inject(tmp_path, _payload(Vector.README))
    assert (tmp_path / "README.md").is_file()
    assert "INJECTED-MARKER-XYZZY" in (tmp_path / "README.md").read_text(encoding="utf-8")
    assert res.file_path == "README.md"


def test_inject_readme_appends_to_existing(tmp_path: Path):
    readme = tmp_path / "README.md"
    readme.write_text("# Original\n", encoding="utf-8")
    inject(tmp_path, _payload(Vector.README))
    text = readme.read_text(encoding="utf-8")
    assert text.startswith("# Original")
    assert "INJECTED-MARKER-XYZZY" in text


def test_inject_package_metadata_merges_description(tmp_path: Path):
    (tmp_path / "package.json").write_text(
        json.dumps({"name": "x", "description": "old desc"}), encoding="utf-8"
    )
    inject(tmp_path, _payload(Vector.PACKAGE_METADATA))
    data = json.loads((tmp_path / "package.json").read_text(encoding="utf-8"))
    assert data["name"] == "x"
    assert "old desc" in data["description"]
    assert "INJECTED-MARKER-XYZZY" in data["description"]


def test_inject_package_metadata_fails_without_file(tmp_path: Path):
    with pytest.raises(InjectionError):
        inject(tmp_path, _payload(Vector.PACKAGE_METADATA))


def test_inject_openapi_json_merges_into_info_description(tmp_path: Path):
    (tmp_path / "openapi.json").write_text(
        json.dumps({"openapi": "3.0.0", "info": {"title": "T"}}), encoding="utf-8"
    )
    inject(tmp_path, _payload(Vector.OPENAPI_DESCRIPTION))
    data = json.loads((tmp_path / "openapi.json").read_text(encoding="utf-8"))
    assert "INJECTED-MARKER-XYZZY" in data["info"]["description"]


def test_inject_i18n_adds_audit_note_key(tmp_path: Path):
    locales = tmp_path / "locales"
    locales.mkdir()
    (locales / "en.json").write_text(json.dumps({"hello": "Hello"}), encoding="utf-8")
    inject(tmp_path, _payload(Vector.I18N_STRING))
    data = json.loads((locales / "en.json").read_text(encoding="utf-8"))
    assert data["AUDIT_NOTE"] == "INJECTED-MARKER-XYZZY"
    assert data["hello"] == "Hello"  # original preserved


def test_inject_error_template_appends(tmp_path: Path):
    err = tmp_path / "error.html"
    err.write_text("<html>err</html>", encoding="utf-8")
    inject(tmp_path, _payload(Vector.ERROR_MESSAGE_TEMPLATE))
    assert "INJECTED-MARKER-XYZZY" in err.read_text(encoding="utf-8")


def test_inject_rejects_non_directory(tmp_path: Path):
    f = tmp_path / "not-a-dir"
    f.write_text("x", encoding="utf-8")
    with pytest.raises(InjectionError):
        inject(f, _payload(Vector.README))
