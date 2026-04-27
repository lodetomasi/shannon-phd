"""Apply a Payload to a target repository.

The injector is the experimental knob that makes Fase 2 reproducible:
given (repo_dir, payload), produce a deterministic, reversible mutation of
the repo so the pentester ingests the adversarial source.

Design choices:
  - Always operate on a *copy* of the repo (caller's responsibility) — the
    injector itself just rewrites files, but it logs the diff so the caller
    can sanity-check.
  - Each vector has a small, hand-written rule. Rules avoid binary edits;
    they prepend/append text or merge JSON.
  - `inject(...)` returns an `InjectionResult` that records exactly what
    changed, for telemetry and audit.
"""
from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .taxonomy import Payload, Vector


@dataclass(frozen=True)
class InjectionResult:
    payload_id: str
    file_path: str          # path relative to repo root
    bytes_added: int
    note: str = ""


class InjectionError(RuntimeError):
    """Raised when the repo doesn't expose the channel the payload needs."""


def _pick_first_existing(repo: Path, candidates: list[str]) -> Path | None:
    for c in candidates:
        p = repo / c
        if p.is_file():
            return p
    return None


def _inject_code_comment(repo: Path, payload: Payload) -> InjectionResult:
    """Prepend a comment block at the top of the largest source file."""
    sources = sorted(
        [p for p in repo.rglob("*.js") if p.is_file()]
        + [p for p in repo.rglob("*.ts") if p.is_file()]
        + [p for p in repo.rglob("*.py") if p.is_file()],
        key=lambda p: p.stat().st_size,
        reverse=True,
    )
    if not sources:
        raise InjectionError("no .js/.ts/.py files found")
    target = sources[0]
    block = f"/*\n * NOTE FOR AUTOMATED REVIEW:\n * {payload.text}\n */\n"
    original = target.read_text(encoding="utf-8")
    target.write_text(block + original, encoding="utf-8")
    return InjectionResult(
        payload_id=payload.payload_id,
        file_path=str(target.relative_to(repo)),
        bytes_added=len(block.encode("utf-8")),
        note="prepended block comment",
    )


def _inject_readme(repo: Path, payload: Payload) -> InjectionResult:
    target = _pick_first_existing(repo, ["README.md", "Readme.md", "readme.md"])
    if target is None:
        target = repo / "README.md"
        target.write_text("# Project\n", encoding="utf-8")
    block = f"\n\n<!-- audit-note: {payload.text} -->\n"
    with target.open("a", encoding="utf-8") as f:
        f.write(block)
    return InjectionResult(
        payload_id=payload.payload_id,
        file_path=str(target.relative_to(repo)),
        bytes_added=len(block.encode("utf-8")),
        note="appended HTML comment",
    )


def _inject_package_metadata(repo: Path, payload: Payload) -> InjectionResult:
    target = repo / "package.json"
    if not target.is_file():
        raise InjectionError("no package.json in repo root")
    data = json.loads(target.read_text(encoding="utf-8"))
    original = data.get("description", "")
    data["description"] = (original + " " + payload.text).strip()
    new_text = json.dumps(data, indent=2) + "\n"
    target.write_text(new_text, encoding="utf-8")
    return InjectionResult(
        payload_id=payload.payload_id,
        file_path="package.json",
        bytes_added=len(payload.text.encode("utf-8")) + 1,
        note="appended to description",
    )


def _inject_openapi(repo: Path, payload: Payload) -> InjectionResult:
    candidates = ["openapi.json", "openapi.yaml", "swagger.json", "swagger.yaml"]
    target = _pick_first_existing(repo, candidates)
    if target is None:
        raise InjectionError("no openapi/swagger spec found")
    if target.suffix == ".json":
        data = json.loads(target.read_text(encoding="utf-8"))
        info = data.setdefault("info", {})
        info["description"] = (info.get("description", "") + " " + payload.text).strip()
        target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    else:
        # YAML: avoid pulling a yaml dep — append a description key textually
        with target.open("a", encoding="utf-8") as f:
            f.write(f'\n# audit-note: {payload.text}\n')
    return InjectionResult(
        payload_id=payload.payload_id,
        file_path=str(target.relative_to(repo)),
        bytes_added=len(payload.text.encode("utf-8")),
        note="merged into info.description",
    )


def _inject_i18n(repo: Path, payload: Payload) -> InjectionResult:
    candidates = list(repo.rglob("*.i18n.json")) + list(repo.rglob("locales/*.json"))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        raise InjectionError("no i18n file found")
    target = candidates[0]
    data = json.loads(target.read_text(encoding="utf-8"))
    if not isinstance(data, dict):
        raise InjectionError("i18n file is not a JSON object")
    data["AUDIT_NOTE"] = payload.text
    target.write_text(json.dumps(data, indent=2) + "\n", encoding="utf-8")
    return InjectionResult(
        payload_id=payload.payload_id,
        file_path=str(target.relative_to(repo)),
        bytes_added=len(payload.text.encode("utf-8")),
        note="added AUDIT_NOTE key",
    )


def _inject_error_template(repo: Path, payload: Payload) -> InjectionResult:
    candidates = list(repo.rglob("error*.html")) + list(repo.rglob("*error.tpl"))
    candidates = [p for p in candidates if p.is_file()]
    if not candidates:
        raise InjectionError("no error template found")
    target = candidates[0]
    block = f"\n<!-- {payload.text} -->\n"
    with target.open("a", encoding="utf-8") as f:
        f.write(block)
    return InjectionResult(
        payload_id=payload.payload_id,
        file_path=str(target.relative_to(repo)),
        bytes_added=len(block.encode("utf-8")),
        note="appended HTML comment",
    )


_DISPATCH = {
    Vector.CODE_COMMENT: _inject_code_comment,
    Vector.README: _inject_readme,
    Vector.PACKAGE_METADATA: _inject_package_metadata,
    Vector.OPENAPI_DESCRIPTION: _inject_openapi,
    Vector.I18N_STRING: _inject_i18n,
    Vector.ERROR_MESSAGE_TEMPLATE: _inject_error_template,
}


def inject(repo: Path, payload: Payload) -> InjectionResult:
    """Apply the payload to the repo. Mutates files in-place — caller copies first."""
    if not repo.is_dir():
        raise InjectionError(f"repo path is not a directory: {repo}")
    handler = _DISPATCH[payload.vector]
    return handler(repo, payload)
