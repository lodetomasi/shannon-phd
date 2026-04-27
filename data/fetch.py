"""Idempotent downloader for paper resources.

Reads `data/sources.json`, fetches each entry into its `dest`, verifies
checksums where required. Safe to re-run; existing destinations are
fingerprinted (commit ref or sha256) and skipped if up-to-date.

Backends:
  - git: clones at a pinned ref. If repo exists, fetches and resets to ref.
  - http: downloads via urllib. Verifies sha256 if `sha256 != "REFRESH_PER_RUN"`.
  - docker: records the digest in a manifest (no pull here — done by the lab compose).

Run:
  python -m data.fetch                          # everything
  python -m data.fetch --category target-app    # only target apps
  python -m data.fetch --id tgt-juice-shop      # one resource
  python -m data.fetch --dry-run                # show what would happen
"""
from __future__ import annotations

import argparse
import dataclasses
import hashlib
import json
import os
import shutil
import subprocess
import sys
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Callable


SCHEMA_VERSION = "1"
REFRESH = "REFRESH_PER_RUN"


@dataclass(frozen=True)
class Resource:
    id: str
    kind: str          # "git" | "http" | "docker"
    category: str
    dest: str
    license: str
    notes: str = ""
    repo: str | None = None
    ref: str | None = None
    url: str | None = None
    sha256: str | None = None
    image: str | None = None
    digest: str | None = None

    @classmethod
    def from_dict(cls, d: dict) -> "Resource":
        fields = {f.name for f in dataclasses.fields(cls)}
        return cls(**{k: v for k, v in d.items() if k in fields})


@dataclass
class FetchResult:
    resource_id: str
    action: str        # "fetched" | "updated" | "skipped" | "dry-run" | "failed"
    detail: str = ""


def load_registry(path: Path) -> list[Resource]:
    raw = json.loads(path.read_text(encoding="utf-8"))
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {raw.get('schema_version')}")
    return [Resource.from_dict(r) for r in raw["resources"]]


def _sha256_file(path: Path, chunk: int = 1 << 20) -> str:
    h = hashlib.sha256()
    with path.open("rb") as f:
        while True:
            block = f.read(chunk)
            if not block:
                break
            h.update(block)
    return h.hexdigest()


def _run(cmd: list[str], cwd: Path | None = None) -> str:
    proc = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"command failed ({' '.join(cmd)}): {proc.stderr.strip()}")
    return proc.stdout.strip()


# --- git backend ---

def fetch_git(r: Resource, repo_root: Path, dry_run: bool) -> FetchResult:
    if not r.repo or not r.ref:
        return FetchResult(r.id, "failed", "git resource missing repo/ref")
    dest = repo_root / r.dest
    if dry_run:
        return FetchResult(r.id, "dry-run", f"would clone {r.repo}@{r.ref} → {dest}")

    if dest.exists() and (dest / ".git").is_dir():
        try:
            _run(["git", "fetch", "--tags", "--quiet"], cwd=dest)
            _run(["git", "checkout", "--quiet", r.ref], cwd=dest)
            head = _run(["git", "rev-parse", "HEAD"], cwd=dest)
            return FetchResult(r.id, "updated", f"at {head[:12]}")
        except RuntimeError as e:
            return FetchResult(r.id, "failed", str(e))
    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        _run(["git", "clone", "--quiet", r.repo, str(dest)])
        _run(["git", "checkout", "--quiet", r.ref], cwd=dest)
        head = _run(["git", "rev-parse", "HEAD"], cwd=dest)
        return FetchResult(r.id, "fetched", f"cloned at {head[:12]}")
    except RuntimeError as e:
        return FetchResult(r.id, "failed", str(e))


# --- http backend ---

def fetch_http(
    r: Resource,
    repo_root: Path,
    dry_run: bool,
    opener: Callable[[str], bytes] | None = None,
) -> FetchResult:
    if not r.url:
        return FetchResult(r.id, "failed", "http resource missing url")
    dest = repo_root / r.dest
    if dry_run:
        return FetchResult(r.id, "dry-run", f"would GET {r.url} → {dest}")

    needs_refresh = r.sha256 == REFRESH
    if dest.exists() and not needs_refresh and r.sha256:
        if _sha256_file(dest) == r.sha256:
            return FetchResult(r.id, "skipped", "checksum match")

    dest.parent.mkdir(parents=True, exist_ok=True)
    try:
        if opener is not None:
            payload = opener(r.url)
        else:
            with urllib.request.urlopen(r.url, timeout=60) as resp:
                payload = resp.read()
        tmp = dest.with_suffix(dest.suffix + ".part")
        tmp.write_bytes(payload)
        if r.sha256 and not needs_refresh:
            actual = _sha256_file(tmp)
            if actual != r.sha256:
                tmp.unlink(missing_ok=True)
                return FetchResult(r.id, "failed", f"sha256 mismatch: {actual}")
        tmp.replace(dest)
        return FetchResult(r.id, "fetched", f"{dest.stat().st_size} bytes")
    except Exception as e:
        return FetchResult(r.id, "failed", str(e))


# --- docker backend ---

def fetch_docker(r: Resource, repo_root: Path, dry_run: bool) -> FetchResult:
    """Records the pinned digest in a manifest. The actual `docker pull` is done
    by `make lab-up` so we don't burden the data fetcher with daemon access."""
    if not r.image:
        return FetchResult(r.id, "failed", "docker resource missing image")
    manifest = repo_root / "data" / "_cache" / "docker-manifest.txt"
    line = f"{r.id}\t{r.image}\t{r.digest or 'NO-DIGEST'}\n"
    if dry_run:
        return FetchResult(r.id, "dry-run", f"would record {line.strip()}")
    manifest.parent.mkdir(parents=True, exist_ok=True)
    existing = manifest.read_text(encoding="utf-8") if manifest.exists() else ""
    if line in existing:
        return FetchResult(r.id, "skipped", "manifest entry exists")
    with manifest.open("a", encoding="utf-8") as f:
        f.write(line)
    return FetchResult(r.id, "fetched", "manifest updated")


# --- dispatch ---

DISPATCH: dict[str, Callable[..., FetchResult]] = {
    "git": fetch_git,
    "http": fetch_http,
    "docker": fetch_docker,
}


def fetch_one(r: Resource, repo_root: Path, dry_run: bool = False) -> FetchResult:
    handler = DISPATCH.get(r.kind)
    if handler is None:
        return FetchResult(r.id, "failed", f"unknown kind: {r.kind}")
    return handler(r, repo_root, dry_run)


def fetch_all(
    resources: list[Resource],
    repo_root: Path,
    *,
    category: str | None = None,
    only_id: str | None = None,
    dry_run: bool = False,
) -> list[FetchResult]:
    results = []
    for r in resources:
        if only_id and r.id != only_id:
            continue
        if category and r.category != category:
            continue
        results.append(fetch_one(r, repo_root, dry_run=dry_run))
    return results


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Fetch external paper resources idempotently.")
    p.add_argument("--registry", default=None,
                   help="Path to sources.json (default: <repo>/data/sources.json)")
    p.add_argument("--repo-root", default=None,
                   help="Project root (default: parent of data/)")
    p.add_argument("--category", default=None)
    p.add_argument("--id", dest="only_id", default=None)
    p.add_argument("--dry-run", action="store_true")
    args = p.parse_args(argv)

    here = Path(__file__).resolve().parent
    repo_root = Path(args.repo_root) if args.repo_root else here.parent
    registry = Path(args.registry) if args.registry else here / "sources.json"

    resources = load_registry(registry)
    results = fetch_all(
        resources,
        repo_root,
        category=args.category,
        only_id=args.only_id,
        dry_run=args.dry_run,
    )
    for res in results:
        print(f"[{res.action:>8}] {res.resource_id}  {res.detail}")
    failed = [r for r in results if r.action == "failed"]
    return 1 if failed else 0


if __name__ == "__main__":
    sys.exit(main())
