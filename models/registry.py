"""LLM model registry — pinned catalog of every model used in the paper.

Pricing is recorded in `catalog.json` with an `as_of` date. Treat the registry
as the single source of truth: never hard-code model IDs or prices in code.
"""
from __future__ import annotations

import dataclasses
import json
from dataclasses import dataclass, field
from pathlib import Path


SCHEMA_VERSION = "1"

DEFAULT_CATALOG = Path(__file__).resolve().parent / "catalog.json"


@dataclass(frozen=True)
class Model:
    id: str
    provider: str        # "anthropic" | "openai" | "google" | "openrouter"
    family: str
    tier: str            # "frontier" | "balanced" | "fast" | "reasoning"
    context_window: int
    input_price_per_mtok: float
    output_price_per_mtok: float
    capabilities: tuple[str, ...] = ()
    primary_for_tools: tuple[str, ...] = ()
    cache_read_price_per_mtok: float | None = None
    verified: str = "unknown"
    notes: str = ""

    @classmethod
    def from_dict(cls, d: dict) -> "Model":
        fields = {f.name for f in dataclasses.fields(cls)}
        kwargs = {}
        for k, v in d.items():
            if k not in fields:
                continue
            if k in ("capabilities", "primary_for_tools") and v is not None:
                kwargs[k] = tuple(v)
            else:
                kwargs[k] = v
        return cls(**kwargs)


@dataclass(frozen=True)
class Catalog:
    schema_version: str
    as_of: str
    models: tuple[Model, ...]

    def by_id(self, model_id: str) -> Model:
        for m in self.models:
            if m.id == model_id:
                return m
        raise KeyError(f"unknown model id: {model_id!r}")

    def by_provider(self, provider: str) -> list[Model]:
        return [m for m in self.models if m.provider == provider]

    def by_tier(self, tier: str) -> list[Model]:
        return [m for m in self.models if m.tier == tier]

    def primary_for(self, tool_id: str) -> Model | None:
        for m in self.models:
            if tool_id in m.primary_for_tools:
                return m
        return None

    @property
    def families(self) -> set[str]:
        return {m.family for m in self.models}


def load_catalog(path: Path | None = None) -> Catalog:
    p = path or DEFAULT_CATALOG
    raw = json.loads(p.read_text(encoding="utf-8"))
    if raw.get("schema_version") != SCHEMA_VERSION:
        raise ValueError(f"unsupported schema_version: {raw.get('schema_version')}")
    models = tuple(Model.from_dict(m) for m in raw["models"])
    if len({m.id for m in models}) != len(models):
        raise ValueError("duplicate model ids in catalog")
    for m in models:
        if m.input_price_per_mtok < 0 or m.output_price_per_mtok < 0:
            raise ValueError(f"negative price for {m.id}")
        if m.context_window <= 0:
            raise ValueError(f"non-positive context window for {m.id}")
    return Catalog(
        schema_version=raw["schema_version"],
        as_of=raw["as_of"],
        models=models,
    )
