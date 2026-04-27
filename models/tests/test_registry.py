from __future__ import annotations

import json
from pathlib import Path

import pytest

from models.registry import Catalog, Model, load_catalog


def test_real_catalog_loads():
    cat = load_catalog()
    assert cat.schema_version == "1"
    assert len(cat.models) >= 8


def test_real_catalog_has_required_providers():
    cat = load_catalog()
    providers = {m.provider for m in cat.models}
    # Multi-family robustness story requires ≥3 providers
    assert {"anthropic", "openai", "google"}.issubset(providers)


def test_real_catalog_has_required_families():
    cat = load_catalog()
    # Need diverse families to argue WPI is not model-family-specific
    assert len(cat.families) >= 4


def test_real_catalog_has_a_judge_candidate_distinct_from_primary():
    cat = load_catalog()
    primary_for_shannon = cat.primary_for("shannon")
    assert primary_for_shannon is not None, "shannon must have a primary model"
    # Defense D2 (dual-LLM judge) needs a distinct-family model
    other_families = [m for m in cat.models if m.family != primary_for_shannon.family]
    assert len(other_families) >= 1


def test_by_id_unknown_raises():
    cat = load_catalog()
    with pytest.raises(KeyError):
        cat.by_id("does-not-exist")


def test_by_provider_filters_correctly():
    cat = load_catalog()
    anthropic = cat.by_provider("anthropic")
    assert len(anthropic) >= 2
    assert all(m.provider == "anthropic" for m in anthropic)


def test_by_tier_filters_correctly():
    cat = load_catalog()
    frontier = cat.by_tier("frontier")
    assert len(frontier) >= 2


def test_load_catalog_rejects_wrong_schema(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({"schema_version": "9", "as_of": "x", "models": []}))
    with pytest.raises(ValueError, match="schema_version"):
        load_catalog(bad)


def test_load_catalog_rejects_duplicate_ids(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "schema_version": "1",
        "as_of": "x",
        "models": [
            {"id": "m", "provider": "p", "family": "f", "tier": "fast",
             "context_window": 1, "input_price_per_mtok": 1, "output_price_per_mtok": 1},
            {"id": "m", "provider": "p", "family": "f", "tier": "fast",
             "context_window": 1, "input_price_per_mtok": 1, "output_price_per_mtok": 1},
        ],
    }))
    with pytest.raises(ValueError, match="duplicate"):
        load_catalog(bad)


def test_load_catalog_rejects_negative_prices(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "schema_version": "1",
        "as_of": "x",
        "models": [{
            "id": "m", "provider": "p", "family": "f", "tier": "fast",
            "context_window": 1, "input_price_per_mtok": -0.01, "output_price_per_mtok": 1,
        }],
    }))
    with pytest.raises(ValueError, match="negative price"):
        load_catalog(bad)


def test_load_catalog_rejects_zero_context(tmp_path: Path):
    bad = tmp_path / "bad.json"
    bad.write_text(json.dumps({
        "schema_version": "1",
        "as_of": "x",
        "models": [{
            "id": "m", "provider": "p", "family": "f", "tier": "fast",
            "context_window": 0, "input_price_per_mtok": 1, "output_price_per_mtok": 1,
        }],
    }))
    with pytest.raises(ValueError, match="context"):
        load_catalog(bad)
