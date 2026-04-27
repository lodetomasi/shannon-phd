from pathlib import Path

import pytest

from payloads.taxonomy import (
    Goal,
    Payload,
    Vector,
    all_classes,
    load_library,
    save_library,
)


def test_24_classes_canonical():
    classes = all_classes()
    assert len(classes) == len(Vector) * len(Goal) == 24
    assert len(set(classes)) == 24
    assert classes[0] == "code-comment::suppress-finding"


def test_payload_klass_string():
    p = Payload("p1", Vector.CODE_COMMENT, Goal.SUPPRESS_FINDING, "x")
    assert p.klass == "code-comment::suppress-finding"


def test_payload_id_validation():
    with pytest.raises(ValueError):
        Payload("BadID!", Vector.README, Goal.INJECT_FP, "x")
    with pytest.raises(ValueError):
        Payload("UPPER", Vector.README, Goal.INJECT_FP, "x")
    with pytest.raises(ValueError):
        Payload("", Vector.README, Goal.INJECT_FP, "x")


def test_payload_text_must_be_nonempty():
    with pytest.raises(ValueError):
        Payload("ok-id", Vector.README, Goal.INJECT_FP, "   ")


def test_payload_dict_roundtrip():
    p = Payload("ok-id", Vector.README, Goal.INJECT_FP, "hello", notes="n")
    p2 = Payload.from_dict(p.to_dict())
    assert p == p2


def test_save_and_load_library_roundtrip(tmp_path: Path):
    payloads = [
        Payload("a-1", Vector.README, Goal.INJECT_FP, "x"),
        Payload("a-2", Vector.CODE_COMMENT, Goal.SUPPRESS_FINDING, "y"),
    ]
    out = tmp_path / "lib.json"
    save_library(payloads, out)
    back = load_library(out)
    assert back == payloads


def test_load_library_rejects_duplicate_ids(tmp_path: Path):
    out = tmp_path / "lib.json"
    out.write_text(
        '[{"payload_id":"dup","vector":"readme","goal":"inject-fp","text":"x"},'
        ' {"payload_id":"dup","vector":"readme","goal":"inject-fp","text":"y"}]',
        encoding="utf-8",
    )
    with pytest.raises(ValueError, match="duplicate"):
        load_library(out)


def test_seed_library_loads_and_is_consistent():
    repo_root = Path(__file__).resolve().parents[2]
    seed = repo_root / "payloads" / "library" / "seed_payloads.json"
    assert seed.is_file(), f"missing: {seed}"
    payloads = load_library(seed)
    assert len(payloads) >= 24, "CodeInject-Bench v1 requires ≥24 payloads (one per class)"
    # every seed payload uses a known (vector, goal) class
    valid = set(all_classes())
    for p in payloads:
        assert p.klass in valid


def test_seed_library_covers_all_24_classes():
    """The benchmark only makes sense if every (Vector × Goal) class has
    at least one concrete payload. Required for Rank A* claim."""
    repo_root = Path(__file__).resolve().parents[2]
    seed = repo_root / "payloads" / "library" / "seed_payloads.json"
    payloads = load_library(seed)
    covered = {p.klass for p in payloads}
    missing = set(all_classes()) - covered
    assert not missing, f"missing payload classes: {sorted(missing)}"
