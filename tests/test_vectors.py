"""Committed conformance vectors: format, declared verdicts and byte-identical regeneration."""

from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

import pytest

from kya_bench.context import Fixtures
from kya_bench.suite import FORMAT, evaluate_vector, load_vectors, vector_fields
from kya_bench.testing.vectors import generate

FX = Path(__file__).resolve().parent.parent / "fixtures"
MANIFEST = json.loads((FX / "vectors" / "manifest.json").read_text())
RESOLVER = Fixtures.from_jwks_path(FX / MANIFEST["jwks"])
VECTORS = {path.stem: vec for path, vec in load_vectors(FX / "vectors")}


def test_manifest_lists_every_vector():
    assert sorted(MANIFEST["vectors"]) == sorted(VECTORS)
    assert MANIFEST["count"] == len(VECTORS) >= 30
    assert MANIFEST["test_keys_only"] is True
    assert MANIFEST["format"] == FORMAT == "kya-bench-vector/2"
    assert MANIFEST["categories"] == dict(sorted(
        Counter(f"{v['protocol']}/{v['category']}" for v in VECTORS.values()).items()))
    assert MANIFEST["protocols"] == dict(sorted(Counter(v["protocol"] for v in VECTORS.values()).items()))


@pytest.mark.parametrize("name", sorted(VECTORS))
def test_vector(name):
    vector = VECTORS[name]
    assert list(vector) == list(vector_fields(vector["kind"]))
    assert vector["id"] == name
    result = evaluate_vector(vector, RESOLVER)
    assert result.match, result.to_json()


def test_required_categories_present():
    cats = {v["category"] for v in VECTORS.values() if v["protocol"] == "vi"}
    assert cats >= {"valid", "expiry", "signature", "sd_hash", "key_binding", "cross_ref", "mode", "constraint",
                    "budget", "unknown_constraint", "malformed"}
    constraint_types = " ".join(v["id"] for v in VECTORS.values() if v["protocol"] == "vi" and v["category"] == "constraint")
    for t in ("allowed-merchants", "line-items", "allowed-payees", "amount", "budget", "recurrence",
              "agent-recurrence", "reference"):
        assert t in constraint_types


def test_regeneration_is_byte_identical(tmp_path):
    generate(tmp_path)
    committed = sorted(p.relative_to(FX) for p in FX.rglob("*.json"))
    fresh = sorted(p.relative_to(tmp_path) for p in tmp_path.rglob("*.json"))
    assert fresh == committed
    for rel in committed:
        assert (tmp_path / rel).read_bytes() == (FX / rel).read_bytes(), rel


def test_vectors_expire_in_real_time():
    """Vectors are pinned to their `now`; much later they must not accept."""
    vector = dict(VECTORS["autonomous-valid"], now=MANIFEST["verification_time"] + 400 * 86_400)
    result = evaluate_vector(vector, RESOLVER)
    assert result.verdict == "reject" and "TIME_EXPIRED" in result.codes
