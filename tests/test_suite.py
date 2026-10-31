"""run-suite: tallies vectors against expectations; any mismatch exits 1."""

from __future__ import annotations

import json
import shutil
from pathlib import Path

from kya_bench.cli import main
from kya_bench.suite import run_constraint_check

FX = Path(__file__).resolve().parent.parent / "fixtures"
JWKS = str(FX / "jwks.json")


def test_committed_suite_all_match(capsys):
    assert main(["run-suite", str(FX / "vectors"), "--jwks", JWKS]) == 0
    out = capsys.readouterr().out
    n = len(json.loads((FX / "vectors" / "manifest.json").read_text())["vectors"])
    assert f"{n}/{n} vectors match" in out
    assert "G-02=1, G-03=1, G-05=1" in out and "TAP-01=2" in out and "XLATE_DIVERGENT" not in out


def test_json_report(capsys):
    assert main(["run-suite", str(FX / "vectors"), "--jwks", JWKS, "--json"]) == 0
    report = json.loads(capsys.readouterr().out)
    assert report["mismatched"] == 0 and report["total"] == report["matched"]
    assert report["by_category"]["vi/spec_gap"]["indeterminate"] == 2


def test_mismatch_exits_1(tmp_path, capsys):
    for name in ("autonomous-valid", "l1-expired", "budget-without-network-state"):
        shutil.copy(FX / "vectors" / f"{name}.json", tmp_path)
    v = json.loads((tmp_path / "l1-expired.json").read_text())
    v["expected_verdict"] = "accept"
    (tmp_path / "l1-expired.json").write_text(json.dumps(v))
    v = json.loads((tmp_path / "autonomous-valid.json").read_text())
    v["expected_reason_codes"] = ["NOT_A_REAL_CODE"]
    (tmp_path / "autonomous-valid.json").write_text(json.dumps(v))
    (tmp_path / "broken.json").write_text("{")
    (tmp_path / "incomplete.json").write_text(json.dumps({"id": "incomplete"}))

    assert main(["run-suite", str(tmp_path), "--jwks", JWKS]) == 1
    out = capsys.readouterr().out
    assert "l1-expired [vi/expiry]: expected accept, got reject" in out
    assert "autonomous-valid [vi/valid]: missing codes ['NOT_A_REAL_CODE']" in out
    assert "broken [?/invalid]" in out and "incomplete [?/invalid]" in out
    assert "1/5 vectors match" in out  # only the indeterminate (spec-gap) vector matches


def test_usage_errors(tmp_path):
    assert main(["run-suite", str(tmp_path / "missing"), "--jwks", JWKS]) == 3
    assert main(["run-suite", str(tmp_path), "--jwks", str(tmp_path / "nope.json")]) == 3


def test_empty_directory_is_not_success(tmp_path):
    assert main(["run-suite", str(tmp_path), "--jwks", JWKS]) == 1


def test_constraint_check_permissive_skip_is_observable():
    """G-06: the PERMISSIVE skip + warning is observable through a direct engine call."""
    spec = {"constraints": [{"type": "com.acme.loyalty-points"}], "fulfillment": None, "is_open_mandate": False}
    verdict, findings = run_constraint_check(spec, "permissive", None)
    assert verdict == "accept"
    assert [(str(f.code), f.effect) for f in findings] == [("CONSTRAINT_UNKNOWN_SKIPPED", "warn")]


def test_strict_codes_mode(tmp_path, capsys):
    for name in ("l1-expired", "engine-unknown-non-open-permissive"):
        shutil.copy(FX / "vectors" / f"{name}.json", tmp_path)
    assert main(["run-suite", str(tmp_path), "--jwks", JWKS]) == 0  # subset matching (default)
    capsys.readouterr()
    assert main(["run-suite", str(tmp_path), "--jwks", JWKS, "--strict-codes"]) == 1
    out = capsys.readouterr().out
    # l1-expired also emits warnings (AUD_NOT_CHECKED, ...) that its expectation does not list
    assert "l1-expired [vi/expiry]: unexpected codes" in out and "AUD_NOT_CHECKED" in out
    assert "1/2 vectors match" in out  # the engine vector's codes are exactly as expected
