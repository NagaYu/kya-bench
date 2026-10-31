from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

from kya_bench.cli import main

FX = Path(__file__).resolve().parent.parent / "fixtures"
NOW = str(json.loads((FX / "vectors" / "manifest.json").read_text())["verification_time"])


def cli(capsys, *args):
    code = main(["verify", *args, "--jwks", str(FX / "jwks.json"), "--now", NOW])
    return code, capsys.readouterr()


def vec(name):
    return str(FX / "vectors" / f"{name}.json")


def test_accept_exit_0(capsys):
    code, out = cli(capsys, vec("autonomous-valid"))
    data = json.loads(out.out)
    assert code == 0
    assert data["verdict"] == "accept" and data["strictness"] == "strict"  # strict is the CLI default


def test_reject_exit_1(capsys):
    code, out = cli(capsys, vec("open-mandate-unknown-constraint"), "--strictness", "permissive")
    data = json.loads(out.out)
    assert code == 1
    assert data["strictness"] == "permissive"
    assert [r["code"] for r in data["reasons"]] == ["CONSTRAINT_UNKNOWN_OPEN_MANDATE"]
    rejected = [c for c in data["constraints"] if c["outcome"] == "unknown_rejected"]
    assert rejected[0]["status"] == "violated"
    assert rejected[0]["constraint"] == {"type": "com.acme.loyalty-points", "points": 500}
    assert data["unknown_constraints"] == [
        {"type": "com.acme.loyalty-points", "mandate": "payment", "index": 0, "handling": "rejected_open_mandate"}
    ]
    assert data["reason_codes"] == ["CONSTRAINT_UNKNOWN_OPEN_MANDATE"]
    assert data["evaluated_at"] == int(NOW)


def test_indeterminate_exit_2(capsys):
    code, out = cli(capsys, vec("budget-without-network-state"))
    assert code == 2
    assert json.loads(out.out)["reasons"][0]["gap_id"] == "G-05"


def test_usage_error_exit_3(capsys):
    code, out = cli(capsys, str(FX / "does-not-exist.json"))
    assert code == 3 and out.out == ""


def test_policy_flag(capsys):
    code, _ = cli(capsys, vec("autonomous-valid"), "--policy", "com.acme.x=permissive")
    assert code == 0


def test_module_entrypoint():
    proc = subprocess.run(
        [sys.executable, "-m", "kya_bench", "verify", vec("immediate-valid"), "--jwks", str(FX / "jwks.json"),
         "--now", NOW],
        capture_output=True, text=True, cwd=FX.parent, env={"PYTHONPATH": str(FX.parent / "src")},
    )
    assert proc.returncode == 0, proc.stderr
    assert json.loads(proc.stdout)["mode"] == "immediate"


def test_verify_detects_protocols(capsys):
    for name, protocol, code in (("tap-browse-ed25519-valid", "tap", 0), ("ap2-hnp-valid", "ap2", 0),
                                 ("comp-presenter-mismatch", "composition", 1),
                                 ("xlate-undisclosed-allowlist", "translation", 1)):
        rc, out = cli(capsys, vec(name))
        assert rc == code and json.loads(out.out)["protocol"] == protocol


def test_verify_raw_tap_bundle_from_stdin(capsys, monkeypatch, tmp_path):
    import io

    bundle = json.loads((FX / "vectors" / "tap-revoked-key.json").read_text())["bundle"]
    monkeypatch.setattr("sys.stdin", io.StringIO(json.dumps(bundle)))
    rc, out = cli(capsys, "-")
    data = json.loads(out.out)
    assert rc == 1 and data["protocol"] == "tap" and data["reason_codes"] == ["TAP_KEY_REVOKED"]
