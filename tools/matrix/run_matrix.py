"""Conformance matrix: KYA Bench expectations vs the reference implementations.

    python tools/matrix/run_matrix.py --refs <dir with the three clones> [--out docs]

``<refs>`` must contain ``verifiable-intent``, ``AP2`` and ``trusted-agent-protocol``
checked out at the commits in docs/sources.md (verified at start-up). Needs the
AP2 SDK's dependencies (jwcrypto, pydantic, sd-jwt) and Node.js. Offline once
those are installed. Not part of tools/ci.sh. See docs/conformance-matrix.md.

Status per vector:
- ``agree``        reference verdict == KYA expected verdict
- ``diverge``      they differ; ``kind`` = ``verdict`` (KYA decides accept/reject)
                   or ``spec_gap`` (KYA expects indeterminate, the reference decides)
- ``not_runnable`` the vector cannot be expressed in the reference's input model

A reference exception (``error``) is compared as a rejection; the raw outcome is kept.
"""

from __future__ import annotations

import argparse
import json
import subprocess
import sys
from collections import Counter
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[2]
sys.path.insert(0, str(ROOT / "src"))
sys.path.insert(0, str(Path(__file__).resolve().parent))

from adapters import Ap2Adapter, NotRunnable, TapAdapter, ViAdapter  # noqa: E402
from findings import FINDINGS, MASKS, finding_for  # noqa: E402

from kya_bench.suite import load_vectors  # noqa: E402

PINS = {
    "verifiable-intent": "356c29635f1c44df7de02edb58699ca9f29bece6",
    "AP2": "e1ea56db72a6385bce3e5c1112b3a56ce60acb43",
    "trusted-agent-protocol": "16d59bdf3f8a542bc538d0962edbb80ea30a02af",
}
REFERENCE = {
    "vi": "agent-intent/verifiable-intent@356c296 — verify_chain + check_constraints (examples/helpers.py pipeline)",
    "ap2": "google-agentic-commerce/AP2@e1ea56d — Python SDK MandateClient + Checkout/PaymentMandateChain",
    "tap": "visa/trusted-agent-protocol@16d59bd — cdn-proxy/server.js verifySignature (Node)",
    "composition": "none",
    "translation": "none",
}


def check_pins(refs: Path) -> None:
    for name, sha in PINS.items():
        head = subprocess.run(["git", "-C", str(refs / name), "rev-parse", "HEAD"], capture_output=True, text=True,
                              check=True).stdout.strip()
        if head != sha:
            raise SystemExit(f"{name} is at {head}, expected {sha}")


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--refs", type=Path, required=True)
    ap.add_argument("--out", type=Path, default=ROOT / "docs")
    args = ap.parse_args(argv)
    check_pins(args.refs)
    fx = ROOT / "fixtures"
    jwks = json.loads((fx / "jwks.json").read_text())
    registry = json.loads((fx / "tap_registry.json").read_text())
    vectors = [v for _, v in load_vectors(fx / "vectors")]
    adapters = {
        "vi": ViAdapter(args.refs / "verifiable-intent", jwks),
        "ap2": Ap2Adapter(args.refs / "AP2", jwks),
        "tap": TapAdapter(args.refs / "trusted-agent-protocol", registry),
    }
    adapters["tap"].prepare([v for v in vectors if v["protocol"] == "tap"])
    rows = []
    for v in vectors:
        row: dict[str, Any] = {"id": v["id"], "protocol": v["protocol"], "category": v["category"],
                               "kya_expected": v["expected_verdict"]}
        adapter = adapters.get(v["protocol"])
        try:
            if adapter is None:
                raise NotRunnable(f"no reference implementation exists for '{v['protocol']}' "
                                  "(KYA Bench's own cross-protocol construction)")
            res = adapter.run(v)
        except NotRunnable as exc:
            row |= {"status": "not_runnable", "reason": str(exc)}
            rows.append(row)
            continue
        ref = "reject" if res.verdict == "error" else res.verdict
        row |= {"reference": res.verdict, "reference_detail": res.detail[:400]}
        if ref == v["expected_verdict"]:
            row["status"] = "agree"
            mask = MASKS.get(v["protocol"])
            if mask and ref == "reject" and mask in res.detail:
                row["incidental"] = True  # same verdict, but rejected by an early masking check
        else:
            row["status"] = "diverge"
            row["kind"] = "spec_gap" if v["expected_verdict"] == "indeterminate" else "verdict"
            row["finding"] = finding_for(v["id"])
        rows.append(row)
    summary = {}
    for proto in ("vi", "tap", "ap2", "composition", "translation"):
        rs = [r for r in rows if r["protocol"] == proto]
        c = Counter(r["status"] for r in rs)
        k = Counter(r.get("kind") for r in rs if r["status"] == "diverge")
        summary[proto] = {
            "reference": REFERENCE[proto], "vectors": len(rs), "runnable": len(rs) - c["not_runnable"],
            "agree": c["agree"], "agree_incidental": sum(1 for r in rs if r.get("incidental")),
            "diverge": c["diverge"], "diverge_verdict": k["verdict"],
            "diverge_spec_gap": k["spec_gap"], "not_runnable": c["not_runnable"],
            "not_runnable_reasons": dict(Counter(r["reason"] for r in rs if r["status"] == "not_runnable")),
        }
    doc = {"format": "kya-bench-matrix/1", "pins": PINS, "summary": summary,
           "findings": FINDINGS, "rows": rows}
    (args.out / "conformance-matrix.json").write_text(json.dumps(doc, indent=2, ensure_ascii=False) + "\n")
    for proto, s in summary.items():
        print(f"{proto:12} vectors={s['vectors']:3} runnable={s['runnable']:3} agree={s['agree']:3} "
              f"(incidental {s['agree_incidental']}) "
              f"diverge={s['diverge']:3} (verdict {s['diverge_verdict']}, gap {s['diverge_spec_gap']}) "
              f"not_runnable={s['not_runnable']}")


if __name__ == "__main__":
    main()
