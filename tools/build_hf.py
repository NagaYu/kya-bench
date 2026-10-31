"""Build the Hugging Face dataset and Space folders under hf/ (nothing is uploaded).

    python tools/build_hf.py

Generated (deterministic, checked by tools/ci.sh):
  hf/dataset/README.md                 dataset card
  hf/dataset/data/vectors.jsonl        all vectors, format v2, one per line
  hf/dataset/fixtures/{jwks,tap_registry}.json
  hf/space/README.md, requirements.txt Space card and pinned requirements
  hf/space/data/                       vectors + fixtures for the demo
  hf/space/kya_bench/                  vendored copy of src/kya_bench (without testing/)
hf/space/app.py is hand-written.
"""

from __future__ import annotations

import json
import shutil
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FX = ROOT / "fixtures"
HF = ROOT / "hf"
GRADIO_VERSION = "6.31.0"  # version the Space was checked with locally

PROTOCOL_TEXT = {
    "vi": "Mastercard Verifiable Intent v0.1-draft: L1 issuer SD-JWT, L2 user KB-SD-JWT (Immediate / "
          "Autonomous), L3a/L3b agent KB-SD-JWTs, and the eight registered constraint types.",
    "tap": "Visa Trusted Agent Protocol: RFC 9421 agent signatures (Ed25519, RSA-PSS-SHA256), a local agent "
           "registry, browse/payer tags, replay detection, the Consumer Recognition Object and the Payment "
           "Container.",
    "ap2": "Google Agent Payments Protocol v0.2: delegated SD-JWT chains (`~~`) of open and closed Checkout / "
           "Payment Mandates, human-present and human-not-present flows, AP2's own constraint semantics.",
    "composition": "One presentation with a TAP-signed request and AP2 mandates: does the TAP presenter equal "
                   "the agent the mandates delegate to? (binding rule defined by KYA Bench, see limitations)",
    "translation": "AP2 intent subset (amount range, merchant allowlist, expiry) translated to VI constraints; "
                   "each vector checks whether AP2's and VI's verdicts agree for one probe.",
}


def _vectors() -> list[dict]:
    out = []
    for p in sorted((FX / "vectors").glob("*.json")):
        if p.name != "manifest.json":
            out.append(json.loads(p.read_text()))
    return out


def _jsonl(vectors: list[dict]) -> str:
    return "".join(json.dumps(v, ensure_ascii=True, separators=(",", ":")) + "\n" for v in vectors)


def dataset_card(vectors: list[dict]) -> str:
    by_proto = Counter(v["protocol"] for v in vectors)
    by_verdict = Counter(v["expected_verdict"] for v in vectors)
    rows = "\n".join(f"| `{p}` | {by_proto[p]} | {PROTOCOL_TEXT[p]} |" for p in PROTOCOL_TEXT)
    return f"""---
license: apache-2.0
pretty_name: KYA Bench conformance vectors
language:
- en
tags:
- agent-payments
- conformance
- sd-jwt
- http-message-signatures
- verifiable-intent
- ap2
- trusted-agent-protocol
size_categories:
- n<1K
configs:
- config_name: default
  data_files:
  - split: test
    path: data/vectors.jsonl
---

# KYA Bench conformance vectors

{len(vectors)} deterministic conformance vectors for agent payment protocols, each with the verdict
a spec-faithful verifier should reach. Produced by
[KYA Bench](https://nagayu-portfolio.nagayu.workers.dev/en), a neutral conformance verifier.

| Protocol | Vectors | What is tested |
|---|---|---|
{rows}

Expected verdicts: {by_verdict['accept']} `accept`, {by_verdict['reject']} `reject`,
{by_verdict['indeterminate']} `indeterminate`.

## Format (`kya-bench-vector/2`)

One JSON object per line in `data/vectors.jsonl`:

| Field | Meaning |
|---|---|
| `id` | stable vector id |
| `protocol` | `vi`, `tap`, `ap2`, `composition`, `translation` |
| `kind` | `bundle`, `constraint_check`, `composition`, `translation` — names the payload field |
| `category`, `description`, `spec_ref` | what is tested and which spec section it rests on |
| `strictness` | `strict` / `permissive` (VI unknown-constraint handling) |
| `now` | verification time, Unix seconds (all vectors: 1790000000) |
| `bundle` / `constraint_check` / `presentation` / `translation` | the input, present for its `kind` |
| `expected_verdict` | `accept`, `reject` or `indeterminate` |
| `expected_reason_codes` | codes that must appear among the verifier's findings |

Payload fields are arbitrary JSON (tested to round-trip exactly with `datasets` 5.1, which loads them
with the `Json` feature). Trust fixtures needed to verify are in `fixtures/`: `jwks.json` (issuer,
AP2 trust-list and mock ID-token keys) and `tap_registry.json` (stand-in TAP agent directory).

### `indeterminate` means "the specification does not decide"

An `indeterminate` expectation marks a case the protocol text leaves undefined or contradicts
itself on. The reason code is `SPEC_GAP` (or `XLATE_UNDECIDED` / `XLATE_UNSUPPORTED` for translation).
Each gap is documented with quotes in the KYA Bench repository (`docs/spec-gaps.md`). A verifier
that returns accept or reject there is choosing an interpretation, not failing the vector, but it
does not match the expectation.

### Matching

Default (subset): the verdict equals `expected_verdict` and every expected code appears among the
verifier's findings (reasons and warnings). Strict: additionally, no unexpected code appears. Reason
codes are KYA Bench's vocabulary. Other verifiers should compare verdicts and map codes.

## Limitations and disclosures

- **Test keys only.** All keys derive from a fixed seed (`kya-bench/vi/phase1`). None is real.
- **AP2 fixtures use deterministic signatures.** AP2 requires `checkout_jwt` to use a
  non-deterministic signature scheme. The vectors use RFC 6979 deterministic ECDSA (and seeded
  RSA-PSS salts) so that they regenerate byte-identically. Verifiers cannot tell the difference, but
  the fixtures do not meet that MUST.
- **TAP replay window is an interpretation.** Nonces are tracked per (keyid, nonce) for 8 minutes
  (Visa merchant specification page). The reference proxy tracks nonces globally for 1 hour.
- **Composition binding is KYA Bench's construction.** Neither TAP nor AP2 defines how their agent
  identities bind. KYA Bench treats the TAP signing key's registry agent and the registry agent
  holding the AP2 `cnf` key as the same presenter when they match (gaps XP-01 and XP-02 cover the
  undefined cases).
- **AP2 is v0.2.** The v0.1 Intent / Cart / Payment mandates map to open mandates, the closed
  checkout mandate and the closed payment mandate.
- **Pinned sources.** VI `agent-intent/verifiable-intent@356c296`, TAP
  `visa/trusted-agent-protocol@16d59bd` (plus Visa's unversioned merchant specification page,
  retrieved 2026-10-31), AP2 `google-agentic-commerce/AP2@e1ea56d`.

## License

Apache License 2.0 — vectors and code alike.
"""


def space_card() -> str:
    return f"""---
title: KYA Bench
emoji: 🧾
colorFrom: indigo
colorTo: gray
sdk: gradio
sdk_version: {GRADIO_VERSION}
app_file: app.py
pinned: false
license: apache-2.0
short_description: Conformance verdicts for VI, TAP and AP2 vectors
---

# KYA Bench demo

A read-only demo: pick one of the bundled conformance vectors and see KYA Bench's normalized verdict
JSON, its reason codes, and whether it matches the expected verdict. It accepts no input and makes no
network calls. All keys are test-only.

`kya_bench/` is a vendored copy of the verifier and `data/` holds the vectors and trust fixtures. Both
are generated by `tools/build_hf.py` in the KYA Bench repository.

License: Apache-2.0.
"""


def _copy_package(dst: Path) -> None:
    if dst.exists():
        shutil.rmtree(dst)
    shutil.copytree(ROOT / "src" / "kya_bench", dst,
                    ignore=shutil.ignore_patterns("__pycache__", "*.pyc", "testing"))


def main() -> None:
    vectors = _vectors()
    jsonl = _jsonl(vectors)
    ds, sp = HF / "dataset", HF / "space"
    for d in (ds / "data", ds / "fixtures", sp / "data"):
        d.mkdir(parents=True, exist_ok=True)
    (ds / "data" / "vectors.jsonl").write_text(jsonl)
    (sp / "data" / "vectors.jsonl").write_text(jsonl)
    for name in ("jwks.json", "tap_registry.json"):
        shutil.copyfile(FX / name, ds / "fixtures" / name)
        shutil.copyfile(FX / name, sp / "data" / name)
    (ds / "README.md").write_text(dataset_card(vectors))
    (sp / "README.md").write_text(space_card())
    (sp / "requirements.txt").write_text(f"gradio=={GRADIO_VERSION}\ncryptography>=43\n")
    _copy_package(sp / "kya_bench")
    print(f"hf/: {len(vectors)} vectors -> dataset and space")


if __name__ == "__main__":
    main()
