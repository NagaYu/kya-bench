# KYA Bench

A neutral conformance verifier and test-vector suite for agent payment protocols.
KYA Bench checks Mastercard **Verifiable Intent** (VI), Visa **Trusted Agent Protocol** (TAP),
Google **Agent Payments Protocol** (AP2), TAP + AP2 composition, and AP2 → VI translation
equivalence. Each judgment is grounded in the pinned spec text. Where the text leaves an
outcome undefined, KYA Bench returns **`indeterminate`** and records the gap rather than inventing
behaviour.

[日本語版 README](README.ja.md)

## Headline

**141 deterministic vectors.** VI 58, TAP 29, AP2 32, composition 10, translation 12.
KYA Bench matches all 141 of its own expectations (`run-suite`: 141/141).

**Against the protocols' reference implementations**, run on the same vectors
([conformance matrix](docs/conformance-matrix.md)):

| Protocol | Reference implementation | Runnable | Agree | of which incidental | Diverge: verdict | Diverge: spec gap | Not runnable |
|---|---|---|---|---|---|---|---|
| VI | `agent-intent/verifiable-intent@356c296` | 55 / 58 | 47 | 29 | 5 | 3 | 3 |
| TAP | `visa/trusted-agent-protocol@16d59bd` (cdn-proxy, Node) | 29 / 29 | 19 | 18 | 7 | 3 | 0 |
| AP2 | `google-agentic-commerce/AP2@e1ea56d` (Python SDK) | 32 / 32 | 24 | 0 | 1 | 7 | 0 |
| Composition, translation | none exists | 0 / 22 | — | — | — | — | 22 |

"Incidental" agreements are rejections the reference made for an unrelated early reason. They
reach the same verdict for a different cause. Three root causes explain most divergences:

- **VI.** The reference rejects every valid chain because it requires L1 `card_id` to equal
  `payment_instrument.id`. The spec makes `card_id` optional and opaque, and the spec's own
  examples fail this check.
- **TAP.** The reference proxy reads only the camel-case `keyId` parameter. Every request using RFC
  9421's `keyid` is rejected before any other check.
- **AP2.** The SDK decides the seven cases the spec leaves open. For example, it reads `budget.max` in
  dollars but `amount_range.max` in cents.

## Quick start

```bash
git clone <this repository> kya-bench && cd kya-bench
python3 -m pip install -e '.[test]'
```

Verify one vector (any protocol; detected from the file):

```bash
kya-bench verify fixtures/vectors/ap2-hnp-valid.json --jwks fixtures/jwks.json
```

Run the whole suite:

```bash
kya-bench run-suite fixtures/vectors --jwks fixtures/jwks.json
```

Reproduce CI locally (pytest → byte-identical vector regeneration → run-suite):

```bash
bash tools/ci.sh
```

Python 3.11+, one runtime dependency (`cryptography`). Everything runs offline. Trust fixtures stand
in for JWKS endpoints and the TAP agent directory: `fixtures/jwks.json` and
`fixtures/tap_registry.json`.

## Verdict format

`verify` prints one normalized JSON verdict for every protocol:

```jsonc
{
  "protocol": "vi | tap | ap2 | composition | translation",
  "verdict": "accept | reject | indeterminate",
  "identity_ok": true,
  "delegation_chain_ok": true,
  "constraints": [{"type": "...", "status": "satisfied | violated | not_checked | skipped_unknown", "detail": "..."}],
  "cross_refs": {"l3a_l3b_match": true},
  "unknown_constraints": [{"type": "...", "handling": "rejected_open_mandate | rejected_strict | skipped_permissive"}],
  "reason_codes": ["..."],
  "warnings": [{"code": "...", "message": "..."}],
  "evaluated_at": 1790000000,
  "spec": {"name": "...", "source": "<repo>@<commit>"}
}
```

- Exit codes: `0` accept, `1` reject, `2` indeterminate, `3` usage error.
- There is no `accept_with_warnings`; warnings always go to `warnings[]`.
- Reason codes are namespaced: VI codes are unprefixed; the others use `TAP_`, `AP2_`, `XPROTO_` and `XLATE_`.
- **`indeterminate` always means "the specification does not decide this case"**, with reason
  `SPEC_GAP` and a gap id.

## Vectors and matching

Vectors use format `kya-bench-vector/2`, one file per vector:
`{id, protocol, kind, category, description, spec_ref, strictness, now, <payload>, expected_verdict,
expected_reason_codes}`. They regenerate byte-identically from a fixed seed
(`python3 tools/generate_fixtures.py`). Expected verdicts are declared by hand, and the generator
refuses to write a vector the verifier disagrees with.

`run-suite` has two matching modes:

| Mode | A vector matches when… |
|---|---|
| default (subset) | the verdict equals `expected_verdict` **and** every expected code appears among the findings (reasons and warnings) |
| `--strict-codes` | the above, **and** no code outside `expected_reason_codes` appears |

Subset matching is the regression check for this suite: expectations name the decisive codes, not
every warning. Use `--strict-codes` for exact comparisons. The current vectors do not enumerate every
warning, so 49 of 141 match in strict mode.

## Disclosures

- **TAP replay window.** Nonces are remembered per (keyid, nonce) for **8 minutes**, the window on
  Visa's merchant specification page. The reference proxy instead remembers nonces globally for one
  hour. A nonce reused under a different key is not treated as a replay.
- **AP2 fixtures use deterministic signatures.** AP2 requires the merchant-signed `checkout_jwt` to
  use a non-deterministic signature scheme. The fixtures use RFC 6979 deterministic ECDSA (and seeded
  RSA-PSS salts) so that every vector regenerates byte-identically. A verifier cannot observe the
  difference, but the fixtures do not meet that MUST. **All keys are test-only**, derived from the seed
  `kya-bench/vi/phase1`.
- **Composition binding is KYA Bench's own rule.** Neither TAP nor AP2 defines how their agent
  identities bind. See gaps XP-01/XP-02.
- **AP2 is v0.2.** The v0.1 Intent / Cart / Payment mandates map to open mandates, the closed
  checkout mandate and the closed payment mandate ([docs/sources.md](docs/sources.md)).

## Documentation

- [docs/spec-gaps.md](docs/spec-gaps.md): every undefined or conflicting case (VI G-01…G-14, TAP-01…03,
  AP2-01…08, XP-01…03), with quotes and KYA Bench's behaviour. Each undefined case has a strict `xfail` test.
- [docs/conformance-matrix.md](docs/conformance-matrix.md): the reference-implementation comparison,
  how to reproduce it, and findings per divergence.
- [docs/sources.md](docs/sources.md): pinned commits and the files consulted.

Some documentation is in Japanese (spec-gaps, sources, README.ja.md). The vector format, code and
this README are in English.

## License

Code and test vectors are licensed under the [Apache License 2.0](LICENSE).

Contact: [nagayu-portfolio.nagayu.workers.dev](https://nagayu-portfolio.nagayu.workers.dev/en)
