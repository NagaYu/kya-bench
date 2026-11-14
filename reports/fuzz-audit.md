# KYA Bench — adversarial fuzz audit

**Audit only. No fixes.** The library, fixtures and tests are byte-identical to the
baseline; all new files live under `fuzz/` and `reports/`.

## Baseline

| Item | Value |
|---|---|
| Baseline HEAD | `a0de950b2c96f14f268e25c73713d1c378b6309e` |
| Audit branch | `fuzz-audit` (cut from that HEAD) |
| `python3 -m pytest -q` | **279 passed, 22 xfailed** |
| `kya-bench run-suite fixtures/vectors --jwks fixtures/jwks.json` | **141/141 vectors match** |
| `git diff --stat a0de950 -- src tests fixtures` | empty (library/fixtures/tests unchanged) |

Reproduced at the start of the session and again after the harness run; both unchanged.

## How to run (one command)

```bash
python3 fuzz/fuzz_audit.py
```

Prints the per-attack-line classification table and the list of findings, and writes the
machine-readable `reports/fuzz-audit.json`. `--json` prints that summary to stdout instead.
The harness adds `src/` to `sys.path`, loads `fixtures/jwks.json` (+ the sibling
`tap_registry.json`), and builds every probe with the in-tree test builders
(`kya_bench.testing.{builder,ap2_builder,tap_builder}`), so representation changes are
**re-signed** and do not trivially fail on a broken signature. It never imports or mutates
anything under `tests/` or `fixtures/`.

## Oracle and classification

The oracle is each vector's recorded expectation plus the pinned spec text and
`docs/spec-gaps.md`; where the text is silent the promised verdict is `indeterminate`.
Each probe is classified into exactly one bucket:

- **caught** — handled as the spec/oracle requires.
- **evasion** — a must-reject was accepted, a documented rejection reason was lost, **or the
  "never raises / never crashes" contract broke** (`parser.py`: "Parsing never raises on
  malformed input"; `verifier.py`: "`verify()` never raises on malformed credentials"; brief
  attack line 5: "never a crash, never an accept").
- **spec_ambiguity** — lands on a **recorded** gap; the gap id is cited. Recorded gaps and the
  documented reference-implementation divergences (VI `card_id`, TAP `keyId`, AP2 units) are
  **not** reported as new findings.
- **false_positive** — a representation-only change flipped accept → reject.
- **generator_error** — the harness built something it did not intend.

## Results

681 probes.

| Attack line | caught | evasion | spec_ambiguity | false_positive | generator_error | total |
|---|---:|---:|---:|---:|---:|---:|
| 1 — amount representation | 29 | 0 | 1 | 0 | 0 | 30 |
| 2 — signature & canonicalisation | 22 | 0 | 1 | 0 | 0 | 23 |
| 3 — chain & mandate logic | 9 | 0 | 1 | 0 | 0 | 10 |
| 4 — cross-protocol confusion | 14 | 0 | 0 | 0 | 0 | 14 |
| 5 — parser robustness | 7 | **4** | 0 | 0 | 0 | 11 |
| 6 — vector mutation sweep | 593 | 0 | 0 | 0 | 0 | 593 |
| **Total** | **674** | **4** | **3** | **0** | **0** | **681** |

**No evasion in the accept/reject sense, and no false positive.** Every must-reject artifact
was rejected, every representation-equivalent re-encoding kept its verdict, and no
representation change flipped an accept to a reject. The 4 evasions are all **crashes** on the
parser-robustness line — two distinct root causes where `verify()` raises an uncaught
exception instead of returning a `reject`/`indeterminate` verdict.

## Findings (evasions)

Both findings break the stated "never raises on malformed input" contract (attack line 5:
"never a crash"). In both cases the CLI prints a Python traceback to stderr, emits **no verdict
JSON**, and exits `1` — the **same exit code as a clean `reject`**, so a consumer that keys off
the exit code sees "reject" while actually getting an unhandled exception and no verdict.

### F1 — deeply nested JSON raises `RecursionError` (fail-open by crash)

- **Bucket:** evasion (crash). **Attack line:** 5.
- **Promised behaviour:** `parser.py` module docstring — "Parsing never raises on malformed
  input." `verifier.py` — "`verify()` never raises on malformed credentials; it returns a
  `Verdict`." Brief attack line 5 — deeply nested objects "must end in reject or
  `indeterminate` … never a crash." The shipped `malformed-*` vectors all expect `reject`,
  establishing the fail-closed contract.
- **Observed:** `RecursionError: maximum recursion depth exceeded`, uncaught, propagating out
  of `verify()`. Reached on several attacker-controlled surfaces, none guarded:
  - `strict_json_loads` → `json.loads(..., object_pairs_hook=_no_duplicates)`
    ([src/kya_bench/parser.py:71](src/kya_bench/parser.py:71)); `parse_jws` catches only
    `(ValueError, UnicodeDecodeError)` ([parser.py:175](src/kya_bench/parser.py:175)), and
    `RecursionError` is not a `ValueError`.
  - `resolve_disclosures.walk`, a plain recursive walk of the payload and every disclosure
    value ([parser.py:253](src/kya_bench/parser.py:253), recursion at
    [parser.py:257](src/kya_bench/parser.py:257)). This is the most sensitive surface: it uses
    one Python frame per nesting level, so it crashes at **depth 991** (interpreter
    `recursionlimit` = 1000), well below the `json.loads` C-scanner limit.
  - `_merchant_from_checkout_jwt` ([verifier.py:864](src/kya_bench/verifier.py:864)) and the
    AP2 `checkout_jwt` decode ([ap2/verifier.py:351](src/kya_bench/ap2/verifier.py:351)) catch
    only `ValueError`/`IndexError`/`UnicodeDecodeError`, so the same nesting there is also
    uncaught.
- **Minimal reproducer** (via the public CLI; `$D` is any scratch dir):

  ```python
  import json, base64
  from kya_bench.testing import builder as B
  b64u = lambda s: base64.urlsafe_b64encode(s).rstrip(b"=").decode()
  good = B.build(B.autonomous_spec())
  nested = "[" * 2000 + "1" + "]" * 2000            # deeply nested JSON array
  l2 = (b64u(b'{"alg":"ES256"}') + "." +
        b64u(('{"delegate_payload":%s,"_sd":[],"_sd_alg":"sha-256"}' % nested).encode()) +
        "." + b64u(b"x" * 64) + "~")
  json.dump({"l1": good["l1"], "l2": l2}, open(f"{D}/repro_recursion.json", "w"))
  ```

  ```bash
  kya-bench verify "$D/repro_recursion.json" --jwks fixtures/jwks.json
  ```

  Observed: traceback ending `RecursionError: maximum recursion depth exceeded`
  (`if is_undisclosed_ref(el):`, parser.py:257), no verdict JSON, exit 1. The harness also
  bisects the minimal crash depth (reported as `991`) and triggers the same crash through
  `parse_sd_jwt` directly and through end-to-end `verify()`.

### F2 — non-ASCII in one layer's serialization raises `UnicodeEncodeError`

- **Bucket:** evasion (crash). **Attack line:** 5 (non-ASCII input).
- **Promised behaviour:** same "never raises" contract as F1. A non-ASCII SD-JWT *is*
  recognised — `parse_sd_jwt` flags `SDJWT_NOT_ASCII` ([parser.py:206-208](src/kya_bench/parser.py:206))
  — so the intended outcome is a clean `reject`.
- **Observed:** with a non-ASCII **L1** serialization, L1 parsing correctly records
  `SDJWT_NOT_ASCII` and returns early, but `_verify_l2` then computes the expected L2 `sd_hash`
  as `sha256_b64url(run.l1.serialized)` ([verifier.py:432](src/kya_bench/verifier.py:432)) over
  the still-non-ASCII L1 string. `sha256_b64url` does `text.encode("ascii")`
  ([parser.py:55](src/kya_bench/parser.py:55)) with no guard →
  `UnicodeEncodeError: 'ascii' codec can't encode character …`, uncaught, out of `verify()`.
- **Minimal reproducer:**

  ```python
  import json
  from kya_bench.testing import builder as B
  good = B.build(B.autonomous_spec())
  bundle = {"l1": good["l1"][:-1] + "é~", "l2": good["l2"]}   # one non-ASCII char in L1
  json.dump(bundle, open(f"{D}/repro_unicode.json", "w"))
  ```

  ```bash
  kya-bench verify "$D/repro_unicode.json" --jwks fixtures/jwks.json
  ```

  Observed: traceback ending `UnicodeEncodeError … in position 795` at
  `hashlib.sha256(text.encode("ascii"))` (parser.py:55), no verdict JSON, exit 1.

Both findings are robustness defects, not spec gaps: `docs/spec-gaps.md` and the conformance
matrix make no claim that excuses a crash, and the `malformed-*` vectors establish that
malformed input is meant to produce a `reject`.

## Spec ambiguities (recorded gaps — not new findings)

Three probes landed exactly on recorded gaps; the verifier returned `indeterminate` with the
gap id, as promised. Quoted both ways in `docs/spec-gaps.md`:

- **AP2-04** — `amount_range` with a decimal `max` (`250.0`). Schema: `min`/`max` are integer
  minor units; `payment_mandate.md` example uses `"max": 100.50`. Verifier →
  `indeterminate` (`SPEC_GAP`, `AP2-04`). (Line 1.)
- **TAP-02** — signature parameter spelled `keyId` (reference agent) vs `keyid`
  (RFC 9421 / Visa page). Verifier → `indeterminate` (`SPEC_GAP`, `TAP-02`). This is the
  documented reference-implementation quirk, not re-reported as a finding. (Line 2.)
- **AP2-06** — `budget.max` unit ambiguity: amount over the minor-unit reading but under the
  SDK's major-unit (`×100`) reading. Verifier → `indeterminate` (`SPEC_GAP`, `AP2-06`).
  (Line 3.)

## What held (the attacks that found nothing)

**Line 1 — the money seam (30 probes).** Every non-integer representation of an in-range
amount — `27999.0`, `"27999"`, `" 27999 "`, `"+27999"`, `"2.7999e4"`, full-width `２７９９９`,
Arabic-Indic `٢٧٩٩٩`, `"27,999"`, `True`, `-0.0` — is rejected with `L3_AMOUNT_NOT_INTEGER`
(integer minor units is a MUST, [verifier.py:542](src/kya_bench/verifier.py:542);
`_amount_from` rejects non-ints, [constraints.py:430](src/kya_bench/constraints.py:430)). There
is **no `int()` coercion** of a payload value anywhere, so a string of digits never slips
through. Boundaries are exact (`40000` accept / `40001` reject; `10000` accept / `9999`
reject). Amounts at `2^53-1`, `2^53`, `2^53+1` compare exactly (Python big-ints; no float
rounding). Currency is an exact compare, so `usd`/`Usd` reject rather than case-fold into an
over-accept. The same holds for the independent AP2 amount engine. None of these rejects is a
false positive: each input is non-conformant, and none flips an equivalent accept.

**Line 2 — signatures & canonicalisation (23 probes).** `keyId` → TAP-02 (above); every other
case form (`KEYID`, `KeyID`, `Keyid`, `keyID`) leaves `keyid` missing and rejects with
`TAP_PARAM_MISSING` — the `keyId` salvage is exact-match only
([tap/verifier.py:254](src/kya_bench/tap/verifier.py:254)). `alg` is case-insensitive
(`ED25519`/`Ed25519` accept, TAP-N5) but a foreign `alg` (`ES256` on a TAP request, `EdDSA` on
an AP2 root) never accepts. Expiry/window/created boundaries are exact (`expires==now` ok,
`now-1` expired; window `480` ok, `481` too long; `created==now+60` ok, `+61` future). Unknown
issuer `kid` (VI `JWKS_KID_NOT_FOUND`, AP2 `AP2_ROOT_KEY_UNKNOWN`), alg/key mismatch, and a
truncated signature all reject.

**Line 3 — chain & mandate logic (10 probes).** Reversing an AP2 chain, presenting the
agent-signed terminal token as the root, swapping the agent `cnf` key between the checkout and
payment open mandates (`CNF_PAIR_MISMATCH`), and pointing `cnf` at a key the agent does not hold
(`SIGNATURE_INVALID`) all reject. Cumulative budget is exact at the maximum and one over, in
both the VI (network-state) and AP2 (minor/major unit) formulations; the one genuinely
undecided unit boundary is AP2-06 (above). A missing `budget` companion for
`agent_recurrence` rejects.

**Line 4 — cross-protocol confusion (14 probes).** Feeding an AP2 or VI bundle to the TAP path
(`TAP_BUNDLE_INVALID`), a TAP or VI bundle to the AP2 path (`AP2_MANDATE_MISSING`), and either
to the VI path all reject. A composition with its legs swapped (`{"tap": <ap2>, "ap2": <tap>}`)
rejects; a rejecting AP2 leg rejects the whole composition. For AP2→VI translation: an
out-of-range amount, a currency mismatch and an expired intent are each **reject on both
sides** and reported equivalent (`XLATE_BOTH_REJECT`, translation verdict `accept`) — so a
rejected AP2 mandate never yields an **accepted VI side**; the in-range probe preserves the
amount/currency constraint (both accept); and the undisclosed-allowlist case (AP2 fails, VI
skips) is surfaced as `XLATE_DIVERGENT` (reject), the recorded XP-03 semantic difference.

**Line 6 — vector mutation sweep (593 probes).** All 141 shipped vectors (manifest excluded):

- *(a)* 564 semantics-preserving re-encodings (4 per vector: `sort_keys`+indent, compact,
  `ensure_ascii` on, `ensure_ascii` off) — every one kept both the recorded verdict **and** the
  exact reason-code set. Re-serialising the envelope JSON is verdict-neutral; the cryptographic
  binding of the inner SD-JWT bytes is untouched.
- *(b)* 29 single-field corruptions of the accept vectors — one flipped character in each token
  signature (VI `l1/l2/l3a/l3b`, AP2 `checkout_mandate`/`payment_mandate`, TAP request
  `signature`). Every corruption stopped the vector from accepting. None remained accepted.

## Statement

Within this harness (681 probes across the six attack lines, full counts in
`reports/fuzz-audit.json`): **no must-reject artifact was accepted, no documented rejection
reason was lost, and no representation-only change flipped a verdict.** The money seam, the
chain/binding logic, the cross-protocol boundaries and the AP2→VI translation equivalence all
held, and the 141-vector re-encoding and single-field-corruption sweeps were clean. The only
findings are two robustness defects (F1 deeply nested JSON → `RecursionError`; F2 non-ASCII
layer serialization → `UnicodeEncodeError`) where `verify()` raises an uncaught exception and
emits no verdict, violating the module-level "never raises on malformed input" contract and the
fail-closed behaviour that the `malformed-*` vectors promise. Three probes landed on recorded
spec gaps (AP2-04, TAP-02, AP2-06) and are not new findings.
