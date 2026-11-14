# KYA Bench — fuzz fix (F1 + F2)

**Fail-closed fix for the two robustness defects found by the adversarial fuzz
audit** (`reports/fuzz-audit.md`). Both were crashes — `verify()` raising an
uncaught exception and emitting no verdict — not accept-bypasses. This change
makes every affected surface return a `reject` verdict instead of a traceback.
Scope is limited to F1/F2; no verdict or reason code of any shipped vector
changes.

## Baseline

| Item | Value |
|---|---|
| Fix branch | `fix-f1-f2` (cut from `fuzz-audit`) |
| Base HEAD | `78dee5d` (fuzz-audit: harness + report) |
| `python3 -m pytest -q` (before) | **279 passed, 22 xfailed** |
| `python3 -m pytest -q` (after) | **279 passed, 22 xfailed** |
| `run-suite fixtures/vectors` (before) | **141/141 match** |
| `run-suite fixtures/vectors` (after) | **141/141 match** |

No existing test was edited; no shipped vector's verdict or reason-code set
changed. Recorded spec gaps (AP2-04 / TAP-02 / AP2-06 and all `docs/spec-gaps.md`
entries) were not touched.

## Changed files

| File | Change |
|---|---|
| `src/kya_bench/reasons.py` | add one reason code `INPUT_TOO_DEEPLY_NESTED` (malformed family) |
| `src/kya_bench/parser.py` | depth limit at the JSON parse boundary; depth guard in the disclosure resolve walk; `sha256_b64url` made total (ASCII→UTF-8 encode) |
| `src/kya_bench/verifier.py` | skip the L1 `sd_hash` computation when L1 is non-ASCII; `RecursionError` backstop + `deep_nesting_verdict` helper on `verify()` |
| `src/kya_bench/ap2/verifier.py`, `tap/verifier.py`, `xproto/composition.py`, `xproto/translate.py` | catch `RecursionError` alongside `ValueError` at the top-level JSON string decode |
| `src/kya_bench/cli.py` | catch `RecursionError` at the CLI's top-level `json.loads(raw)` |
| `fuzz/fuzz_audit.py` | score the walk-crash bisection as `caught` when no crashing depth exists (see "Harness scoring" below) |

## F1 — deep nesting is a reject, never a `RecursionError`

The audit identified four attacker-controlled surfaces where deep nesting raised
`RecursionError` out of `verify()` / the CLI:
`strict_json_loads` → `json.loads`, the recursive `resolve_disclosures.walk`,
`_merchant_from_checkout_jwt`, and the AP2 `checkout_jwt` decode. All of them
decode attacker JSON through one of two mechanisms: a `strict_json_loads` call,
or the resolve walk over an already-parsed structure. The fix closes both at the
source, so every one of the four surfaces fails closed with a single change each:

- **Parse boundary — explicit depth limit (`parser.py`).** `strict_json_loads`
  now pre-scans the decoded text for maximum `[`/`{` nesting with a *non-recursive*
  string-aware scanner (`_max_nesting_depth`) and raises `_TooDeep` before
  `json.loads` runs when the depth exceeds the limit. `_TooDeep` is a `ValueError`
  subclass, so every existing parse-boundary handler already fails closed with its
  normal malformed code:
  - `parse_jws` → `JWT_JSON`
  - `parse_disclosure` → `DISCLOSURE_JSON`
  - `_check_bundle` (bundle-as-string) → `BUNDLE_INVALID`
  - `_merchant_from_checkout_jwt` and the AP2 `checkout_jwt` decode → their existing
    `CHECKOUT_JWT_UNDECODABLE` warn paths (`except (… ValueError …)`).
  Because `json.loads` is only ever reached on input of bounded depth, its C
  scanner can no longer be driven to `RecursionError`, and nothing recursive
  downstream can receive an over-deep single structure.

- **Resolve walk — depth guard (`parser.py`).** A crafted *chain* of individually
  shallow array-element disclosures (each passes the parse-boundary limit) can
  still compound in `resolve_disclosures.walk`. `walk` now carries a `depth`
  counter and, past the limit, records `INPUT_TOO_DEEPLY_NESTED` once and stops
  descending. This covers the most sensitive surface (the audit's crash at
  interpreter depth 991) independently of the parse boundary.

- **`verify()` backstop (`verifier.py`).** As a documented last resort — the
  "`verify()` never raises" contract — `verify()` wraps the layer checks in
  `try/except RecursionError` and returns `deep_nesting_verdict("vi", …)`, a
  `reject` verdict carrying `INPUT_TOO_DEEPLY_NESTED`. It only fires on
  pathological input the two guards above do not already reject, so it never
  changes a well-formed credential's verdict. The AP2/TAP/composition/translation
  entry points and the CLI take the same precaution at their one unguarded
  decode: `RecursionError` is caught beside `ValueError` so a pathologically
  nested *top-level* input becomes that protocol's own `*_INVALID` reject.

### Depth limit value

`MAX_JSON_DEPTH = 64`, applied both at the parse boundary and (as the cap on the
resolved tree) in the walk guard.

- **Deepest legitimate structure measured across all 141 vectors + fixtures
  (envelope and embedded token payloads): depth 8.** 64 leaves ~8× headroom, so
  no real credential or shipped vector is anywhere near it (run-suite stays
  141/141).
- 64 sits far below the interpreter recursion limit (~1000) at which both the
  `json` C scanner and the recursive walk raise `RecursionError`, so any input
  that passes the limit cannot drive either into the stack.

### New reason code

`INPUT_TOO_DEEPLY_NESTED` (input-envelope / malformed family). Emitted by the
walk depth guard and by the entry-point `RecursionError` backstops. The common
parse-boundary rejections reuse the existing malformed codes above
(`JWT_JSON` / `DISCLOSURE_JSON` / `BUNDLE_INVALID`), so no catch site changed.

## F2 — a non-ASCII serialization fails closed, never `UnicodeEncodeError`

A non-ASCII **L1** serialization was correctly flagged `SDJWT_NOT_ASCII` at parse,
but `_verify_l2` then computed `sha256_b64url(run.l1.serialized)` over that string,
and `sha256_b64url` did `text.encode("ascii")` with no guard → `UnicodeEncodeError`
out of `verify()`.

- **Primary contract (`verifier.py`).** The L1 `sd_hash` comparison is now gated
  on `run.l1.serialized.isascii()`. A non-ASCII L1 has already produced its
  `SDJWT_NOT_ASCII` reject; its serialization is no longer hashed, the check is
  left skipped, and the verdict ends on the existing reason with no spurious
  `SD_HASH_MISMATCH` added.

- **All callers (`parser.py`).** Inspecting every `sha256_b64url` caller, two more
  could receive a non-ASCII serialization and crash the same way: the L2-view
  `sd_hash` check (`verifier.py:743`) and the AP2 binding/open-checkout hashes
  (`ap2/verifier.py:274,384`). (`parser.py:200`, `verifier.py:555`,
  `ap2/verifier.py:346` are already ASCII-guarded by their call sites.) Rather
  than guard each site, `sha256_b64url` is made **total** at the root: it now
  encodes with `"utf-8"` instead of `"ascii"`. For every ASCII input — i.e. every
  real serialization, disclosure and builder call — UTF-8 and ASCII produce
  identical bytes, so every existing hash is byte-for-byte unchanged (verdicts and
  reason codes unchanged). A non-ASCII input, which can never match an
  ASCII-derived hash and has already triggered a non-ASCII reject on the parse
  side, now yields a non-matching digest instead of raising. Fail-closed is
  preserved because the non-ASCII parse reject is what rejects the credential; the
  hash change only removes the crash.

## Fuzz re-score

`python3 fuzz/fuzz_audit.py` after the fix (681 probes):

| Attack line | caught | evasion | spec_ambiguity | false_positive | generator_error | total |
|---|---:|---:|---:|---:|---:|---:|
| 1 — amount representation | 29 | 0 | 1 | 0 | 0 | 30 |
| 2 — signature & canonicalisation | 22 | 0 | 1 | 0 | 0 | 23 |
| 3 — chain & mandate logic | 9 | 0 | 1 | 0 | 0 | 10 |
| 4 — cross-protocol confusion | 14 | 0 | 0 | 0 | 0 | 14 |
| 5 — parser robustness | **11** | **0** | 0 | 0 | 0 | 11 |
| 6 — vector mutation sweep | 593 | 0 | 0 | 0 | 0 | 593 |
| **Total** | **678** | **0** | **3** | **0** | **0** | **681** |

**Diff vs. the audit (`reports/fuzz-audit.json`): line 5 only.** caught 7 → 11,
evasion 4 → 0. Every other line's bucket counts are identical. The three recorded
spec ambiguities (AP2-04 / TAP-02 / AP2-06) are unchanged. The four line-5 probes
that moved — the two deep-nesting crashes, the non-ASCII crash, and the
walk-crash-depth bisection — all moved from `evasion` to `caught`, and nothing
else moved.

> `reports/fuzz-audit.json` in the tree is the pre-fix audit snapshot (4 evasions),
> kept consistent with `reports/fuzz-audit.md`. Re-running the harness on this
> branch regenerates that file in place with the post-fix scores above (0 evasions).

### Harness scoring

`minimal_crash_depth()` returns `-1` when no probed depth (up to 8000) crashes the
walk. The probe that reports it was hardcoded as `evasion` with
`"RecursionError at depth {depth}"` — correct before the fix (depth was always a
real crashing value), but after the fix it would falsely report
`"RecursionError at depth -1"` for input that no longer crashes. The harness now
scores the `-1` (no-crash) result as `caught`; a real crashing depth is still
reported as an `evasion` exactly as before. This is a correction to the harness's
self-reporting of the fixed state, not a change to the oracle for any real probe.

## Reproducer demonstrations (now reject verdict JSON, exit 1, empty stderr)

| Case | Path | verdict | reason codes |
|---|---|---|---|
| F1 — deep nesting in L2 payload (audit reproducer) | `kya-bench verify` | `reject` | `JWT_JSON` |
| F1 — chained array-element disclosures (walk guard) | `parse_sd_jwt` | `reject` | `INPUT_TOO_DEEPLY_NESTED` (+ `DISCLOSURE_UNREFERENCED`) |
| F1 — deeply nested top-level file | `kya-bench verify` | `reject` | `BUNDLE_INVALID` |
| F2 — one non-ASCII char in L1 (audit reproducer) | `kya-bench verify` | `reject` | `SDJWT_NOT_ASCII` (no `SD_HASH_MISMATCH`; sd_hash left skipped) |

Each printed a complete verdict JSON on stdout with no Python traceback on stderr,
versus the pre-fix behaviour of a traceback and no verdict.

## Out of scope (left unchanged)

- The three recorded spec ambiguities (AP2-04, TAP-02, AP2-06) and all of
  `docs/spec-gaps.md` — documented gaps, not defects.
- The conformance matrix, the Gate, and spec-gap grading — no published number is
  affected.
- Any refactor beyond what F1/F2 require. `reports/fuzz-audit.md` /
  `reports/fuzz-audit.json` are preserved as the audit snapshot.
