#!/usr/bin/env python3
"""KYA Bench adversarial fuzz audit — harness (audit only, no fixes).

Single entry point. Run from the repository root:

    python3 fuzz/fuzz_audit.py            # table + write reports/fuzz-audit.json
    python3 fuzz/fuzz_audit.py --json     # machine-readable summary to stdout

The harness attacks the verifier from OUTSIDE its own vector set. It never
edits src/, tests/ or fixtures/. Every artifact it feeds the verifier is built
with the in-tree test builders (so signatures stay valid under representation
changes) or is a re-encoding / single-field corruption of a shipped vector.

Each probe declares an oracle expectation and is classified into one bucket:

    caught          the probe was handled as the spec/oracle requires
    evasion         a must-reject was accepted, a rejection reason was lost,
                    or the "never raises / never crashes" contract broke
    spec_ambiguity  the probe lands on a recorded spec gap (indeterminate);
                    the gap id is cited — recorded gaps are NOT new findings
    false_positive  a representation-only change flipped accept -> reject
    generator_error the harness built something it did not intend

The oracle is each vector's recorded expectation plus the pinned spec text and
docs/spec-gaps.md. Documented divergences (VI card_id, TAP keyId, AP2 units)
and recorded gaps are not re-reported as findings.
"""

from __future__ import annotations

import argparse
import base64
import copy
import hashlib
import json
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))

from kya_bench.context import Fixtures  # noqa: E402
from kya_bench.verifier import Verdict, verify  # noqa: E402
from kya_bench.ap2.verifier import verify_ap2  # noqa: E402
from kya_bench.tap.verifier import verify_tap  # noqa: E402
from kya_bench.xproto.composition import verify_composition  # noqa: E402
from kya_bench.xproto.translate import check_translation  # noqa: E402
from kya_bench.parser import parse_sd_jwt, strict_json_loads, sha256_b64url  # noqa: E402
from kya_bench.testing import builder as B  # noqa: E402
from kya_bench.testing import ap2_builder as A  # noqa: E402
from kya_bench.testing import tap_builder as T  # noqa: E402

FX = Fixtures.from_jwks_path(str(ROOT / "fixtures" / "jwks.json"))
VECTORS_DIR = ROOT / "fixtures" / "vectors"

# gaps/divergences that are already recorded — landing on one is spec_ambiguity,
# not a new finding.
RECORDED_GAPS = {
    "G-01", "G-02", "G-03", "G-04", "G-05", "G-07", "G-08", "G-09", "G-11",
    "G-12", "G-13", "G-14", "TAP-01", "TAP-02", "TAP-03", "AP2-01", "AP2-02",
    "AP2-03", "AP2-04", "AP2-05", "AP2-06", "AP2-07", "AP2-08", "XP-01",
    "XP-02", "XP-03",
}


def b64u(bs: bytes) -> str:
    return base64.urlsafe_b64encode(bs).rstrip(b"=").decode()


@dataclass
class Probe:
    line: int
    name: str
    bucket: str
    expect: str
    observed: str
    note: str = ""
    codes: list[str] = field(default_factory=list)
    gaps: list[str] = field(default_factory=list)


RESULTS: list[Probe] = []


def _runverdict(runner: Callable[[], Verdict]) -> tuple[Verdict | None, BaseException | None]:
    try:
        return runner(), None
    except BaseException as exc:  # noqa: BLE001 - the contract is "never raises"
        return None, exc


def check(line: int, name: str, runner: Callable[[], Verdict], *, expect: str,
          must_include: tuple[str, ...] = (), gap: str | None = None,
          crash_probe: bool = False, note: str = "") -> Probe:
    """Classify one probe. ``expect`` is accept|reject|indeterminate|not_accept."""
    v, exc = _runverdict(runner)
    if exc is not None:
        p = Probe(line, name, "evasion", expect, f"CRASH:{type(exc).__name__}",
                  note=(note + " verify raised instead of failing closed "
                        "(parser.py/verifier.py promise 'never raises'; attack line 5 "
                        "requires reject/indeterminate, never a crash)").strip())
        RESULTS.append(p)
        return p
    got = v.verdict
    codes = v.reason_codes()
    gaps = sorted({f.gap_id for f in v.findings if f.gap_id})
    all_codes = sorted(v.codes())

    def mk(bucket: str, extra: str = "") -> Probe:
        p = Probe(line, name, bucket, expect, got, (note + " " + extra).strip(),
                  codes=all_codes, gaps=gaps)
        RESULTS.append(p)
        return p

    if expect == "accept":
        if got == "accept":
            return mk("caught")
        if got == "reject":
            return mk("false_positive", "accept flipped to reject on representation alone")
        return mk("spec_ambiguity" if (gaps and set(gaps) & RECORDED_GAPS) else "evasion",
                  f"expected accept, got {got}")
    if expect == "reject":
        if got == "reject":
            missing = [c for c in must_include if c not in all_codes]
            if missing:
                return mk("evasion", f"rejected but required reason(s) {missing} absent (reason lost)")
            return mk("caught")
        if got == "accept":
            return mk("evasion", "must-reject artifact ACCEPTED")
        # indeterminate
        if gap and gap in gaps:
            return mk("spec_ambiguity", f"lands on recorded gap {gap}")
        if gaps and set(gaps) & RECORDED_GAPS:
            return mk("spec_ambiguity", f"indeterminate on recorded gap(s) {gaps}")
        return mk("evasion", "must-reject became indeterminate with no recorded gap (reason lost)")
    if expect == "indeterminate":
        if got == "indeterminate":
            if gap and gap not in gaps:
                return mk("spec_ambiguity", f"indeterminate but gap {gaps} not the expected {gap}")
            return mk("spec_ambiguity", f"recorded gap(s) {gaps}")
        if got == "reject":
            return mk("caught", "stricter than the recorded gap (reject), still fails closed")
        return mk("evasion", "expected indeterminate (spec gap) but ACCEPTED")
    if expect == "not_accept":
        if got in ("reject", "indeterminate"):
            if got == "indeterminate" and gaps and set(gaps) & RECORDED_GAPS:
                return mk("spec_ambiguity", f"indeterminate on recorded gap(s) {gaps}")
            return mk("caught")
        return mk("evasion", "must-not-accept artifact ACCEPTED")
    raise ValueError(f"bad expect {expect!r}")


# shorthand verifier runners -------------------------------------------------

def vi(bundle: Any, now: int = B.NOW, strictness: str = "strict") -> Callable[[], Verdict]:
    return lambda: verify(bundle, strictness=strictness, resolver=FX.jwks, now=now)


def ap2(bundle: Any, now: int = A.NOW) -> Callable[[], Verdict]:
    return lambda: verify_ap2(bundle, fixtures=FX, now=now)


def tap(bundle: Any, now: int = T.NOW) -> Callable[[], Verdict]:
    return lambda: verify_tap(bundle, fixtures=FX, now=now)


# ===========================================================================
# Line 1 — amount representation (the money seam)
# ===========================================================================

def vi_amount_bundle(amount: Any) -> dict[str, Any]:
    sp = B.autonomous_spec()
    sp.hooks = {"l3a_payment": (lambda p: p["payment_amount"].__setitem__("amount", amount))}
    return B.build(sp)


def vi_currency_bundle(cur: Any) -> dict[str, Any]:
    sp = B.autonomous_spec()
    sp.hooks = {"l3a_payment": (lambda p: p["payment_amount"].__setitem__("currency", cur))}
    return B.build(sp)


def ap2_amount_bundle(amount: Any) -> dict[str, Any]:
    sp = A.Ap2Spec(flow="hnp", amount=amount if isinstance(amount, int) else 19900)
    # put the fuzzed representation directly on the closed payment amount, re-signed
    sp.hooks = {"payment_closed": (lambda m: m["payment_amount"].__setitem__("amount", amount))}
    sp.cart_total = amount if isinstance(amount, int) else 19900
    return A.build(sp)


def line1() -> None:
    L = 1
    base = 27999  # in [10000, 40000]
    # Non-integer / string representations of an in-range amount: integer minor
    # units is a MUST (credential-format §4.4.2 / L3_AMOUNT_NOT_INTEGER), so each
    # must reject. A reject here is correct, NOT a false positive.
    for rep, label in [
        (base, "int-canonical"), (float(base), "float 27999.0"), (str(base), 'string "27999"'),
        (f" {base} ", "whitespace-padded"), ("+27999", "plus-prefixed"), ("2.7999e4", "sci-notation string"),
        ("２７９９９", "fullwidth digits"), ("٢٧٩٩٩", "arabic-indic digits"), ("27,999", "thousand-separator"),
        (True, "bool true"), (27999.000000001, "float near-int"),
    ]:
        exp = "accept" if label == "int-canonical" else "reject"
        mi = () if exp == "accept" else ()
        check(L, f"vi amount {label}", vi(vi_amount_bundle(rep)), expect=exp, must_include=mi,
              note="integer minor units is a MUST (L3_AMOUNT_NOT_INTEGER); non-int reps must reject")
    # dollars-vs-cents maxima & boundaries (exact integer compare). 0 is a valid
    # integer but below the amount_range min 10000, so it rejects on value.
    for amt, exp in [(40000, "accept"), (40001, "reject"), (10000, "accept"), (9999, "reject"),
                     (0, "reject")]:
        check(L, f"vi amount boundary {amt}", vi(vi_amount_bundle(amt)), expect=exp)
    # float precision near 2**53 (JSON ints stay exact in Python; no coercion)
    for amt in (2 ** 53, 2 ** 53 + 1, 2 ** 53 - 1):
        check(L, f"vi amount 2^53 region {amt}", vi(vi_amount_bundle(amt)), expect="reject",
              note="above max 40000; exact int compare, no float rounding")
    # negative zero via float
    check(L, "vi amount negative-zero float -0.0", vi(vi_amount_bundle(-0.0)), expect="reject")
    # currency-code case (ISO 4217 is upper-case; exact compare)
    check(L, "vi currency USD", vi(vi_currency_bundle("USD")), expect="accept")
    for c in ("usd", "Usd", "uSd"):
        check(L, f"vi currency {c}", vi(vi_currency_bundle(c)), expect="reject",
              note="currency mismatch; case-folding would be an over-accept, verifier does exact compare")

    # AP2 money seam (independent engine): amount_range + budget
    for rep, label in [(19900, "int-canonical"), (19900.0, "float"), ("19900", "string"),
                       ("１９９００", "fullwidth"), (2 ** 53 + 1, "2^53+1")]:
        exp = "accept" if label == "int-canonical" else "reject"
        check(L, f"ap2 amount {label}", ap2(ap2_amount_bundle(rep)), expect=exp,
              note="AP2 amount is integer minor units in the SDK Amount model")
    # AP2 amount_range decimal max is the recorded gap AP2-04 (spec_ambiguity)
    sp = A.Ap2Spec(flow="hnp")
    sp.payment_constraints = [{"type": "payment.amount_range", "currency": "USD", "min": 1000, "max": 250.0},
                              {"type": "payment.allowed_payees", "allowed": ["$merchant:0", "$merchant:1"]},
                              {"type": "payment.reference", "conditional_transaction_id": "$auto"}]
    check(L, "ap2 amount_range decimal max 250.0", ap2(A.build(sp)), expect="indeterminate", gap="AP2-04")


# ===========================================================================
# Line 2 — signature & canonicalisation (sf.py, keys.py, TAP verifier)
# ===========================================================================

def line2() -> None:
    L = 2
    # keyid spelling / case forms
    check(L, "tap keyid (RFC 9421)", tap(T.bundle(T.TapRequest(keyid_param="keyid"))), expect="accept")
    check(L, "tap keyId (reference agent)", tap(T.bundle(T.TapRequest(keyid_param="keyId"))),
          expect="indeterminate", gap="TAP-02")
    for kp in ("KEYID", "KeyID", "Keyid", "keyID"):
        check(L, f"tap param-name {kp}", tap(T.bundle(T.TapRequest(keyid_param=kp))), expect="reject",
              must_include=("TAP_PARAM_MISSING",),
              note="only exact 'keyId' is salvaged (TAP-02); other case forms leave keyid missing")
    # algorithm-label case variants (documented case-insensitive, TAP-N5)
    for alg in ("ed25519", "ED25519", "Ed25519"):
        check(L, f"tap alg case {alg}", tap(T.bundle(T.TapRequest(keyid="primary-ed25519", alg=alg))),
              expect="accept", note="alg label is case-insensitive per the repo (TAP-N5)")
    # parameter order re-signed (SF dictionaries are unordered; base uses received text)
    # Reordering with a fresh signature over the new base must still accept.
    req = T.TapRequest()
    r = req.build()
    check(L, "tap params as-built (order baseline)", tap({"requests": [r]}), expect="accept")
    # duplicate signature parameter in Signature-Input (RFC 8941: last wins)
    r2 = copy.deepcopy(r)
    si = r2["headers"]["signature-input"]
    r2b = copy.deepcopy(r2)
    r2b["headers"]["signature-input"] = si.replace(";nonce=", ";nonce=\"dup\";nonce=", 1)
    check(L, "tap duplicated nonce param", tap({"requests": [r2b]}), expect="not_accept",
          note="duplicate SF key; base no longer matches the signature -> must not accept")
    # expiry boundaries
    check(L, "tap expires==now (valid edge)", tap(T.bundle(T.TapRequest(created=T.NOW - 60, expires=T.NOW))),
          expect="accept")
    check(L, "tap expires==now-1 (expired)", tap(T.bundle(T.TapRequest(created=T.NOW - 61, expires=T.NOW - 1))),
          expect="reject", must_include=("TAP_EXPIRED",))
    check(L, "tap window==480 (edge ok)", tap(T.bundle(T.TapRequest(created=T.NOW - 60, expires=T.NOW - 60 + 480))),
          expect="accept")
    check(L, "tap window==481 (too long)", tap(T.bundle(T.TapRequest(created=T.NOW - 60, expires=T.NOW - 60 + 481))),
          expect="reject", must_include=("TAP_WINDOW_TOO_LONG",))
    check(L, "tap created==now+60 (edge ok)", tap(T.bundle(T.TapRequest(created=T.NOW + 60, expires=T.NOW + 60 + 400))),
          expect="accept")
    check(L, "tap created==now+61 (future)", tap(T.bundle(T.TapRequest(created=T.NOW + 61, expires=T.NOW + 61 + 400))),
          expect="reject", must_include=("TAP_CREATED_IN_FUTURE",))

    # JWK selection — VI issuer
    sp = B.autonomous_spec()
    sp.hooks = {"L1_header": (lambda h: h.__setitem__("kid", "no-such-kid"))}
    check(L, "vi L1 unknown kid", vi(B.build(sp)), expect="reject", must_include=("JWKS_KID_NOT_FOUND",))
    # AP2 root unknown kid
    sp2 = A.Ap2Spec(flow="hnp")
    sp2.hooks = {"checkout_root_header": (lambda h: h.__setitem__("kid", "no-such-kid"))}
    check(L, "ap2 root unknown kid", ap2(A.build(sp2)), expect="reject", must_include=("AP2_ROOT_KEY_UNKNOWN",))

    # key-type confusion between protocols: give the AP2 root a TAP ed25519-style
    # alg label; verifier only does ES256 -> indeterminate (unsupported), never accept.
    sp3 = A.Ap2Spec(flow="hnp")
    sp3.hooks = {"checkout_root_header": (lambda h: h.__setitem__("alg", "EdDSA"))}
    check(L, "ap2 root alg EdDSA (type confusion)", ap2(A.build(sp3)), expect="not_accept",
          note="AP2 verifies only ES256; a foreign alg must not accept")
    # TAP request claiming ES256 alg (VI/AP2 world) — unsupported for TAP
    check(L, "tap alg es256 (foreign)", tap(T.bundle(T.TapRequest(keyid="primary-ed25519", alg="ES256"))),
          expect="reject", must_include=("TAP_ALG_UNSUPPORTED",))
    # TAP alg/key mismatch: ed25519 key but rsa-pss alg label
    check(L, "tap alg/key mismatch", tap(T.bundle(T.TapRequest(keyid="primary-ed25519", alg="rsa-pss-sha256"))),
          expect="reject", must_include=("TAP_ALG_KEY_MISMATCH",))
    # truncated / tampered signature on TAP
    rt = T.TapRequest().build()
    rt["headers"]["signature"] = rt["headers"]["signature"][:-6] + ":"
    check(L, "tap truncated signature", tap({"requests": [rt]}), expect="not_accept")


# ===========================================================================
# Line 3 — chain & mandate logic
# ===========================================================================

def line3() -> None:
    L = 3
    # AP2: reverse the chain tokens (root no longer first)
    b = A.build(A.Ap2Spec(flow="hnp"))
    rev = dict(b)
    rev["checkout_mandate"] = "~~".join(reversed(b["checkout_mandate"].split("~~")))
    check(L, "ap2 reversed checkout chain", ap2(rev), expect="reject")
    # AP2: present the terminal (agent-signed) token alone as if it were the root
    term_only = dict(b)
    term_only["checkout_mandate"] = b["checkout_mandate"].split("~~")[-1]
    check(L, "ap2 terminal-as-root", ap2(term_only), expect="reject")

    # VI: swap the agent cnf key between checkout and payment open mandates
    sp = B.autonomous_spec()
    other = B.public_jwk("ap2-other-agent", B.AGENT_KID)  # a different EC key, same kid
    sp.hooks = {"payment_mandate": (lambda m: m.__setitem__("cnf", {"jwk": other}))}
    check(L, "vi cnf pair mismatch", vi(B.build(sp)), expect="reject", must_include=("CNF_PAIR_MISMATCH",))

    # VI: swap the whole agent binding to a key the L3 is NOT signed by
    sp2 = B.autonomous_spec()
    good = B.public_jwk("ap2-other-agent", B.AGENT_KID)
    sp2.hooks = {
        "checkout_mandate": (lambda m: m.__setitem__("cnf", {"jwk": good})),
        "payment_mandate": (lambda m: m.__setitem__("cnf", {"jwk": good})),
    }
    check(L, "vi L3 signed by non-bound key", vi(B.build(sp2)), expect="reject",
          must_include=("SIGNATURE_INVALID",),
          note="cnf points at a key the agent does not hold; L3 signature must fail")

    # VI cumulative budget at the maximum and one cent over (network_state present)
    def vi_budget(spent: int, maxv: int = 40000, amount: int = 10000) -> dict[str, Any]:
        s = B.autonomous_spec()
        s.payment_mandate["constraints"] = [
            {"type": "mandate.payment.amount_range", "currency": "USD", "min": 1, "max": 10 ** 9},
            {"type": "mandate.payment.budget", "currency": "USD", "max": maxv},
            {"type": "mandate.payment.allowed_payees", "allowed": ["$merchant:0", "$merchant:1"]},
            {"type": "mandate.payment.reference", "conditional_transaction_id": "$auto"},
        ]
        s.hooks = {"l3a_payment": (lambda p: p["payment_amount"].__setitem__("amount", amount))}
        bb = B.build(s)
        bb["network_state"] = {"cumulative_spent": spent}
        return bb
    check(L, "vi budget spent+amount==max", vi(vi_budget(spent=30000, maxv=40000, amount=10000)), expect="accept")
    check(L, "vi budget spent+amount==max+1", vi(vi_budget(spent=30001, maxv=40000, amount=10000)),
          expect="reject", must_include=("CONSTRAINT_VIOLATION",))

    # AP2 budget: at max and one over, in each unit reading
    def ap2_budget(mx: Any, amount: int, total: int = 0) -> dict[str, Any]:
        s = A.Ap2Spec(flow="hnp", amount=amount)
        s.payment_constraints = [
            {"type": "payment.amount_range", "currency": "USD", "min": 1, "max": 10 ** 12},
            {"type": "payment.budget", "currency": "USD", "max": mx}]
        s.mandate_context = {"total_amount": total, "total_uses": 0}
        s.cart_total = amount
        s.cart = [{"id": "li_1", "item": {"id": A.ITEMS[0]["id"], "title": "x", "price": amount},
                   "quantity": 1, "totals": [{"type": "total", "amount": amount}]}]
        return A.build(s)
    # minor-unit exact max: amount==max -> ok under both readings
    check(L, "ap2 budget minor max exact", ap2(ap2_budget(25000, 25000)), expect="accept")
    # amount just over the minor max but under major(x100): recorded unit gap AP2-06
    check(L, "ap2 budget minor over / major under", ap2(ap2_budget(200, 250)),
          expect="indeterminate", gap="AP2-06")
    # over under both readings -> violation
    check(L, "ap2 budget over both readings", ap2(ap2_budget(200, 25000)), expect="reject",
          must_include=("AP2_CONSTRAINT_VIOLATION",))

    # VI agent_recurrence companion requirement (edge form: missing budget sibling)
    sp3 = B.autonomous_spec()
    sp3.payment_mandate["constraints"] = [
        {"type": "mandate.payment.amount_range", "currency": "USD", "min": 1, "max": 10 ** 9},
        {"type": "mandate.payment.agent_recurrence", "frequency": "ON_DEMAND",
         "start_date": "2026-01-01", "end_date": "2027-01-01"},
        {"type": "mandate.payment.allowed_payees", "allowed": ["$merchant:0", "$merchant:1"]},
        {"type": "mandate.payment.reference", "conditional_transaction_id": "$auto"},
    ]
    check(L, "vi agent_recurrence missing budget sibling", vi(B.build(sp3)), expect="reject",
          must_include=("CONSTRAINT_VIOLATION",))


# ===========================================================================
# Line 4 — cross-protocol confusion
# ===========================================================================

def line4() -> None:
    L = 4
    ap2b = A.build(A.Ap2Spec(flow="hnp"))
    tapb = T.bundle(T.TapRequest())
    vib = B.build(B.autonomous_spec())
    check(L, "verify_tap(ap2 bundle)", tap(ap2b), expect="reject", must_include=("TAP_BUNDLE_INVALID",))
    check(L, "verify_tap(vi bundle)", tap(vib), expect="reject", must_include=("TAP_BUNDLE_INVALID",))
    check(L, "verify_ap2(tap bundle)", ap2(tapb), expect="reject", must_include=("AP2_MANDATE_MISSING",))
    check(L, "verify_ap2(vi bundle)", ap2(vib), expect="reject", must_include=("AP2_MANDATE_MISSING",))
    check(L, "verify_vi(ap2 bundle)", vi(ap2b), expect="reject")
    check(L, "verify_vi(tap bundle)", vi(tapb), expect="reject")

    # composition with each leg replaced by the other protocol's artifact
    check(L, "composition tap<-ap2 ap2<-tap", lambda: verify_composition({"tap": ap2b, "ap2": tapb},
                                                                         fixtures=FX, now=A.NOW),
          expect="reject")
    # composition: valid ap2 alone -> accept with identity-layer-absent warning
    check(L, "composition ap2-only", lambda: verify_composition({"ap2": ap2b}, fixtures=FX, now=A.NOW),
          expect="accept")
    # composition: a rejecting AP2 leg rejects the whole composition
    bad_ap2 = A.build(A.Ap2Spec(flow="hnp", amount=99999999))  # over amount_range max -> reject
    check(L, "composition with rejecting ap2 leg", lambda: verify_composition({"ap2": bad_ap2}, fixtures=FX, now=A.NOW),
          expect="reject")

    # Translation verdict semantics: "accept" = the two sides agree (equivalent,
    # including both-reject), "reject" = XLATE_DIVERGENT (one accepts, one rejects),
    # "indeterminate" = one side undecided. The safety invariant for line 4 is: a
    # REJECTED AP2 mandate must never be reported equivalent to an ACCEPTED VI side.
    def check_xlate(name: str, payload: dict[str, Any], *, expect: str, gap: str | None = None,
                    note: str = "") -> None:
        v, exc = _runverdict(lambda: check_translation(payload, now=A.NOW))
        if exc is not None:
            RESULTS.append(Probe(L, name, "evasion", expect, f"CRASH:{type(exc).__name__}", note=note))
            return
        d = v.details
        ar, vr = d.get("ap2_result"), d.get("vi_result")
        # safety: AP2 reject + VI accept must surface as a reject (divergence), never accept/indeterminate
        if ar == "reject" and vr == "accept" and v.verdict != "reject":
            RESULTS.append(Probe(L, name, "evasion", "reject", v.verdict,
                                 note=f"AP2 rejected but VI accepted and translation did not reject (ap2={ar}, vi={vr})"))
            return
        bucket = "caught" if v.verdict == expect else (
            "spec_ambiguity" if gap else "evasion")
        RESULTS.append(Probe(L, name, bucket, expect, v.verdict,
                             note=f"{note} (ap2={ar}, vi={vr})".strip(),
                             codes=sorted(v.codes()),
                             gaps=sorted({f.gap_id for f in v.findings if f.gap_id})))

    rng = {"type": "payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}
    base_intent = {"payment_constraints": [rng], "checkout_constraints": [], "exp": A.NOW + 3600}
    merch = {"id": "m1", "name": "M", "website": "https://m"}
    # out-of-range amount: AP2 rejects (below min), VI rejects -> equivalent (verdict accept),
    # and crucially the VI side does NOT accept.
    check_xlate("translation out-of-range amount",
                {"intent": base_intent, "probe": {"payment_amount": {"amount": 5000, "currency": "USD"}, "merchant": merch}},
                expect="accept", note="both reject -> equivalent; VI side must not accept")
    # in-range: both accept -> amount+currency constraint preserved
    check_xlate("translation in-range (constraint preserved)",
                {"intent": base_intent, "probe": {"payment_amount": {"amount": 20000, "currency": "USD"}, "merchant": merch}},
                expect="accept")
    # currency mismatch: both reject -> equivalent
    check_xlate("translation currency mismatch",
                {"intent": base_intent, "probe": {"payment_amount": {"amount": 20000, "currency": "EUR"}, "merchant": merch}},
                expect="accept")
    # expired intent: both reject under their own clock skew -> equivalent
    check_xlate("translation expiry",
                {"intent": {**base_intent, "exp": A.NOW - 100000},
                 "probe": {"payment_amount": {"amount": 20000, "currency": "USD"}, "merchant": merch}},
                expect="accept")
    # XP-03: undisclosed allowlist -> AP2 rejects, VI skips/accepts -> must be flagged DIVERGENT (reject)
    check_xlate("translation undisclosed allowlist (XP-03)",
                {"intent": {"payment_constraints": [], "exp": A.NOW + 3600,
                            "checkout_constraints": [{"type": "checkout.allowed_merchants",
                                                      "allowed": [{"...": sha256_b64url("x")}]}]},
                 "probe": {"payment_amount": {"amount": 20000, "currency": "USD"}, "merchant": merch}},
                expect="reject", note="recorded XP-03 divergence correctly surfaces as XLATE_DIVERGENT")


# ===========================================================================
# Line 5 — parser robustness
# ===========================================================================

def _jwt_with_payload(payload_json: str) -> str:
    return b64u(b'{"alg":"ES256"}') + "." + b64u(payload_json.encode()) + "." + b64u(b"x" * 64) + "~"


def line5() -> None:
    L = 5
    # Duplicate JSON keys inside a signed payload (a second "amount" hiding behind
    # the first): strict parser must reject, not silently take one.
    dup = '{"amount":1,"amount":2,"_sd":[],"_sd_alg":"sha-256"}'
    sp = parse_sd_jwt(_jwt_with_payload(dup), "L2")
    codes = [str(f.code) for f in sp.findings]
    RESULTS.append(Probe(L, "duplicate JSON key in payload", "caught" if "JWT_DUPLICATE_KEY" in codes else "evasion",
                         "reject", "reject" if codes else "accept",
                         note="second 'amount' must be rejected (JWT_DUPLICATE_KEY)", codes=codes))
    # Unicode-escaped field name colliding with a real one -> duplicate after decode
    due = '{"amount":1,"\\u0061mount":2,"_sd":[],"_sd_alg":"sha-256"}'
    sp2 = parse_sd_jwt(_jwt_with_payload(due), "L2")
    c2 = [str(f.code) for f in sp2.findings]
    RESULTS.append(Probe(L, "unicode-escaped duplicate field name", "caught" if "JWT_DUPLICATE_KEY" in c2 else "evasion",
                         "reject", "reject" if c2 else "accept",
                         note=r"amount decodes to amount -> duplicate must reject", codes=c2))
    # Oversized integer literal (> int-str digit limit)
    big = '{"n":' + "9" * 6000 + ',"_sd":[],"_sd_alg":"sha-256"}'
    sp3 = parse_sd_jwt(_jwt_with_payload(big), "L2")
    c3 = [str(f.code) for f in sp3.findings]
    RESULTS.append(Probe(L, "oversized integer literal (6000 digits)", "caught" if c3 else "evasion",
                         "reject", "reject" if c3 else "accept", note="must reject, not crash", codes=c3))
    # Trailing garbage after JSON
    tg = '{"a":1,"_sd":[],"_sd_alg":"sha-256"} trailing'
    sp4 = parse_sd_jwt(_jwt_with_payload(tg), "L2")
    c4 = [str(f.code) for f in sp4.findings]
    RESULTS.append(Probe(L, "trailing garbage after JSON", "caught" if "JWT_JSON" in c4 else "evasion",
                         "reject", "reject" if c4 else "accept", codes=c4))
    # Truncated signature (not 64 bytes) in a real VI bundle
    spb = B.autonomous_spec()
    bb = B.build(spb)
    jws, _, rest = bb["l1"].partition("~")
    h, p, s = jws.split(".")
    bb["l1"] = ".".join([h, p, s[:10]]) + "~" + rest
    check(L, "truncated L1 signature", vi(bb), expect="reject")
    # Non-ASCII in the serialized SD-JWT
    bb2 = B.build(B.autonomous_spec())
    bb2["l1"] = bb2["l1"][:-1] + "é~"
    check(L, "non-ascii in SD-JWT serialization", vi(bb2), expect="reject")
    # Bundle that is not JSON (string input to verify)
    check(L, "bundle not JSON (string)", vi("}{not json"), expect="reject")

    # --- deeply nested objects: the "never raises / never crashes" contract ---
    # Build nested JSON and feed it through three attacker-reachable parse surfaces.
    def nest_arr(n: int) -> str:
        return "[" * n + "1" + "]" * n

    def nested_disc_token(n: int) -> str:
        val = json.loads(nest_arr(n))
        disc = b64u(json.dumps(["salt", val]).encode())
        d = sha256_b64url(disc)
        payload = json.dumps({"_sd": [d], "x": [{"...": d}], "_sd_alg": "sha-256"})
        return _jwt_with_payload(payload)[:-1] + "~" + disc + "~"

    # Surface A: resolve_disclosures.walk (recursive) — reachable via any disclosure value
    pA = parse_or_crash(lambda: parse_sd_jwt(nested_disc_token(6000), "L2"))
    RESULTS.append(Probe(L, "deep nesting via disclosure value (resolve walk)",
                         "evasion" if pA[1] else "caught", "not_accept",
                         f"CRASH:{type(pA[1]).__name__}" if pA[1] else "handled",
                         note="recursive resolve_disclosures.walk raised instead of failing closed"))
    # Surface B: parse_jws json payload
    pB = parse_or_crash(lambda: parse_sd_jwt(_jwt_with_payload(nest_arr(6000)), "L2"))
    RESULTS.append(Probe(L, "deep nesting via JWS payload (json.loads)",
                         "evasion" if pB[1] else "caught", "not_accept",
                         f"CRASH:{type(pB[1]).__name__}" if pB[1] else "handled",
                         note="strict_json_loads raised instead of failing closed"))
    # Surface C: full VI verify() with a deep structure in the L2 payload
    spc = B.autonomous_spec()
    deep = {}
    cur = deep
    for _ in range(6000):
        cur["x"] = {}
        cur = cur["x"]
    spc.hooks = {"L2_payload": (lambda p: p.__setitem__("junk", deep))}
    try:
        built = B.build(spc)
        check(L, "deep nesting via verify(bundle)", vi(built), expect="not_accept", crash_probe=True,
              note="end-to-end verify() on a deeply nested (signed) payload")
    except BaseException as exc:  # noqa: BLE001
        RESULTS.append(Probe(L, "deep nesting via verify(bundle) [build]", "evasion", "not_accept",
                             f"CRASH:{type(exc).__name__}",
                             note="builder json.dumps also recurses; the signed artifact cannot even be formed"))
    # Minimal crash depth on the walk surface (non-fabricated bisection).
    # minimal_crash_depth() returns -1 when no probed depth crashes, i.e. the
    # walk fails closed at every depth; that is the handled outcome (caught),
    # not an evasion. A real crashing depth is still reported as an evasion.
    depth = minimal_crash_depth()
    if depth < 0:
        RESULTS.append(Probe(L, "minimal crash depth (resolve walk): no crash up to depth 8000",
                             "caught", "not_accept", "no RecursionError; walk fails closed",
                             note="the recursive disclosure walk no longer crashes at any probed depth"))
    else:
        RESULTS.append(Probe(L, f"minimal crash depth (resolve walk) = {depth}", "evasion", "not_accept",
                             f"RecursionError at depth {depth}",
                             note="smallest nesting that crashes the recursive disclosure walk"))


def parse_or_crash(fn: Callable[[], Any]) -> tuple[Any, BaseException | None]:
    try:
        return fn(), None
    except BaseException as exc:  # noqa: BLE001
        return None, exc


def minimal_crash_depth() -> int:
    def crashes(n: int) -> bool:
        val = "[" * n + "1" + "]" * n
        try:
            disc = b64u(json.dumps(["salt", json.loads(val)]).encode())
        except RecursionError:
            return True
        d = sha256_b64url(disc)
        payload = json.dumps({"_sd": [d], "x": [{"...": d}], "_sd_alg": "sha-256"})
        tok = _jwt_with_payload(payload)[:-1] + "~" + disc + "~"
        try:
            parse_sd_jwt(tok, "L2")
            return False
        except RecursionError:
            return True
    lo, hi = 1, 8000
    if not crashes(hi):
        return -1
    while lo < hi:
        mid = (lo + hi) // 2
        if crashes(mid):
            hi = mid
        else:
            lo = mid + 1
    return lo


# ===========================================================================
# Line 6 — vector mutation sweep (all 141 shipped vectors)
# ===========================================================================

def _eval_vector(vec: dict[str, Any]) -> tuple[str, list[str]]:
    from kya_bench.suite import evaluate_vector
    r = evaluate_vector(vec, FX)
    return (r.verdict or "ERROR"), sorted(r.codes)


def line6() -> None:
    L = 6
    paths = sorted(p for p in VECTORS_DIR.glob("*.json") if p.name != "manifest.json")
    for path in paths:
        raw = path.read_text(encoding="utf-8")
        vec = json.loads(raw)
        base_v, base_codes = _eval_vector(vec)
        # (a) semantics-preserving re-encodings of the whole vector JSON:
        #     key reorder + indentation + ensure_ascii toggled (unicode escapes).
        reencs = {
            "sorted+indent": json.dumps(vec, sort_keys=True, indent=2),
            "compact": json.dumps(vec, separators=(",", ":")),
            "ascii-escaped": json.dumps(vec, ensure_ascii=True),
            "ascii-raw": json.dumps(vec, ensure_ascii=False),
        }
        for label, s in reencs.items():
            v2, c2 = _eval_vector(json.loads(s))
            if v2 == base_v and c2 == base_codes:
                RESULTS.append(Probe(L, f"re-encode {label}: {path.stem}", "caught", base_v, v2))
            else:
                bucket = "false_positive" if base_v == "accept" and v2 == "reject" else "evasion"
                RESULTS.append(Probe(L, f"re-encode {label}: {path.stem}", bucket, base_v, v2,
                                     note=f"verdict/codes changed {base_v}/{base_codes} -> {v2}/{c2}"))
        # (b) single-field corruption of ACCEPT vectors: tamper one char in a token
        #     signature; an accepted artifact must no longer accept.
        if base_v == "accept":
            for corrupt_name, corrupted in _corruptions(vec).items():
                v3, c3 = _eval_vector(corrupted)
                RESULTS.append(Probe(L, f"corrupt {corrupt_name}: {path.stem}",
                                     "caught" if v3 != "accept" else "evasion", "not_accept", v3,
                                     note="" if v3 != "accept" else "single-field corruption REMAINED accepted"))


def _corruptions(vec: dict[str, Any]) -> dict[str, dict[str, Any]]:
    """Return copies of the vector with exactly one signature byte flipped per
    token field, for bundle-kind VI/AP2/TAP vectors."""
    out: dict[str, dict[str, Any]] = {}
    kind = vec.get("kind")
    payload = vec.get(_payload_field(kind))
    if not isinstance(payload, dict):
        return out
    # VI bundle tokens
    for key in ("l1", "l2", "l3a", "l3b"):
        tok = payload.get(key)
        if isinstance(tok, str) and tok.count(".") >= 2:
            c = copy.deepcopy(vec)
            c[_payload_field(kind)][key] = _flip_sig(tok)
            out[key] = c
    # AP2 chains
    for key in ("checkout_mandate", "payment_mandate"):
        tok = payload.get(key)
        if isinstance(tok, str) and "." in tok:
            c = copy.deepcopy(vec)
            c[_payload_field(kind)][key] = _flip_sig(tok)
            out[key] = c
    # TAP request signature header
    reqs = payload.get("requests")
    if isinstance(reqs, list) and reqs and isinstance(reqs[0], dict):
        hdrs = reqs[0].get("headers", {})
        if isinstance(hdrs, dict) and isinstance(hdrs.get("signature"), str):
            c = copy.deepcopy(vec)
            s = c[_payload_field(kind)]["requests"][0]["headers"]["signature"]
            # flip a base64 char inside the sig value :...:
            c[_payload_field(kind)]["requests"][0]["headers"]["signature"] = _flip_tap_sig(s)
            out["tap-signature"] = c
    return out


def _payload_field(kind: str | None) -> str:
    return {"bundle": "bundle", "composition": "presentation", "translation": "translation",
            "constraint_check": "constraint_check"}.get(kind or "", "bundle")


def _flip_sig(tok: str) -> str:
    """Flip one character of the first JWS signature segment in an SD-JWT."""
    jws, sep, rest = tok.partition("~")
    try:
        h, p, s = jws.split(".")
    except ValueError:
        return tok
    flipped = ("B" if s[0] != "B" else "C") + s[1:] if s else s
    return ".".join([h, p, flipped]) + sep + rest


def _flip_tap_sig(sigval: str) -> str:
    # format: label=:base64:  -> flip first base64 char
    i = sigval.find(":")
    j = sigval.find(":", i + 1)
    if i < 0 or j < 0 or j <= i + 1:
        return sigval
    body = sigval[i + 1:j]
    nb = ("B" if body[0] != "B" else "C") + body[1:]
    return sigval[:i + 1] + nb + sigval[j:]


# ===========================================================================
# main
# ===========================================================================

def tally() -> dict[str, Any]:
    buckets = ("caught", "evasion", "spec_ambiguity", "false_positive", "generator_error")
    per_line: dict[int, dict[str, int]] = {}
    for p in RESULTS:
        row = per_line.setdefault(p.line, {b: 0 for b in buckets})
        row[p.bucket] = row.get(p.bucket, 0) + 1
    totals = {b: sum(r.get(b, 0) for r in per_line.values()) for b in buckets}
    findings = [p.__dict__ for p in RESULTS if p.bucket in ("evasion", "false_positive", "generator_error")]
    ambiguities = [p.__dict__ for p in RESULTS if p.bucket == "spec_ambiguity"]
    return {
        "total_probes": len(RESULTS),
        "by_line": {str(k): per_line[k] for k in sorted(per_line)},
        "totals": totals,
        "findings": findings,
        "spec_ambiguities": ambiguities,
    }


def main() -> int:
    ap = argparse.ArgumentParser(description="KYA Bench adversarial fuzz audit harness")
    ap.add_argument("--json", action="store_true", help="print the summary as JSON")
    args = ap.parse_args()
    for fn in (line1, line2, line3, line4, line5, line6):
        fn()
    summary = tally()
    out_path = ROOT / "reports" / "fuzz-audit.json"
    out_path.write_text(json.dumps(summary, indent=2, ensure_ascii=False), encoding="utf-8")
    if args.json:
        print(json.dumps(summary, indent=2, ensure_ascii=False))
        return 0
    print("KYA Bench fuzz audit — probe classification\n")
    cols = ("caught", "evasion", "spec_ambiguity", "false_positive", "generator_error")
    print(f"{'line':<6}" + "".join(f"{c:>16}" for c in cols) + f"{'total':>8}")
    print("-" * (6 + 16 * len(cols) + 8))
    for k in sorted(summary["by_line"], key=int):
        row = summary["by_line"][k]
        tot = sum(row.values())
        print(f"{'L' + k:<6}" + "".join(f"{row[c]:>16}" for c in cols) + f"{tot:>8}")
    print("-" * (6 + 16 * len(cols) + 8))
    t = summary["totals"]
    print(f"{'ALL':<6}" + "".join(f"{t[c]:>16}" for c in cols) + f"{summary['total_probes']:>8}")
    print(f"\nwrote {out_path.relative_to(ROOT)}")
    print("\nEVASIONS / FALSE-POSITIVES / GENERATOR-ERRORS:")
    fnd = summary["findings"]
    if not fnd:
        print("  (none)")
    for f in fnd:
        print(f"  [L{f['line']}] {f['name']}: expect={f['expect']} observed={f['observed']}")
        if f["note"]:
            print(f"        {f['note']}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
