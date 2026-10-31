"""Deterministic conformance-vector generator.

    python tools/generate_fixtures.py [--out fixtures]

Writes ``<out>/jwks.json`` and ``<out>/vectors/<id>.json`` (one vector per file,
see ``kya_bench.suite`` for the format) plus ``vectors/manifest.json``. Running
it twice produces byte-identical files: keys come from ``SEED``, timestamps from
``NOW``, signatures are RFC 6979 deterministic. All keys are TEST-ONLY.

Each vector's expected verdict and reason codes are declared by hand below;
generation fails if the verifier disagrees, so the generator never snapshots
whatever the verifier happens to say.
"""

from __future__ import annotations

import argparse
import json
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from ..keys import LocalJwksResolver
from ..parser import b64url_decode, b64url_encode
from ..context import Fixtures
from ..suite import FORMAT, MANIFEST, PAYLOAD_FIELD, evaluate_vector, vector_fields
from .builder import NOW, SEED, autonomous_spec, build, immediate_spec, jwks_fixture, public_jwk

UNKNOWN = {"type": "com.acme.loyalty-points", "points": 500}


# --------------------------------------------------------------------------
# bundle tampering helpers (applied after signing)
# --------------------------------------------------------------------------


def _edit_payload(sd_jwt: str, fn: Callable[[dict[str, Any]], None]) -> str:
    jws, *rest = sd_jwt.split("~")
    h, p, s = jws.split(".")
    payload = json.loads(b64url_decode(p))
    fn(payload)
    p2 = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    return "~".join([f"{h}.{p2}.{s}", *rest])


def _flip_signature(sd_jwt: str) -> str:
    jws, *rest = sd_jwt.split("~")
    h, p, s = jws.split(".")
    s2 = ("B" if s[0] == "A" else "A") + s[1:]  # first char: always changes the decoded bytes
    return "~".join([f"{h}.{p}.{s2}", *rest])


def _spec(base: Callable[[], Any], mutate: Callable[[Any], None] | None = None) -> Callable[[], dict[str, Any]]:
    def make() -> dict[str, Any]:
        s = base()
        if mutate:
            mutate(s)
        return build(s)

    return make


def _bundle(base: Callable[[], Any], post: Callable[[dict[str, Any]], Any]) -> Callable[[], Any]:
    def make() -> Any:
        b = build(base())
        out = post(b)
        return b if out is None else out

    return make


def _set(d: dict[str, Any], **kw: Any) -> None:
    d.update(kw)


class Payload(dict):
    """A non-bundle vector payload, tagged with its ``kind``."""

    def __init__(self, kind: str, value: dict[str, Any]):
        super().__init__(value)
        self.kind = kind


def _engine(constraints: list[Any], is_open: bool, fulfillment: dict[str, Any] | None = None):
    return lambda: Payload("constraint_check", {
        "constraints": constraints,
        "fulfillment": fulfillment,
        "is_open_mandate": is_open,
        "mandate": "payment",
    })


# --------------------------------------------------------------------------
# mutations used by several vectors
# --------------------------------------------------------------------------


def _l2_only(s):
    s.include_l3 = ()


def _multi_pair(s):
    s.pairs = 2
    s.view_l3a_items = ["$payment", "$merchant:0"]
    s.view_l3b_items = ["$checkout", "$item:0"]


def _add_payment_constraints(*cs, state=None):
    def mutate(s):
        s.payment_mandate["constraints"][0:0] = [dict(c) for c in cs]
        if state is not None:
            s.extra_bundle = {"network_state": state}
    return mutate


def _immediate_with_l3(b):
    auto = build(autonomous_spec())
    b["l3a"], b["l3b"] = auto["l3a"], auto["l3b"]


def _foreign_view(b):
    b["l2_view_l3b"] += build(immediate_spec())["l2"].split("~")[1] + "~"


def _drop_l1_disclosures(b):
    b["l1"] = b["l1"].split("~")[0] + "~"


def _unreferenced_disclosure(b):
    from .builder import disclosure

    b["l2"] += disclosure({"note": "not committed to by the signer"}, "c2FsdA") + "~"


# --------------------------------------------------------------------------
# the vector set: (id, category, spec_ref, description, strictness, make, verdict, codes)
# --------------------------------------------------------------------------

A, I = autonomous_spec, immediate_spec

VECTORS: list[tuple[str, str, str, str, str, Callable[[], Any], str, list[str]]] = [
    # valid ---------------------------------------------------------------
    ("immediate-valid", "valid", "CF §4.4, §4.7",
     "Immediate mode L1+L2 with final checkout/payment mandates; every check passes",
     "strict", _spec(I), "accept", []),
    ("autonomous-valid", "valid", "CF §4.5, §5; C §4",
     "Autonomous mode L1+L2+L3a+L3b; chain valid and all constraints satisfied",
     "strict", _spec(A), "accept", []),
    ("autonomous-l2-only", "valid", "CF §13.4.11; C §5.1",
     "Open mandate before fulfillment: chain valid, constraints not checked",
     "strict", _spec(A, _l2_only), "accept", []),
    ("autonomous-multi-pair", "valid", "CF §8.1, §8.2, §5.4",
     "L2 with two mandate pairs; L3 bound to the first pair through its selective views",
     "strict", _spec(A, _multi_pair), "accept", []),
    # expiry --------------------------------------------------------------
    ("l1-expired", "expiry", "CF §3.5 rule 4", "L1 exp beyond the 300 s clock skew",
     "strict", _spec(I, lambda s: _set(s.l1_claims, exp=NOW - 3600)), "reject", ["TIME_EXPIRED"]),
    ("l2-expired", "expiry", "CF §4.7 rule 4", "L2 exp in the past",
     "strict", _spec(I, lambda s: _set(s.l2_claims, exp=NOW - 400)), "reject", ["TIME_EXPIRED"]),
    ("l2-iat-in-future", "expiry", "CF §4.7 rule 4", "L2 iat later than now + clock skew",
     "strict", _spec(I, lambda s: _set(s.l2_claims, iat=NOW + 400, exp=NOW + 900)), "reject", ["TIME_IAT_FUTURE"]),
    ("l3a-expired", "expiry", "CF §5.7 rule 6", "L3a exp in the past",
     "strict", _spec(A, lambda s: _set(s.l3a_claims, exp=NOW - 301)), "reject", ["TIME_EXPIRED"]),
    ("l3b-expired", "expiry", "CF §5.7 rule 6", "L3b exp in the past",
     "strict", _spec(A, lambda s: _set(s.l3b_claims, exp=NOW - 301)), "reject", ["TIME_EXPIRED"]),
    ("l3-lifetime-over-1h", "expiry", "CF §5.3, §7", "L3a lifetime longer than the 1 hour maximum",
     "strict", _spec(A, lambda s: _set(s.l3a_claims, exp=s.l3a_claims["iat"] + 3601)), "reject",
     ["TIME_LIFETIME_EXCEEDED"]),
    ("l2-autonomous-outlives-l1", "expiry", "CF §7", "Autonomous L2 exp later than L1 exp",
     "strict", _spec(A, lambda s: _set(s.l2_claims, exp=s.l1_claims["exp"] + 1)), "reject",
     ["TIME_LIFETIME_EXCEEDED"]),
    # signature -----------------------------------------------------------
    ("l1-bad-signature", "signature", "CF §3.5 rule 3", "L1 signed by a key other than the JWKS key",
     "strict", _spec(I, lambda s: s.signers.update(L1="attacker")), "reject", ["SIGNATURE_INVALID"]),
    ("l1-unknown-kid", "signature", "CF §3.5 rule 2", "L1 kid not present in the issuer JWKS",
     "strict", _spec(I, lambda s: _set(s.l1_header, kid="rotated-away")), "reject", ["JWKS_KID_NOT_FOUND"]),
    ("l2-wrong-signer", "signature", "CF §4.7 rule 1", "L2 not signed by the L1 cnf.jwk key",
     "strict", _spec(I, lambda s: s.signers.update(L2="not-the-user")), "reject", ["SIGNATURE_INVALID"]),
    ("l2-payload-tampered", "signature", "CF §4.7 rule 1; C §7.5", "L2 payload aud changed after signing",
     "strict", _bundle(I, lambda b: _set(b, l2=_edit_payload(b["l2"], lambda p: _set(p, aud="https://evil.example")))),
     "reject", ["SIGNATURE_INVALID"]),
    ("l3a-wrong-agent-key", "signature", "CF §5.7 rule 2", "L3a signed by a key other than L2 cnf.jwk",
     "strict", _spec(A, lambda s: s.signers.update(L3a="rogue-agent")), "reject", ["SIGNATURE_INVALID"]),
    ("l3b-signature-tampered", "signature", "CF §5.7 rule 2", "L3b signature bytes altered",
     "strict", _bundle(A, lambda b: _set(b, l3b=_flip_signature(b["l3b"]))), "reject", ["SIGNATURE_INVALID"]),
    # sd_hash -------------------------------------------------------------
    ("l2-sd-hash-mismatch", "sd_hash", "CF §4.7 rule 2, §6.1", "L2 sd_hash does not hash the presented L1",
     "strict", _spec(I, lambda s: s.hooks.update(L2_payload=lambda p: _set(p, sd_hash="A" * 43))), "reject",
     ["SD_HASH_MISMATCH"]),
    ("l2-sd-hash-l1-presentation-changed", "sd_hash", "CF §6.1",
     "L1 re-presented without the disclosure the L2 signer received",
     "strict", _bundle(I, _drop_l1_disclosures), "reject", ["SD_HASH_MISMATCH"]),
    ("l3a-sd-hash-wrong-view", "sd_hash", "CF §5.4, §5.7 rule 4",
     "L3a checked against the full L2 instead of the network view it bound to",
     "strict", _bundle(A, lambda b: _set(b, l2_view_l3a=b["l2"])), "reject", ["SD_HASH_MISMATCH"]),
    ("l3b-view-foreign-disclosure", "sd_hash", "CF §5.4", "L2 view for L3b carries a disclosure L2 never committed to",
     "strict", _bundle(A, _foreign_view), "reject", ["L3_VIEW_FOREIGN_DISCLOSURE"]),
    # key binding ---------------------------------------------------------
    ("l3-kid-mismatch", "key_binding", "CF §5.2, §5.7 rule 1", "L3b kid does not match L2 cnf.jwk.kid",
     "strict", _spec(A, lambda s: _set(s.l3b_header, kid="agent-key-2")), "reject", ["L3_KID_MISMATCH"]),
    ("l2-cnf-pair-mismatch", "key_binding", "CF §4.6", "Checkout and payment mandates bind different agent keys",
     "strict", _spec(A, lambda s: _set(s.payment_mandate, cnf={"jwk": public_jwk("other-agent", "agent-key-1")})),
     "reject", ["CNF_PAIR_MISMATCH"]),
    ("l2-autonomous-cnf-missing", "key_binding", "CF §4.7 rule 6", "Autonomous checkout mandate without cnf.jwk",
     "strict", _spec(A, lambda s: s.checkout_mandate.pop("cnf")), "reject", ["CNF_MISSING"]),
    ("l3-header-jwk", "key_binding", "CF §13.3 rule 3, §13.4 rule 7", "L3a header carries a self-asserted jwk",
     "strict", _spec(A, lambda s: _set(s.l3a_header, jwk=public_jwk("agent"))), "reject", ["HEADER_JWK_FORBIDDEN"]),
    ("l3-cnf-present", "key_binding", "CF §5.7 rule 5", "L3a payload contains a cnf claim",
     "strict", _spec(A, lambda s: s.hooks.update(L3a_payload=lambda p: _set(p, cnf={"jwk": public_jwk("x")}))),
     "reject", ["CNF_FORBIDDEN"]),
    ("immediate-cnf-present", "key_binding", "CF §4.7 rule 5", "Immediate payment mandate contains cnf",
     "strict", _spec(I, lambda s: _set(s.payment_mandate, cnf={"jwk": public_jwk("agent", "agent-key-1")})),
     "reject", ["CNF_FORBIDDEN"]),
    # cross references ----------------------------------------------------
    ("l3-cross-reference-mismatch", "cross_ref", "CF §5.7 rule 10, §6.2", "L3a.transaction_id != L3b.checkout_hash",
     "strict", _spec(A, lambda s: _set(s.l3a_payment, transaction_id="unrelated-checkout")), "reject",
     ["L3_CROSS_REF_MISMATCH"]),
    ("l3b-checkout-hash-mismatch", "cross_ref", "CF §6.2", "L3b checkout_hash is not the hash of its checkout_jwt",
     "strict", _spec(A, lambda s: _set(s.l3b_checkout, checkout_hash="A" * 43)), "reject",
     ["CHECKOUT_HASH_MISMATCH"]),
    ("immediate-transaction-id-mismatch", "cross_ref", "CF §8.2", "Immediate payment transaction_id matches no checkout",
     "strict", _spec(I, lambda s: _set(s.payment_mandate, transaction_id="not-the-checkout-hash")), "reject",
     ["MANDATE_ORPHAN"]),
    # mode ----------------------------------------------------------------
    ("immediate-with-l3", "mode", "CF §2, §5.1", "L3 presented with an Immediate-mode L2",
     "strict", _bundle(I, _immediate_with_l3), "reject", ["MODE_L3_IN_IMMEDIATE"]),
    ("mixed-mode-mandates", "mode", "CF §4.6", "L2 mixes an open checkout and a final payment mandate",
     "strict", _spec(A, lambda s: _set(s.payment_mandate, vct="mandate.payment.1")), "reject", ["MODE_MIXED"]),
    ("l2-typ-mode-mismatch", "mode", "CF §4.7 rule 3", "Autonomous mandates under typ kb-sd-jwt",
     "strict", _spec(A, lambda s: _set(s.l2_header, typ="kb-sd-jwt")), "reject", ["HEADER_TYP_INVALID"]),
    ("immediate-with-constraints", "mode", "CF §4.4.1; C §2.2", "Immediate checkout mandate carries constraints",
     "strict", _spec(I, lambda s: _set(s.checkout_mandate, constraints=[
         {"type": "mandate.payment.amount_range", "currency": "USD", "max": 1}])), "reject",
     ["MANDATE_CONSTRAINTS_FORBIDDEN"]),
    # constraint violations (one per registered type) --------------------
    ("constraint-allowed-merchants-violated", "constraint", "C §4.1",
     "checkout_jwt merchant is not in the disclosed allowlist",
     "strict", _spec(A, lambda s: _set(s.checkout_jwt_payload, id="merchant-uuid-999", name="Shady",
                                       website="https://shady.example")), "reject", ["CONSTRAINT_VIOLATION"]),
    ("constraint-line-items-violated", "constraint", "C §4.2, §8.3", "L3b selects an item outside acceptable_items",
     "strict", _spec(A, lambda s: _set(s.l3b_checkout["line_items"][0], item={"id": "PRI99101", "title": "String"})),
     "reject", ["CONSTRAINT_VIOLATION"]),
    ("constraint-allowed-payees-violated", "constraint", "C §4.3, §8.3", "L3a payee is not an allowed payee",
     "strict", _spec(A, lambda s: _set(s.l3a_payment, payee={"name": "Unauthorized Store",
                                                             "website": "https://unauthorized-store.example.com"})),
     "reject", ["CONSTRAINT_VIOLATION"]),
    ("constraint-amount-exceeded", "constraint", "C §4.4, §8.3", "L3a amount above amount_range max",
     "strict", _spec(A, lambda s: _set(s.l3a_payment["payment_amount"], amount=50000)), "reject",
     ["CONSTRAINT_VIOLATION"]),
    ("constraint-budget-violated", "constraint", "C §4.5 step 3", "L3a amount below the budget per-transaction minimum",
     "strict", _spec(A, _add_payment_constraints({"type": "mandate.payment.budget", "currency": "USD", "min": 30000,
                                                  "max": 90000}, state={"cumulative_spent": 0})),
     "reject", ["CONSTRAINT_VIOLATION"]),
    ("constraint-recurrence-violated", "constraint", "C §4.6", "Merchant recurrence with a non-ISO 20022 frequency",
     "strict", _spec(A, _add_payment_constraints({"type": "mandate.payment.recurrence", "frequency": "SOMETIMES",
                                                  "start_date": "2026-09-01", "end_date": "2027-09-01",
                                                  "number": 12})),
     "reject", ["CONSTRAINT_MALFORMED"]),
    ("constraint-agent-recurrence-violated", "constraint", "C §4.7 step 1",
     "Agent-managed recurrence whose window ended before the transaction",
     "strict", _spec(A, _add_payment_constraints(
         {"type": "mandate.payment.agent_recurrence", "frequency": "ON_DEMAND", "start_date": "2026-08-01",
          "end_date": "2026-08-31", "max_occurrences": 5},
         {"type": "mandate.payment.budget", "currency": "USD", "max": 90000},
         state={"cumulative_spent": 0, "occurrence_count": 0})),
     "reject", ["CONSTRAINT_VIOLATION"]),
    ("constraint-reference-violated", "constraint", "C §4.8; CF §4.5.3, §8.2",
     "Payment reference conditional_transaction_id does not hash the checkout mandate disclosure",
     "strict", _spec(A, lambda s: _set(s.payment_mandate["constraints"][2], conditional_transaction_id="A" * 43)),
     "reject", ["MANDATE_ORPHAN", "CONSTRAINT_VIOLATION"]),
    # budget (cumulative) -------------------------------------------------
    ("budget-cumulative-exceeded", "budget", "C §4.5 steps 4-6",
     "Network state 30000 + this 27999 exceeds the 50000 budget",
     "strict", _spec(A, _add_payment_constraints({"type": "mandate.payment.budget", "currency": "USD", "max": 50000},
                                                 state={"cumulative_spent": 30000})),
     "reject", ["CONSTRAINT_VIOLATION"]),
    ("budget-cumulative-within", "budget", "C §4.5", "Network state 10000 + this 27999 stays within the 50000 budget",
     "strict", _spec(A, _add_payment_constraints({"type": "mandate.payment.budget", "currency": "USD", "max": 50000},
                                                 state={"cumulative_spent": 10000})),
     "accept", []),
    ("budget-without-network-state", "budget", "C §4.5; spec gap G-05",
     "Cumulative budget with no network state supplied: outcome undefined",
     "strict", _spec(A, _add_payment_constraints({"type": "mandate.payment.budget", "currency": "USD", "max": 50000})),
     "indeterminate", ["SPEC_GAP"]),
    # unknown constraint types -------------------------------------------
    ("open-mandate-unknown-constraint", "unknown_constraint", "C §5.3, §5.4",
     "Unknown constraint type in an open payment mandate (strict)",
     "strict", _spec(A, _add_payment_constraints(UNKNOWN)), "reject", ["CONSTRAINT_UNKNOWN_OPEN_MANDATE"]),
    ("open-mandate-unknown-constraint-permissive", "unknown_constraint", "C §5.4",
     "Same under PERMISSIVE: open mandates reject unknown types regardless of strictness",
     "permissive", _spec(A, _add_payment_constraints(UNKNOWN)), "reject", ["CONSTRAINT_UNKNOWN_OPEN_MANDATE"]),
    ("open-mandate-unknown-constraint-unfulfilled", "unknown_constraint", "C §5.4",
     "Unknown type in an open checkout mandate before any L3 exists",
     "permissive", _spec(A, lambda s: (_l2_only(s), s.checkout_mandate["constraints"].append(
         {"type": "urn:example:gift-wrap", "required": True}))), "reject", ["CONSTRAINT_UNKNOWN_OPEN_MANDATE"]),
    ("engine-unknown-non-open-permissive", "unknown_constraint", "C §5.3, §5.4 PERMISSIVE",
     "Constraint engine called directly with is_open_mandate=false: unknown type skipped with a warning",
     "permissive", _engine([UNKNOWN], False), "accept", ["CONSTRAINT_UNKNOWN_SKIPPED"]),
    ("engine-unknown-non-open-strict", "unknown_constraint", "C §5.3, §5.4 STRICT",
     "Constraint engine called directly with is_open_mandate=false under STRICT: rejected",
     "strict", _engine([UNKNOWN], False), "reject", ["CONSTRAINT_UNKNOWN_STRICT"]),
    ("engine-unknown-open-permissive", "unknown_constraint", "C §5.4",
     "Constraint engine called directly with is_open_mandate=true under PERMISSIVE: rejected",
     "permissive", _engine([UNKNOWN], True), "reject", ["CONSTRAINT_UNKNOWN_OPEN_MANDATE"]),
    # malformed input -----------------------------------------------------
    ("malformed-bundle-not-json", "malformed", "KYA Bench bundle", "Bundle is not JSON",
     "strict", lambda: "{not json", "reject", ["BUNDLE_INVALID"]),
    ("malformed-missing-l1", "malformed", "KYA Bench bundle", "Bundle has no L1",
     "strict", _bundle(I, lambda b: b.pop("l1") and None), "reject", ["LAYER_MISSING"]),
    ("malformed-l2-no-trailing-tilde", "malformed", "RFC 9901 §4; CF §6.1", "L2 serialization lacks the trailing '~'",
     "strict", _bundle(I, lambda b: _set(b, l2=b["l2"].rstrip("~"))), "reject", ["SDJWT_NO_TRAILING_TILDE"]),
    ("malformed-disclosure-not-base64", "malformed", "RFC 9901 §4.2", "L2 carries a disclosure that is not base64url",
     "strict", _bundle(I, lambda b: _set(b, l2=b["l2"] + "!!not-base64!!~")), "reject", ["DISCLOSURE_BASE64"]),
    ("malformed-unreferenced-disclosure", "malformed", "RFC 9901 §7.1",
     "L2 carries a disclosure whose digest the signed payload never lists",
     "strict", _bundle(I, _unreferenced_disclosure), "reject", ["DISCLOSURE_UNREFERENCED"]),
    # spec gaps -----------------------------------------------------------
    ("gap-g02-checkout-jwt-without-merchant-id", "spec_gap", "C §4.1 step 4; CF §6.3; spec gap G-02",
     "allowed_merchants cannot be validated: checkout_jwt has no merchant id",
     "strict", _spec(A, lambda s: [s.checkout_jwt_payload.pop(k) for k in ("id", "name", "website")]),
     "indeterminate", ["SPEC_GAP"]),
    ("gap-g03-line-items-sku-shape", "spec_gap", "CF §5.5 vs C §4.2; spec gap G-03",
     "L3b line_items in the credential-format example shape (sku) instead of item.id",
     "strict", _spec(A, lambda s: _set(s.l3b_checkout, line_items=[
         {"sku": "BAB86345", "name": "Babolat Pure Aero", "quantity": 1, "unit_price": 27999, "currency": "USD"}])),
     "indeterminate", ["SPEC_GAP"]),
]


def make_vector(protocol: str, vid: str, cat: str, ref: str, desc: str, strictness: str, payload: Any,
                verdict: str, codes: list[str], now: int = NOW) -> dict[str, Any]:
    kind = payload.kind if isinstance(payload, Payload) else "bundle"
    vector = {
        "id": vid,
        "protocol": protocol,
        "kind": kind,
        "category": cat,
        "description": desc,
        "spec_ref": ref,
        "strictness": strictness,
        "now": now,
        PAYLOAD_FIELD[kind]: dict(payload) if isinstance(payload, Payload) else payload,
        "expected_verdict": verdict,
        "expected_reason_codes": codes,
    }
    assert list(vector) == list(vector_fields(kind))
    return vector


def build_vectors() -> list[dict[str, Any]]:
    from .phase2_vectors import phase2_vectors

    out = [make_vector("vi", vid, cat, ref, desc, strictness, make(), verdict, codes)
           for vid, cat, ref, desc, strictness, make, verdict, codes in VECTORS]
    return out + phase2_vectors()


def _dump(obj: Any) -> str:
    return json.dumps(obj, indent=2, ensure_ascii=True) + "\n"


def generate(out: Path) -> list[dict[str, Any]]:
    """Write jwks.json and vectors/ under ``out``; verify every expectation first."""
    from .phase2_vectors import fixture_documents

    jwks = jwks_fixture()
    extra_docs = fixture_documents()
    jwks.update(extra_docs["jwks"])
    fixtures = Fixtures(LocalJwksResolver(jwks), jwks, extra_docs["tap_registry"])
    vectors = build_vectors()
    ids = [v["id"] for v in vectors]
    if len(ids) != len(set(ids)):
        raise SystemExit("duplicate vector ids")
    failures = [r for r in (evaluate_vector(v, fixtures) for v in vectors) if not r.match]
    if failures:
        lines = [f"  {r.id}: expected {r.expected_verdict} {r.expected_codes}, got {r.verdict} {r.codes}"
                 for r in failures]
        raise SystemExit("declared expectations disagree with the verifier:\n" + "\n".join(lines))

    vdir = out / "vectors"
    vdir.mkdir(parents=True, exist_ok=True)
    for stale in vdir.glob("*.json"):
        if stale.stem not in ids and stale.name != MANIFEST:
            stale.unlink()
    (out / "jwks.json").write_text(_dump(jwks))
    (out / "tap_registry.json").write_text(_dump(extra_docs["tap_registry"]))
    for v in vectors:
        (vdir / f"{v['id']}.json").write_text(_dump(v))
    manifest = {
        "format": FORMAT,
        "generator": "kya_bench.testing.vectors",
        "seed": SEED,
        "test_keys_only": True,
        "verification_time": NOW,
        "jwks": "jwks.json",
        "tap_registry": "tap_registry.json",
        "count": len(vectors),
        "protocols": dict(sorted(Counter(v["protocol"] for v in vectors).items())),
        "categories": dict(sorted(Counter(f"{v['protocol']}/{v['category']}" for v in vectors).items())),
        "vectors": ids,
    }
    (vdir / MANIFEST).write_text(_dump(manifest))
    return vectors


def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(description="Regenerate KYA Bench fixtures deterministically")
    ap.add_argument("--out", type=Path, default=Path(__file__).resolve().parents[3] / "fixtures")
    args = ap.parse_args(argv)
    vectors = generate(args.out)
    counts = Counter(f"{v['protocol']}/{v['category']}" for v in vectors)
    print(f"wrote {len(vectors)} vectors to {args.out / 'vectors'}")
    for cat, n in sorted(counts.items()):
        print(f"  {cat:32} {n}")
