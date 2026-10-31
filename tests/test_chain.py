"""Verifier core: identity (L1), delegation chain (L2/L3), mode consistency."""

from __future__ import annotations

from kya_bench import LocalJwksResolver, verify
from kya_bench.testing.builder import (
    ISSUER,
    NOW,
    autonomous_spec,
    build,
    immediate_spec,
    jwks_fixture,
    public_jwk,
    sign_jws,
)


def rejected_with(v, code: str):
    assert v.verdict == "reject", v.to_json()
    assert code in v.codes(), sorted(v.codes())


# ---------------------------------------------------------------- happy paths


def test_immediate_accept(run):
    v = run(immediate_spec())
    assert (v.verdict, v.mode, v.identity_ok, v.delegation_chain_ok) == ("accept", "immediate", True, True)
    assert v.constraints == []


def test_autonomous_accept(run):
    v = run(autonomous_spec())
    assert (v.verdict, v.mode, v.identity_ok, v.delegation_chain_ok) == ("accept", "autonomous", True, True)
    assert {c.status for c in v.constraints} == {"pass"}
    assert len(v.constraints) == 5


def test_autonomous_l2_only_accept_with_unevaluated_constraints(run):
    spec = autonomous_spec()
    spec.include_l3 = ()
    v = run(spec)
    assert v.verdict == "accept"
    statuses = {c.type: c.status for c in v.constraints}
    assert statuses["mandate.payment.amount_range"] == "not_evaluated"
    assert statuses["mandate.payment.reference"] == "pass"


def test_expected_aud_nonce(run):
    spec = immediate_spec()
    spec.extra_bundle = {"expected": {"l2_aud": spec.l2_claims["aud"], "l2_nonce": spec.l2_claims["nonce"]}}
    v = run(spec)
    assert v.verdict == "accept" and "AUD_NOT_CHECKED" not in v.codes()
    spec.extra_bundle = {"expected": {"l2_aud": "https://other.example", "l2_nonce": "zzz"}}
    v = run(spec)
    rejected_with(v, "AUD_MISMATCH")
    assert "NONCE_MISMATCH" in v.codes()


# ---------------------------------------------------------------- L1 identity


def test_l1_signed_by_wrong_key(run):
    spec = immediate_spec()
    spec.signers["L1"] = "attacker"
    v = run(spec)
    rejected_with(v, "SIGNATURE_INVALID")
    assert not v.identity_ok


def test_l1_unknown_issuer_and_kid(run):
    spec = immediate_spec()
    spec.l1_claims["iss"] = "https://unknown-issuer.example"
    rejected_with(run(spec), "JWKS_ISSUER_UNKNOWN")
    spec = immediate_spec()
    spec.l1_header["kid"] = "rotated-away"
    rejected_with(run(spec), "JWKS_KID_NOT_FOUND")
    spec = immediate_spec()
    del spec.l1_header["kid"]
    rejected_with(run(spec), "HEADER_KID_MISSING")


def test_l1_ambiguous_kid():
    jwks = jwks_fixture()
    jwks[ISSUER]["keys"].append(dict(jwks[ISSUER]["keys"][0]))
    v = verify(build(immediate_spec()), strictness="strict", resolver=LocalJwksResolver(jwks), now=NOW)
    rejected_with(v, "JWKS_KID_AMBIGUOUS")


def test_l1_expiry_and_claims(run):
    spec = immediate_spec()
    spec.l1_claims["exp"] = NOW - 301
    rejected_with(run(spec), "TIME_EXPIRED")
    spec.l1_claims["exp"] = NOW - 299  # within clock skew
    assert run(spec).verdict == "accept"

    spec = immediate_spec()
    spec.l1_claims["vct"] = "not a uri"
    rejected_with(run(spec), "L1_VCT_INVALID")

    spec = immediate_spec()
    del spec.l1_claims["pan_last_four"]
    rejected_with(run(spec), "L1_PROFILE_CLAIM_MISSING")

    spec = immediate_spec()
    spec.l1_claims["sd_hash"] = "x"
    rejected_with(run(spec), "L1_SD_HASH_PRESENT")

    spec = immediate_spec()
    spec.l1_header["typ"] = "JWT"
    rejected_with(run(spec), "HEADER_TYP_INVALID")

    spec = immediate_spec()
    del spec.l1_claims["cnf"]
    v = run(spec)
    rejected_with(v, "CNF_MISSING")
    assert not v.delegation_chain_ok  # L2 signature cannot be checked


# ---------------------------------------------------------------- L2


def test_l2_signed_by_non_cnf_key(run):
    spec = immediate_spec()
    spec.signers["L2"] = "someone-else"
    v = run(spec)
    rejected_with(v, "SIGNATURE_INVALID")
    assert v.identity_ok and not v.delegation_chain_ok


def test_l2_sd_hash_must_bind_l1_as_received(run):
    bundle = build(immediate_spec())
    jws, *_ = bundle["l1"].split("~")
    bundle["l1"] = jws + "~"  # same L1, email disclosure withheld -> different serialization
    rejected_with(run(bundle), "SD_HASH_MISMATCH")

    spec = immediate_spec()
    spec.hooks["L2_payload"] = lambda p: p.pop("sd_hash")
    rejected_with(run(spec), "SD_HASH_MISSING")


def test_l2_time(run):
    spec = immediate_spec()
    spec.l2_claims["exp"] = NOW - 400
    rejected_with(run(spec), "TIME_EXPIRED")
    spec = immediate_spec()
    spec.l2_claims["iat"] = NOW + 400
    spec.l2_claims["exp"] = NOW + 900
    rejected_with(run(spec), "TIME_IAT_FUTURE")
    spec = autonomous_spec()
    spec.l2_claims["exp"] = spec.l1_claims["exp"] + 1
    rejected_with(run(spec), "TIME_LIFETIME_EXCEEDED")


def test_l2_typ_must_match_mode(run):
    spec = immediate_spec()
    spec.l2_header["typ"] = "kb-sd-jwt+kb"
    rejected_with(run(spec), "HEADER_TYP_INVALID")
    spec = autonomous_spec()
    spec.l2_header["typ"] = "kb-sd-jwt"
    rejected_with(run(spec), "HEADER_TYP_INVALID")


def test_immediate_mandate_rules(run):
    spec = immediate_spec()
    spec.payment_mandate["cnf"] = {"jwk": public_jwk("agent", "agent-key-1")}
    rejected_with(run(spec), "CNF_FORBIDDEN")

    spec = immediate_spec()
    spec.checkout_mandate["constraints"] = [{"type": "mandate.payment.amount_range", "currency": "USD"}]
    rejected_with(run(spec), "MANDATE_CONSTRAINTS_FORBIDDEN")

    spec = immediate_spec()
    spec.checkout_mandate["checkout_hash"] = "AAAA"
    rejected_with(run(spec), "CHECKOUT_HASH_MISMATCH")

    spec = immediate_spec()
    spec.payment_mandate["transaction_id"] = "not-the-checkout-hash"
    rejected_with(run(spec), "MANDATE_ORPHAN")


def test_unknown_mandate_vct(run):
    spec = immediate_spec()
    spec.payment_mandate["vct"] = "mandate.payment.2"
    rejected_with(run(spec), "VCT_UNKNOWN")


def test_mixed_mode_rejected(run):
    spec = autonomous_spec()
    spec.payment_mandate["vct"] = "mandate.payment.1"
    rejected_with(run(spec), "MODE_MIXED")


def test_immediate_with_l3_rejected(run):
    imm = build(immediate_spec())
    auto = build(autonomous_spec())
    imm["l3a"] = auto["l3a"]
    rejected_with(run(imm), "MODE_L3_IN_IMMEDIATE")


def test_autonomous_mandate_rules(run):
    spec = autonomous_spec()
    del spec.checkout_mandate["cnf"]
    rejected_with(run(spec), "CNF_MISSING")

    spec = autonomous_spec()
    del spec.payment_mandate["cnf"]["jwk"]["kid"]
    rejected_with(run(spec), "CNF_KID_MISSING")

    spec = autonomous_spec()
    spec.payment_mandate["cnf"] = {"jwk": public_jwk("other-agent", "agent-key-1")}
    rejected_with(run(spec), "CNF_PAIR_MISMATCH")

    spec = autonomous_spec()
    spec.checkout_mandate["constraints"] = []
    rejected_with(run(spec), "MANDATE_CONSTRAINTS_EMPTY")

    spec = autonomous_spec()
    spec.payment_mandate["constraints"] = spec.payment_mandate["constraints"][:2]
    v = run(spec)
    rejected_with(v, "PAYMENT_REFERENCE_MISSING")
    assert "MANDATE_ORPHAN" in v.codes()

    spec = autonomous_spec()
    spec.payment_mandate["constraints"][2]["conditional_transaction_id"] = "wrong"
    rejected_with(run(spec), "MANDATE_ORPHAN")


def test_partial_l2_disclosure_is_not_orphan(run):
    spec = autonomous_spec()
    spec.include_l3 = ()
    spec.l2_disclose = ["$checkout", "$merchant:0", "$merchant:1", "$item:0"]
    v = run(spec)
    assert v.verdict == "accept", v.to_json()["reasons"]


# ---------------------------------------------------------------- L3


def test_l3_signed_by_wrong_agent(run):
    spec = autonomous_spec()
    spec.signers["L3a"] = "rogue-agent"
    v = run(spec)
    rejected_with(v, "SIGNATURE_INVALID")
    assert not v.delegation_chain_ok


def test_l3_kid_and_header_rules(run):
    spec = autonomous_spec()
    spec.l3b_header["kid"] = "agent-key-2"
    rejected_with(run(spec), "L3_KID_MISMATCH")

    spec = autonomous_spec()
    spec.l3a_header["jwk"] = public_jwk("agent")
    rejected_with(run(spec), "HEADER_JWK_FORBIDDEN")

    spec = autonomous_spec()
    spec.l3a_header["typ"] = "kb-sd-jwt+kb"
    rejected_with(run(spec), "HEADER_TYP_INVALID")


def test_l3_payload_rules(run):
    spec = autonomous_spec()
    spec.hooks["L3a_payload"] = lambda p: p.update(cnf={"jwk": public_jwk("x")})
    rejected_with(run(spec), "CNF_FORBIDDEN")

    spec = autonomous_spec()
    spec.l3b_checkout["constraints"] = []
    rejected_with(run(spec), "MANDATE_CONSTRAINTS_FORBIDDEN")

    spec = autonomous_spec()
    spec.l3a_claims["nonce"] = spec.l2_claims["nonce"]
    rejected_with(run(spec), "NONCE_REUSED")

    spec = autonomous_spec()
    spec.l3a_claims["exp"] = spec.l3a_claims["iat"] + 3601
    rejected_with(run(spec), "TIME_LIFETIME_EXCEEDED")

    spec = autonomous_spec()
    spec.l3b_claims["exp"] = NOW - 301
    rejected_with(run(spec), "TIME_EXPIRED")

    spec = autonomous_spec()
    spec.l3a_payment["payment_amount"]["amount"] = "279.99"
    rejected_with(run(spec), "L3_AMOUNT_NOT_INTEGER")


def test_l3_sd_hash_selective_binding(run):
    bundle = build(autonomous_spec())
    full_l2 = bundle["l2"]
    # L3a was bound to the network view; presenting a different view breaks sd_hash.
    bundle["l2_view_l3a"] = full_l2
    rejected_with(run(bundle), "SD_HASH_MISMATCH")

    bundle = build(autonomous_spec())
    other = build(immediate_spec())["l2"].split("~")[1]
    bundle["l2_view_l3b"] = bundle["l2_view_l3b"] + other + "~"
    rejected_with(run(bundle), "L3_VIEW_FOREIGN_DISCLOSURE")

    bundle = build(autonomous_spec())
    jws = bundle["l2"].split("~")[0]
    other_spec = autonomous_spec()
    other_spec.l2_claims["nonce"] = "another-l2-nonce"  # builds are deterministic; force a different L2 JWT
    bundle["l2_view_l3b"] = bundle["l2_view_l3b"].replace(jws, build(other_spec)["l2"].split("~")[0])
    rejected_with(run(bundle), "L3_VIEW_BASE_MISMATCH")


def test_l3_view_fallback_warns(run):
    spec = autonomous_spec()
    spec.include_views = False
    spec.view_l3a_items = ["$merchant:0", "$merchant:1", "$item:0", "$checkout", "$payment"]
    spec.view_l3b_items = list(spec.view_l3a_items)
    v = run(spec)
    assert v.verdict == "accept", v.to_json()["reasons"]
    assert "L3_VIEW_FALLBACK" in v.codes()


def test_l3_cross_reference(run):
    spec = autonomous_spec()
    spec.l3a_payment["transaction_id"] = "some-other-checkout"
    rejected_with(run(spec), "L3_CROSS_REF_MISMATCH")

    spec = autonomous_spec()
    spec.l3b_checkout["checkout_hash"] = "AAAA"
    rejected_with(run(spec), "CHECKOUT_HASH_MISMATCH")


def test_single_l3_skips_cross_reference(run):
    spec = autonomous_spec()
    spec.include_l3 = ("l3a",)
    v = run(spec)
    assert v.verdict == "accept"
    assert any(c.id == "L3.cross_reference" and c.status == "skipped" for c in v.checks)
    assert {c.type: c.status for c in v.constraints}["mandate.checkout.line_items"] == "not_evaluated"


def test_l3_missing_mandate(run):
    spec = autonomous_spec()
    spec.l3a_payment["vct"] = "mandate.checkout.1"
    v = run(spec)
    rejected_with(v, "L3_MANDATE_MISSING")


def test_verdict_json_shape(run):
    out = run(autonomous_spec()).to_json()
    for key in ("verdict", "identity_ok", "delegation_chain_ok", "constraints", "reasons", "warnings", "checks",
                "strictness", "mode", "protocol", "spec_version"):
        assert key in out
    assert out["constraints"][0].keys() >= {"type", "status", "messages", "constraint", "mandate"}


def test_never_raises_on_bad_bundles(run):
    for bundle in [None, 1, "not json", "[]", {}, {"l1": 1, "l2": None}, {"l1": "x~", "l2": "y~", "l3a": 5}]:
        v = run(bundle)
        assert v.verdict == "reject"


def test_sign_helper_roundtrip():
    tok = sign_jws({"alg": "ES256"}, {"a": 1}, "issuer")
    assert tok.count(".") == 2


# ---------------------------------------------------------------- normalized output fields


def test_output_fields_accept(run):
    out = run(autonomous_spec()).to_json()
    assert out["evaluated_at"] == NOW
    assert out["reason_codes"] == [] and out["unknown_constraints"] == []
    assert out["cross_refs"] == {
        "l3a_l3b_match": True, "l3a_l3b_same_pair": True, "l2_sd_hash_l1": True,
        "l3a_sd_hash_l2_view": True, "l3b_sd_hash_l2_view": True, "l3a_kid_l2_cnf": True,
        "l3b_kid_l2_cnf": True, "l2_mandate_pairing": True, "l2_checkout_hash": None, "l3b_checkout_hash": True,
    }
    assert {c["status"] for c in out["constraints"]} == {"satisfied"}
    assert all(set(c) >= {"type", "status", "detail"} for c in out["constraints"])


def test_output_fields_reject(run):
    spec = autonomous_spec()
    spec.l3a_payment["transaction_id"] = "unrelated"
    spec.l3a_payment["payment_amount"]["amount"] = 50000
    out = run(spec).to_json()
    assert out["cross_refs"]["l3a_l3b_match"] is False
    assert out["reason_codes"] == ["L3_CROSS_REF_MISMATCH", "CONSTRAINT_VIOLATION"]
    amount = next(c for c in out["constraints"] if c["type"] == "mandate.payment.amount_range")
    assert (amount["status"], amount["detail"]) == ("violated", "Amount exceeded: 50000 > 40000 USD")

    spec = autonomous_spec()
    spec.include_l3 = ()
    out = run(spec).to_json()
    assert {c["status"] for c in out["constraints"]} == {"not_checked", "satisfied"}
    assert out["cross_refs"]["l3a_l3b_match"] is None
