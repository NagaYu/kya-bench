"""Phase 2: TAP, AP2, composition and translation beyond the vector suite."""

from __future__ import annotations

import pytest

from kya_bench.ap2 import verify_ap2
from kya_bench.context import Fixtures
from kya_bench.keys import LocalJwksResolver
from kya_bench.sf import SFError, parse_dictionary
from kya_bench.tap import NonceCache, verify_tap
from kya_bench.testing.ap2_builder import Ap2Spec
from kya_bench.testing.ap2_builder import build as ap2_build
from kya_bench.testing.builder import NOW
from kya_bench.testing.phase2_vectors import _mixed_flows, fixture_documents
from kya_bench.testing.tap_builder import TapRequest, apc, bundle
from kya_bench.xproto.composition import verify_composition
from kya_bench.xproto.translate import check_translation, translate


@pytest.fixture(scope="module")
def fx() -> Fixtures:
    docs = fixture_documents()
    return Fixtures(LocalJwksResolver(docs["jwks"]), docs["jwks"], docs["tap_registry"])


# ---------------------------------------------------------------- RFC 8941


def test_sf_dictionary_keeps_raw_member_and_flags_uppercase_keys():
    d = parse_dictionary('sig2=("@authority" "@path"); created=1; keyId="k"; tag="t", sig3=:AAEC:')
    m = d["sig2"]
    assert [i.value for i in m.value] == ["@authority", "@path"]
    assert m.params == {"created": 1, "keyId": "k", "tag": "t"}
    assert m.raw == '("@authority" "@path"); created=1; keyId="k"; tag="t"'
    assert m.nonconformant_keys == ["keyId"]
    assert d["sig3"].value == b"\x00\x01\x02"


@pytest.mark.parametrize("bad", ['sig=("a"', "sig=:@@:", "sig=1,", 'sig="unterminated'])
def test_sf_rejects_malformed(bad):
    with pytest.raises(SFError):
        parse_dictionary(bad)


# ---------------------------------------------------------------- TAP


def test_tap_output_shape(fx):
    out = verify_tap(bundle(TapRequest()), fixtures=fx, now=NOW).to_json()
    assert out["protocol"] == "tap" and out["spec"]["source"].endswith("16d59bdf3f8a542bc538d0962edbb80ea30a02af")
    assert out["details"]["requests"][0] | {} == {
        "keyid": "primary-ed25519", "alg": "ed25519", "tag": "agent-browser-auth",
        "nonce": TapRequest().nonce, "agent_id": 1, "agent_domain": "shopping-agent.example"}
    assert out["identity_ok"] and out["delegation_chain_ok"]


def test_tap_reason_codes_are_namespaced(fx):
    v = verify_tap(bundle(TapRequest(keyid="old-ed25519")), fixtures=fx, now=NOW)
    assert v.reason_codes() and all(c.startswith("TAP_") for c in v.reason_codes())


def test_tap_nonce_cache_spans_calls(fx):
    cache = NonceCache()
    assert verify_tap(bundle(TapRequest()), fixtures=fx, now=NOW, nonce_cache=cache).verdict == "accept"
    again = verify_tap(bundle(TapRequest(path="/products/9")), fixtures=fx, now=NOW, nonce_cache=cache)
    assert again.verdict == "reject" and "TAP_NONCE_REPLAY" in again.codes()
    # outside the 8-minute window the nonce may be reused
    later = TapRequest(created=NOW - 30 + 600, expires=NOW - 30 + 900)
    assert "TAP_NONCE_REPLAY" not in verify_tap(bundle(later), fixtures=fx, now=NOW + 600, nonce_cache=cache).codes()


def test_tap_cro_never_blocks(fx):
    from kya_bench.testing.tap_builder import cro

    body = {"agenticConsumer": cro("wrong", "someone-else")}
    v = verify_tap(bundle(TapRequest(keyid="primary", body=body)), fixtures=fx, now=NOW)
    assert v.verdict == "accept"
    assert {"TAP_CRO_NONCE_MISMATCH", "TAP_CRO_KID_MISMATCH"} <= v.codes()
    assert v.cross_refs()["cro_nonce_matches_signature"] is False


def test_tap_bad_bundles_never_raise(fx):
    for b in (None, "x", {}, {"requests": []}, {"requests": [1]}, {"requests": [{"method": "GET"}]}):
        assert verify_tap(b, fixtures=fx, now=NOW).verdict == "reject"


# ---------------------------------------------------------------- AP2


def test_ap2_output_shape(fx):
    out = verify_ap2(ap2_build(Ap2Spec()), fixtures=fx, now=NOW).to_json()
    assert out["protocol"] == "ap2" and out["mode"] == "human_not_present"
    assert {c["type"] for c in out["constraints"]} == {
        "checkout.allowed_merchants", "checkout.line_items", "payment.amount_range",
        "payment.allowed_payees", "payment.reference"}
    assert out["cross_refs"]["payment_reference_matches_open_checkout"] is True
    assert out["details"]["agent_jwk"]["payment"]["kty"] == "EC"


def test_ap2_line_items_exact_quantity(fx):
    under = Ap2Spec(cart=[{"id": "li_1", "item": {"id": "supershoe_gold_w9", "title": "Shoe", "price": 9950},
                           "quantity": 2, "totals": [{"type": "total", "amount": 19900}]}])
    v = verify_ap2(ap2_build(under), fixtures=fx, now=NOW)
    assert v.verdict == "reject"  # requirement quantity 1, cart 2: exact matching fails


def test_ap2_issuer_jwt_hash_survives_redaction(fx):
    b = ap2_build(Ap2Spec(hash_mode="issuer_jwt_hash"))
    assert verify_ap2(b, fixtures=fx, now=NOW).verdict == "accept"


def test_ap2_bad_bundles_never_raise(fx):
    for b in (None, "x", {}, {"checkout_mandate": 1, "payment_mandate": "~~"}):
        assert verify_ap2(b, fixtures=fx, now=NOW).verdict == "reject"


# ---------------------------------------------------------------- composition & translation


def test_composition_binding_cross_ref(fx):
    pres = {"tap": bundle(TapRequest(operation="payment", tag="agent-payer-auth")), "ap2": ap2_build(Ap2Spec())}
    v = verify_composition(pres, fixtures=fx, now=NOW)
    assert v.verdict == "accept" and v.cross_refs()["presenter_matches_mandate_agent"] is True
    assert v.to_json()["protocol"] == "composition"


def test_composition_tap_alone_with_valid_container_is_not_accept(fx):
    """Brief expected accept; the container's signature base is undefined (TAP-01)."""
    req = TapRequest(keyid="primary", operation="payment", tag="agent-payer-auth",
                     body={"agenticPaymentContainer": apc(TapRequest().nonce, "primary")})
    v = verify_composition({"tap": bundle(req)}, fixtures=fx, now=NOW)
    assert v.verdict == "indeterminate" and {f.gap_id for f in v.findings} == {"TAP-01"}


def test_translator_maps_types_and_exp():
    vi, exp, unsupported = translate({
        "payment_constraints": [{"type": "payment.amount_range", "currency": "USD", "max": 5}],
        "checkout_constraints": [{"type": "checkout.allowed_merchants", "allowed": []}],
        "exp": 123,
    })
    assert vi == {"checkout": [{"type": "mandate.checkout.allowed_merchants", "allowed": []}],
                  "payment": [{"type": "mandate.payment.amount_range", "currency": "USD", "max": 5}]}
    assert exp == 123 and unsupported == []


def test_translation_divergence_reports_both_sides():
    v = check_translation({
        "intent": {"checkout_constraints": [{"type": "checkout.allowed_merchants", "allowed": [{"...": "x"}]}]},
        "probe": {"payment_amount": {"amount": 1, "currency": "USD"}, "merchant": {"id": "m"}},
    }, now=NOW)
    assert v.verdict == "reject"
    assert (v.details["ap2_result"], v.details["vi_result"]) == ("reject", "accept")


# ---------------------------------------------------------------- Phase 2 spec gaps (strict xfail)


def _gap_cases(fx):
    from kya_bench.testing.tap_builder import TapRequest as T

    pay = {"operation": "payment", "tag": "agent-payer-auth"}
    return {
        "TAP-01": lambda: verify_tap(bundle(T(keyid="primary", **pay, body={
            "agenticPaymentContainer": apc(T().nonce, "primary")})), fixtures=fx, now=NOW),
        "TAP-02": lambda: verify_tap(bundle(T(keyid_param="keyId")), fixtures=fx, now=NOW),
        "TAP-03": lambda: verify_tap(bundle(T(tag="agent-payer-auth")), fixtures=fx, now=NOW),
        "AP2-01": lambda: verify_ap2(ap2_build(Ap2Spec(cart_total=25000)), fixtures=fx, now=NOW),
        "AP2-04": lambda: verify_ap2(ap2_build(_spec_payment(0, {"type": "payment.amount_range", "currency": "USD",
                                                                  "max": 250.0})), fixtures=fx, now=NOW),
        "AP2-06": lambda: verify_ap2(ap2_build(_spec_insert({"type": "payment.budget", "max": 250, "currency": "USD"},
                                                            mandate_context={"total_amount": 0})), fixtures=fx,
                                     now=NOW),
        "AP2-02": lambda: verify_ap2(_mixed_flows(), fixtures=fx, now=NOW),
        "AP2-05": lambda: verify_ap2(ap2_build(_spec_insert(
            {"type": "payment.agent_recurrence", "frequency": "MONTHLY", "max_occurrences": 12},
            mandate_context={"total_amount": 0, "total_uses": 1, "last_used_date": NOW - 864000},
            extra={"type": "payment.budget", "max": 100000, "currency": "USD"})), fixtures=fx, now=NOW),
        "AP2-07": lambda: verify_ap2(ap2_build(Ap2Spec(cart=[{"id": "li_1", "product": {"id": "supershoe_gold_w9"},
                                                               "quantity": 1}])), fixtures=fx, now=NOW),
        "AP2-08": lambda: verify_ap2(ap2_build(Ap2Spec(open_disclose={"checkout": ["$merchant:0", "$merchant:1"]})),
                                     fixtures=fx, now=NOW),
        "XP-01": lambda: verify_composition({"tap": bundle(T(**pay)), "ap2": ap2_build(
            Ap2Spec(flow="hp", hp_closed_cnf=False))}, fixtures=fx, now=NOW),
        "XP-02": lambda: verify_composition({"tap": bundle(T(**pay)), "ap2": ap2_build(Ap2Spec(
            agent="ap2-stranger", signers={"checkout_root": "ap2-provider", "payment_root": "ap2-provider",
                                           "checkout_term": "ap2-stranger", "payment_term": "ap2-stranger",
                                           "merchant": "ap2-merchant"}))}, fixtures=fx, now=NOW),
    }


def _spec_payment(i, c):
    s = Ap2Spec()
    s.payment_constraints[i] = c
    return s


def _spec_insert(c, extra=None, **kw):
    s = Ap2Spec(**kw)
    s.payment_constraints[0:0] = [c] + ([extra] if extra else [])
    return s


GAPS = ["TAP-01", "TAP-02", "TAP-03", "AP2-01", "AP2-02", "AP2-04", "AP2-05", "AP2-06", "AP2-07", "AP2-08",
        "XP-01", "XP-02"]


@pytest.mark.parametrize("gap_id", GAPS)
def test_phase2_gap_is_indeterminate(fx, gap_id):
    v = _gap_cases(fx)[gap_id]()
    assert v.verdict == "indeterminate" and {f.gap_id for f in v.findings if f.gap_id} == {gap_id}


@pytest.mark.parametrize("gap_id", [
    pytest.param(g, id=g, marks=pytest.mark.xfail(strict=True, reason=f"spec gap {g}: outcome undefined; "
                                                                       "see docs/spec-gaps.md"))
    for g in GAPS
])
def test_phase2_gap_has_definite_verdict(fx, gap_id):
    assert _gap_cases(fx)[gap_id]().verdict in ("accept", "reject")
