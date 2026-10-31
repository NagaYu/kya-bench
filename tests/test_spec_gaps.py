"""Behaviour the VI v0.1-draft spec leaves undefined (docs/spec-gaps.md).

For each undefined case KYA Bench returns ``indeterminate`` with a
``SPEC_GAP`` reason instead of inventing an outcome. Each ``xfail`` test states
what a conformance suite *would* assert — a definite verdict — and is strict:
once the spec defines the behaviour and the verifier implements it, the test
XPASSes and fails the run, forcing the expectation to be pinned down.

The ``*_is_indeterminate`` companions pin the current, deliberate behaviour.
Documented interpretations and conflicts (G-01, G-06, G-09, G-10) are not
undefined outcomes; their tests pass normally.
"""

from __future__ import annotations

import pytest

from kya_bench.testing.builder import NOW, autonomous_spec, build, immediate_spec

from .conftest import constraint


def gaps(v) -> set[str]:
    return {f.gap_id for f in v.findings if f.gap_id}


def xfail_gap(gap_id: str, why: str):
    return pytest.mark.xfail(strict=True, reason=f"spec gap {gap_id}: {why}")


# ---------------------------------------------------------------- scenarios


def g02_spec():
    spec = autonomous_spec()
    for k in ("id", "name", "website"):
        spec.checkout_jwt_payload.pop(k)
    return spec


def g03_spec():
    spec = autonomous_spec()
    # credential-format §11.2 / §5.5 example shape: {sku, name, quantity, unit_price, currency}
    spec.l3b_checkout["line_items"] = [
        {"sku": "BAB86345", "name": "Babolat Pure Aero", "quantity": 1, "unit_price": 27999, "currency": "USD"}
    ]
    return spec


def g04_spec():
    spec = autonomous_spec()
    spec.include_l3 = ("l3b",)
    spec.l2_disclose = ["$checkout", "$merchant:0", "$merchant:1"]  # item disclosure withheld
    spec.l3b_checkout["line_items"][0]["item"]["id"] = "OTHER-SKU"
    return spec


def g05_spec():
    spec = autonomous_spec()
    spec.payment_mandate["constraints"].insert(1, {"type": "mandate.payment.budget", "currency": "USD", "max": 50000})
    return spec


def g07_bundle():
    spec = autonomous_spec()
    spec.pairs = 2
    spec.include_views = False
    spec.view_l3a_items = ["$merchant:0", "$merchant:1", "$item:0", "$checkout", "$payment",
                           "$checkout:2", "$payment:2"]
    spec.view_l3b_items = list(spec.view_l3a_items)
    return spec


def g08_spec():
    spec = autonomous_spec()
    # NOW = 2026-09-21T14:13:20Z: already 2026-09-22 in UTC+14, still 2026-09-21 in UTC-12.
    spec.payment_mandate["constraints"][:0] = [
        {"type": "mandate.payment.agent_recurrence", "frequency": "ON_DEMAND",
         "start_date": "2026-09-01", "end_date": "2026-09-21"},
        {"type": "mandate.payment.budget", "currency": "USD", "max": 90000},
    ]
    spec.extra_bundle = {"network_state": {"cumulative_spent": 0, "occurrence_count": 0}}
    return spec


def g11_spec():
    spec = autonomous_spec()
    spec.checkout_mandate["constraints"].append(
        {"type": "mandate.payment.amount_range", "currency": "USD", "max": 40000}
    )
    return spec


def g12_spec():
    spec = autonomous_spec()
    spec.l3a_payment["payment_instrument"] = {"type": "mastercard.srcDigitalCard", "id": "another-token"}
    return spec


def g13_spec():
    spec = autonomous_spec()
    spec.checkout_mandate["constraints"][1]["items"].append({"id": "line-2", "acceptable_items": [], "quantity": 1})
    spec.l3b_checkout["line_items"][0]["quantity"] = 2
    return spec


def g14_spec():
    spec = immediate_spec()
    spec.l2_disclose = []
    return spec


CASES = [
    ("G-02", g02_spec, "allowed_merchants with no merchant id in checkout_jwt: 'cannot be validated', outcome undefined"),
    ("G-03", g03_spec, "L3b line_items schema differs between credential-format §5.5 and constraints.md §4.2"),
    ("G-04", g04_spec, "line item not among disclosed acceptable_items while others are undisclosed"),
    ("G-05", g05_spec, "cumulative budget without payment-network state: verdict for non-network verifiers"),
    ("G-07", g07_bundle, "which mandate pair an L3 binds to when its L2 view covers several pairs"),
    ("G-08", g08_spec, "agent_recurrence 'current date' has no time zone"),
    ("G-11", g11_spec, "registered constraint type placed in the other mandate kind"),
    ("G-12", g12_spec, "L3a payment_instrument vs L2 payment_instrument: no binding rule"),
    ("G-13", g13_spec, "per-SKU quantity cap with wildcard line item entries"),
    ("G-14", g14_spec, "Immediate L2 presented with zero mandate disclosures"),
]


@pytest.mark.parametrize(("gap_id", "make", "why"), CASES, ids=[c[0] for c in CASES])
def test_gap_is_indeterminate(run, gap_id, make, why):
    v = run(make())
    assert v.verdict == "indeterminate", v.to_json()["reasons"]
    assert gaps(v) == {gap_id}


@pytest.mark.parametrize(
    ("gap_id", "make", "why"),
    [pytest.param(g, m, w, marks=xfail_gap(g, w), id=g) for g, m, w in CASES],
)
def test_gap_has_definite_verdict(run, gap_id, make, why):
    """What a conformance suite would assert once the spec defines the case."""
    assert run(make()).verdict in ("accept", "reject")


# ---------------------------------------------------------------- interpretations / conflicts


def test_g01_digest_listed_in_sd_and_delegate_payload_is_accepted(run):
    """VI §11 lists mandate digests in both _sd and delegate_payload; RFC 9901 §7.1 would reject."""
    assert run(autonomous_spec()).verdict == "accept"


def test_g05_resolved_when_network_state_supplied(run):
    spec = g05_spec()
    spec.extra_bundle = {"network_state": {"cumulative_spent": 10000, "occurrence_count": 0}}
    v = run(spec)
    assert v.verdict == "accept"
    spec.extra_bundle = {"network_state": {"cumulative_spent": 30000, "occurrence_count": 0}}
    assert constraint(run(spec), "mandate.payment.budget").status == "violation"


def test_g06_strictness_does_not_change_conformant_e2e_verdicts(run):
    """Constraints only exist in open mandates, so strict/permissive agree end to end."""
    spec = autonomous_spec()
    spec.checkout_mandate["constraints"].append({"type": "com.acme.gift-wrap", "required": True})
    assert run(spec, strictness="strict").verdict == run(spec, strictness="permissive").verdict == "reject"


def test_g07_resolved_by_selective_views(run):
    spec = autonomous_spec()
    spec.pairs = 2
    assert run(spec).verdict == "accept"


def test_g08_unambiguous_dates_decide(run):
    spec = g08_spec()
    spec.payment_mandate["constraints"][0]["end_date"] = "2026-09-30"
    assert run(spec).verdict == "accept"


def test_g09_immediate_lifetime_over_15_minutes_warns(run):
    spec = immediate_spec()
    spec.l2_claims["exp"] = spec.l2_claims["iat"] + 3600
    v = run(spec)
    assert v.verdict == "accept" and "TIME_LIFETIME_SHOULD" in v.codes()


def test_g10_neutral_verifier_uses_full_l2_presentation(run):
    spec = autonomous_spec()
    spec.l2_disclose = ["$checkout", "$payment", "$item:0"]  # merchants withheld from the verifier
    spec.checkout_jwt_payload.update(id="merchant-uuid-999")
    v = run(spec)
    assert constraint(v, "mandate.checkout.allowed_merchants").status == "pass"  # §4.1 step 3: skipped
    assert NOW  # keep import used
