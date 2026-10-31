"""Constraint engine: the eight registered types and unknown-type handling."""

from __future__ import annotations

import copy

import pytest

from kya_bench import Fulfillment, NetworkState, check_constraints
from kya_bench.testing.builder import NOW, autonomous_spec

from .conftest import constraint

TW = {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"}
BAB = {"id": "merchant-uuid-2", "name": "Babolat", "website": "https://babolat.com"}


def ful(**kw) -> Fulfillment:
    base = dict(
        has_checkout=True,
        has_payment=True,
        line_items=[{"id": "li-1", "item": {"id": "BAB86345", "title": "Racket"}, "quantity": 1}],
        merchant=dict(TW),
        payee=dict(TW),
        payment_amount={"currency": "USD", "amount": 27999},
    )
    base.update(kw)
    return Fulfillment(**base)


def one(c, f=None, *, strictness="strict", is_open=True, **kw):
    [r] = check_constraints([c], f if f is not None else ful(), strictness=strictness, is_open_mandate=is_open, **kw)
    return r


# ------------------------------------------------------------ unknown types


UNKNOWN = {"type": "com.acme.loyalty-points", "points": 500, "x-extra": {"nested": True}}


@pytest.mark.parametrize("strictness", ["strict", "permissive"])
def test_unknown_in_open_mandate_always_rejected(strictness):
    r = one(UNKNOWN, strictness=strictness, is_open=True)
    assert r.status == "unknown_rejected"
    assert [str(f.code) for f in r.findings] == ["CONSTRAINT_UNKNOWN_OPEN_MANDATE"]
    assert r.findings[0].effect == "reject"


@pytest.mark.parametrize("strictness", ["strict", "permissive"])
def test_unknown_in_open_mandate_rejected_even_with_permissive_policy(strictness):
    r = one(UNKNOWN, strictness=strictness, is_open=True, policy={UNKNOWN["type"]: "permissive"})
    assert r.status == "unknown_rejected"


def test_unknown_non_open_strict_rejects():
    r = one(UNKNOWN, strictness="strict", is_open=False)
    assert r.status == "unknown_rejected"
    assert str(r.findings[0].code) == "CONSTRAINT_UNKNOWN_STRICT"


def test_unknown_non_open_permissive_skips_with_warning():
    r = one(UNKNOWN, strictness="permissive", is_open=False)
    assert r.status == "unknown_skipped"
    assert [(str(f.code), f.effect) for f in r.findings] == [("CONSTRAINT_UNKNOWN_SKIPPED", "warn")]


def test_policy_overrides_global_mode_for_non_open():
    assert one(UNKNOWN, strictness="strict", is_open=False, policy={UNKNOWN["type"]: "permissive"}).status == (
        "unknown_skipped"
    )
    assert one(UNKNOWN, strictness="permissive", is_open=False, policy={UNKNOWN["type"]: "strict"}).status == (
        "unknown_rejected"
    )


def test_unknown_fields_preserved():
    c = {"type": "mandate.payment.amount_range", "currency": "USD", "max": 40000, "x-future": [1, 2]}
    original = copy.deepcopy(c)
    r = one(c)
    assert r.status == "pass"
    assert r.constraint == original and r.constraint["x-future"] == [1, 2]
    assert one(UNKNOWN, strictness="permissive", is_open=False).constraint == UNKNOWN


def test_processing_continues_after_violation():
    cs = [
        {"type": "mandate.payment.amount_range", "currency": "USD", "max": 100},
        UNKNOWN,
        {"type": "mandate.payment.allowed_payees", "allowed": [BAB]},
    ]
    rs = check_constraints(cs, ful(), strictness="strict", is_open_mandate=True)
    assert [r.status for r in rs] == ["violation", "unknown_rejected", "violation"]


def test_malformed_constraint_objects():
    rs = check_constraints([1, {"no": "type"}, {"type": ""}], ful(), strictness="permissive", is_open_mandate=False)
    assert [r.status for r in rs] == ["violation"] * 3
    assert {str(f.code) for r in rs for f in r.findings} == {"CONSTRAINT_MALFORMED"}


# ------------------------------------------------------------ e2e: open mandate


@pytest.mark.parametrize("strictness", ["strict", "permissive"])
@pytest.mark.parametrize("with_l3", [True, False])
def test_e2e_unknown_constraint_in_open_mandate_rejected(run, strictness, with_l3):
    spec = autonomous_spec()
    spec.payment_mandate["constraints"].insert(0, dict(UNKNOWN))
    if not with_l3:
        spec.include_l3 = ()
    v = run(spec, strictness=strictness)
    assert v.verdict == "reject"
    assert "CONSTRAINT_UNKNOWN_OPEN_MANDATE" in v.codes()
    assert v.identity_ok and v.delegation_chain_ok  # chain is fine; the mandate is not
    rc = constraint(v, UNKNOWN["type"])
    assert rc.constraint == UNKNOWN  # preserved verbatim in the verdict


# ------------------------------------------------------------ allowlists


def test_allowed_merchants():
    c = {"type": "mandate.checkout.allowed_merchants", "allowed": [TW, BAB]}
    assert one(c).status == "pass"
    assert one(c, ful(merchant={"id": "evil"})).status == "violation"
    assert one({**c, "allowed": []}).messages == ["Empty merchant allowlist is unsatisfiable"]
    only_refs = {**c, "allowed": [{"...": "h1"}]}
    assert one(only_refs, ful(merchant={"id": "evil"})).status == "pass"  # §4.1 step 3
    no_id = {"type": "mandate.checkout.allowed_merchants", "allowed": [{"name": TW["name"], "website": TW["website"]}]}
    assert one(no_id).status == "pass"  # falls back to name+website
    assert one(no_id, ful(merchant={"id": "x", "name": TW["name"], "website": "https://tw.evil"})).status == (
        "violation"
    )
    assert one(c, ful(has_checkout=False)).status == "not_evaluated"


def test_allowed_payees_exact_match():
    c = {"type": "mandate.payment.allowed_payees", "allowed": [{"name": "Tennis Warehouse",
                                                                "website": "https://tennis-warehouse.com"}]}
    assert one(c).status == "pass"
    assert one(c, ful(payee={"name": "tennis warehouse", "website": "https://tennis-warehouse.com"})).status == (
        "violation"
    )
    assert one({**c, "allowed": []}).status == "violation"
    assert one(c, ful(has_payment=False)).status == "not_evaluated"


# ------------------------------------------------------------ line items


LI = {
    "type": "mandate.checkout.line_items",
    "items": [{"id": "line-1", "acceptable_items": [{"id": "BAB86345", "title": "Racket"}], "quantity": 1}],
}


def _li(pid, qty):
    return [{"id": "x", "item": {"id": pid, "title": "t"}, "quantity": qty}]


def test_line_items():
    assert one(LI).status == "pass"
    assert one(LI, ful(line_items=_li("PRI99101", 1))).messages == ["Item PRI99101 not in acceptable items list"]
    assert one(LI, ful(line_items=_li("BAB86345", 2))).status == "violation"
    assert one(LI, ful(line_items=[])).messages == ["Empty cart does not satisfy line_items constraint"]
    assert one({**LI, "items": []}).status == "violation"
    no_title = {**LI, "items": [{"id": "line-1", "acceptable_items": [{"id": "BAB86345"}], "quantity": 1}]}
    assert one(no_title).status == "violation"
    wildcard = {**LI, "items": [{"id": "line-1", "acceptable_items": [], "quantity": 3}]}
    assert one(wildcard, ful(line_items=_li("ANYTHING", 3))).status == "pass"
    assert one({**LI, "match_mode": "bogus"}).status == "violation"


def test_line_items_exact_mode():
    two = {**LI, "match_mode": "exact", "items": LI["items"] + [
        {"id": "line-2", "acceptable_items": [{"id": "STR1", "title": "String"}], "quantity": 2}]}
    assert one(two).status == "violation"
    both = ful(line_items=_li("BAB86345", 1) + _li("STR1", 2))
    assert one(two, both).status == "pass"
    assert one({**two, "match_mode": "minimum"}).status == "pass"


# ------------------------------------------------------------ amounts


def test_amount_range():
    c = {"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000}
    assert one(c).status == "pass"
    assert one(c, ful(payment_amount={"currency": "USD", "amount": 50000})).messages == [
        "Amount exceeded: 50000 > 40000 USD"
    ]
    assert one(c, ful(payment_amount={"currency": "USD", "amount": 5000})).messages == [
        "Amount below minimum: 5000 < 10000 USD"
    ]
    assert one(c, ful(payment_amount={"currency": "EUR", "amount": 27999})).status == "violation"
    assert one(c, ful(payment_amount={"currency": "USD", "amount": 279.99})).messages == ["Invalid amount format"]
    assert one(c, ful(payment_amount={"currency": "USD", "amount": True})).status == "violation"
    assert one({**c, "max": "40000"}).status == "violation"


def test_budget_with_state():
    c = {"type": "mandate.payment.budget", "currency": "USD", "max": 50000}
    assert one(c, network_state=NetworkState(cumulative_spent=0)).status == "pass"
    r = one(c, network_state=NetworkState(cumulative_spent=30000))
    assert r.messages == ["Budget exceeded: 57999 > 50000 USD"]
    assert one({**c, "min": 30000}, network_state=NetworkState(0)).status == "violation"
    assert one({**c, "max": 20000}).status == "violation"  # exceeded by this transaction alone


# ------------------------------------------------------------ recurrence


def test_recurrence():
    c = {"type": "mandate.payment.recurrence", "frequency": "MNTH", "start_date": "2026-03-01",
         "end_date": "2027-03-01", "number": 12}
    r = one(c)
    assert r.status == "pass" and not r.findings
    r = one({k: v for k, v in c.items() if k != "number"})
    assert r.status == "pass" and [str(f.code) for f in r.findings] == ["RECURRENCE_UNBOUNDED"]
    assert one({**c, "frequency": "SOMETIMES"}).status == "violation"


def test_agent_recurrence():
    c = {"type": "mandate.payment.agent_recurrence", "frequency": "ON_DEMAND",
         "start_date": "2026-09-01", "end_date": "2026-09-30", "max_occurrences": 3}
    siblings = [c, {"type": "mandate.payment.amount_range", "currency": "USD", "max": 40000},
                {"type": "mandate.payment.budget", "currency": "USD", "max": 90000}]
    state = NetworkState(cumulative_spent=0, occurrence_count=1)
    rs = check_constraints(siblings, ful(), strictness="strict", is_open_mandate=True, network_state=state, now=NOW)
    assert [r.status for r in rs] == ["pass", "pass", "pass"]
    # missing companions
    [r] = check_constraints([c], ful(), strictness="strict", is_open_mandate=True, network_state=state, now=NOW)
    assert r.status == "violation" and len(r.messages) == 2
    # occurrence cap
    rs = check_constraints(siblings, ful(), strictness="strict", is_open_mandate=True,
                           network_state=NetworkState(0, 3), now=NOW)
    assert rs[0].messages == ["Maximum occurrences exceeded: 3 >= 3"]
    # outside the window in every time zone
    late = [{**c, "end_date": "2026-08-31"}] + siblings[1:]
    rs = check_constraints(late, ful(), strictness="strict", is_open_mandate=True, network_state=state, now=NOW)
    assert rs[0].messages == ["Agent recurrence period expired or not yet started"]


def test_reference_constraint_follows_chain_result():
    c = {"type": "mandate.payment.reference", "conditional_transaction_id": "abc"}
    assert one(c, reference_ok=True).status == "pass"
    assert one(c, reference_ok=False).status == "violation"
    assert one(c).status == "not_evaluated"
    assert one({"type": "mandate.payment.reference"}).status == "violation"


# ------------------------------------------------------------ e2e violations


def test_e2e_amount_exceeded(run):
    spec = autonomous_spec()
    spec.l3a_payment["payment_amount"]["amount"] = 50000
    v = run(spec)
    assert v.verdict == "reject" and "CONSTRAINT_VIOLATION" in v.codes()
    assert v.identity_ok and v.delegation_chain_ok
    assert constraint(v, "mandate.payment.amount_range").status == "violation"


def test_e2e_item_not_allowed(run):
    spec = autonomous_spec()
    spec.l3b_checkout["line_items"][0]["item"] = {"id": "PRI99101", "title": "Prince Synthetic Gut"}
    v = run(spec)
    assert constraint(v, "mandate.checkout.line_items").messages == ["Item PRI99101 not in acceptable items list"]


def test_e2e_merchant_outside_allowlist(run):
    spec = autonomous_spec()
    spec.checkout_jwt_payload.update(id="merchant-uuid-999", name="Shady", website="https://shady.example")
    v = run(spec)
    assert constraint(v, "mandate.checkout.allowed_merchants").status == "violation"


def test_e2e_merchant_pointer(run):
    spec = autonomous_spec()
    p = spec.checkout_jwt_payload
    p["merchant"] = {k: p.pop(k) for k in ("id", "name", "website")}
    assert constraint(run(spec, merchant_pointer="/merchant"), "mandate.checkout.allowed_merchants").status == "pass"
