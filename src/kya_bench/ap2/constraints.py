"""AP2 constraint evaluation, on AP2's own fields and semantics.

Deliberately independent of the VI constraint engine: AP2 differs in type
names (``payment.amount_range`` vs ``mandate.payment.amount_range``), unknown
handling (always failing, agent_authorization.md "Verification and Processing
Rules" step 3), allowlists with nothing revealed (invalid, not skipped), line
items (exact max-flow matching), and budget units.

Sources: docs/ap2/checkout_mandate.md, docs/ap2/payment_mandate.md and the SDK
(code/sdk/python/ap2/sdk/constraints.py, max_flow_helper.py) at e1ea56d. Where
docs and SDK disagree, the outcome is a spec gap unless both readings agree.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from ..constraints import ConstraintResult
from ..parser import is_undisclosed_ref
from ..reasons import Finding, gap, reject

AGENT_RECURRENCE_FREQ = ("ON_DEMAND", "DAILY", "WEEKLY", "BIWEEKLY", "MONTHLY", "QUARTERLY", "ANNUALLY")
PAYMENT_TYPES = (
    "payment.amount_range", "payment.allowed_payees", "payment.reference", "payment.agent_recurrence",
    "payment.allowed_payment_instruments", "payment.allowed_pisps", "payment.budget", "payment.execution_date",
)
CHECKOUT_TYPES = ("checkout.allowed_merchants", "checkout.line_items")


@dataclass
class Ap2Context:
    """Inputs a constraint may need beyond the closed mandate."""

    closed_payment: dict[str, Any] | None = None
    checkout_payload: dict[str, Any] | None = None  # decoded checkout_jwt payload
    open_checkout_hash: str | None = None  # sd_hash of the presented open checkout token
    mandate_context: dict[str, Any] | None = None  # SDK MandateContext: total_amount, total_uses, last_used_date
    siblings: set[str] = field(default_factory=set)


class _Ev:
    def __init__(self, ctype: str):
        self.ctype, self.messages, self.findings = ctype, [], []
        self.violated = self.gapped = False

    def violation(self, msg: str) -> None:
        self.violated = True
        self.messages.append(msg)
        self.findings.append(reject("AP2_CONSTRAINT_VIOLATION", f"{self.ctype}: {msg}", "constraints"))

    def gap(self, gid: str, msg: str) -> None:
        self.gapped = True
        self.messages.append(f"[{gid}] {msg}")
        self.findings.append(gap(gid, f"{self.ctype}: {msg}", "constraints"))

    @property
    def status(self) -> str:
        return "violation" if self.violated else "indeterminate" if self.gapped else "pass"


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def merchant_matches(candidate: Any, target: Any) -> bool:
    """SDK ``merchant_matches``: id when both have one, else name + website."""
    if not isinstance(candidate, dict) or not isinstance(target, dict):
        return False
    if candidate.get("id") and target.get("id"):
        return candidate["id"] == target["id"]
    return bool(candidate.get("name")) and bool(candidate.get("website")) and \
        candidate.get("name") == target.get("name") and candidate.get("website") == target.get("website")


def evaluate(constraints: Any, mandate: str, ctx: Ap2Context) -> list[ConstraintResult]:
    if not isinstance(constraints, list):
        f = reject("AP2_MANDATE_FIELD_MISSING", "open mandate constraints must be an array", "constraints")
        return [ConstraintResult(-1, mandate, None, False, "violation", constraints, [f.message], [f])]
    ctx.siblings = {c.get("type") for c in constraints if isinstance(c, dict)}
    known = PAYMENT_TYPES if mandate == "payment" else CHECKOUT_TYPES
    out = []
    for i, c in enumerate(constraints):
        ctype = c.get("type") if isinstance(c, dict) else None
        if ctype not in known:
            msg = f"unknown constraint {ctype!r} fails evaluation (agent_authorization.md step 3)"
            f = reject("AP2_CONSTRAINT_UNKNOWN", msg, "constraints")
            out.append(ConstraintResult(i, mandate, ctype, False, "unknown_rejected", c, [msg], [f]))
            continue
        ev = _Ev(ctype)
        _EVAL[ctype](ev, c, ctx)
        out.append(ConstraintResult(i, mandate, ctype, True, ev.status, c, ev.messages, ev.findings))
    return out


# ---------------------------------------------------------------- payment


def _amount(ctx: Ap2Context) -> tuple[int | None, Any]:
    pa = (ctx.closed_payment or {}).get("payment_amount")
    if not isinstance(pa, dict) or not _is_int(pa.get("amount")):
        return None, None
    return pa["amount"], pa.get("currency")


def _amount_range(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    lo, hi, cur = c.get("min"), c.get("max"), c.get("currency")
    for name, v in (("min", lo), ("max", hi)):
        if v is not None and not _is_int(v):
            if isinstance(v, (int, float)):
                return ev.gap("AP2-04", f"'{name}' {v!r} is not an integer: the schema says integer minor units "
                                        "but payment_mandate.md's example uses decimal major units")
            return ev.violation(f"'{name}' must be a number")
    if hi is None or not isinstance(cur, str):
        return ev.violation("schema requires 'currency' and 'max'")
    amount, currency = _amount(ctx)
    if amount is None:
        return ev.violation("closed payment has no integer payment_amount.amount")
    if currency != cur:
        ev.violation(f"Currency mismatch: expected {cur}, got {currency}")
    if lo is not None and amount < lo:
        ev.violation(f"Amount {amount} below minimum {lo}")
    if amount > hi:
        ev.violation(f"Amount {amount} exceeds maximum {hi}")
    return None


def _allowed_payees(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    allowed = c.get("allowed")
    if not isinstance(allowed, list):
        return ev.violation("'allowed' must be an array")
    revealed = [a for a in allowed if not is_undisclosed_ref(a)]
    payee = (ctx.closed_payment or {}).get("payee")
    if not any(merchant_matches(a, payee) for a in revealed):
        ev.violation(f"Payee {payee.get('name') if isinstance(payee, dict) else payee!r} not in allowed list")
    return None


def _reference(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    cti = c.get("conditional_transaction_id")
    if not isinstance(cti, str):
        return ev.violation("'conditional_transaction_id' is required")
    if ctx.open_checkout_hash is None:
        return ev.violation("no open checkout mandate in the checkout chain to match (payment_mandate.md Reference)")
    if cti != ctx.open_checkout_hash:
        ev.violation("conditional_transaction_id does not match the open checkout mandate hash")
    return None


def _agent_recurrence(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    freq, mo = c.get("frequency"), c.get("max_occurrences")
    if freq not in AGENT_RECURRENCE_FREQ:
        return ev.violation(f"frequency must be one of {AGENT_RECURRENCE_FREQ}")
    # SDK check_payment_constraints: recurrence needs amount_range and budget companions.
    for companion in ("payment.amount_range", "payment.budget"):
        if companion not in ctx.siblings:
            ev.violation(f"payment.agent_recurrence requires {companion} constraint")
    mc = ctx.mandate_context
    if mc is None:
        return ev.gap("AP2-05", "recurrence needs the presentation history (mandate context), which was not supplied")
    uses = mc.get("total_uses", 0)
    if _is_int(mo) and uses + 1 > mo:
        ev.violation(f"Maximum occurrences exceeded: {uses + 1} > {mo}")
    if freq != "ON_DEMAND" and mc.get("last_used_date") is not None:
        ev.gap("AP2-05", f"'sufficiently separated in time' for {freq} has no defined period boundaries")
    return None


def _allowed_instruments(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    inst = (ctx.closed_payment or {}).get("payment_instrument")
    allowed = [a for a in c.get("allowed", []) if isinstance(a, dict)]
    if not isinstance(inst, dict):
        return ev.violation("Missing payment instrument in closed mandate")
    if not any(a.get("id") == inst.get("id") for a in allowed):
        ev.violation(f"Payment instrument {inst.get('id')} not in allowed list")
    return None


def _allowed_pisps(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    pisp = (ctx.closed_payment or {}).get("pisp")
    if not isinstance(pisp, dict):
        return ev.violation("Missing PISP in closed mandate")
    keys = ("domain_name", "legal_name", "brand_name")
    if not any(isinstance(a, dict) and all(a.get(k) == pisp.get(k) for k in keys) for a in c.get("allowed", [])):
        ev.violation("PISP not in allowed list")
    return None


def _budget(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    mx, cur = c.get("max"), c.get("currency")
    if not isinstance(mx, (int, float)) or isinstance(mx, bool) or not isinstance(cur, str):
        return ev.violation("schema requires numeric 'max' and 'currency'")
    amount, currency = _amount(ctx)
    if amount is None:
        return ev.violation("closed payment has no integer payment_amount.amount")
    if currency != cur:
        return ev.violation(f"Budget currency mismatch: expected {cur}, got {currency}")
    if ctx.mandate_context is None:
        # SDK BudgetEvaluator: missing context is a violation.
        return ev.violation("Missing mandate context required to evaluate budget")
    total = ctx.mandate_context.get("total_amount", 0) + amount
    as_major = total <= int(mx * 100)  # SDK: budget max in major units
    as_minor = total <= mx  # Amount type everywhere else: minor units
    if as_major and as_minor:
        return None
    if not as_major and not as_minor:
        return ev.violation(f"Cumulative spend {total} exceeds budget {mx} under either unit reading")
    return ev.gap("AP2-06", f"budget max {mx}: the SDK reads major units (x100), the Amount type uses minor "
                            "units; the outcome differs between the two readings")


def _execution_date(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    d = (ctx.closed_payment or {}).get("execution_date")
    if d is None:
        return None  # SDK: absent execution date means immediate execution
    if c.get("not_before") and d < c["not_before"]:
        ev.violation(f"Execution date {d} is before allowed window {c['not_before']}")
    if c.get("not_after") and d > c["not_after"]:
        ev.violation(f"Execution date {d} is after allowed window {c['not_after']}")
    return None


# ---------------------------------------------------------------- checkout


def _allowed_merchants(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    allowed = c.get("allowed")
    if not isinstance(allowed, list):
        return ev.violation("'allowed' must be an array")
    revealed = [a for a in allowed if not is_undisclosed_ref(a)]
    if not revealed:
        # checkout_mandate.md: no revealed elements -> the constraint is invalid.
        return ev.violation("allowed contains no revealed merchants")
    merchant = (ctx.checkout_payload or {}).get("merchant")
    if not isinstance(merchant, dict):
        return ev.violation("Missing merchant in checkout")
    if not any(merchant_matches(a, merchant) for a in revealed):
        ev.violation(f"Merchant {merchant.get('name', '')} not in allowed list")
    return None


def _line_items(ev: _Ev, c: dict, ctx: Ap2Context) -> None:
    reqs = c.get("items")
    if not isinstance(reqs, list) or not reqs:
        return ev.violation("schema requires a non-empty 'items' array")
    lines = (ctx.checkout_payload or {}).get("line_items")
    if not isinstance(lines, list) or not lines:
        return ev.violation("Empty cart does not satisfy line_items constraint")
    cart: dict[str, int] = {}
    for li in lines:
        item = li.get("item") if isinstance(li, dict) else None
        if not isinstance(item, dict) or not isinstance(item.get("id"), str) or not _is_int(li.get("quantity")):
            return ev.gap("AP2-07", "checkout line item lacks item.id/quantity: the UCP schema uses 'item', the "
                                    "checkout_mandate.md example uses 'product'")
        cart[item["id"]] = cart.get(item["id"], 0) + li["quantity"]
    req_sets: list[set[str]] = []
    qtys: list[int] = []
    for r in reqs:
        if not isinstance(r, dict) or not _is_int(r.get("quantity")) or r["quantity"] <= 0 \
                or not isinstance(r.get("acceptable_items"), list):
            return ev.violation("line item requirement needs acceptable_items and a positive quantity")
        revealed = {a["id"] for a in r["acceptable_items"] if isinstance(a, dict) and isinstance(a.get("id"), str)}
        if not revealed:
            return ev.gap("AP2-08", f"requirement {r.get('id')!r} has no revealed acceptable_items: the spec "
                                    "matches nothing, the SDK treats it as a wildcard")
        req_sets.append(revealed)
        qtys.append(r["quantity"])
    flow = _max_flow(req_sets, qtys, cart)
    if flow != sum(qtys) or flow != sum(cart.values()):
        ev.violation(f"line items do not match exactly (matched {flow}, required {sum(qtys)}, "
                     f"in cart {sum(cart.values())})")
    return None


def _max_flow(req_sets: list[set[str]], qtys: list[int], cart: dict[str, int]) -> int:
    """checkout_mandate.md Line Items: source->requirement (qty), requirement->item (inf), item->sink (qty)."""
    skus = list(cart)
    n_r, n_s = len(req_sets), len(skus)
    src, sink = 0, 1 + n_r + n_s
    cap: dict[tuple[int, int], int] = {}

    def add(u: int, v: int, c: int) -> None:
        cap[(u, v)] = cap.get((u, v), 0) + c
        cap.setdefault((v, u), 0)

    for i, q in enumerate(qtys):
        add(src, 1 + i, q)
        for j, s in enumerate(skus):
            if s in req_sets[i]:
                add(1 + i, 1 + n_r + j, 10**9)
    for j, s in enumerate(skus):
        add(1 + n_r + j, sink, cart[s])
    adj: dict[int, list[int]] = {}
    for (u, v) in cap:
        adj.setdefault(u, []).append(v)
    total = 0
    while True:
        parent = {src: src}
        queue = [src]
        while queue and sink not in parent:
            u = queue.pop(0)
            for v in adj.get(u, []):
                if v not in parent and cap[(u, v)] > 0:
                    parent[v] = u
                    queue.append(v)
        if sink not in parent:
            return total
        v, push = sink, 10**9
        while v != src:
            push = min(push, cap[(parent[v], v)])
            v = parent[v]
        v = sink
        while v != src:
            cap[(parent[v], v)] -= push
            cap[(v, parent[v])] += push
            v = parent[v]
        total += push


_EVAL = {
    "payment.amount_range": _amount_range,
    "payment.allowed_payees": _allowed_payees,
    "payment.reference": _reference,
    "payment.agent_recurrence": _agent_recurrence,
    "payment.allowed_payment_instruments": _allowed_instruments,
    "payment.allowed_pisps": _allowed_pisps,
    "payment.budget": _budget,
    "payment.execution_date": _execution_date,
    "checkout.allowed_merchants": _allowed_merchants,
    "checkout.line_items": _line_items,
}


def findings_of(results: list[ConstraintResult]) -> list[Finding]:
    return [f for r in results for f in r.findings]
