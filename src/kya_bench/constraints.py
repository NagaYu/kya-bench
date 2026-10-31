"""VI constraint evaluation (constraints.md §4–§5).

Core rule (§5.3/§5.4): an unknown constraint ``type`` is
  - rejected when the mandate is open, regardless of strictness or policy;
  - otherwise rejected under STRICT and skipped under PERMISSIVE.
A PERMISSIVE skip is always recorded as a warning, even when the overall
verdict is accept.

Constraint objects are never rewritten: each result carries the original
object, so unknown fields survive (§3.2, §6.1).
"""

from __future__ import annotations

import datetime as _dt
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

from .parser import is_undisclosed_ref
from .reasons import Code, Finding, gap, reject, warn

Status = Literal["pass", "violation", "not_evaluated", "unknown_skipped", "unknown_rejected", "indeterminate"]
PublicStatus = Literal["satisfied", "violated", "not_checked", "skipped_unknown"]

# Output vocabulary of the normalized verdict. The internal status keeps the finer
# distinction and is emitted as "outcome": an unknown type rejected (open mandate or
# STRICT) is a violation of the mandate, and a spec-gap result was not checked.
PUBLIC_STATUS: dict[str, PublicStatus] = {
    "pass": "satisfied",
    "violation": "violated",
    "not_evaluated": "not_checked",
    "indeterminate": "not_checked",
    "unknown_skipped": "skipped_unknown",
    "unknown_rejected": "violated",
}

UNKNOWN_HANDLING = {
    "CONSTRAINT_UNKNOWN_OPEN_MANDATE": "rejected_open_mandate",
    "CONSTRAINT_UNKNOWN_STRICT": "rejected_strict",
    "CONSTRAINT_UNKNOWN_SKIPPED": "skipped_permissive",
}


class Strictness(StrEnum):
    STRICT = "strict"
    PERMISSIVE = "permissive"


ALLOWED_MERCHANTS = "mandate.checkout.allowed_merchants"
LINE_ITEMS = "mandate.checkout.line_items"
ALLOWED_PAYEES = "mandate.payment.allowed_payees"
AMOUNT_RANGE = "mandate.payment.amount_range"
BUDGET = "mandate.payment.budget"
RECURRENCE = "mandate.payment.recurrence"
AGENT_RECURRENCE = "mandate.payment.agent_recurrence"
REFERENCE = "mandate.payment.reference"

REGISTERED_TYPES: dict[str, str] = {
    ALLOWED_MERCHANTS: "checkout",
    LINE_ITEMS: "checkout",
    ALLOWED_PAYEES: "payment",
    AMOUNT_RANGE: "payment",
    BUDGET: "payment",
    RECURRENCE: "payment",
    AGENT_RECURRENCE: "payment",
    REFERENCE: "payment",
}

ISO20022_FREQUENCIES = frozenset(
    {"INDA", "DAIL", "WEEK", "TOWK", "TWMN", "MNTH", "TOMN", "QUTR", "FOMN", "SEMI", "YEAR", "TYEA"}
)


@dataclass
class Fulfillment:
    """Final values extracted from L3 (constraints.md §2.4).

    ``has_checkout`` / ``has_payment`` say whether L3b / L3a were presented;
    constraints that need an absent side are ``not_evaluated``.
    ``merchant_findings`` carries problems met while extracting the merchant
    from ``checkout_jwt`` (e.g. spec gap G-02).
    """

    has_checkout: bool = False
    has_payment: bool = False
    line_items: Any = None
    merchant: dict[str, Any] | None = None
    merchant_findings: list[Finding] = field(default_factory=list)
    payee: Any = None
    payment_instrument: Any = None
    payment_amount: Any = None


@dataclass
class NetworkState:
    """Payment-network tracking state for one L2 mandate pair (§4.5, §4.7)."""

    cumulative_spent: int | None = None
    occurrence_count: int | None = None


@dataclass
class ConstraintResult:
    index: int
    mandate: str | None
    type: str | None
    registered: bool
    status: Status
    constraint: Any
    messages: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    @property
    def public_status(self) -> PublicStatus:
        return PUBLIC_STATUS[self.status]

    def to_json(self) -> dict[str, Any]:
        return {
            "type": self.type,
            "status": self.public_status,
            "detail": "; ".join(self.messages),
            "outcome": self.status,
            "mandate": self.mandate,
            "index": self.index,
            "registered": self.registered,
            "messages": self.messages,
            "constraint": self.constraint,
        }


class _Eval:
    """Accumulates the outcome of one registered-constraint evaluation."""

    def __init__(self, ctype: str):
        self.ctype = ctype
        self.messages: list[str] = []
        self.findings: list[Finding] = []
        self.violated = False
        self.gapped = False
        self.unevaluated = False

    def violation(self, msg: str, code: Code = Code.CONSTRAINT_VIOLATION) -> None:
        self.violated = True
        self.messages.append(msg)
        self.findings.append(reject(code, f"{self.ctype}: {msg}", "constraints"))

    def gap(self, gap_id: str, msg: str) -> None:
        self.gapped = True
        self.messages.append(f"[{gap_id}] {msg}")
        self.findings.append(gap(gap_id, f"{self.ctype}: {msg}", "constraints"))

    def note(self, msg: str) -> None:
        self.messages.append(msg)

    def warn(self, code: Code, msg: str) -> None:
        self.messages.append(msg)
        self.findings.append(warn(code, f"{self.ctype}: {msg}", "constraints"))

    def not_evaluated(self, msg: str) -> None:
        self.unevaluated = True
        self.messages.append(msg)

    @property
    def status(self) -> Status:
        if self.violated:
            return "violation"
        if self.gapped:
            return "indeterminate"
        if self.unevaluated:
            return "not_evaluated"
        return "pass"


def _is_int(v: Any) -> bool:
    return isinstance(v, int) and not isinstance(v, bool)


def _is_nonneg_int(v: Any) -> bool:
    return _is_int(v) and v >= 0


def _nonempty_str(v: Any) -> bool:
    return isinstance(v, str) and v != ""


def check_constraints(
    constraints: Any,
    fulfillment: Fulfillment | None,
    *,
    strictness: Strictness | str,
    is_open_mandate: bool,
    mandate: str | None = None,
    policy: dict[str, Strictness | str] | None = None,
    network_state: NetworkState | None = None,
    now: int | None = None,
    reference_ok: bool | None = None,
) -> list[ConstraintResult]:
    """Evaluate a mandate's ``constraints`` array against a fulfillment.

    ``fulfillment=None`` means no L3 was presented: registered constraints are
    schema-checked only and reported ``not_evaluated``. ``reference_ok`` is the
    chain verifier's result for ``mandate.payment.reference`` (§4.8: validated
    by chain verification, not by the constraint checker).
    """
    strictness = Strictness(strictness)
    results: list[ConstraintResult] = []
    if not isinstance(constraints, list):
        f = reject(Code.CONSTRAINT_MALFORMED, "constraints must be an array", "constraints")
        return [ConstraintResult(-1, mandate, None, False, "violation", constraints, [f.message], [f])]

    sibling_types = {c.get("type") for c in constraints if isinstance(c, dict)}

    for idx, c in enumerate(constraints):
        if not isinstance(c, dict) or not _nonempty_str(c.get("type")):
            f = reject(Code.CONSTRAINT_MALFORMED, "constraint must be an object with a string 'type'", "constraints")
            results.append(ConstraintResult(idx, mandate, None, False, "violation", c, [f.message], [f]))
            continue
        ctype = c["type"]

        if ctype not in REGISTERED_TYPES:
            effective = Strictness((policy or {}).get(ctype, strictness))
            if is_open_mandate:
                msg = f"Unknown constraint type in open mandate: {ctype}"
                f = reject(Code.CONSTRAINT_UNKNOWN_OPEN_MANDATE, msg, "constraints")
                results.append(ConstraintResult(idx, mandate, ctype, False, "unknown_rejected", c, [msg], [f]))
            elif effective is Strictness.STRICT:
                msg = f"Unknown constraint type: {ctype}"
                f = reject(Code.CONSTRAINT_UNKNOWN_STRICT, msg, "constraints")
                results.append(ConstraintResult(idx, mandate, ctype, False, "unknown_rejected", c, [msg], [f]))
            else:
                msg = f"Unknown constraint type skipped (permissive): {ctype}"
                f = warn(Code.CONSTRAINT_UNKNOWN_SKIPPED, msg, "constraints")
                results.append(ConstraintResult(idx, mandate, ctype, False, "unknown_skipped", c, [msg], [f]))
            continue

        ev = _Eval(ctype)
        expected_mandate = REGISTERED_TYPES[ctype]
        if mandate is not None and mandate != expected_mandate:
            ev.gap(
                "G-11",
                f"registered type appears in a {mandate} mandate; spec lists it for {expected_mandate} mandates "
                "but does not define the outcome",
            )
        _EVALUATORS[ctype](ev, c, fulfillment, network_state, now, sibling_types, reference_ok)
        results.append(ConstraintResult(idx, mandate, ctype, True, ev.status, c, ev.messages, ev.findings))
    return results


# --------------------------------------------------------------------------
# allowlists (§4.1, §4.3)
# --------------------------------------------------------------------------


def _party_matches(candidate: Any, target: dict[str, Any]) -> bool:
    """§4.1/§4.3/§7.3: ``id`` when present on both sides, else exact name+website."""
    if not isinstance(candidate, dict):
        return False
    if _nonempty_str(candidate.get("id")) and _nonempty_str(target.get("id")):
        return candidate["id"] == target["id"]
    return (
        _nonempty_str(candidate.get("name"))
        and _nonempty_str(candidate.get("website"))
        and candidate.get("name") == target.get("name")
        and candidate.get("website") == target.get("website")
    )


def _check_party_schema(ev: _Eval, allowed: list[Any]) -> list[dict[str, Any]]:
    disclosed = [a for a in allowed if not is_undisclosed_ref(a)]
    for a in disclosed:
        if not isinstance(a, dict) or not _nonempty_str(a.get("name")) or not _nonempty_str(a.get("website")):
            ev.violation("allowlist entry must be an object with name and website", Code.CONSTRAINT_MALFORMED)
    return [a for a in disclosed if isinstance(a, dict)]


def _eval_allowed_merchants(ev: _Eval, c, ful: Fulfillment | None, *_):
    allowed = c.get("allowed")
    if not isinstance(allowed, list):
        return ev.violation("'allowed' must be an array", Code.CONSTRAINT_MALFORMED)
    if not allowed:
        return ev.violation("Empty merchant allowlist is unsatisfiable")
    disclosed = _check_party_schema(ev, allowed)
    if ev.violated:
        return None
    if ful is None or not ful.has_checkout:
        return ev.not_evaluated("no L3b checkout mandate presented")
    if not disclosed:
        return ev.note("no merchants disclosed to this verifier; check skipped (§4.1 step 3)")
    if ful.merchant is None:
        ev.findings.extend(ful.merchant_findings)
        return ev.gap(
            "G-02",
            "merchant identifier not found in checkout_jwt; spec says the constraint "
            "'cannot be validated' without defining the outcome",
        )
    if not any(_party_matches(m, ful.merchant) for m in disclosed):
        ev.violation("Merchant not in allowed list")
    return None


def _eval_allowed_payees(ev: _Eval, c, ful: Fulfillment | None, *_):
    allowed = c.get("allowed")
    if not isinstance(allowed, list):
        return ev.violation("'allowed' must be an array", Code.CONSTRAINT_MALFORMED)
    if not allowed:
        return ev.violation("Empty payee allowlist is unsatisfiable")
    disclosed = _check_party_schema(ev, allowed)
    if ev.violated:
        return None
    if ful is None or not ful.has_payment:
        return ev.not_evaluated("no L3a payment mandate presented")
    if not disclosed:
        return ev.note("no payees disclosed to this verifier; check skipped (§4.3 step 3)")
    payee = ful.payee
    if not isinstance(payee, dict):
        return ev.violation("L3a payment mandate has no payee object")
    if not any(_party_matches(p, payee) for p in disclosed):
        ev.violation(f"Payee {payee.get('name')!s} not in allowed payees")
    return None


# --------------------------------------------------------------------------
# line items (§4.2)
# --------------------------------------------------------------------------


def _eval_line_items(ev: _Eval, c, ful: Fulfillment | None, *_):
    items = c.get("items")
    if not isinstance(items, list):
        return ev.violation("'items' must be an array", Code.CONSTRAINT_MALFORMED)
    if not items:
        return ev.violation("Empty items allowlist is unsatisfiable")
    match_mode = c.get("match_mode", "minimum")
    if match_mode not in ("minimum", "exact"):
        ev.violation(f"Unrecognized match_mode: {match_mode!r}")

    entries: list[tuple[set[str] | None, bool, int]] = []  # (ids or None=wildcard, has_undisclosed, qty)
    for entry in items:
        if not isinstance(entry, dict) or not _nonempty_str(entry.get("id")):
            ev.violation("line item entry must have a non-empty 'id'", Code.CONSTRAINT_MALFORMED)
            continue
        acc = entry.get("acceptable_items")
        qty = entry.get("quantity")
        if not isinstance(acc, list):
            ev.violation(f"entry {entry['id']}: 'acceptable_items' must be an array", Code.CONSTRAINT_MALFORMED)
            continue
        if not _is_nonneg_int(qty):
            ev.violation(f"entry {entry['id']}: 'quantity' must be a non-negative integer", Code.CONSTRAINT_MALFORMED)
            continue
        ids: set[str] = set()
        undisclosed = False
        for it in acc:
            if is_undisclosed_ref(it):
                undisclosed = True
            elif not isinstance(it, dict) or not _nonempty_str(it.get("id")):
                ev.violation(f"entry {entry['id']}: acceptable item must have an 'id'", Code.CONSTRAINT_MALFORMED)
            elif not _nonempty_str(it.get("title")):
                ev.violation(f"entry {entry['id']}: acceptable item {it['id']} is missing 'title'")
            else:
                ids.add(it["id"])
        entries.append((None if not acc else ids, undisclosed, qty))
    if ev.violated:
        return None
    if ful is None or not ful.has_checkout:
        return ev.not_evaluated("no L3b checkout mandate presented")

    lines = ful.line_items
    if not isinstance(lines, list) or not lines:
        return ev.violation("Empty cart does not satisfy line_items constraint")

    selected: dict[str, int] = {}
    for li in lines:
        item = li.get("item") if isinstance(li, dict) else None
        pid = item.get("id") if isinstance(item, dict) else None
        qty = li.get("quantity") if isinstance(li, dict) else None
        if not _nonempty_str(pid) or not _is_nonneg_int(qty):
            return ev.gap(
                "G-03",
                "L3b line item has no item.id/integer quantity; the L3b line_items schema is inconsistent "
                "between credential-format §5.5 and constraints.md §4.2/§8.2",
            )
        selected[pid] = selected.get(pid, 0) + qty

    for pid, qty in selected.items():
        explicit = [e for e in entries if e[0] is not None and pid in e[0]]
        wildcard = [e for e in entries if e[0] is None]
        if not explicit and not wildcard:
            if any(e[1] for e in entries):
                ev.gap("G-04", f"item {pid} not among disclosed acceptable_items but some are undisclosed")
            else:
                ev.violation(f"Item {pid} not in acceptable items list")
            continue
        cap_explicit = sum(e[2] for e in explicit)
        cap_with_wild = cap_explicit + sum(e[2] for e in wildcard)
        if qty > cap_with_wild:
            ev.violation(f"Quantity of {pid} exceeds per-item limit: {qty} > {cap_with_wild}")
        elif qty > cap_explicit and explicit and wildcard:
            ev.gap("G-13", f"per-item cap for {pid} depends on whether wildcard entries count (§4.2 step 5c)")

    total_cap = sum(e[2] for e in entries)
    total = sum(selected.values())
    if total > total_cap:
        ev.violation(f"Total quantity exceeds limit: {total} > {total_cap}")

    if match_mode == "exact":
        for ids, undisclosed, _qty in entries:
            if ids is None:
                if not any(q > 0 for q in selected.values()):
                    ev.violation("exact match: wildcard line item entry not fulfilled")
            elif not any(selected.get(i, 0) > 0 for i in ids):
                if undisclosed:
                    ev.gap("G-04", "exact match cannot be decided: entry has undisclosed acceptable_items")
                else:
                    ev.violation("exact match: allowed line item entry not fulfilled")
    return None


# --------------------------------------------------------------------------
# amounts (§4.4, §4.5)
# --------------------------------------------------------------------------


def _amount_from(ev: _Eval, ful: Fulfillment) -> tuple[int, Any] | None:
    pa = ful.payment_amount
    if not isinstance(pa, dict):
        ev.violation("Missing payment_amount in L3a payment mandate")
        return None
    amount = pa.get("amount")
    if not _is_nonneg_int(amount):
        ev.violation("Invalid amount format")
        return None
    return amount, pa.get("currency")


def _eval_amount_range(ev: _Eval, c, ful: Fulfillment | None, *_):
    cur, lo, hi = c.get("currency"), c.get("min"), c.get("max")
    if not _nonempty_str(cur):
        return ev.violation("'currency' is required", Code.CONSTRAINT_MALFORMED)
    for name, v in (("min", lo), ("max", hi)):
        if v is not None and not _is_nonneg_int(v):
            return ev.violation(f"'{name}' must be a non-negative integer", Code.CONSTRAINT_MALFORMED)
    if ful is None or not ful.has_payment:
        return ev.not_evaluated("no L3a payment mandate presented")
    got = _amount_from(ev, ful)
    if got is None:
        return None
    amount, currency = got
    if hi is not None and amount > hi:
        ev.violation(f"Amount exceeded: {amount} > {hi} {cur}")
    if lo is not None and amount < lo:
        ev.violation(f"Amount below minimum: {amount} < {lo} {cur}")
    if currency != cur:
        ev.violation(f"Currency mismatch: expected {cur}, got {currency}")
    return None


def _eval_budget(ev: _Eval, c, ful: Fulfillment | None, state: NetworkState | None, *_):
    cur, lo, hi = c.get("currency"), c.get("min"), c.get("max")
    if not _nonempty_str(cur):
        return ev.violation("'currency' is required", Code.CONSTRAINT_MALFORMED)
    if not _is_nonneg_int(hi):
        return ev.violation("'max' is required and must be a non-negative integer", Code.CONSTRAINT_MALFORMED)
    if lo is not None and not (_is_int(lo) and lo > 0):
        return ev.violation("'min' must be a positive integer", Code.CONSTRAINT_MALFORMED)
    if ful is None or not ful.has_payment:
        return ev.not_evaluated("no L3a payment mandate presented")
    got = _amount_from(ev, ful)
    if got is None:
        return None
    amount, currency = got
    if lo is not None and amount < lo:
        ev.violation(f"Amount below budget minimum: {amount} < {lo} {cur}")
    if currency != cur:
        ev.violation(f"Currency mismatch: expected {cur}, got {currency}")
    spent = state.cumulative_spent if state else None
    if spent is not None:
        if amount + spent > hi:
            ev.violation(f"Budget exceeded: {amount + spent} > {hi} {cur}")
    elif amount > hi:
        # cumulative_spent >= 0, so new_cumulative >= amount > max regardless of state.
        ev.violation(f"Budget exceeded: {amount} > {hi} {cur} (already exceeded by this transaction alone)")
    elif not ev.violated:
        ev.gap("G-05", "cumulative budget needs payment-network state (cumulative_spent), which was not supplied")
    return None


# --------------------------------------------------------------------------
# recurrence (§4.6, §4.7)
# --------------------------------------------------------------------------


def _parse_date(v: Any) -> _dt.date | None:
    if not isinstance(v, str):
        return None
    try:
        return _dt.date.fromisoformat(v)
    except ValueError:
        return None


def _eval_recurrence(ev: _Eval, c, *_):
    if c.get("frequency") not in ISO20022_FREQUENCIES:
        ev.violation("'frequency' must be an ISO 20022 frequency code", Code.CONSTRAINT_MALFORMED)
    if _parse_date(c.get("start_date")) is None:
        ev.violation("'start_date' must be an ISO 8601 date", Code.CONSTRAINT_MALFORMED)
    if "end_date" in c and _parse_date(c["end_date"]) is None:
        ev.violation("'end_date' must be an ISO 8601 date", Code.CONSTRAINT_MALFORMED)
    if "number" in c and not (_is_int(c["number"]) and c["number"] > 0):
        ev.violation("'number' must be a positive integer", Code.CONSTRAINT_MALFORMED)
    if ev.violated:
        return
    if "end_date" not in c or "number" not in c:
        ev.warn(Code.RECURRENCE_UNBOUNDED, "end_date and/or number absent; recurrence may be open-ended (§7.4)")
    # §4.6: merchant recurrence metadata format is implementation-defined in v0.1;
    # validation happens only when metadata is available. KYA Bench receives none.
    ev.note("no merchant recurrence metadata available; nothing further to validate (§4.6 note)")


def _eval_agent_recurrence(ev: _Eval, c, ful, state: NetworkState | None, now: int | None, siblings, _ref):
    freq = c.get("frequency")
    if freq != "ON_DEMAND" and freq not in ISO20022_FREQUENCIES:
        ev.violation("'frequency' must be ON_DEMAND or an ISO 20022 code", Code.CONSTRAINT_MALFORMED)
    start, end = _parse_date(c.get("start_date")), _parse_date(c.get("end_date"))
    if start is None or end is None:
        ev.violation("'start_date' and 'end_date' must be ISO 8601 dates", Code.CONSTRAINT_MALFORMED)
    mo = c.get("max_occurrences")
    if mo is not None and not (_is_int(mo) and mo > 0):
        ev.violation("'max_occurrences' must be a positive integer", Code.CONSTRAINT_MALFORMED)
    if ev.violated:
        return
    if AMOUNT_RANGE not in siblings:
        ev.violation(f"{AGENT_RECURRENCE} requires {AMOUNT_RANGE} constraint")
    if BUDGET not in siblings:
        ev.violation(f"{AGENT_RECURRENCE} requires {BUDGET} constraint")
    if ful is None or not ful.has_payment:
        return ev.not_evaluated("no L3a payment mandate presented")
    if now is not None:
        # "current date" has no time zone in §4.7; evaluate at the extremes of
        # UTC-12..UTC+14 and only decide when every zone agrees (G-08).
        verdicts = set()
        for offset_h in (-12, 14):
            d = (_dt.datetime.fromtimestamp(now, _dt.UTC) + _dt.timedelta(hours=offset_h)).date()
            verdicts.add(start <= d <= end)
        if verdicts == {False}:
            ev.violation("Agent recurrence period expired or not yet started")
        elif len(verdicts) > 1:
            ev.gap("G-08", "current date is in/out of range depending on time zone, which §4.7 does not specify")
    count = state.occurrence_count if state else None
    if mo is not None:
        if count is None:
            ev.gap("G-05", "max_occurrences needs payment-network state (occurrence_count), which was not supplied")
        elif count >= mo:
            ev.violation(f"Maximum occurrences exceeded: {count} >= {mo}")
    return None


def _eval_reference(ev: _Eval, c, ful, state, now, siblings, reference_ok: bool | None):
    if not _nonempty_str(c.get("conditional_transaction_id")):
        return ev.violation("'conditional_transaction_id' is required", Code.CONSTRAINT_MALFORMED)
    if reference_ok is None:
        return ev.not_evaluated("validated by chain verification (§4.8); no chain context supplied")
    if not reference_ok:
        return ev.violation("conditional_transaction_id does not match the checkout mandate disclosure hash")
    ev.note("verified by chain verification (§4.8)")
    return None


_EVALUATORS = {
    ALLOWED_MERCHANTS: _eval_allowed_merchants,
    LINE_ITEMS: _eval_line_items,
    ALLOWED_PAYEES: _eval_allowed_payees,
    AMOUNT_RANGE: _eval_amount_range,
    BUDGET: _eval_budget,
    RECURRENCE: _eval_recurrence,
    AGENT_RECURRENCE: _eval_agent_recurrence,
    REFERENCE: _eval_reference,
}
