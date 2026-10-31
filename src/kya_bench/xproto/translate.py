"""AP2 -> VI translation and translation-equivalence checking.

The translator maps a subset of an AP2 human-not-present intent (open
mandates) onto VI:

======================================  ======================================
AP2 v0.2                                VI v0.1
======================================  ======================================
``payment.amount_range``                ``mandate.payment.amount_range``
``checkout.allowed_merchants``          ``mandate.checkout.allowed_merchants``
open mandate ``exp``                    Autonomous L2 ``exp`` (CF §4.3, §4.7)
======================================  ======================================

Anything else is untranslatable (``XLATE_UNSUPPORTED``). The equivalence
checker evaluates one fulfillment probe twice: with AP2's own scope logic
(``kya_bench.ap2.constraints`` + the SDK's exp rule) and with the translated
constraints through the Phase 1 VI engine (+ VI's exp rule). Agreement means
the translation preserves meaning for that probe; disagreement is either a
translator bug or a semantic difference between the specs — the vectors and
docs/spec-gaps.md record which.

Translation payload::

    {"intent": {"payment_constraints": [...], "checkout_constraints": [...], "exp": int},
     "probe": {"payment_amount": {...}, "payee"?: {...}, "merchant": {...}}}
"""

from __future__ import annotations

import json
import time
from enum import StrEnum
from typing import Any

from ..ap2 import constraints as ap2c
from ..ap2.verifier import CLOCK_SKEW as AP2_SKEW
from ..constraints import Fulfillment, Strictness, check_constraints
from ..reasons import Finding, reject, warn
from ..verifier import DEFAULT_CLOCK_SKEW as VI_SKEW
from ..verifier import Check, Verdict

TRANSLATABLE = {
    "payment.amount_range": "mandate.payment.amount_range",
    "checkout.allowed_merchants": "mandate.checkout.allowed_merchants",
}


class XlateCode(StrEnum):
    XLATE_INPUT_INVALID = "XLATE_INPUT_INVALID"
    XLATE_UNSUPPORTED = "XLATE_UNSUPPORTED"
    XLATE_EQUIVALENT = "XLATE_EQUIVALENT"
    XLATE_DIVERGENT = "XLATE_DIVERGENT"
    XLATE_UNDECIDED = "XLATE_UNDECIDED"
    XLATE_BOTH_ACCEPT = "XLATE_BOTH_ACCEPT"
    XLATE_BOTH_REJECT = "XLATE_BOTH_REJECT"


def translate(intent: dict[str, Any]) -> tuple[dict[str, list[dict[str, Any]]], int | None, list[str]]:
    """Return ({"checkout": [...], "payment": [...]} VI constraints, VI L2 exp, untranslatable types)."""
    out: dict[str, list[dict[str, Any]]] = {"checkout": [], "payment": []}
    unsupported = []
    for side in ("checkout", "payment"):
        for c in intent.get(f"{side}_constraints", []):
            t = c.get("type") if isinstance(c, dict) else None
            if t not in TRANSLATABLE:
                unsupported.append(str(t))
                continue
            vi = {k: v for k, v in c.items() if k != "type"}
            out[side].append({"type": TRANSLATABLE[t], **vi})
    exp = intent.get("exp")
    return out, exp if isinstance(exp, int) else None, unsupported


def _ap2_side(intent: dict[str, Any], probe: dict[str, Any], now: int) -> tuple[str, list[str]]:
    closed = {"payment_amount": probe.get("payment_amount"), "payee": probe.get("payee", probe.get("merchant"))}
    ctx = ap2c.Ap2Context(closed_payment=closed, checkout_payload={"merchant": probe.get("merchant")})
    results = ap2c.evaluate(intent.get("checkout_constraints", []), "checkout", ctx)
    results += ap2c.evaluate(intent.get("payment_constraints", []), "payment", ap2c.Ap2Context(
        closed_payment=closed, checkout_payload=ctx.checkout_payload))
    notes = [f"{r.type}: {r.status} {'; '.join(r.messages)}".strip() for r in results]
    exp = intent.get("exp")
    expired = isinstance(exp, int) and now > exp + AP2_SKEW  # SDK chain._check_time_claims
    if expired:
        notes.append(f"open mandate expired at {exp}")
    statuses = {r.status for r in results}
    if expired or statuses & {"violation", "unknown_rejected"}:
        return "reject", notes
    return ("indeterminate" if "indeterminate" in statuses else "accept"), notes


def _vi_side(vi: dict[str, list[dict[str, Any]]], exp: int | None, probe: dict[str, Any],
             now: int) -> tuple[str, list[str]]:
    ful = Fulfillment(has_checkout=True, has_payment=True, merchant=probe.get("merchant"),
                      payee=probe.get("payee", probe.get("merchant")), payment_amount=probe.get("payment_amount"))
    results = []
    for side in ("checkout", "payment"):
        results += check_constraints(vi[side], ful, strictness=Strictness.STRICT, is_open_mandate=True,
                                     mandate=side, now=now)
    notes = [f"{r.type}: {r.status} {'; '.join(r.messages)}".strip() for r in results]
    expired = exp is not None and now > exp + VI_SKEW  # CF §4.7 rule 4
    if expired:
        notes.append(f"L2 expired at {exp}")
    statuses = {r.status for r in results}
    if expired or statuses & {"violation", "unknown_rejected"}:
        return "reject", notes
    return ("indeterminate" if "indeterminate" in statuses else "accept"), notes


def check_translation(payload: Any, *, now: int | None = None) -> Verdict:
    now = int(time.time()) if now is None else now
    if isinstance(payload, str):
        try:
            payload = json.loads(payload)
        except ValueError:
            payload = None
    findings: list[Finding] = []
    L = "translation"
    intent = payload.get("intent") if isinstance(payload, dict) else None
    probe = payload.get("probe") if isinstance(payload, dict) else None
    if not isinstance(intent, dict) or not isinstance(probe, dict):
        findings.append(reject(XlateCode.XLATE_INPUT_INVALID, "translation needs 'intent' and 'probe' objects", L))
        return _verdict(findings, [], {}, now)
    vi, exp, unsupported = translate(intent)
    if unsupported:
        findings.append(Finding(XlateCode.XLATE_UNSUPPORTED, "indeterminate",
                                f"untranslatable AP2 constraint types {unsupported}", L))
        return _verdict(findings, [], {"vi": vi}, now)
    a, a_notes = _ap2_side(intent, probe, now)
    v, v_notes = _vi_side(vi, exp, probe, now)
    detail = {"ap2": a, "vi": v}
    checks = [Check("translation.ap2", "pass" if a == "accept" else "fail", "; ".join(a_notes)),
              Check("translation.vi", "pass" if v == "accept" else "fail", "; ".join(v_notes))]
    if "indeterminate" in (a, v):
        findings.append(Finding(XlateCode.XLATE_UNDECIDED, "indeterminate",
                                f"one side is undecided (AP2 {a}, VI {v})", L, None, detail))
    elif a == v:
        findings.append(warn(XlateCode.XLATE_EQUIVALENT, f"both sides {a}", L, **detail))
        findings.append(warn(XlateCode.XLATE_BOTH_ACCEPT if a == "accept" else XlateCode.XLATE_BOTH_REJECT,
                             f"AP2 and translated VI agree: {a}", L))
    else:
        findings.append(reject(XlateCode.XLATE_DIVERGENT, f"AP2 says {a}, translated VI says {v}", L, **detail))
    return _verdict(findings, checks, {"vi": vi, "vi_exp": exp, "ap2_result": a, "vi_result": v}, now)


def _verdict(findings: list[Finding], checks: list[Check], details: dict[str, Any], now: int) -> Verdict:
    verdict = "reject" if any(f.effect == "reject" for f in findings) else \
        "indeterminate" if any(f.effect == "indeterminate" for f in findings) else "accept"
    return Verdict(
        verdict=verdict, mode=None, strictness=Strictness.STRICT, evaluated_at=now,
        identity_ok=False, delegation_chain_ok=False, constraints=[], findings=findings, checks=checks,
        protocol="translation",
        cross_ref_map={"equivalent": None if verdict == "indeterminate" else verdict == "accept"},
        details=details,
    )
