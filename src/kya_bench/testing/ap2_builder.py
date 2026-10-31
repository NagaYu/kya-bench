"""AP2 v0.2 test mandate chains (TEST-ONLY keys, deterministic, offline).

Shapes follow AP2@e1ea56d docs/ap2/checkout_mandate.md examples and the SDK:
root SD-JWT signed by a trusted Agent Provider key (``kid`` from the trust
list), mandate content as an array-element disclosure referenced from
``delegate_payload``; closed checkout mandates carry ``checkout_jwt`` as a
property disclosure; the agent's terminal hop is a ``kb+sd-jwt`` bound by
``sd_hash``. Note: AP2 requires ``checkout_jwt`` to use a non-deterministic
signature scheme; fixtures use RFC 6979 ECDSA for reproducibility (see
docs/spec-gaps.md AP2 notes). Verifiers cannot observe the difference.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from ..parser import sha256_b64url
from .builder import NOW, _Salts, disclosure, public_jwk, ref, sign_jws

PROVIDER_ISS = "https://agent-provider.example"
PROVIDER_KID = "agent-provider-key-1"
MERCHANTS = [
    {"id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example"},
    {"id": "merchant_2", "name": "Second Merchant", "website": "https://second-merchant.example"},
]
ITEMS = [{"id": "supershoe_gold_w9", "title": "SuperShoe Limited Edition Gold"}]
INSTRUMENT = {"id": "b3f1c8a2-6d4e-4f9a-9e3d-8a7c2f1b9d34", "type": "dpc", "description": "DPC ···· 4444"}

Hook = Callable[[dict[str, Any]], None]


def trust_jwks() -> dict[str, Any]:
    """Trust list of Agent Providers (stand-in for the verifier's configured roots)."""
    jwk = public_jwk("ap2-provider", PROVIDER_KID) | {"use": "sig", "alg": "ES256"}
    return {PROVIDER_ISS: {"keys": [jwk]}}


@dataclass
class Ap2Spec:
    flow: str = "hnp"  # "hnp" (human-not-present) | "hp" (human-present)
    now: int = NOW
    agent: str = "ap2-agent"
    signers: dict[str, str] = field(default_factory=lambda: {
        "checkout_root": "ap2-provider", "payment_root": "ap2-provider",
        "checkout_term": "ap2-agent", "payment_term": "ap2-agent", "merchant": "ap2-merchant"})
    amount: int = 19900
    currency: str = "USD"
    merchant: dict[str, Any] = field(default_factory=lambda: dict(MERCHANTS[0]))
    payee: dict[str, Any] | None = None  # default: the checkout merchant
    cart: list[dict[str, Any]] = field(default_factory=lambda: [
        {"id": "li_1", "item": {"id": ITEMS[0]["id"], "title": ITEMS[0]["title"], "price": 19900}, "quantity": 1,
         "totals": [{"type": "total", "amount": 19900}]}])
    cart_total: int | None = None  # default: amount
    merchants: list[dict[str, Any]] = field(default_factory=lambda: copy.deepcopy(MERCHANTS))
    items: list[dict[str, Any]] = field(default_factory=lambda: copy.deepcopy(ITEMS))
    checkout_constraints: list[Any] = field(default_factory=lambda: [
        {"type": "checkout.allowed_merchants", "allowed": ["$merchant:0", "$merchant:1"]},
        {"type": "checkout.line_items", "items": [{"id": "line_1", "acceptable_items": ["$item:0"], "quantity": 1}]},
    ])
    payment_constraints: list[Any] = field(default_factory=lambda: [
        {"type": "payment.amount_range", "currency": "USD", "min": 1000, "max": 25000},
        {"type": "payment.allowed_payees", "allowed": ["$merchant:0", "$merchant:1"]},
        {"type": "payment.reference", "conditional_transaction_id": "$auto"},
    ])
    open_payment_extra: dict[str, Any] = field(default_factory=dict)  # pre-set claims
    closed_payment_extra: dict[str, Any] = field(default_factory=dict)
    open_exp: int | None = None  # default now + 1 h
    hp_closed_cnf: bool = True  # human-present closed mandates name the agent via cnf (OpenID4VP example)
    hooks: dict[str, Hook] = field(default_factory=dict)
    include: tuple[str, ...] = ("checkout_mandate", "payment_mandate")
    expected: bool = True
    mandate_context: dict[str, Any] | None = None
    open_disclose: dict[str, list[str]] | None = None  # side -> nested refs to reveal (default: all)
    hash_mode: str = "sd_hash"  # or "issuer_jwt_hash" (SDK MandateClient.present hash_mode)


def _subst(node: Any, table: dict[str, Any]) -> Any:
    if isinstance(node, str) and node in table:
        return table[node]
    if isinstance(node, list):
        return [_subst(x, table) for x in node]
    if isinstance(node, dict):
        return {k: _subst(v, table) for k, v in node.items()}
    return node


def _hook(spec: Ap2Spec, name: str, obj: dict[str, Any]) -> dict[str, Any]:
    if name in spec.hooks:
        spec.hooks[name](obj)
    return obj


def _token(jws: str, discs: list[str]) -> str:
    return "~".join([jws, *discs]) + "~"


def _root(spec: Ap2Spec, side: str, mandate: dict[str, Any], nested: list[str], salt: _Salts) -> str:
    md = disclosure(_hook(spec, f"{side}_mandate", mandate), salt())
    payload = _hook(spec, f"{side}_root_payload", {
        "iss": PROVIDER_ISS, "iat": spec.now - 600, "_sd_alg": "sha-256", "delegate_payload": [ref(md)]})
    header = _hook(spec, f"{side}_root_header", {"alg": "ES256", "typ": "example+sd-jwt", "kid": PROVIDER_KID})
    return _token(sign_jws(header, payload, spec.signers[f"{side}_root"]), [*nested, md])


def _terminal(spec: Ap2Spec, side: str, prev: str, mandate: dict[str, Any], extra: list[str], salt: _Salts) -> str:
    md = disclosure(_hook(spec, f"{side}_closed", mandate), salt())
    payload = _hook(spec, f"{side}_term_payload", {
        "delegate_payload": [ref(md)], "iat": spec.now - 30, "aud": AUD[side], "nonce": NONCE[side],
        spec.hash_mode: sha256_b64url(prev if spec.hash_mode == "sd_hash" else prev.split("~")[0]),
        "_sd_alg": "sha-256"})
    header = _hook(spec, f"{side}_term_header", {"alg": "ES256", "typ": "kb+sd-jwt"})
    return _token(sign_jws(header, payload, spec.signers[f"{side}_term"]), [*extra, md])


AUD = {"checkout": "https://demo-merchant.example", "payment": "https://credential-provider.example"}
NONCE = {"checkout": "b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4", "payment": "4e5d6c7b8a9f0e1d2c3b4a5f6e7d8c9b"}


def checkout_jwt(spec: Ap2Spec) -> str:
    payload = _hook(spec, "checkout_jwt_payload", {
        "id": "checkout_09414145",
        "merchant": spec.merchant,
        "line_items": spec.cart,
        "status": "ready_for_complete",
        "currency": spec.currency,
        "totals": [{"type": "total", "amount": spec.amount if spec.cart_total is None else spec.cart_total}],
        "links": [],
    })
    return sign_jws({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"}, payload, spec.signers["merchant"])


def build(spec: Ap2Spec) -> dict[str, Any]:
    spec = copy.deepcopy(spec)
    salt = _Salts(f"ap2/{spec.flow}/{spec.now}")
    agent_cnf = {"jwk": public_jwk(spec.agent)}
    cj = checkout_jwt(spec)
    ch = sha256_b64url(cj)
    cj_disc = disclosure(cj, salt(), "checkout_jwt")
    closed_checkout = {"_sd": [sha256_b64url(cj_disc)], "vct": "mandate.checkout.1", "checkout_hash": ch}
    closed_payment = {
        "vct": "mandate.payment.1",
        "transaction_id": ch,
        "payee": spec.payee if spec.payee is not None else spec.merchant,
        "payment_amount": {"amount": spec.amount, "currency": spec.currency},
        "payment_instrument": INSTRUMENT,
    } | spec.closed_payment_extra
    out: dict[str, Any] = {}
    if spec.flow == "hp":
        if spec.hp_closed_cnf:
            closed_checkout["cnf"] = agent_cnf
        out["checkout_mandate"] = _root(spec, "checkout", closed_checkout, [cj_disc], salt)
        out["payment_mandate"] = _root(spec, "payment", closed_payment, [], salt)
    else:
        table: dict[str, Any] = {}
        named: dict[str, str] = {}
        for i, m in enumerate(spec.merchants):
            d = disclosure(m, salt())
            named[f"$merchant:{i}"], table[f"$merchant:{i}"] = d, ref(d)
        for i, it in enumerate(spec.items):
            d = disclosure(it, salt())
            named[f"$item:{i}"], table[f"$item:{i}"] = d, ref(d)
        exp = spec.now + 3600 if spec.open_exp is None else spec.open_exp

        def nested(side: str, constraints: list[Any]) -> list[str]:
            used = [n for n in named if n in repr(constraints)]
            if spec.open_disclose and side in spec.open_disclose:
                used = [n for n in used if n in spec.open_disclose[side]]
            return [named[n] for n in used]

        open_checkout = {"vct": "mandate.checkout.open.1", "constraints": _subst(spec.checkout_constraints, table),
                         "cnf": agent_cnf, "iat": spec.now - 600, "exp": exp}
        co_root = _root(spec, "checkout", open_checkout, nested("checkout", spec.checkout_constraints), salt)
        pay_cs = _subst(spec.payment_constraints, table)
        for c in pay_cs:
            if isinstance(c, dict) and c.get("conditional_transaction_id") == "$auto":
                c["conditional_transaction_id"] = sha256_b64url(co_root)
        open_payment = {"vct": "mandate.payment.open.1", "constraints": pay_cs, "cnf": agent_cnf,
                        "iat": spec.now - 600, "exp": exp} | spec.open_payment_extra
        pa_root = _root(spec, "payment", open_payment, nested("payment", spec.payment_constraints), salt)
        co_term = _terminal(spec, "checkout", co_root, closed_checkout, [cj_disc], salt)
        pa_term = _terminal(spec, "payment", pa_root, closed_payment, [], salt)
        out["checkout_mandate"] = co_root[:-1] + "~~" + co_term
        out["payment_mandate"] = pa_root[:-1] + "~~" + pa_term
    bundle = {k: v for k, v in out.items() if k in spec.include}
    if spec.expected and spec.flow == "hnp":
        bundle["expected"] = {"checkout_aud": AUD["checkout"], "checkout_nonce": NONCE["checkout"],
                              "payment_aud": AUD["payment"], "payment_nonce": NONCE["payment"]}
    if spec.mandate_context is not None:
        bundle["mandate_context"] = spec.mandate_context
    return bundle
