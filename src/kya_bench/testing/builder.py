"""Build VI credential bundles for tests and fixtures.

Everything is offline and deterministic: keys are derived from ``SEED`` plus a
label, salts from a counter, timestamps from ``NOW``, and ES256 signatures use
RFC 6979 deterministic nonces. Building the same spec twice yields byte-identical
output. ALL KEYS HERE ARE TEST-ONLY and must never be used for anything real.

Usage: create a spec with ``immediate_spec()`` / ``autonomous_spec()``, mutate
any dict on it to model a defect, then call ``build(spec)``. ``hooks`` run on a
layer's header/payload right before signing, after automatic fields (sd_hash,
checkout_hash, ...) are filled in.

Wire format follows the VI reference implementation: every disclosure is an
array-element disclosure listed in ``_sd`` and referenced via ``{"...": d}``.
"""

from __future__ import annotations

import copy
import hashlib
import json
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature

from ..parser import b64url_encode, sha256_b64url

SEED = "kya-bench/vi/phase1"  # root of all test key material (TEST ONLY)
NOW = 1_790_000_000  # 2026-09-21T14:13:20Z — fixed verification time for vectors
ISSUER = "https://issuer.example.com"
ISSUER_KID = "issuer-key-1"
AGENT_KID = "agent-key-1"
MC_CARD_VCT = "https://credentials.mastercard.com/card"
_P256_ORDER = 0xFFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551


# --------------------------------------------------------------------------
# keys / JWS
# --------------------------------------------------------------------------


def private_key(label: str) -> ec.EllipticCurvePrivateKey:
    """Deterministic P-256 test key derived from a label. TEST ONLY."""
    d = int.from_bytes(hashlib.sha256(f"{SEED}/test-key/{label}".encode()).digest(), "big")
    return ec.derive_private_key(d % (_P256_ORDER - 1) + 1, ec.SECP256R1())


def public_jwk(label: str, kid: str | None = None) -> dict[str, Any]:
    nums = private_key(label).public_key().public_numbers()
    jwk = {
        "kty": "EC",
        "crv": "P-256",
        "x": b64url_encode(nums.x.to_bytes(32, "big")),
        "y": b64url_encode(nums.y.to_bytes(32, "big")),
    }
    if kid:
        jwk["kid"] = kid
    return jwk


def sign_jws(header: dict[str, Any], payload: dict[str, Any], key_label: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    der = private_key(key_label).sign(
        f"{h}.{p}".encode("ascii"), ec.ECDSA(hashes.SHA256(), deterministic_signing=True)
    )
    r, s = decode_dss_signature(der)
    return f"{h}.{p}.{b64url_encode(r.to_bytes(32, 'big') + s.to_bytes(32, 'big'))}"


def jwks_fixture() -> dict[str, Any]:
    """Local stand-in for the issuer's JWKS endpoint."""
    jwk = public_jwk("issuer", ISSUER_KID) | {"use": "sig", "alg": "ES256"}
    return {ISSUER: {"keys": [jwk]}}


class _Salts:
    def __init__(self, prefix: str):
        self.prefix, self.n = prefix, 0

    def __call__(self) -> str:
        self.n += 1
        return b64url_encode(hashlib.sha256(f"{SEED}/salt/{self.prefix}/{self.n}".encode()).digest()[:16])


def disclosure(value: Any, salt: str, name: str | None = None) -> str:
    arr = [salt, name, value] if name is not None else [salt, value]
    return b64url_encode(json.dumps(arr, separators=(",", ":")).encode())


def ref(disc: str) -> dict[str, str]:
    return {"...": sha256_b64url(disc)}


def sd_jwt(jws: str, discs: list[str]) -> str:
    return "~".join([jws, *discs]) + "~"


# --------------------------------------------------------------------------
# specs
# --------------------------------------------------------------------------

Hook = Callable[[dict[str, Any]], None]


@dataclass
class Spec:
    mode: str
    now: int = NOW
    signers: dict[str, str] = field(
        default_factory=lambda: {"L1": "issuer", "L2": "user", "L3a": "agent", "L3b": "agent", "merchant": "merchant"}
    )
    user_key: str = "user"
    agent_key: str = "agent"
    l1_header: dict[str, Any] = field(default_factory=dict)
    l1_claims: dict[str, Any] = field(default_factory=dict)
    l1_sd_claims: dict[str, Any] = field(default_factory=dict)
    l2_header: dict[str, Any] = field(default_factory=dict)
    l2_claims: dict[str, Any] = field(default_factory=dict)
    merchants: list[dict[str, Any]] = field(default_factory=list)
    items: list[dict[str, Any]] = field(default_factory=list)
    checkout_jwt_payload: dict[str, Any] = field(default_factory=dict)
    checkout_mandate: dict[str, Any] = field(default_factory=dict)
    payment_mandate: dict[str, Any] = field(default_factory=dict)
    l3a_header: dict[str, Any] = field(default_factory=dict)
    l3a_claims: dict[str, Any] = field(default_factory=dict)
    l3a_payment: dict[str, Any] = field(default_factory=dict)
    l3a_selected_merchant: int | None = 0
    l3b_header: dict[str, Any] = field(default_factory=dict)
    l3b_claims: dict[str, Any] = field(default_factory=dict)
    l3b_checkout: dict[str, Any] = field(default_factory=dict)
    view_l3a_items: list[str] = field(default_factory=lambda: ["$payment", "$merchant:0"])
    view_l3b_items: list[str] = field(default_factory=lambda: ["$checkout", "$item:0"])
    include_l3: tuple[str, ...] = ("l3a", "l3b")
    include_views: bool = True
    l2_disclose: list[str] | None = None  # e.g. ["$checkout"] for a partial presentation
    pairs: int = 1  # >1 repeats the mandate pair (fresh salts) to model a multi-pair L2
    hooks: dict[str, Hook] = field(default_factory=dict)
    extra_bundle: dict[str, Any] = field(default_factory=dict)


PAYMENT_INSTRUMENT = {
    "type": "mastercard.srcDigitalCard",
    "id": "f199c3dd-7106-478b-9b5f-7af9ca725170",
    "description": "Mastercard **** 1234",
}
MERCHANTS = [
    {"id": "merchant-uuid-1", "name": "Tennis Warehouse", "website": "https://tennis-warehouse.com"},
    {"id": "merchant-uuid-2", "name": "Babolat", "website": "https://babolat.com"},
]
ITEMS = [{"id": "BAB86345", "title": "Babolat Pure Aero Tennis Racket"}]


def _common(spec: Spec) -> Spec:
    now = spec.now
    spec.l1_header = {"alg": "ES256", "typ": "sd+jwt", "kid": ISSUER_KID}
    spec.l1_claims = {
        "iss": ISSUER,
        "sub": "user-8a3f9c21",
        "iat": now - 86_400,
        "exp": now + 300 * 86_400,
        "vct": MC_CARD_VCT,
        "cnf": {"jwk": public_jwk(spec.user_key)},
        "pan_last_four": "1234",
        "scheme": "mastercard",
        "card_id": "card-mc-8842",
    }
    spec.l1_sd_claims = {"email": "user@example.com"}
    spec.checkout_jwt_payload = {
        "iss": MERCHANTS[0]["website"],
        "id": MERCHANTS[0]["id"],
        "name": MERCHANTS[0]["name"],
        "website": MERCHANTS[0]["website"],
        "iat": now - 60,
        "cart": {"items": [{"sku": "BAB86345", "quantity": 1, "unit_price": 27999}], "currency": "USD"},
    }
    return spec


def immediate_spec(now: int = NOW) -> Spec:
    spec = _common(Spec(mode="immediate", now=now, include_l3=(), include_views=False))
    spec.l2_header = {"alg": "ES256", "typ": "kb-sd-jwt", "kid": "user-device-key-1"}
    spec.l2_claims = {
        "nonce": "a3f9c21b8e4d7f2a",
        "aud": "https://network.example.com/vi/authorize",
        "iat": now - 60,
        "exp": now - 60 + 900,
    }
    spec.checkout_mandate = {"vct": "mandate.checkout.1", "checkout_jwt": "$auto", "checkout_hash": "$auto"}
    spec.payment_mandate = {
        "vct": "mandate.payment.1",
        "payment_instrument": dict(PAYMENT_INSTRUMENT),
        "payment_amount": {"currency": "USD", "amount": 27999},
        "payee": {"name": MERCHANTS[0]["name"], "website": MERCHANTS[0]["website"]},
        "transaction_id": "$auto",
    }
    return spec


def autonomous_spec(now: int = NOW) -> Spec:
    spec = _common(Spec(mode="autonomous", now=now))
    spec.l2_header = {"alg": "ES256", "typ": "kb-sd-jwt+kb", "kid": "user-device-key-1"}
    spec.l2_claims = {
        "nonce": "b7e2f4a9c1d3e8b2",
        "aud": "https://agent.example.com",
        "iat": now - 3600,
        "exp": now - 3600 + 7 * 86_400,
    }
    spec.merchants = copy.deepcopy(MERCHANTS)
    spec.items = copy.deepcopy(ITEMS)
    agent = public_jwk(spec.agent_key, AGENT_KID)
    spec.checkout_mandate = {
        "vct": "mandate.checkout.open.1",
        "cnf": {"jwk": dict(agent)},
        "constraints": [
            {"type": "mandate.checkout.allowed_merchants", "allowed": ["$merchant:0", "$merchant:1"]},
            {
                "type": "mandate.checkout.line_items",
                "items": [{"id": "line-1", "acceptable_items": ["$item:0"], "quantity": 1}],
            },
        ],
        "prompt_summary": "Buy a Babolat Pure Aero under $400 from approved merchants",
    }
    spec.payment_mandate = {
        "vct": "mandate.payment.open.1",
        "cnf": {"jwk": dict(agent)},
        "payment_instrument": dict(PAYMENT_INSTRUMENT),
        "constraints": [
            {"type": "mandate.payment.amount_range", "currency": "USD", "min": 10000, "max": 40000},
            {"type": "mandate.payment.allowed_payees", "allowed": ["$merchant:0", "$merchant:1"]},
            {"type": "mandate.payment.reference", "conditional_transaction_id": "$auto"},
        ],
    }
    spec.l3a_header = {"alg": "ES256", "typ": "kb-sd-jwt", "kid": AGENT_KID}
    spec.l3a_claims = {
        "nonce": "c9d1e2f3a4b5c6d7",
        "aud": "https://network.example.com/vi/authorize",
        "iat": now - 30,
        "exp": now - 30 + 300,
    }
    spec.l3a_payment = {
        "vct": "mandate.payment.1",
        "payment_instrument": dict(PAYMENT_INSTRUMENT),
        "payment_amount": {"currency": "USD", "amount": 27999},
        "payee": dict(MERCHANTS[0]),
        "transaction_id": "$auto",
    }
    spec.l3b_header = {"alg": "ES256", "typ": "kb-sd-jwt", "kid": AGENT_KID}
    spec.l3b_claims = {
        "nonce": "d8e2f4a5b6c7d8e9",
        "aud": "https://tennis-warehouse.com/checkout",
        "iat": now - 30,
        "exp": now - 30 + 300,
    }
    spec.l3b_checkout = {
        "vct": "mandate.checkout.1",
        "checkout_jwt": "$auto",
        "checkout_hash": "$auto",
        "line_items": [{"id": "line-item-1", "item": dict(ITEMS[0]), "quantity": 1}],
    }
    return spec


# --------------------------------------------------------------------------
# build
# --------------------------------------------------------------------------


def _hook(spec: Spec, name: str, obj: dict[str, Any]) -> dict[str, Any]:
    if name in spec.hooks:
        spec.hooks[name](obj)
    return obj


def _subst(node: Any, table: dict[str, Any]) -> Any:
    if isinstance(node, str) and node in table:
        return table[node]
    if isinstance(node, list):
        return [_subst(x, table) for x in node]
    if isinstance(node, dict):
        return {k: _subst(v, table) for k, v in node.items()}
    return node


def _issue(spec: Spec, layer: str, header: dict, claims: dict, discs: list[str], refs: list[dict]) -> str:
    payload = dict(claims)
    payload["delegate_payload"] = refs
    payload["_sd"] = [sha256_b64url(d) for d in discs]
    payload["_sd_alg"] = "sha-256"
    return sign_jws(_hook(spec, f"{layer}_header", dict(header)), _hook(spec, f"{layer}_payload", payload),
                    spec.signers[layer])


def build(spec: Spec) -> dict[str, Any]:
    """Return a KYA Bench bundle dict for ``spec``."""
    spec = copy.deepcopy(spec)
    salt = _Salts(f"{spec.mode}/{spec.now}")

    # L1 ------------------------------------------------------------------
    l1_discs = [disclosure(v, salt(), k) for k, v in spec.l1_sd_claims.items()]
    l1_payload = dict(spec.l1_claims)
    l1_payload["_sd"] = [sha256_b64url(d) for d in l1_discs]
    l1_payload["_sd_alg"] = "sha-256"
    l1 = sd_jwt(
        sign_jws(_hook(spec, "L1_header", dict(spec.l1_header)), _hook(spec, "L1_payload", l1_payload),
                 spec.signers["L1"]),
        l1_discs,
    )

    # checkout_jwt (merchant-signed) ----------------------------------------
    checkout_jwt = sign_jws({"alg": "ES256", "typ": "JWT", "kid": "merchant-key-1"},
                            _hook(spec, "checkout_jwt_payload", dict(spec.checkout_jwt_payload)),
                            spec.signers["merchant"])
    checkout_hash = sha256_b64url(checkout_jwt)
    auto = {"checkout_jwt": checkout_jwt, "checkout_hash": checkout_hash, "transaction_id": checkout_hash}

    def fill(m: dict[str, Any]) -> dict[str, Any]:
        return {k: (auto[k] if v == "$auto" and k in auto else v) for k, v in m.items()}

    # L2 ------------------------------------------------------------------
    table: dict[str, Any] = {}
    named: dict[str, str] = {}
    discs: list[str] = []
    for i, m in enumerate(spec.merchants):
        d = disclosure(m, salt())
        discs.append(d)
        named[f"$merchant:{i}"] = d
        table[f"$merchant:{i}"] = ref(d)
    for i, it in enumerate(spec.items):
        d = disclosure(it, salt())
        discs.append(d)
        named[f"$item:{i}"] = d
        table[f"$item:{i}"] = ref(d)
    checkout = fill(_subst(spec.checkout_mandate, table))
    checkout_disc = disclosure(_hook(spec, "checkout_mandate", checkout), salt())
    named["$checkout"] = checkout_disc
    payment = _subst(spec.payment_mandate, table)
    for c in payment.get("constraints", []):
        if isinstance(c, dict) and c.get("conditional_transaction_id") == "$auto":
            c["conditional_transaction_id"] = sha256_b64url(checkout_disc)
    payment_disc = disclosure(_hook(spec, "payment_mandate", fill(payment)), salt())
    named["$payment"] = payment_disc
    discs += [checkout_disc, payment_disc]
    mandate_refs = [ref(checkout_disc), ref(payment_disc)]
    for n in range(2, spec.pairs + 1):
        c_disc = disclosure(checkout, salt())
        p = copy.deepcopy(payment)
        for c in p.get("constraints", []):
            if isinstance(c, dict) and c.get("type") == "mandate.payment.reference":
                c["conditional_transaction_id"] = sha256_b64url(c_disc)
        p_disc = disclosure(fill(p), salt())
        named[f"$checkout:{n}"], named[f"$payment:{n}"] = c_disc, p_disc
        discs += [c_disc, p_disc]
        mandate_refs += [ref(c_disc), ref(p_disc)]

    l2_claims = dict(spec.l2_claims)
    l2_claims["sd_hash"] = sha256_b64url(l1)
    l2_jws = _issue(spec, "L2", spec.l2_header, l2_claims, discs, mandate_refs)
    presented = discs if spec.l2_disclose is None else [named[n] for n in spec.l2_disclose]
    bundle: dict[str, Any] = {"l1": l1, "l2": sd_jwt(l2_jws, presented)}

    # L3 ------------------------------------------------------------------
    if spec.mode == "autonomous":
        views = {
            "l3a": sd_jwt(l2_jws, [named[n] for n in spec.view_l3a_items]),
            "l3b": sd_jwt(l2_jws, [named[n] for n in spec.view_l3b_items]),
        }
        if "l3a" in spec.include_l3:
            l3_discs = []
            if spec.l3a_selected_merchant is not None:
                l3_discs.append(disclosure(spec.merchants[spec.l3a_selected_merchant], salt()))
            l3_discs.append(disclosure(_hook(spec, "l3a_payment", fill(spec.l3a_payment)), salt()))
            claims = dict(spec.l3a_claims) | {"sd_hash": sha256_b64url(views["l3a"])}
            jws = _issue(spec, "L3a", spec.l3a_header, claims, l3_discs, [ref(d) for d in l3_discs])
            bundle["l3a"] = sd_jwt(jws, l3_discs)
        if "l3b" in spec.include_l3:
            l3_discs = [disclosure(_hook(spec, "l3b_checkout", fill(spec.l3b_checkout)), salt())]
            claims = dict(spec.l3b_claims) | {"sd_hash": sha256_b64url(views["l3b"])}
            jws = _issue(spec, "L3b", spec.l3b_header, claims, l3_discs, [ref(d) for d in l3_discs])
            bundle["l3b"] = sd_jwt(jws, l3_discs)
        if spec.include_views:
            for k in spec.include_l3:
                bundle[f"l2_view_{k}"] = views[k]

    bundle.update(spec.extra_bundle)
    return bundle
