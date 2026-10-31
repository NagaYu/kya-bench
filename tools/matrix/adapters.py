"""Adapters that hand KYA Bench vectors to each protocol's reference implementation.

Each adapter returns ``RefResult(verdict, detail)`` with verdict ``accept`` /
``reject`` / ``error`` (the reference raised), or raises ``NotRunnable`` with a
reason when a vector cannot be expressed in the reference's input model.
Nothing here re-implements protocol logic: adapters only decode inputs, resolve
keys from the same offline fixtures, freeze the clock at the vector's ``now``,
and call the reference APIs in the order the reference's own examples/samples do.
"""

from __future__ import annotations

import json
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Any


class NotRunnable(Exception):
    pass


@dataclass
class RefResult:
    verdict: str  # accept | reject | error
    detail: str


def _jwk_by_kid(jwks: dict[str, Any], kid: str) -> tuple[str, dict[str, Any]] | None:
    hits = [(iss, k) for iss, doc in jwks.items() for k in doc.get("keys", []) if k.get("kid") == kid]
    return hits[0] if len(hits) == 1 else None


# ---------------------------------------------------------------------------- VI


class ViAdapter:
    """agent-intent/verifiable-intent@356c296 (src/verifiable_intent).

    Pipeline = examples/helpers.py ``verify_network``: ``verify_chain`` (with the
    L3a/L3b selective views), then ``check_constraints`` on the L2 payment
    mandate's constraints against the L3a payment mandate, STRICT, with payee
    allowlists resolved from L2 disclosures. Constraint-engine vectors call
    ``check_constraints`` directly with the vector's mode and is_open_mandate.
    """

    def __init__(self, repo: Path, jwks: dict[str, Any]):
        sys.path.insert(0, str(repo / "src"))
        from verifiable_intent.crypto.disclosure import hash_disclosure
        from verifiable_intent.crypto.sd_jwt import decode_sd_jwt
        from verifiable_intent.crypto.signing import jwk_to_public_key
        from verifiable_intent.verification import chain as chain_mod
        from verifiable_intent.verification.constraint_checker import StrictnessMode, check_constraints

        self.decode, self.jwk_to_key, self.hash_disclosure = decode_sd_jwt, jwk_to_public_key, hash_disclosure
        self.chain_mod, self.check, self.Mode = chain_mod, check_constraints, StrictnessMode
        self.jwks = jwks

    def _freeze(self, now: int) -> None:
        class _T:
            @staticmethod
            def time() -> float:
                return float(now)

        self.chain_mod.time = _T  # chain.py: now = int(time.time())

    def run(self, vector: dict[str, Any]) -> RefResult:
        if vector["kind"] == "constraint_check":
            cc = vector["constraint_check"]
            mode = self.Mode.STRICT if vector["strictness"] == "strict" else self.Mode.PERMISSIVE
            ful = {k: v for k, v in (cc.get("fulfillment") or {}).items() if not k.startswith("has_")}
            r = self.check(cc["constraints"], ful, mode=mode, is_open_mandate=bool(cc.get("is_open_mandate")))
            return RefResult("accept" if r.satisfied else "reject",
                             "; ".join(r.violations) or f"checked={r.checked} skipped={r.skipped}")
        b = vector["bundle"]
        if not isinstance(b, dict) or not isinstance(b.get("l1"), str) or not isinstance(b.get("l2"), str):
            raise NotRunnable("envelope-level vector: there is no L1/L2 pair to hand to verify_chain")
        self._freeze(vector["now"])
        try:
            l1, l2 = self.decode(b["l1"]), self.decode(b["l2"])
            l3a = self.decode(b["l3a"]) if isinstance(b.get("l3a"), str) else None
            l3b = self.decode(b["l3b"]) if isinstance(b.get("l3b"), str) else None
        except Exception as exc:  # noqa: BLE001 - reference decoder rejects
            return RefResult("reject", f"decode_sd_jwt: {exc}")
        hit = _jwk_by_kid(self.jwks, l1.header.get("kid", "")) if isinstance(l1.header, dict) else None
        if hit is None or hit[0] != l1.payload.get("iss"):
            raise NotRunnable("issuer key discovery (JWKS by iss+kid) is outside verify_chain's API; "
                              "the vector's iss/kid does not resolve to a key the adapter could pass in")
        exp = b.get("expected") or {}
        try:
            res = self.chain_mod.verify_chain(
                l1, l2, l3_payment=l3a, l3_checkout=l3b, issuer_public_key=self.jwk_to_key(hit[1]),
                l1_serialized=b["l1"], l2_serialized=b["l2"],
                l2_payment_serialized=b.get("l2_view_l3a"), l2_checkout_serialized=b.get("l2_view_l3b"),
                expected_l2_aud=exp.get("l2_aud"), expected_l2_nonce=exp.get("l2_nonce"),
                expected_l3_payment_aud=exp.get("l3a_aud"), expected_l3_payment_nonce=exp.get("l3a_nonce"),
                expected_l3_checkout_aud=exp.get("l3b_aud"), expected_l3_checkout_nonce=exp.get("l3b_nonce"),
            )
        except Exception as exc:  # noqa: BLE001
            return RefResult("error", f"verify_chain raised {type(exc).__name__}: {exc}")
        if not res.valid:
            return RefResult("reject", "; ".join(res.errors))
        # examples/helpers.py verify_network: payment constraints vs L3a, STRICT
        constraints = next((d.get("constraints", []) for d in res.l2_claims.get("delegate_payload", [])
                            if isinstance(d, dict) and d.get("vct") in ("mandate.payment.open.1", "mandate.payment.1")),
                           [])
        ful = next((dict(d) for d in res.l3_payment_claims.get("delegate_payload", [])
                    if isinstance(d, dict) and d.get("vct") == "mandate.payment.1"), {})
        if constraints and ful:
            by_hash = {self.hash_disclosure(s): v for s, v in zip(l2.disclosures, l2.disclosure_values, strict=False)}
            for c in constraints:
                if c.get("type") == "mandate.payment.allowed_payees":
                    ful["allowed_merchants"] = [by_hash[r["..."]][-1] for r in c.get("allowed", [])
                                                if isinstance(r, dict) and r.get("...") in by_hash]
            r = self.check(constraints, ful, mode=self.Mode.STRICT)
            if not r.satisfied:
                return RefResult("reject", "; ".join(r.violations))
        return RefResult("accept", f"chain valid; payment constraints checked={bool(constraints and ful)}")


# ---------------------------------------------------------------------------- AP2


class Ap2Adapter:
    """google-agentic-commerce/AP2@e1ea56d Python SDK (code/sdk/python/ap2/sdk).

    Per chain: ``MandateClient.verify`` (root key by kid from the trust fixture,
    terminal aud/nonce from the bundle's ``expected``, ``current_time`` = vector
    now). Human-not-present: ``CheckoutMandateChain.verify(checkout_jwt=...)`` and
    ``PaymentMandateChain.verify(expected_transaction_id, expected_open_checkout_hash,
    mandate_context)`` — the inputs the merchant / credential-provider samples pass.
    Human-present: single-token verify, plus the transaction_id == checkout_hash
    comparison the SDK performs through ``expected_transaction_id``.
    """

    def __init__(self, repo: Path, jwks: dict[str, Any]):
        sys.path.insert(0, str(repo / "code" / "sdk" / "python"))
        import logging

        logging.disable(logging.CRITICAL)
        from jwcrypto.jwk import JWK

        from ap2.sdk.checkout_mandate_chain import CheckoutMandateChain
        from ap2.sdk.constraints import MandateContext
        from ap2.sdk.generated.checkout_mandate import CheckoutMandate
        from ap2.sdk.generated.payment_mandate import PaymentMandate
        from ap2.sdk.mandate import MandateClient
        from ap2.sdk.payment_mandate_chain import PaymentMandateChain
        from ap2.sdk.sdjwt.common import compute_sd_hash, parse_token

        self.JWK, self.Client, self.Ctx = JWK, MandateClient, MandateContext
        self.CoChain, self.PaChain = CheckoutMandateChain, PaymentMandateChain
        self.models = {"checkout": CheckoutMandate, "payment": PaymentMandate}
        self.parse_token, self.sd_hash = parse_token, compute_sd_hash
        self.jwks = jwks

    def _key(self, token: Any) -> Any:
        hit = _jwk_by_kid(self.jwks, token.header.get("kid", ""))
        if hit is None:
            raise ValueError(f"kid {token.header.get('kid')!r} not in the trust list")
        return self.JWK(**hit[1])

    def run(self, vector: dict[str, Any]) -> RefResult:
        b = vector["bundle"]
        now, exp = vector["now"], (b.get("expected") or {}) if isinstance(b, dict) else {}
        if not isinstance(b, dict):
            raise NotRunnable("not an AP2 bundle object")
        out: dict[str, Any] = {}
        try:
            for side in ("checkout", "payment"):
                tok = b.get(f"{side}_mandate")
                if tok is None:
                    continue
                if not isinstance(tok, str):
                    return RefResult("reject", f"{side} mandate is not a string")
                segs = tok.split("~~")
                if len(segs) == 1:
                    root = self.parse_token(tok)
                    m = self.Client().verify(tok, self._key(root), payload_type=self.models[side], current_time=now)
                    out[side] = [m.mandate_payload.model_dump(exclude_none=True)]
                else:
                    out[side] = self.Client().verify(tok, self._key, expected_aud=exp.get(f"{side}_aud"),
                                                     expected_nonce=exp.get(f"{side}_nonce"), current_time=now)
                    out[f"{side}_open_token"] = segs[0] + ("" if segs[0].endswith("~") else "~")
        except Exception as exc:  # noqa: BLE001 - the SDK signals failures by raising
            return RefResult("reject", f"{type(exc).__name__}: {exc}")
        if not out:
            return RefResult("reject", "no mandates")
        violations: list[str] = []
        try:
            co, pa = out.get("checkout"), out.get("payment")
            if co and len(co) == 2:
                violations += self.CoChain.parse(co).verify(checkout_jwt=co[1].get("checkout_jwt"))
            if pa and len(pa) == 2:
                mc = b.get("mandate_context")
                open_hash = self.sd_hash(self.parse_token(out["checkout_open_token"])) \
                    if "checkout_open_token" in out else None
                violations += self.PaChain.parse(pa).verify(
                    expected_transaction_id=co[-1].get("checkout_hash") if co else None,
                    expected_open_checkout_hash=open_hash,
                    mandate_context=self.Ctx(**mc) if isinstance(mc, dict) else None)
            elif pa and co and pa[-1].get("transaction_id") != co[-1].get("checkout_hash"):
                violations.append("transaction_id != checkout_hash")
        except Exception as exc:  # noqa: BLE001
            return RefResult("error", f"chain.verify raised {type(exc).__name__}: {exc}")
        if violations:
            return RefResult("reject", "; ".join(violations))
        sides = [s for s in ("checkout", "payment") if s in out]
        return RefResult("accept", f"verified {sides}")


# ---------------------------------------------------------------------------- TAP


class TapAdapter:
    """visa/trusted-agent-protocol@16d59bd cdn-proxy/server.js ``verifySignature`` under Node.

    The proxy's route gate (signatures only for paths starting ``/product/``) is
    bypassed: the middleware is called directly, so every vector request is verified.
    """

    def __init__(self, repo: Path, registry: dict[str, Any], node: str = "node"):
        self.server_js = repo / "cdn-proxy" / "server.js"
        self.registry, self.node = registry, node
        self.results: dict[str, Any] = {}

    def prepare(self, vectors: list[dict[str, Any]]) -> None:
        batch = [{"id": v["id"], "now": v["now"], "requests": v["bundle"]["requests"]}
                 for v in vectors if isinstance(v.get("bundle"), dict)
                 and isinstance(v["bundle"].get("requests"), list) and v["bundle"]["requests"]
                 and all(isinstance(r, dict) and isinstance(r.get("headers"), dict) for r in v["bundle"]["requests"])]
        payload = json.dumps({"server_js": str(self.server_js), "registry": self.registry, "now": 0, "vectors": batch})
        harness = Path(__file__).with_name("tap_harness.js")
        proc = subprocess.run([self.node, str(harness)], input=payload, capture_output=True, text=True, check=True)
        self.results = json.loads(proc.stdout)

    def run(self, vector: dict[str, Any]) -> RefResult:
        if vector["id"] not in self.results:
            raise NotRunnable("bundle has no well-formed request list to replay against the middleware")
        rs = self.results[vector["id"]]
        failed = [r for r in rs if not r["passed"]]
        if failed:
            f = failed[0]
            return RefResult("reject", f"{f['status']} {f['title']}: {f['message']}".strip())
        return RefResult("accept", f"{len(rs)} request(s) passed verifySignature")
