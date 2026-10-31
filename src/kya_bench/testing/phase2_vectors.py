"""Phase 2 vectors (TAP, AP2, composition, translation) and their fixture documents.

Expected verdicts and reason codes are declared here by hand; the generator
fails if the verifiers disagree. All keys are TEST-ONLY and derived from SEED.
"""

from __future__ import annotations

import copy
from collections.abc import Callable
from typing import Any

from .ap2_builder import Ap2Spec
from .ap2_builder import build as ap2_build
from .ap2_builder import trust_jwks
from .builder import NOW
from .tap_builder import TapRequest, apc, bundle, cro, id_token, id_token_jwks, registry_fixture

PAY = {"operation": "payment", "tag": "agent-payer-auth", "method": "POST", "path": "/cart/checkout"}
NONCE = TapRequest().nonce

Row = tuple[str, str, str, str, Callable[[], Any], str, list[str]]


def fixture_documents() -> dict[str, Any]:
    """Extra trust fixtures: JWKS entries merged into jwks.json, and the TAP registry."""
    return {"jwks": trust_jwks() | id_token_jwks(), "tap_registry": registry_fixture()}


# ---------------------------------------------------------------- TAP helpers


def _tap(*reqs: TapRequest) -> Callable[[], dict[str, Any]]:
    return lambda: bundle(*reqs)


def _post(req: TapRequest, fn: Callable[[dict[str, Any]], None]) -> Callable[[], dict[str, Any]]:
    def make() -> dict[str, Any]:
        b = bundle(req)
        fn(b["requests"][0])
        return b
    return make


def _body_req(body: dict[str, Any], **kw: Any) -> TapRequest:
    return TapRequest(**({"keyid": "primary"} | kw), body=body)


def _drop_header(name: str) -> Callable[[dict[str, Any]], None]:
    return lambda r: r["headers"].pop(name)


def _set_header(name: str, value: str) -> Callable[[dict[str, Any]], None]:
    return lambda r: r["headers"].__setitem__(name, value)


def _apc_without(field: str) -> dict[str, Any]:
    return {k: v for k, v in apc(NONCE, "primary").items() if k != field}


DIGEST_REQ = TapRequest(**PAY, components=("@authority", "@path", "content-digest"),
                        body={"cartId": "c-1"}, content_digest=True)

TAP_VECTORS: list[Row] = [
    ("tap-browse-ed25519-valid", "valid", "REPO tap-agent create_ed25519_signature; cdn-proxy verifySignature",
     "Browse request signed with Ed25519 under agent-browser-auth", _tap(TapRequest()), "accept", []),
    ("tap-payment-rsa-pss-valid", "valid", "REPO rsa-pss-sha256 (PSS.MAX_LENGTH); SPEC tag agent-payer-auth",
     "Payment request signed with RSA-PSS-SHA256 under agent-payer-auth",
     _tap(TapRequest(keyid="primary", **PAY)), "accept", []),
    ("tap-content-digest-covered-valid", "valid", "RFC 9421 §2.1; RFC 9530",
     "POST covering @method and content-digest with a matching body digest",
     _tap(TapRequest(**PAY, components=("@authority", "@path", "@method", "content-digest"),
                     body={"cartId": "c-1"}, content_digest=True)), "accept", []),
    ("tap-cro-valid", "consumer_recognition", "SPEC Agentic Consumer Recognition Object; spec gap TAP-01",
     "Consumer Recognition Object with a valid ID token; object signature unverifiable (advisory)",
     _tap(_body_req({"agenticConsumer": cro(NONCE, "primary")})), "accept", ["TAP_CRO_SIGNATURE_UNVERIFIABLE"]),
    ("tap-cro-nonce-mismatch", "consumer_recognition", "SPEC CRO: nonce must match the HTTP signature nonce",
     "CRO nonce differs from the signature nonce: advisory warning, request not blocked",
     _tap(_body_req({"agenticConsumer": cro("other-nonce", "primary")})), "accept", ["TAP_CRO_NONCE_MISMATCH"]),
    ("tap-cro-id-token-forged", "consumer_recognition", "SPEC ID token (PS256, kid); mock issuer JWKS",
     "ID token signed by a key the mock issuer does not publish",
     _tap(_body_req({"agenticConsumer": cro(NONCE, "primary", idToken=id_token(signer="tap-forger"))})),
     "accept", ["TAP_CRO_ID_TOKEN_INVALID"]),
    ("tap-signature-tampered-path", "signature", "RFC 9421 §3.2; REPO verifyEd25519Signature",
     "Request path changed after signing", _post(TapRequest(), lambda r: r.__setitem__("path", "/products/2")),
     "reject", ["TAP_SIGNATURE_INVALID"]),
    ("tap-signed-by-other-key", "signature", "RFC 9421 §3.2", "Signed with a key other than the registered one",
     _tap(TapRequest(sign_with="tap-other-ed")), "reject", ["TAP_SIGNATURE_INVALID"]),
    ("tap-content-digest-mismatch", "signature", "RFC 9530 §2", "Body altered: Content-Digest no longer matches",
     _post(DIGEST_REQ, lambda r: r.__setitem__("body", '{"cartId":"c-2"}')), "reject",
     ["TAP_CONTENT_DIGEST_MISMATCH"]),
    ("tap-unknown-keyid", "registry", "REPO getKeyById: key not found -> 403", "keyid not in the agent registry",
     _tap(TapRequest(keyid="ghost-key", sign_with="tap-ghost")), "reject", ["TAP_KEY_UNKNOWN"]),
    ("tap-revoked-key", "registry", "REPO is_active != 'true' -> 403", "Registered key marked inactive",
     _tap(TapRequest(keyid="old-ed25519")), "reject", ["TAP_KEY_REVOKED"]),
    ("tap-revoked-agent", "registry", "REPO agent-registry: inactive agent", "Agent itself marked inactive",
     _tap(TapRequest(keyid="revoked-agent-key")), "reject", ["TAP_AGENT_REVOKED"]),
    ("tap-alg-key-mismatch", "registry", "RFC 9421 §3.3.7; REPO algorithm per key",
     "alg rsa-pss-sha256 declared for a registered Ed25519 key",
     _tap(TapRequest(alg="rsa-pss-sha256", sign_with="tap-agent-rsa")), "reject", ["TAP_ALG_KEY_MISMATCH"]),
    ("tap-expired", "time", "REPO expires < now -> 403", "Signature expired",
     _tap(TapRequest(created=NOW - 600, expires=NOW - 200)), "reject", ["TAP_EXPIRED"]),
    ("tap-created-in-future", "time", "REPO created > now + 60 -> 403", "created beyond the 60 s tolerance",
     _tap(TapRequest(created=NOW + 120, expires=NOW + 300)), "reject", ["TAP_CREATED_IN_FUTURE"]),
    ("tap-window-over-8-minutes", "time", "SPEC: expires - created <= 8 minutes", "Validity window of 9 minutes",
     _tap(TapRequest(created=NOW - 30, expires=NOW - 30 + 540)), "reject", ["TAP_WINDOW_TOO_LONG"]),
    ("tap-nonce-replay", "replay", "REPO nonceCache; SPEC reject a nonce seen in the last 8 minutes",
     "Second request reuses the nonce with the same key", _tap(TapRequest(), TapRequest(path="/products/2")),
     "reject", ["TAP_NONCE_REPLAY"]),
    ("tap-nonce-reused-by-other-key", "replay", "KYA replay key = (keyid, nonce); spec gap notes TAP-N3",
     "Same nonce under two different keys is not a replay",
     _tap(TapRequest(), TapRequest(keyid="other-ed25519", path="/products/2")), "accept", []),
    ("tap-missing-nonce", "params", "SPEC minimum fields; REPO missing nonce -> 403",
     "Signature parameters lack nonce", _tap(TapRequest(omit_params=("nonce",))), "reject", ["TAP_PARAM_MISSING"]),
    ("tap-path-not-covered", "params", "SPEC minimum components @authority, @path",
     "Signature covers @authority only", _tap(TapRequest(components=("@authority",))),
     "reject", ["TAP_COMPONENT_MISSING"]),
    ("tap-browse-tag-on-payment", "tag", "SPEC tag binds the operation; REPO payer tag for checkout",
     "agent-browser-auth used on a payment operation",
     _tap(TapRequest(**(PAY | {"tag": "agent-browser-auth"}))), "reject", ["TAP_TAG_OPERATION_MISMATCH"]),
    ("tap-unknown-tag", "tag", "SPEC verification step (a); REPO cdn-proxy comment uses agent-payment-auth",
     "Tag agent-payment-auth is not one of the two defined tags",
     _tap(TapRequest(**(PAY | {"tag": "agent-payment-auth"}))), "reject", ["TAP_TAG_UNKNOWN"]),
    ("tap-payer-tag-on-browse", "spec_gap", "spec gap TAP-03", "agent-payer-auth used on a browse operation",
     _tap(TapRequest(tag="agent-payer-auth")), "indeterminate", ["SPEC_GAP"]),
    ("tap-repo-keyId-parameter", "spec_gap", "spec gap TAP-02; REPO agent_app.py signature_params",
     "Reference agent's camel-case keyId parameter", _tap(TapRequest(keyid_param="keyId")),
     "indeterminate", ["SPEC_GAP"]),
    ("tap-apc-signature-undefined", "spec_gap", "spec gap TAP-01; SPEC Agentic Payment Container",
     "Structurally valid payment container whose signature base is undefined",
     _tap(_body_req({"agenticPaymentContainer": apc(NONCE, "primary")}, **PAY)), "indeterminate", ["SPEC_GAP"]),
    ("tap-apc-nonce-mismatch", "payment_container", "SPEC APC: nonce must match; failure blocks payment",
     "Payment container nonce differs from the signature nonce",
     _tap(_body_req({"agenticPaymentContainer": apc("other-nonce", "primary")}, **PAY)),
     "reject", ["TAP_APC_NONCE_MISMATCH"]),
    ("tap-apc-missing-kid", "payment_container", "SPEC APC required fields nonce, kid, alg, signature",
     "Payment container without kid",
     _tap(_body_req({"agenticPaymentContainer": _apc_without("kid")}, **PAY)), "reject", ["TAP_APC_FIELD_MISSING"]),
    ("tap-malformed-signature-input", "malformed", "RFC 8941 §3.2", "Signature-Input is not a structured dictionary",
     _post(TapRequest(), _set_header("signature-input", 'sig2=("@authority" "@path";created=1')),
     "reject", ["TAP_SIGNATURE_INPUT_MALFORMED"]),
    ("tap-missing-signature-headers", "malformed", "REPO missing signature headers -> 403",
     "Request without a Signature header", _post(TapRequest(), _drop_header("signature")),
     "reject", ["TAP_SIGNATURE_HEADERS_MISSING"]),
]


# ---------------------------------------------------------------- AP2 helpers


def _ap2(**kw: Any) -> Callable[[], dict[str, Any]]:
    return lambda: ap2_build(Ap2Spec(**kw))


def _ap2_spec(spec_fn: Callable[[], Ap2Spec]) -> Callable[[], dict[str, Any]]:
    return lambda: ap2_build(spec_fn())


def _ap2_post(fn: Callable[[dict[str, Any]], None], **kw: Any) -> Callable[[], dict[str, Any]]:
    def make() -> dict[str, Any]:
        b = ap2_build(Ap2Spec(**kw))
        fn(b)
        return b
    return make


def _set(key: str, value: Any) -> Callable[[dict[str, Any]], None]:
    return lambda d: d.__setitem__(key, value)


def _signers(**over: str) -> dict[str, str]:
    base = {"checkout_root": "ap2-provider", "payment_root": "ap2-provider", "checkout_term": "ap2-agent",
            "payment_term": "ap2-agent", "merchant": "ap2-merchant"}
    return base | over


def _with_payment_constraint(c: dict[str, Any], extra: list[dict[str, Any]] = (), **kw: Any
                             ) -> Callable[[], Ap2Spec]:
    def make() -> Ap2Spec:
        spec = Ap2Spec(**kw)
        spec.payment_constraints[0:0] = [c, *extra]
        return spec
    return make


def _mixed_flows() -> dict[str, Any]:
    hp = ap2_build(Ap2Spec(flow="hp"))
    hnp_spec = Ap2Spec()
    hnp_spec.payment_constraints = hnp_spec.payment_constraints[:2]  # no payment.reference: there is no open checkout
    hnp = ap2_build(hnp_spec)
    return {"checkout_mandate": hp["checkout_mandate"], "payment_mandate": hnp["payment_mandate"],
            "expected": {k: v for k, v in hnp["expected"].items() if k.startswith("payment_")}}


def _replace_payment_constraint(i: int, c: dict[str, Any]) -> Callable[[], Ap2Spec]:
    def make() -> Ap2Spec:
        spec = Ap2Spec()
        spec.payment_constraints[i] = c
        return spec
    return make


OTHER_MERCHANT = {"id": "merchant_9", "name": "Shady Store", "website": "https://shady.example"}
def _line(lid: str, item_id: str, title: str, price: int, qty: int = 1) -> dict[str, Any]:
    """A UCP-valid line item (line_item.json / item.json required fields)."""
    return {"id": lid, "item": {"id": item_id, "title": title, "price": price}, "quantity": qty,
            "totals": [{"type": "total", "amount": price * qty}]}


SHOE = ("supershoe_gold_w9", "SuperShoe Limited Edition Gold")
OVER_CART = [_line("li_1", *SHOE, 30000)]

AP2_VECTORS: list[Row] = [
    ("ap2-hnp-valid", "valid", "specification.md Autonomous; SDK verify_chain",
     "Human-not-present: user-signed open mandates, agent-signed closed mandates, constraints met",
     _ap2(), "accept", []),
    ("ap2-hp-valid", "valid", "specification.md Direct",
     "Human-present: closed mandates signed via the trusted surface", _ap2(flow="hp"), "accept", []),
    ("ap2-hnp-issuer-jwt-hash", "valid", "SDK common.verify_binding (issuer_jwt_hash)",
     "Agent hops bound with issuer_jwt_hash instead of sd_hash", _ap2(hash_mode="issuer_jwt_hash"), "accept", []),
    ("ap2-root-key-untrusted", "signature", "SDK X5cOrKidPublicKeyProvider", "Root token kid not in the trust list",
     _ap2(hooks={"payment_root_header": _set("kid", "unknown-provider")}), "reject", ["AP2_ROOT_KEY_UNKNOWN"]),
    ("ap2-root-bad-signature", "signature", "SDK sd_jwt.verify", "Root token signed by a key other than its kid",
     _ap2(signers=_signers(payment_root="ap2-impostor")), "reject", ["AP2_SIGNATURE_INVALID"]),
    ("ap2-closed-not-signed-by-cnf-agent", "signature", "SDK kb_sd_jwt.verify: previous hop cnf.jwk",
     "Closed payment mandate signed by an agent other than the open mandate's cnf",
     _ap2(signers=_signers(payment_term="ap2-other-agent")), "reject", ["AP2_SIGNATURE_INVALID"]),
    ("ap2-sd-hash-mismatch", "binding", "SDK common.verify_binding", "Agent hop's sd_hash does not bind the open mandate",
     _ap2(hooks={"checkout_term_payload": _set("sd_hash", "A" * 43)}), "reject", ["AP2_BINDING_MISMATCH"]),
    ("ap2-terminal-carries-cnf", "binding", "SDK kb_sd_jwt: terminal MUST NOT carry cnf",
     "Terminal closed mandate re-delegates with cnf",
     _ap2(hooks={"payment_closed": _set("cnf", {"jwk": {"kty": "EC"}})}), "reject", ["AP2_CNF_FORBIDDEN"]),
    ("ap2-terminal-wrong-typ", "binding", "SDK kb_sd_jwt TYP_TERMINAL", "Agent hop typ is plain JWT",
     _ap2(hooks={"payment_term_header": _set("typ", "JWT")}), "reject", ["AP2_TYP_INVALID"]),
    ("ap2-aud-mismatch", "binding", "SDK verify_expected_claims", "Payment hop audience is not the expected verifier",
     _ap2_post(lambda b: b["expected"].__setitem__("payment_aud", "https://someone-else.example")),
     "reject", ["AP2_AUD_MISMATCH"]),
    ("ap2-open-mandate-expired", "expiry", "SDK chain._check_time_claims (300 s skew)", "Open mandates expired",
     _ap2(open_exp=NOW - 400), "reject", ["AP2_EXPIRED"]),
    ("ap2-checkout-hash-mismatch", "mandate", "checkout_mandate.md checkout_hash",
     "Closed checkout mandate's checkout_hash is not the hash of checkout_jwt",
     _ap2(hooks={"checkout_closed": _set("checkout_hash", "A" * 43)}), "reject", ["AP2_CHECKOUT_HASH_MISMATCH"]),
    ("ap2-transaction-id-mismatch", "mandate", "specification.md Payment Mandate: bound by the checkout JWT hash",
     "Payment transaction_id is not the checkout hash", _ap2(closed_payment_extra={"transaction_id": "B" * 43}),
     "reject", ["AP2_TRANSACTION_ID_MISMATCH"]),
    ("ap2-payment-mandate-missing", "mandate", "specification.md Modes: verifiers always receive both mandates",
     "Only the checkout mandate is presented", _ap2(include=("checkout_mandate",)), "reject", ["AP2_MANDATE_MISSING"]),
    ("ap2-unknown-vct", "mandate", "specification.md Mandate Versioning", "Closed payment mandate with vct .2",
     _ap2(closed_payment_extra={"vct": "mandate.payment.2"}), "reject", ["AP2_VCT_UNKNOWN"]),
    ("ap2-preset-claim-changed", "mandate", "agent_authorization.md processing rule 2",
     "Open mandate pre-sets the instrument; the closed mandate uses another",
     _ap2(open_payment_extra={"payment_instrument": {"id": "other-card", "type": "dpc"}}),
     "reject", ["AP2_PRESET_CLAIM_CHANGED"]),
    ("ap2-amount-over-max", "scope", "payment_mandate.md Amount Range", "Payment above amount_range max",
     _ap2(amount=30000, cart=OVER_CART), "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("ap2-payee-not-allowed", "scope", "payment_mandate.md Allowed Payees", "Payee outside the allowed payees",
     _ap2(payee=OTHER_MERCHANT), "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("ap2-merchant-not-allowed", "scope", "checkout_mandate.md Allowed Merchants", "Checkout merchant not allowed",
     _ap2(merchant=OTHER_MERCHANT), "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("ap2-no-merchant-revealed", "scope", "checkout_mandate.md: no revealed elements -> invalid",
     "Allowed merchants all left undisclosed", _ap2(open_disclose={"checkout": ["$item:0"]}),
     "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("ap2-line-items-extra-item", "scope", "checkout_mandate.md Line Items (max flow, exact)",
     "Cart holds an extra item that no requirement covers",
     _ap2(amount=21400, cart=[_line("li_1", *SHOE, 19900), _line("li_2", "socks", "Socks", 1500)]),
     "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("ap2-payment-reference-mismatch", "scope", "payment_mandate.md Reference",
     "Payment reference names a different open checkout mandate",
     _ap2_spec(_replace_payment_constraint(2, {"type": "payment.reference", "conditional_transaction_id": "C" * 43})),
     "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("ap2-unknown-constraint", "scope", "agent_authorization.md step 3: unknown constraints fail",
     "Open payment mandate with an unknown constraint type",
     _ap2_spec(_with_payment_constraint({"type": "com.acme.loyalty", "points": 5})),
     "reject", ["AP2_CONSTRAINT_UNKNOWN"]),
    ("ap2-budget-cumulative-exceeded", "scope", "payment_mandate.md Budget; SDK BudgetEvaluator",
     "Past spend plus this payment exceeds the budget under either unit reading",
     _ap2_spec(_with_payment_constraint({"type": "payment.budget", "max": 200, "currency": "USD"},
                                        mandate_context={"total_amount": 10000, "total_uses": 1})),
     "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("ap2-cart-total-mismatch", "spec_gap", "spec gap AP2-01", "Checkout total differs from the payment amount",
     _ap2(cart_total=25000), "indeterminate", ["SPEC_GAP"]),
    ("ap2-budget-unit-ambiguous", "spec_gap", "spec gap AP2-06",
     "Budget max 250: within budget as dollars (SDK), over budget as cents (Amount type)",
     _ap2_spec(_with_payment_constraint({"type": "payment.budget", "max": 250, "currency": "USD"},
                                        mandate_context={"total_amount": 0, "total_uses": 0})),
     "indeterminate", ["SPEC_GAP"]),
    ("ap2-amount-range-decimal-max", "spec_gap", "spec gap AP2-04",
     "amount_range max given as 250.0 (documentation example style)",
     _ap2_spec(_replace_payment_constraint(0, {"type": "payment.amount_range", "currency": "USD", "min": 1000,
                                               "max": 250.0})), "indeterminate", ["SPEC_GAP"]),
    ("ap2-mixed-flows", "spec_gap", "spec gap AP2-02", "Human-present checkout with a human-not-present payment",
     lambda: _mixed_flows(), "indeterminate", ["SPEC_GAP"]),
    ("ap2-recurrence-period-undefined", "spec_gap", "spec gap AP2-05",
     "Monthly agent recurrence with a previous use: period boundaries are undefined",
     _ap2_spec(_with_payment_constraint({"type": "payment.agent_recurrence", "frequency": "MONTHLY",
                                         "max_occurrences": 12},
                                        mandate_context={"total_amount": 0, "total_uses": 1,
                                                         "last_used_date": NOW - 10 * 86400},
                                        extra=[{"type": "payment.budget", "max": 100000, "currency": "USD"}])),
     "indeterminate", ["SPEC_GAP"]),
    ("ap2-line-item-product-shape", "spec_gap", "spec gap AP2-07",
     "Cart line item uses the documentation's 'product' instead of UCP 'item'",
     _ap2(cart=[{"id": "li_1", "product": {"id": SHOE[0], "title": SHOE[1], "price": 19900}, "quantity": 1,
                 "totals": [{"type": "total", "amount": 19900}]}]),
     "indeterminate", ["SPEC_GAP"]),
    ("ap2-acceptable-items-undisclosed", "spec_gap", "spec gap AP2-08",
     "Line-item requirement whose acceptable items are all undisclosed",
     _ap2(open_disclose={"checkout": ["$merchant:0", "$merchant:1"]}), "indeterminate", ["SPEC_GAP"]),
    ("ap2-malformed-chain", "malformed", "SDK common.parse_token", "Payment chain is not an SD-JWT",
     _ap2_post(_set("payment_mandate", "not-a-token")), "reject", ["AP2_TOKEN_MALFORMED"]),
]


# ---------------------------------------------------------------- composition


def _comp(tap: TapRequest | None, ap2: Ap2Spec | None) -> Callable[[], Any]:
    from .vectors import Payload

    def make() -> Any:
        out: dict[str, Any] = {}
        if tap is not None:
            out["tap"] = bundle(tap)
        if ap2 is not None:
            out["ap2"] = ap2_build(ap2)
        return Payload("composition", out)
    return make


TAP_PAY = TapRequest(**PAY)
STRANGER = Ap2Spec(agent="ap2-stranger", signers=_signers(checkout_term="ap2-stranger", payment_term="ap2-stranger"))

COMPOSITION_VECTORS: list[Row] = [
    ("comp-tap-ap2-bound", "binding", "KYA binding rule (XP-02 note); brief: bound -> accept",
     "TAP payment request and AP2 mandates name the same registry agent", _comp(TAP_PAY, Ap2Spec()), "accept", []),
    ("comp-presenter-mismatch", "binding", "KYA binding rule; brief: mismatch -> reject",
     "TAP request signed by agent 2, AP2 mandates delegate to agent 1",
     _comp(TapRequest(**(PAY | {"keyid": "other-ed25519"})), Ap2Spec()), "reject", ["XPROTO_PRESENTER_MISMATCH"]),
    ("comp-ap2-only", "identity_layer", "brief: AP2 alone is a legal flow",
     "AP2 mandates without a TAP identity layer", _comp(None, Ap2Spec()), "accept", ["XPROTO_IDENTITY_LAYER_ABSENT"]),
    ("comp-tap-payment-with-container", "identity_layer", "brief: TAP payment + valid container -> accept; TAP-01",
     "TAP payment intent with a payment container: container validity is undefined (TAP-01)",
     _comp(_body_req({"agenticPaymentContainer": apc(NONCE, "primary")}, **PAY), None),
     "indeterminate", ["SPEC_GAP"]),
    ("comp-browse-tag-payment", "binding", "brief: browse-tag payment attempt -> reject",
     "Browse-tagged TAP request presenting AP2 payment mandates",
     _comp(TapRequest(**(PAY | {"tag": "agent-browser-auth"})), Ap2Spec()), "reject", ["TAP_TAG_OPERATION_MISMATCH"]),
    ("comp-tap-only-browse", "identity_layer", "TAP verdict carries through", "TAP browse request with no mandates",
     _comp(TapRequest(), None), "accept", []),
    ("comp-revoked-presenter", "binding", "REPO inactive key; composition takes the worst component",
     "Bound agent but the TAP key is revoked",
     _comp(TapRequest(**(PAY | {"keyid": "old-ed25519"})), Ap2Spec()), "reject", ["TAP_KEY_REVOKED"]),
    ("comp-ap2-rejects", "binding", "composition takes the worst component",
     "Bound agent but the AP2 payment exceeds the intent",
     _comp(TAP_PAY, Ap2Spec(amount=30000, cart=OVER_CART)), "reject", ["AP2_CONSTRAINT_VIOLATION"]),
    ("comp-ap2-agent-unregistered", "spec_gap", "spec gap XP-02", "AP2 agent key held by no registry agent",
     _comp(TAP_PAY, STRANGER), "indeterminate", ["SPEC_GAP"]),
    ("comp-hp-without-agent-key", "spec_gap", "spec gap XP-01", "Human-present mandates that name no agent key",
     _comp(TAP_PAY, Ap2Spec(flow="hp", hp_closed_cnf=False)), "indeterminate", ["SPEC_GAP"]),
]


# ---------------------------------------------------------------- translation

M1 = {"id": "merchant_1", "name": "Demo Merchant", "website": "https://demo-merchant.example"}
INTENT = {
    "payment_constraints": [{"type": "payment.amount_range", "currency": "USD", "min": 1000, "max": 25000}],
    "checkout_constraints": [{"type": "checkout.allowed_merchants", "allowed": [
        M1, {"name": "Second Merchant", "website": "https://second-merchant.example"}]}],
    "exp": NOW + 3600,
}


def _probe(amount: int = 19900, currency: str = "USD", merchant: dict[str, Any] | None = None) -> dict[str, Any]:
    return {"payment_amount": {"amount": amount, "currency": currency}, "merchant": merchant or M1}


def _intent(**kw: Any) -> dict[str, Any]:
    return copy.deepcopy(INTENT) | kw


def _xl(intent: dict[str, Any], probe: dict[str, Any]) -> Callable[[], Any]:
    from .vectors import Payload

    return lambda: Payload("translation", {"intent": copy.deepcopy(intent), "probe": probe})


AGREE_OK = ["XLATE_EQUIVALENT", "XLATE_BOTH_ACCEPT"]
AGREE_NO = ["XLATE_EQUIVALENT", "XLATE_BOTH_REJECT"]

TRANSLATION_VECTORS: list[Row] = [
    ("xlate-in-range", "agree", "AP2 Amount Range ~ VI C §4.4", "Amount and merchant within the intent",
     _xl(INTENT, _probe()), "accept", AGREE_OK),
    ("xlate-over-max", "agree", "AP2 Amount Range ~ VI C §4.4", "Amount above max on both sides",
     _xl(INTENT, _probe(30000)), "accept", AGREE_NO),
    ("xlate-below-min", "agree", "AP2 Amount Range ~ VI C §4.4", "Amount below min on both sides",
     _xl(INTENT, _probe(500)), "accept", AGREE_NO),
    ("xlate-currency-mismatch", "agree", "AP2 Amount Range ~ VI C §4.4 step 6", "Currency differs",
     _xl(INTENT, _probe(currency="EUR")), "accept", AGREE_NO),
    ("xlate-merchant-outside", "agree", "AP2 Allowed Merchants ~ VI C §4.1", "Merchant not in the allowlist",
     _xl(INTENT, _probe(merchant={"id": "merchant_9", "name": "Shady", "website": "https://shady.example"})),
     "accept", AGREE_NO),
    ("xlate-merchant-by-name-website", "agree", "id-else-name+website matching on both sides",
     "Merchant without id matched by name and website",
     _xl(INTENT, _probe(merchant={"name": "Second Merchant", "website": "https://second-merchant.example"})),
     "accept", AGREE_OK),
    ("xlate-expired", "agree", "AP2 SDK exp + 300 s ~ VI CF §4.7 exp + 300 s", "Intent expired 10 minutes ago",
     _xl(_intent(exp=NOW - 600), _probe()), "accept", AGREE_NO),
    ("xlate-within-clock-skew", "agree", "both apply a 300 s skew", "Intent expired 200 s ago (inside the skew)",
     _xl(_intent(exp=NOW - 200), _probe()), "accept", AGREE_OK),
    ("xlate-empty-allowlist", "agree", "AP2 'no revealed elements' ~ VI 'empty allowlist unsatisfiable'",
     "Allowlist with no entries",
     _xl(_intent(checkout_constraints=[{"type": "checkout.allowed_merchants", "allowed": []}]), _probe()),
     "accept", AGREE_NO),
    ("xlate-undisclosed-allowlist", "divergence", "AP2 checkout_mandate.md vs VI C §4.1 step 3 (XP-03)",
     "Every allowlist entry undisclosed: AP2 fails the constraint, VI skips it",
     _xl(_intent(checkout_constraints=[{"type": "checkout.allowed_merchants", "allowed": [{"...": "D" * 43}]}]),
         _probe()), "reject", ["XLATE_DIVERGENT"]),
    ("xlate-decimal-max", "undecided", "spec gap AP2-04", "amount_range max as a decimal (AP2 doc example style)",
     _xl(_intent(payment_constraints=[{"type": "payment.amount_range", "currency": "USD", "max": 250.0}]), _probe()),
     "indeterminate", ["XLATE_UNDECIDED"]),
    ("xlate-unsupported-type", "undecided", "translator scope", "Budget has no translation in this subset",
     _xl(_intent(payment_constraints=[{"type": "payment.budget", "max": 500, "currency": "USD"}]), _probe()),
     "indeterminate", ["XLATE_UNSUPPORTED"]),
]


def phase2_vectors() -> list[dict[str, Any]]:
    from .vectors import make_vector

    out = []
    for protocol, table in (("tap", TAP_VECTORS), ("ap2", AP2_VECTORS), ("composition", COMPOSITION_VECTORS),
                            ("translation", TRANSLATION_VECTORS)):
        for vid, cat, ref, desc, make, verdict, codes in table:
            out.append(make_vector(protocol, vid, cat, ref, desc, "strict", make(), verdict, codes))
    return out
