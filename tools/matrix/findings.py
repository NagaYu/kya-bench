"""Findings for each divergence root cause, assessed against the spec text.

Each entry: what the reference does, what the spec says (with docs/spec-gaps.md
cross-references), and which side follows the text. ``MASKS`` lists reference
checks that fire before most others; an agreement whose reference rejection
comes from one of them is an *incidental* agreement — same verdict, different
reason — and is counted separately.
"""

from __future__ import annotations

FINDINGS: dict[str, dict[str, str]] = {
    "VI-M1": {
        "title": "Reference rejects when L1 card_id differs from payment_instrument.id",
        "reference": "verification/chain.py step '4c-bis' (commented 'Optional card_id cross-check (SHOULD-level)') "
                     "returns an error whenever L1 carries card_id and it differs from the mandate's "
                     "payment_instrument.id.",
        "spec": "credential-format.md §3.3: card_id is OPTIONAL, an 'Opaque card-level identifier assigned by the "
                "Issuer'; payment_instrument.id is an 'Instrument instance identifier (e.g., a token UUID)' "
                "(§4.4.2). No section requires them to be equal, and the spec's own examples use "
                "card_id 'card-mc-8842' (§3.6) with payment_instrument.id 'f199c3dd-…' (§11).",
        "assessment": "KYA follows the text. The reference enforces an unwritten binding as a hard failure despite "
                      "its own 'SHOULD-level' comment. Not a KYA bug; candidate note for the VI Issue.",
    },
    "TAP-M1": {
        "title": "Reference only reads the camel-case keyId parameter",
        "reference": "cdn-proxy/server.js parseRFC9421SignatureInput returns attributes.keyId; with RFC 9421 "
                     "'keyid' it is undefined, validateKeyId fails and the request is rejected with "
                     "'Invalid Key ID Format' before any other check.",
        "spec": "RFC 9421 §2.3 and the Visa merchant specification page use 'keyid'; RFC 8941 keys are lower-case "
                "only. The repo's own merchant-backend verifier also expects 'keyid'. See spec gap TAP-02.",
        "assessment": "KYA follows RFC 9421 and the Visa page; the reference proxy and agent agree with each other "
                      "but not with either. Every RFC-spelled TAP vector is rejected for this one reason, so TAP "
                      "agreements on reject vectors are incidental.",
    },
    "TAP-M2": {
        "title": "Reference accepts the keyId spelling that KYA leaves undefined",
        "reference": "The reference agent emits keyId and the proxy accepts it.",
        "spec": "Spec gap TAP-02: repo (keyId) vs RFC 9421 / Visa page (keyid).",
        "assessment": "Expected: the reference resolves the gap in favour of its own spelling. Confirms TAP-02 is a "
                      "real interoperability split rather than a theoretical one.",
    },
    "AP2-M1": {
        "title": "SDK verifies a checkout mandate presented without a payment mandate",
        "reference": "MandateClient.verify works per chain; the adapter (like the merchant sample) verifies "
                     "whatever chains are presented.",
        "spec": "specification.md Modes: 'Verifiers of Mandates always receive a closed Payment and Checkout "
                "Mandate, regardless of the mode.' Verification rules are per role (Merchant: checkout; "
                "Credential Provider/Network: payment).",
        "assessment": "Both readings are defensible: KYA, as a neutral whole-transaction verifier, applies the "
                      "'always receive both' sentence; a single-role verifier legitimately sees one chain. "
                      "Recorded as a scoping difference, not a bug on either side.",
    },
    "AP2-G": {
        "title": "SDK decides cases KYA leaves undefined",
        "reference": "AP2-01 cart total vs amount: not compared (accept). AP2-02 mixed flows: accept. AP2-04 "
                     "decimal max 250.0: treated as minor units (reject). AP2-05 recurrence period: SDK's own "
                     "period arithmetic (accept). AP2-06 budget: major units, max x 100 (accept). AP2-07 'product' "
                     "line items: UCP schema validation fails (reject). AP2-08 no revealed acceptable_items: "
                     "wildcard (accept).",
        "spec": "See docs/spec-gaps.md AP2-01..AP2-08: in each case the docs are silent or contradict the "
                "schema/SDK.",
        "assessment": "These are the reference's choices where the text does not decide. AP2-04 and AP2-06 "
                      "together show the unit problem: the SDK reads amount_range.max as minor units but "
                      "budget.max as major units.",
    },
    "AP2-O1": {
        "title": "Observation: the SDK's checkout chain does not recompute checkout_hash on its own",
        "reference": "CheckoutMandateChain.verify compares checkout_hash only with a caller-supplied "
                     "expected_checkout_hash; ap2-checkout-hash-mismatch is rejected through the payment chain's "
                     "transaction_id comparison instead.",
        "spec": "specification.md Merchant verification: 'Verify that the hash of the Checkout JWT sent for "
                "approval matches the value included for the checkout_hash claim.'",
        "assessment": "Same verdict here, but a merchant that verifies only the checkout chain must recompute the "
                      "hash itself. Not a divergence; noted for implementers.",
    },
    "VI-G": {
        "title": "Spec-gap vectors masked by the card_id check",
        "reference": "Rejected by VI-M1 before the gap-relevant logic runs.",
        "spec": "G-02, G-03, G-05.",
        "assessment": "No information about the reference's handling of these gaps; recorded for completeness.",
    },
    "TAP-G": {
        "title": "Spec-gap vectors masked by the keyId check",
        "reference": "Rejected by TAP-M1 before tag or payment-container handling.",
        "spec": "TAP-01, TAP-03. The reference implements neither the payment container nor a tag/operation check.",
        "assessment": "No information beyond TAP-M1.",
    },
}

BY_VECTOR: dict[str, str] = {
    **{v: "VI-M1" for v in ("immediate-valid", "autonomous-valid", "autonomous-l2-only", "autonomous-multi-pair",
                            "budget-cumulative-within")},
    **{v: "VI-G" for v in ("budget-without-network-state", "gap-g02-checkout-jwt-without-merchant-id",
                           "gap-g03-line-items-sku-shape")},
    **{v: "TAP-M1" for v in ("tap-browse-ed25519-valid", "tap-payment-rsa-pss-valid", "tap-content-digest-covered-valid",
                             "tap-cro-valid", "tap-cro-nonce-mismatch", "tap-cro-id-token-forged",
                             "tap-nonce-reused-by-other-key")},
    "tap-repo-keyId-parameter": "TAP-M2",
    **{v: "TAP-G" for v in ("tap-payer-tag-on-browse", "tap-apc-signature-undefined")},
    "ap2-payment-mandate-missing": "AP2-M1",
    **{v: "AP2-G" for v in ("ap2-cart-total-mismatch", "ap2-mixed-flows", "ap2-amount-range-decimal-max",
                            "ap2-recurrence-period-undefined", "ap2-budget-unit-ambiguous",
                            "ap2-line-item-product-shape", "ap2-acceptable-items-undisclosed")},
}

# Reference checks that run early and reject for their own reason (see VI-M1, TAP-M1).
MASKS = {"vi": "L1 card_id", "tap": "Invalid Key ID Format"}


def finding_for(vector_id: str) -> str | None:
    return BY_VECTOR.get(vector_id)
