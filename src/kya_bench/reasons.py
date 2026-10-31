"""Reason codes and findings.

The verifier never raises on bad input: every problem becomes a ``Finding``
with a stable reason code. A finding's ``effect`` decides how it influences
the verdict:

- ``reject``        — a MUST-level requirement of the spec is violated.
- ``indeterminate`` — the spec does not define the outcome (see docs/spec-gaps.md).
- ``warn``          — recorded, never changes the verdict on its own.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any, Literal

Effect = Literal["reject", "indeterminate", "warn"]


class Code(StrEnum):
    # --- input envelope -------------------------------------------------
    BUNDLE_INVALID = "BUNDLE_INVALID"
    BUNDLE_UNKNOWN_FIELD = "BUNDLE_UNKNOWN_FIELD"
    LAYER_MISSING = "LAYER_MISSING"

    # --- SD-JWT / JWS framing ------------------------------------------
    SDJWT_NOT_ASCII = "SDJWT_NOT_ASCII"
    SDJWT_NO_TRAILING_TILDE = "SDJWT_NO_TRAILING_TILDE"
    SDJWT_EMPTY_DISCLOSURE = "SDJWT_EMPTY_DISCLOSURE"
    JWT_SEGMENT_COUNT = "JWT_SEGMENT_COUNT"
    JWT_BASE64 = "JWT_BASE64"
    JWT_JSON = "JWT_JSON"
    JWT_DUPLICATE_KEY = "JWT_DUPLICATE_KEY"
    JWT_NOT_OBJECT = "JWT_NOT_OBJECT"
    DISCLOSURE_BASE64 = "DISCLOSURE_BASE64"
    DISCLOSURE_JSON = "DISCLOSURE_JSON"
    DISCLOSURE_SHAPE = "DISCLOSURE_SHAPE"
    DISCLOSURE_DUPLICATE = "DISCLOSURE_DUPLICATE"
    DISCLOSURE_UNREFERENCED = "DISCLOSURE_UNREFERENCED"
    SD_CLAIM_CONFLICT = "SD_CLAIM_CONFLICT"
    SD_ALG_INVALID = "SD_ALG_INVALID"

    # --- headers / claims -----------------------------------------------
    HEADER_ALG_INVALID = "HEADER_ALG_INVALID"
    HEADER_TYP_INVALID = "HEADER_TYP_INVALID"
    HEADER_KID_MISSING = "HEADER_KID_MISSING"
    HEADER_JWK_FORBIDDEN = "HEADER_JWK_FORBIDDEN"
    CLAIM_MISSING = "CLAIM_MISSING"
    CLAIM_TYPE_INVALID = "CLAIM_TYPE_INVALID"

    # --- L1 / issuer keys ----------------------------------------------
    L1_VCT_INVALID = "L1_VCT_INVALID"
    L1_SD_HASH_PRESENT = "L1_SD_HASH_PRESENT"
    L1_PROFILE_CLAIM_MISSING = "L1_PROFILE_CLAIM_MISSING"
    JWKS_ISSUER_UNKNOWN = "JWKS_ISSUER_UNKNOWN"
    JWKS_KID_NOT_FOUND = "JWKS_KID_NOT_FOUND"
    JWKS_KID_AMBIGUOUS = "JWKS_KID_AMBIGUOUS"
    JWK_INVALID = "JWK_INVALID"

    # --- crypto / binding ------------------------------------------------
    SIGNATURE_INVALID = "SIGNATURE_INVALID"
    SD_HASH_MISSING = "SD_HASH_MISSING"
    SD_HASH_MISMATCH = "SD_HASH_MISMATCH"
    CNF_MISSING = "CNF_MISSING"
    CNF_FORBIDDEN = "CNF_FORBIDDEN"
    CNF_KID_MISSING = "CNF_KID_MISSING"
    CNF_PAIR_MISMATCH = "CNF_PAIR_MISMATCH"
    L3_KID_MISMATCH = "L3_KID_MISMATCH"

    # --- time -------------------------------------------------------------
    TIME_EXPIRED = "TIME_EXPIRED"
    TIME_IAT_FUTURE = "TIME_IAT_FUTURE"
    TIME_LIFETIME_EXCEEDED = "TIME_LIFETIME_EXCEEDED"
    TIME_LIFETIME_SHOULD = "TIME_LIFETIME_SHOULD"

    # --- mode / mandates --------------------------------------------------
    MODE_MIXED = "MODE_MIXED"
    MODE_UNDETERMINED = "MODE_UNDETERMINED"
    MODE_L3_IN_IMMEDIATE = "MODE_L3_IN_IMMEDIATE"
    VCT_UNKNOWN = "VCT_UNKNOWN"
    DELEGATE_PAYLOAD_INVALID = "DELEGATE_PAYLOAD_INVALID"
    MANDATE_FIELD_MISSING = "MANDATE_FIELD_MISSING"
    MANDATE_CONSTRAINTS_FORBIDDEN = "MANDATE_CONSTRAINTS_FORBIDDEN"
    MANDATE_CONSTRAINTS_EMPTY = "MANDATE_CONSTRAINTS_EMPTY"
    MANDATE_ORPHAN = "MANDATE_ORPHAN"
    MANDATE_DUPLICATE_PAIR = "MANDATE_DUPLICATE_PAIR"
    PAYMENT_REFERENCE_MISSING = "PAYMENT_REFERENCE_MISSING"
    CHECKOUT_HASH_MISMATCH = "CHECKOUT_HASH_MISMATCH"
    L3_CROSS_REF_MISMATCH = "L3_CROSS_REF_MISMATCH"
    L3_MANDATE_MISSING = "L3_MANDATE_MISSING"
    L3_AMOUNT_NOT_INTEGER = "L3_AMOUNT_NOT_INTEGER"

    # --- L3 selective views ----------------------------------------------
    L3_VIEW_BASE_MISMATCH = "L3_VIEW_BASE_MISMATCH"
    L3_VIEW_FOREIGN_DISCLOSURE = "L3_VIEW_FOREIGN_DISCLOSURE"
    L3_VIEW_NO_MANDATE = "L3_VIEW_NO_MANDATE"
    L3_VIEW_PAIR_MISMATCH = "L3_VIEW_PAIR_MISMATCH"
    L3_VIEW_FALLBACK = "L3_VIEW_FALLBACK"

    # --- replay context --------------------------------------------------
    AUD_MISMATCH = "AUD_MISMATCH"
    NONCE_MISMATCH = "NONCE_MISMATCH"
    NONCE_REUSED = "NONCE_REUSED"
    AUD_NOT_CHECKED = "AUD_NOT_CHECKED"
    NONCE_NOT_CHECKED = "NONCE_NOT_CHECKED"

    # --- constraints -----------------------------------------------------
    CONSTRAINT_VIOLATION = "CONSTRAINT_VIOLATION"
    CONSTRAINT_MALFORMED = "CONSTRAINT_MALFORMED"
    CONSTRAINT_UNKNOWN_OPEN_MANDATE = "CONSTRAINT_UNKNOWN_OPEN_MANDATE"
    CONSTRAINT_UNKNOWN_STRICT = "CONSTRAINT_UNKNOWN_STRICT"
    CONSTRAINT_UNKNOWN_SKIPPED = "CONSTRAINT_UNKNOWN_SKIPPED"
    CONSTRAINT_STATEFUL_NOT_CHECKED = "CONSTRAINT_STATEFUL_NOT_CHECKED"
    RECURRENCE_UNBOUNDED = "RECURRENCE_UNBOUNDED"
    CHECKOUT_JWT_SIGNATURE_NOT_VERIFIED = "CHECKOUT_JWT_SIGNATURE_NOT_VERIFIED"
    CHECKOUT_JWT_UNDECODABLE = "CHECKOUT_JWT_UNDECODABLE"

    # --- spec gaps -------------------------------------------------------
    SPEC_GAP = "SPEC_GAP"


@dataclass(frozen=True)
class Finding:
    code: Code
    effect: Effect
    message: str
    layer: str | None = None
    gap_id: str | None = None
    detail: dict[str, Any] = field(default_factory=dict)

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": str(self.code), "effect": self.effect, "message": self.message}
        if self.layer:
            out["layer"] = self.layer
        if self.gap_id:
            out["gap_id"] = self.gap_id
        if self.detail:
            out["detail"] = self.detail
        return out


def reject(code: Code, message: str, layer: str | None = None, **detail: Any) -> Finding:
    return Finding(code, "reject", message, layer, None, detail)


def warn(code: Code, message: str, layer: str | None = None, **detail: Any) -> Finding:
    return Finding(code, "warn", message, layer, None, detail)


def gap(gap_id: str, message: str, layer: str | None = None, **detail: Any) -> Finding:
    return Finding(Code.SPEC_GAP, "indeterminate", message, layer, gap_id, detail)
