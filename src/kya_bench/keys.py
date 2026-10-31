"""Key handling: JWK → public key, ES256 verification, issuer key discovery.

Issuer keys are discovered through a ``KeyResolver``. The spec requires
JWKS-based discovery (credential-format §3.5 rule 2); Phase 1 is fully
offline, so ``LocalJwksResolver`` reads JWKS documents from a local fixture
file instead of fetching ``<iss>/.well-known/...``. A network resolver can be
dropped in later behind the same protocol.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Protocol

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.asymmetric.utils import encode_dss_signature

from .parser import b64url_decode
from .reasons import Code, Finding, reject

PublicKey = ec.EllipticCurvePublicKey


def jwk_to_public_key(jwk: Any) -> PublicKey:
    """Convert an EC P-256 public JWK into a key. Raises ValueError if unusable."""
    if not isinstance(jwk, dict):
        raise ValueError("JWK must be an object")
    if jwk.get("kty") != "EC" or jwk.get("crv") != "P-256":
        raise ValueError("JWK must be kty=EC, crv=P-256")
    try:
        x, y = b64url_decode(jwk["x"]), b64url_decode(jwk["y"])
    except (KeyError, ValueError, TypeError) as exc:
        raise ValueError("JWK x/y missing or not base64url") from exc
    if len(x) != 32 or len(y) != 32:
        raise ValueError("JWK x/y must be 32 bytes")
    try:
        return ec.EllipticCurvePublicNumbers(
            int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1()
        ).public_key()
    except ValueError as exc:
        raise ValueError("JWK point is not on P-256") from exc


def es256_verify(signing_input: bytes, signature: bytes, key: PublicKey) -> bool:
    """Verify a JWS ES256 signature (raw 64-byte R||S, RFC 7518 §3.4)."""
    if len(signature) != 64:
        return False
    der = encode_dss_signature(int.from_bytes(signature[:32], "big"), int.from_bytes(signature[32:], "big"))
    try:
        key.verify(der, signing_input, ec.ECDSA(hashes.SHA256()))
    except InvalidSignature:
        return False
    return True


class KeyResolver(Protocol):
    """Resolves an issuer signing key from (iss, kid)."""

    def resolve(self, iss: str, kid: str) -> tuple[PublicKey | None, list[Finding]]: ...


class LocalJwksResolver:
    """Issuer JWKS documents loaded from a local file.

    File format: ``{"<issuer URI>": {"keys": [<JWK>, ...]}, ...}`` — each value
    is a standard RFC 7517 JWK Set, exactly what the issuer's JWKS endpoint
    would serve.
    """

    def __init__(self, jwks_by_issuer: dict[str, Any]):
        self._jwks = jwks_by_issuer

    @classmethod
    def from_file(cls, path: str | Path) -> LocalJwksResolver:
        return cls(json.loads(Path(path).read_text(encoding="utf-8")))

    def resolve(self, iss: str, kid: str) -> tuple[PublicKey | None, list[Finding]]:
        jwks = self._jwks.get(iss)
        if not isinstance(jwks, dict) or not isinstance(jwks.get("keys"), list):
            return None, [reject(Code.JWKS_ISSUER_UNKNOWN, f"no JWKS for issuer {iss!r}", "L1")]
        matches = [k for k in jwks["keys"] if isinstance(k, dict) and k.get("kid") == kid]
        if not matches:
            return None, [reject(Code.JWKS_KID_NOT_FOUND, f"kid {kid!r} not in issuer JWKS", "L1")]
        if len(matches) > 1:
            return None, [reject(Code.JWKS_KID_AMBIGUOUS, f"kid {kid!r} matches {len(matches)} keys", "L1")]
        jwk = matches[0]
        if jwk.get("use", "sig") != "sig" or jwk.get("alg", "ES256") != "ES256":
            return None, [reject(Code.JWK_INVALID, "issuer JWK is not an ES256 signing key", "L1")]
        try:
            return jwk_to_public_key(jwk), []
        except ValueError as exc:
            return None, [reject(Code.JWK_INVALID, f"issuer JWK unusable: {exc}", "L1")]
