"""TAP test requests, registry and mock ID-token issuer (TEST-ONLY keys, offline).

Signed requests follow the reference agent: label ``sig2``, components
``("@authority" "@path")``, parameters in the order created, expires, key id,
alg, nonce, tag. The parameter is serialized as RFC 9421 ``keyid`` unless the
request asks for the reference agent's ``keyId`` spelling.
"""

from __future__ import annotations

import base64
import copy
import hashlib
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.hazmat.primitives import serialization

from ..parser import b64url_encode
from .builder import NOW, private_key
from .keys import ed25519_key, ed25519_public_b64, pss_sign, ps256_jwt, rsa_public_jwk, rsa_public_pem

AUTHORITY = "merchant.example"
ID_TOKEN_ISSUER = "https://idtoken.mock-issuer.example"  # mock stand-in for the Visa ID token issuer
ID_TOKEN_KID = "mock-idtoken-key-1"

# key_id -> (signing label, algorithm)
SIGNERS = {
    "primary-ed25519": ("tap-agent-ed", "ed25519"),
    "primary": ("tap-agent-rsa", "rsa-pss-sha256"),
    "old-ed25519": ("tap-agent-old", "ed25519"),
    "other-ed25519": ("tap-other-ed", "ed25519"),
    "revoked-agent-key": ("tap-revoked-agent", "ed25519"),
}


def _ec_pem(label: str) -> str:
    return private_key(label).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def registry_fixture() -> dict[str, Any]:
    """Local stand-in for the Visa agent directory (reference agent-registry shape)."""

    def key(kid: str, active: str = "true") -> dict[str, Any]:
        label, alg = SIGNERS[kid]
        pub = ed25519_public_b64(label) if alg == "ed25519" else rsa_public_pem(label)
        return {"key_id": kid, "algorithm": alg, "public_key": pub, "is_active": active}

    def ap2_key(kid: str, label: str) -> dict[str, Any]:
        # The agent's AP2 key (cnf.jwk in AP2 open mandates), registered so that
        # composition can tie the TAP presenter to the AP2 mandate agent.
        return {"key_id": kid, "algorithm": "ES256", "public_key": _ec_pem(label), "is_active": "true"}

    return {"agents": [
        {"id": 1, "name": "Shopping Agent", "domain": "shopping-agent.example", "is_active": "true",
         "keys": [key("primary-ed25519"), key("primary"), key("old-ed25519", "false"),
                  ap2_key("shopping-agent-ap2", "ap2-agent")]},
        {"id": 2, "name": "Other Agent", "domain": "other-agent.example", "is_active": "true",
         "keys": [key("other-ed25519"), ap2_key("other-agent-ap2", "ap2-other-agent")]},
        {"id": 3, "name": "Revoked Agent", "domain": "revoked-agent.example", "is_active": "false",
         "keys": [key("revoked-agent-key")]},
    ]}


def id_token_jwks() -> dict[str, Any]:
    return {ID_TOKEN_ISSUER: {"keys": [rsa_public_jwk("tap-idtoken-issuer", ID_TOKEN_KID)]}}


def id_token(now: int = NOW, *, signer: str = "tap-idtoken-issuer", **overrides: Any) -> str:
    payload = {
        "iss": ID_TOKEN_ISSUER,
        "sub": "consumer-7f3a",
        "aud": f"https://{AUTHORITY}",
        "iat": now - 60,
        "exp": now + 3600,
        "email_mask": "u***@example.com",
        "phone_number_mask": "***-***-1234",
    } | overrides
    return ps256_jwt({"alg": "PS256", "kid": ID_TOKEN_KID, "typ": "JWT+ext.id_token"}, payload, signer)


def _object_signature(obj: dict[str, Any], label: str) -> str:
    """ILLUSTRATIVE ONLY: the spec gives no serialization for CRO/APC signatures (TAP-01).
    Fixtures sign the JSON of the other fields with the agent key so the field is populated;
    the verifier never relies on this."""
    data = json.dumps({k: v for k, v in obj.items() if k != "signature"}, separators=(",", ":")).encode()
    return b64url_encode(pss_sign(label, data, salt_len=32) if label.endswith("rsa") else ed25519_key(label).sign(data))


def cro(nonce: str, kid: str, now: int = NOW, *, label: str = "tap-agent-rsa", **overrides: Any) -> dict[str, Any]:
    obj = {
        "nonce": nonce,
        "idToken": id_token(now),
        "contextualData": {"countryCode": "US", "zip": "94105", "ipAddress": "203.0.113.7",
                           "deviceData": {"deviceId": "dev-01"}},
        "kid": kid,
        "alg": "PS256",
    } | overrides
    obj["signature"] = _object_signature(obj, label)
    return obj


def apc(nonce: str, kid: str, *, label: str = "tap-agent-rsa", **overrides: Any) -> dict[str, Any]:
    obj = {
        "nonce": nonce,
        "cardMetadata": {"lastFour": "1234", "paymentAccountReference": "V0010013018326012345678901234",
                         "shortDescription": "Visa ···· 1234"},
        "kid": kid,
        "alg": "PS256",
    } | overrides
    obj["signature"] = _object_signature(obj, label)
    return obj


@dataclass
class TapRequest:
    keyid: str = "primary-ed25519"
    method: str = "GET"
    path: str = "/products/1"
    query: str = ""
    operation: str | None = "browse"
    tag: str = "agent-browser-auth"
    nonce: str = "a5e3f0d2-6c1b-4e8a-9f7d-2b4c6e8a0f13"
    created: int = NOW - 30
    expires: int = NOW - 30 + 8 * 60
    components: tuple[str, ...] = ("@authority", "@path")
    alg: str | None = None  # default: the key's algorithm
    sign_with: str | None = None  # signing label override (wrong-key cases)
    keyid_param: str = "keyid"  # "keyId" reproduces the reference agent
    omit_params: tuple[str, ...] = ()
    label: str = "sig2"
    body: dict[str, Any] | str | None = None
    extra_headers: dict[str, str] = field(default_factory=dict)
    content_digest: bool = False

    def build(self) -> dict[str, Any]:
        label_key, key_alg = SIGNERS.get(self.keyid, ("tap-unregistered", "ed25519"))
        signer = self.sign_with or label_key
        alg = self.alg or key_alg
        body = json.dumps(self.body, separators=(",", ":")) if isinstance(self.body, dict) else self.body
        headers = dict(self.extra_headers)
        if self.content_digest:
            digest = base64.b64encode(hashlib.sha256((body or "").encode()).digest()).decode()
            headers["content-digest"] = f"sha-256=:{digest}:"
            headers["content-type"] = "application/json"
        params = [("created", self.created), ("expires", self.expires), (self.keyid_param, self.keyid),
                  ("alg", alg), ("nonce", self.nonce), ("tag", self.tag)]
        params = [(k, v) for k, v in params if k not in self.omit_params]
        comp = " ".join(f'"{c}"' for c in self.components)
        raw = f"({comp})" + "".join(f";{k}={v}" if isinstance(v, int) else f';{k}="{v}"' for k, v in params)
        lines = []
        for c in self.components:
            if c == "@authority":
                lines.append(f'"@authority": {AUTHORITY}')
            elif c == "@path":
                lines.append(f'"@path": {self.path}')
            elif c == "@method":
                lines.append(f'"@method": {self.method}')
            elif c == "@query":
                lines.append(f'"@query": ?{self.query}')
            else:
                lines.append(f'"{c}": {headers[c]}')
        lines.append(f'"@signature-params": {raw}')
        base = "\n".join(lines).encode()
        sig = pss_sign(signer, base) if alg == "rsa-pss-sha256" else ed25519_key(signer).sign(base)
        headers["signature-input"] = f"{self.label}={raw}"
        headers["signature"] = f"{self.label}=:{base64.b64encode(sig).decode()}:"
        req: dict[str, Any] = {"method": self.method, "authority": AUTHORITY, "path": self.path}
        if self.query:
            req["query"] = self.query
        req["headers"] = headers
        if body is not None:
            req["body"] = body
        if self.operation is not None:
            req["operation"] = self.operation
        return req


def bundle(*requests: TapRequest | dict[str, Any]) -> dict[str, Any]:
    return {"requests": [copy.deepcopy(r.build() if isinstance(r, TapRequest) else r) for r in requests]}
