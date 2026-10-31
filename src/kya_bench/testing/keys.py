"""Deterministic TEST-ONLY Ed25519 / RSA keys and signatures for Phase 2 vectors.

Every key derives from ``SEED`` plus a label, so fixtures regenerate
byte-identically. RSA-PSS normally draws a random salt; ``pss_sign`` instead
derives the salt from the seed and message (EMSA-PSS-ENCODE, RFC 8017 §9.1.1)
so signatures are reproducible. Verification in KYA Bench uses the standard
``cryptography`` PSS verifier, so these signatures are ordinary PSS signatures.
"""

from __future__ import annotations

import base64
import hashlib
import json
import random
from functools import lru_cache
from typing import Any

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, rsa

from ..parser import b64url_encode
from .builder import SEED

_E = 65537


def _seed_bytes(label: str, purpose: str, n: int = 32) -> bytes:
    return hashlib.shake_256(f"{SEED}/{purpose}/{label}".encode()).digest(n)


# ------------------------------------------------------------------ Ed25519


def ed25519_key(label: str) -> ed25519.Ed25519PrivateKey:
    return ed25519.Ed25519PrivateKey.from_private_bytes(_seed_bytes(label, "ed25519"))


def ed25519_public_b64(label: str) -> str:
    """Raw 32-byte public key, standard base64 — the reference registry's format."""
    raw = ed25519_key(label).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    return base64.b64encode(raw).decode()


# ------------------------------------------------------------------ RSA


def _is_probable_prime(n: int, rng: random.Random) -> bool:
    if n < 2:
        return False
    for p in (2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37):
        if n % p == 0:
            return n == p
    d, r = n - 1, 0
    while d % 2 == 0:
        d //= 2
        r += 1
    for _ in range(40):
        x = pow(rng.randrange(2, n - 1), d, n)
        if x in (1, n - 1):
            continue
        for _ in range(r - 1):
            x = pow(x, 2, n)
            if x == n - 1:
                break
        else:
            return False
    return True


def _prime(rng: random.Random, bits: int) -> int:
    while True:
        c = rng.getrandbits(bits) | (3 << (bits - 2)) | 1
        if (c - 1) % _E and _is_probable_prime(c, rng):
            return c


@lru_cache(maxsize=None)
def rsa_key(label: str, bits: int = 2048) -> rsa.RSAPrivateKey:
    rng = random.Random(int.from_bytes(_seed_bytes(label, "rsa"), "big"))
    while True:
        p, q = _prime(rng, bits // 2), _prime(rng, bits // 2)
        if p != q and (p * q).bit_length() == bits:
            break
    if p < q:
        p, q = q, p
    d = pow(_E, -1, (p - 1) * (q - 1))
    pub = rsa.RSAPublicNumbers(_E, p * q)
    return rsa.RSAPrivateNumbers(p, q, d, d % (p - 1), d % (q - 1), pow(q, -1, p), pub).private_key()


def rsa_public_pem(label: str) -> str:
    return rsa_key(label).public_key().public_bytes(
        serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()


def rsa_public_jwk(label: str, kid: str) -> dict[str, Any]:
    nums = rsa_key(label).public_key().public_numbers()
    n_len = (nums.n.bit_length() + 7) // 8
    return {
        "kty": "RSA",
        "kid": kid,
        "use": "sig",
        "alg": "PS256",
        "n": b64url_encode(nums.n.to_bytes(n_len, "big")),
        "e": b64url_encode(nums.e.to_bytes(3, "big")),
    }


def _mgf1(seed: bytes, length: int) -> bytes:
    out = b""
    counter = 0
    while len(out) < length:
        out += hashlib.sha256(seed + counter.to_bytes(4, "big")).digest()
        counter += 1
    return out[:length]


def pss_sign(label: str, message: bytes, salt_len: int | None = None) -> bytes:
    """RSASSA-PSS (SHA-256, MGF1-SHA-256) with a deterministic salt.

    ``salt_len=None`` uses the maximum salt length (the reference TAP agent's
    ``PSS.MAX_LENGTH``); JWS PS256 uses 32 (RFC 7518 §3.5).
    """
    priv = rsa_key(label).private_numbers()
    n, d = priv.public_numbers.n, priv.d
    mod_bits = n.bit_length()
    em_bits = mod_bits - 1
    em_len = (em_bits + 7) // 8
    h_len = 32
    s_len = em_len - h_len - 2 if salt_len is None else salt_len
    salt = hashlib.shake_256(f"{SEED}/pss-salt/{label}".encode() + message).digest(s_len)
    m_hash = hashlib.sha256(message).digest()
    h = hashlib.sha256(b"\x00" * 8 + m_hash + salt).digest()
    db = b"\x00" * (em_len - s_len - h_len - 2) + b"\x01" + salt
    masked = bytearray(a ^ b for a, b in zip(db, _mgf1(h, em_len - h_len - 1), strict=True))
    masked[0] &= 0xFF >> (8 * em_len - em_bits)
    em = bytes(masked) + h + b"\xbc"
    sig = pow(int.from_bytes(em, "big"), d, n)
    return sig.to_bytes((mod_bits + 7) // 8, "big")


def ps256_jwt(header: dict[str, Any], payload: dict[str, Any], label: str) -> str:
    h = b64url_encode(json.dumps(header, separators=(",", ":")).encode())
    p = b64url_encode(json.dumps(payload, separators=(",", ":")).encode())
    sig = pss_sign(label, f"{h}.{p}".encode("ascii"), salt_len=32)
    return f"{h}.{p}.{b64url_encode(sig)}"
