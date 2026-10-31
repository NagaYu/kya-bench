"""Parser: malformed input becomes reason-coded findings, never exceptions."""

from __future__ import annotations

import random

import pytest

from kya_bench import parse_sd_jwt
from kya_bench.parser import b64url_encode, sha256_b64url
from kya_bench.testing.builder import autonomous_spec, build, disclosure, sign_jws


def codes(parsed):
    return {str(f.code) for f in parsed.findings}


_EMPTY = b64url_encode(b"{}")
_DUP = b64url_encode(b'{"a":1,"a":2}')


def test_valid_l2_structure():
    bundle = build(autonomous_spec())
    p = parse_sd_jwt(bundle["l2"], "L2")
    assert p.ok
    assert p.header["typ"] == "kb-sd-jwt+kb"
    mandates = p.resolved["delegate_payload"]
    assert [m["vct"] for m in mandates] == ["mandate.checkout.open.1", "mandate.payment.open.1"]
    # nested disclosures are resolved inside constraints
    allowed = mandates[0]["constraints"][0]["allowed"]
    assert allowed[0]["name"] == "Tennis Warehouse"
    assert all(d.digest == sha256_b64url(d.raw) for d in p.disclosures)


@pytest.mark.parametrize(
    ("value", "code"),
    [
        (None, "SDJWT_NOT_ASCII"),
        (42, "SDJWT_NOT_ASCII"),
        ("ünïcode~", "SDJWT_NOT_ASCII"),
        ("a.b.c", "SDJWT_NO_TRAILING_TILDE"),
        ("a.b~", "JWT_SEGMENT_COUNT"),
        ("a=.b.c~", "JWT_BASE64"),
        (b64url_encode(b"not json") + f".{_EMPTY}.AA~", "JWT_JSON"),
        (b64url_encode(b"[1]") + f".{_EMPTY}.AA~", "JWT_NOT_OBJECT"),
        (f"{_DUP}.{_EMPTY}.AA~", "JWT_DUPLICATE_KEY"),
    ],
)
def test_malformed_jws(value, code):
    p = parse_sd_jwt(value, "L1")
    assert not p.ok
    assert code in codes(p)


def _jws(payload):
    return sign_jws({"alg": "ES256", "typ": "sd+jwt", "kid": "k"}, payload, "issuer")


def test_disclosure_errors():
    good = disclosure({"a": 1}, "salt")
    jws = _jws({"_sd": [sha256_b64url(good)], "_sd_alg": "sha-256"})
    assert parse_sd_jwt(f"{jws}~{good}~", "L1").ok
    assert "SDJWT_EMPTY_DISCLOSURE" in codes(parse_sd_jwt(f"{jws}~~{good}~", "L1"))
    assert "DISCLOSURE_DUPLICATE" in codes(parse_sd_jwt(f"{jws}~{good}~{good}~", "L1"))
    assert "DISCLOSURE_BASE64" in codes(parse_sd_jwt(f"{jws}~!!~", "L1"))
    bad_shape = b64url_encode(b'["salt"]')
    assert "DISCLOSURE_SHAPE" in codes(parse_sd_jwt(f"{jws}~{bad_shape}~", "L1"))
    orphan = disclosure("x", "s2")
    assert "DISCLOSURE_UNREFERENCED" in codes(parse_sd_jwt(f"{jws}~{good}~{orphan}~", "L1"))


def test_property_disclosure_conflict():
    d = disclosure("x@example.com", "salt", "email")
    jws = _jws({"email": "other", "_sd": [sha256_b64url(d)]})
    assert "SD_CLAIM_CONFLICT" in codes(parse_sd_jwt(f"{jws}~{d}~", "L1"))


def test_undisclosed_refs_are_kept():
    d = disclosure({"m": 1}, "salt")
    jws = _jws({"list": [{"...": sha256_b64url(d)}, {"...": "undisclosed"}]})
    p = parse_sd_jwt(f"{jws}~{d}~", "L2")
    assert p.ok
    assert p.resolved["list"] == [{"m": 1}, {"...": "undisclosed"}]


def test_never_raises_on_garbage():
    rng = random.Random(1234)
    bundle = build(autonomous_spec())
    src = bundle["l2"]
    alphabet = "~.-_=AZaz09!{}\"[]"
    for _ in range(400):
        s = list(src)
        for _ in range(rng.randint(1, 6)):
            s[rng.randrange(len(s))] = rng.choice(alphabet)
        parse_sd_jwt("".join(s)[: rng.randint(0, len(s))], "L2")  # must not raise
