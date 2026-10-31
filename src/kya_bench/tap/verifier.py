"""TAP verifier: RFC 9421 agent signatures, registry, CRO and payment container.

Sources (see docs/spec-gaps.md for every place they disagree or are silent):

- REPO = github.com/visa/trusted-agent-protocol@16d59bd — primary. The
  reference agent (tap-agent/agent_app.py) signs ``("@authority" "@path")``
  with ``created``, ``expires``, ``keyId``, ``alg``, ``nonce``, ``tag``; the
  CDN proxy (cdn-proxy/server.js) verifies Ed25519 and RSA-PSS-SHA256 against
  the agent registry and rejects reused nonces.
- SPEC = Visa "Trusted Agent Protocol: Merchant Specification" page
  (unversioned, retrieved 2026-10-31) — secondary, used only where the repo is
  silent: the required parameter set, the 8-minute window, the tag vocabulary,
  and the ``agenticConsumer`` / ``agenticPaymentContainer`` body objects, which
  the repo does not implement at all.

Bundle (KYA Bench envelope)::

    {"requests": [{"method", "authority", "path", "query"?, "headers": {...},
                   "body"?: "<raw body>", "operation"?: "browse" | "payment"}]}

``operation`` is the merchant's own classification of the endpoint; TAP binds
the tag to the operation but leaves endpoint classification to the merchant.
Requests are verified in order with a shared nonce cache, so a replay inside
one bundle is detected.
"""

from __future__ import annotations

import base64
import hashlib
import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ed25519, padding, rsa

from ..constraints import Strictness
from ..context import Fixtures
from ..parser import b64url_decode, parse_jws
from ..reasons import Finding, gap, reject, warn
from ..sf import SFError, parse_dictionary
from ..verifier import Check, Verdict

TAG_BROWSE = "agent-browser-auth"
TAG_PAYER = "agent-payer-auth"
TAGS = {TAG_BROWSE: "browse", TAG_PAYER: "payment"}
REQUIRED_PARAMS = ("created", "expires", "keyid", "alg", "nonce", "tag")  # SPEC §minimum fields
REQUIRED_COMPONENTS = ("@authority", "@path")  # SPEC minimum; what REPO signs
SUPPORTED_ALGS = ("ed25519", "rsa-pss-sha256")  # REPO
CREATED_FUTURE_TOLERANCE = 60  # REPO server.js: created > now + 60 -> reject
MAX_WINDOW = 8 * 60  # SPEC: expires - created <= 8 minutes; replay memory of 8 minutes
CRO_FIELDS = ("nonce", "idToken", "contextualData", "kid", "alg", "signature")  # SPEC table
APC_FIELDS = ("nonce", "kid", "alg", "signature")  # SPEC table
ID_TOKEN_ALGS = ("PS256", "RS256")  # SPEC §ID token: PS256 preferred, RS256 allowed, none not supported


class TapCode(StrEnum):
    TAP_BUNDLE_INVALID = "TAP_BUNDLE_INVALID"
    TAP_REQUEST_INVALID = "TAP_REQUEST_INVALID"
    TAP_SIGNATURE_HEADERS_MISSING = "TAP_SIGNATURE_HEADERS_MISSING"
    TAP_SIGNATURE_INPUT_MALFORMED = "TAP_SIGNATURE_INPUT_MALFORMED"
    TAP_SIGNATURE_MALFORMED = "TAP_SIGNATURE_MALFORMED"
    TAP_SIGNATURE_LABEL_MISMATCH = "TAP_SIGNATURE_LABEL_MISMATCH"
    TAP_MULTIPLE_SIGNATURES = "TAP_MULTIPLE_SIGNATURES"
    TAP_PARAM_MISSING = "TAP_PARAM_MISSING"
    TAP_COMPONENT_MISSING = "TAP_COMPONENT_MISSING"
    TAP_COMPONENT_ABSENT = "TAP_COMPONENT_ABSENT"
    TAP_COMPONENT_UNSUPPORTED = "TAP_COMPONENT_UNSUPPORTED"
    TAP_CONTENT_DIGEST_MALFORMED = "TAP_CONTENT_DIGEST_MALFORMED"
    TAP_CONTENT_DIGEST_MISMATCH = "TAP_CONTENT_DIGEST_MISMATCH"
    TAP_CREATED_IN_FUTURE = "TAP_CREATED_IN_FUTURE"
    TAP_EXPIRED = "TAP_EXPIRED"
    TAP_WINDOW_TOO_LONG = "TAP_WINDOW_TOO_LONG"
    TAP_NONCE_REPLAY = "TAP_NONCE_REPLAY"
    TAP_KEY_UNKNOWN = "TAP_KEY_UNKNOWN"
    TAP_KEY_AMBIGUOUS = "TAP_KEY_AMBIGUOUS"
    TAP_KEY_REVOKED = "TAP_KEY_REVOKED"
    TAP_AGENT_REVOKED = "TAP_AGENT_REVOKED"
    TAP_KEY_INVALID = "TAP_KEY_INVALID"
    TAP_ALG_UNSUPPORTED = "TAP_ALG_UNSUPPORTED"
    TAP_ALG_KEY_MISMATCH = "TAP_ALG_KEY_MISMATCH"
    TAP_SIGNATURE_INVALID = "TAP_SIGNATURE_INVALID"
    TAP_TAG_UNKNOWN = "TAP_TAG_UNKNOWN"
    TAP_TAG_OPERATION_MISMATCH = "TAP_TAG_OPERATION_MISMATCH"
    TAP_OPERATION_NOT_DECLARED = "TAP_OPERATION_NOT_DECLARED"
    TAP_CRO_FIELD_MISSING = "TAP_CRO_FIELD_MISSING"
    TAP_CRO_NONCE_MISMATCH = "TAP_CRO_NONCE_MISMATCH"
    TAP_CRO_KID_MISMATCH = "TAP_CRO_KID_MISMATCH"
    TAP_CRO_ID_TOKEN_INVALID = "TAP_CRO_ID_TOKEN_INVALID"
    TAP_CRO_SIGNATURE_UNVERIFIABLE = "TAP_CRO_SIGNATURE_UNVERIFIABLE"
    TAP_APC_FIELD_MISSING = "TAP_APC_FIELD_MISSING"
    TAP_APC_NONCE_MISMATCH = "TAP_APC_NONCE_MISMATCH"
    TAP_APC_KEY_UNKNOWN = "TAP_APC_KEY_UNKNOWN"


class NonceCache:
    """Process-local replay cache keyed by (keyid, nonce), remembering MAX_WINDOW seconds."""

    def __init__(self) -> None:
        self._seen: dict[tuple[str, str], int] = {}

    def check_and_add(self, keyid: str, nonce: str, created: int) -> bool:
        """Return False if (keyid, nonce) was already used within the window."""
        prev = self._seen.get((keyid, nonce))
        if prev is not None and abs(created - prev) <= MAX_WINDOW:
            return False
        self._seen[(keyid, nonce)] = created
        return True


@dataclass
class _Req:
    index: int
    layer: str
    findings: list[Finding] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    keyid: str | None = None
    nonce: str | None = None
    tag: str | None = None
    alg: str | None = None
    agent: dict[str, Any] | None = None
    key_entry: dict[str, Any] | None = None
    signature_ok: bool = False
    registry_ok: bool = False
    scope_ok: bool = True
    cross: dict[str, bool | None] = field(default_factory=dict)

    def check(self, cid: str, fs: list[Finding] | Finding | None = None, *, skipped: str = "") -> bool:
        cid = f"{self.layer}.{cid}"
        if skipped:
            self.checks.append(Check(cid, "skipped", skipped))
            return False
        fs = [fs] if isinstance(fs, Finding) else list(fs or [])
        self.findings.extend(fs)
        ok = not any(f.effect == "reject" for f in fs)
        self.checks.append(Check(cid, "pass" if ok else "fail", "; ".join(f.message for f in fs)))
        return ok


def verify_tap(
    bundle: Any,
    *,
    fixtures: Fixtures,
    now: int | None = None,
    nonce_cache: NonceCache | None = None,
) -> Verdict:
    """Verify every request in a TAP bundle; the verdict is the worst outcome."""
    now = int(time.time()) if now is None else now
    cache = nonce_cache or NonceCache()
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except ValueError:
            bundle = None
    reqs = bundle.get("requests") if isinstance(bundle, dict) else None
    if not isinstance(reqs, list) or not reqs:
        f = reject(TapCode.TAP_BUNDLE_INVALID, "TAP bundle needs a non-empty 'requests' array", "bundle")
        return _verdict([], [f], [Check("bundle.shape", "fail", f.message)], now)
    results = [_verify_request(i, r, fixtures, now, cache) for i, r in enumerate(reqs)]
    findings = [f for r in results for f in r.findings]
    checks = [c for r in results for c in r.checks]
    return _verdict(results, findings, checks, now)


def _verdict(results: list[_Req], findings: list[Finding], checks: list[Check], now: int) -> Verdict:
    if any(f.effect == "reject" for f in findings):
        verdict = "reject"
    elif any(f.effect == "indeterminate" for f in findings):
        verdict = "indeterminate"
    else:
        verdict = "accept"
    cross: dict[str, bool | None] = {}
    for r in results:
        prefix = "" if len(results) == 1 else f"{r.layer}."
        cross.update({f"{prefix}{k}": v for k, v in r.cross.items()})
    return Verdict(
        verdict=verdict,
        mode=None,
        strictness=Strictness.STRICT,
        evaluated_at=now,
        identity_ok=bool(results) and all(r.signature_ok and r.registry_ok for r in results),
        delegation_chain_ok=bool(results) and all(r.scope_ok for r in results),
        constraints=[],
        findings=findings,
        checks=checks,
        protocol="tap",
        cross_ref_map=cross,
        details={"requests": [
            {
                "keyid": r.keyid,
                "alg": r.alg,
                "tag": r.tag,
                "nonce": r.nonce,
                "agent_id": r.agent.get("id") if r.agent else None,
                "agent_domain": r.agent.get("domain") if r.agent else None,
            }
            for r in results
        ]},
    )


# ==========================================================================
# one request
# ==========================================================================


def _verify_request(i: int, req: Any, fx: Fixtures, now: int, cache: NonceCache) -> _Req:
    r = _Req(i, f"req[{i}]")
    L = r.layer
    if not isinstance(req, dict) or not all(isinstance(req.get(k), str) for k in ("method", "authority", "path")) \
            or not isinstance(req.get("headers", {}), dict):
        r.check("shape", reject(TapCode.TAP_REQUEST_INVALID, "request needs method/authority/path and headers", L))
        r.scope_ok = False
        return r
    headers = {str(k).lower(): v for k, v in req.get("headers", {}).items()}
    sig_in, sig = headers.get("signature-input"), headers.get("signature")
    if not isinstance(sig_in, str) or not isinstance(sig, str):
        r.check("headers", reject(TapCode.TAP_SIGNATURE_HEADERS_MISSING, "Signature-Input and Signature required", L))
        r.scope_ok = False
        return r
    try:
        inputs, sigs = parse_dictionary(sig_in), parse_dictionary(sig)
    except SFError as exc:
        code = TapCode.TAP_SIGNATURE_INPUT_MALFORMED
        try:
            parse_dictionary(sig_in)
        except SFError:
            pass
        else:
            code = TapCode.TAP_SIGNATURE_MALFORMED
        r.check("headers", reject(code, f"structured field parse error: {exc}", L))
        r.scope_ok = False
        return r
    if len(inputs) != 1:
        r.check("headers", Finding(TapCode.TAP_MULTIPLE_SIGNATURES, "indeterminate",
                                   f"{len(inputs)} signatures; KYA Bench verifies exactly one per request", L))
        return r
    label, member = next(iter(inputs.items()))
    if not member.is_inner_list:
        r.check("headers", reject(TapCode.TAP_SIGNATURE_INPUT_MALFORMED, "signature input must be an inner list", L))
        return r
    sig_member = sigs.get(label)
    if sig_member is None or not isinstance(sig_member.value, bytes):
        r.check("headers", reject(TapCode.TAP_SIGNATURE_LABEL_MISMATCH, f"no Signature member '{label}'", L))
        return r
    r.check("headers")

    params = dict(member.params)
    fs: list[Finding] = []
    if "keyid" not in params and "keyId" in params:
        # REPO's agent emits camel-case keyId, which is not a valid RFC 8941 key;
        # RFC 9421 and SPEC say keyid. Accept for the remaining checks, flag the gap.
        params["keyid"] = params["keyId"]
        fs.append(gap("TAP-02", "signature parameter 'keyId' (reference agent) instead of 'keyid' "
                                "(RFC 9421 / Visa spec); which one is normative is undefined", L))
    missing = [p for p in REQUIRED_PARAMS if p not in params]
    if missing:
        fs.append(reject(TapCode.TAP_PARAM_MISSING, f"missing signature parameters {missing}", L))
    types_ok = all(
        isinstance(params.get(p), int) and not isinstance(params.get(p), bool) for p in ("created", "expires")
        if p in params
    ) and all(isinstance(params.get(p), str) for p in ("keyid", "alg", "nonce", "tag") if p in params)
    if not types_ok:
        fs.append(reject(TapCode.TAP_SIGNATURE_INPUT_MALFORMED, "signature parameter has the wrong type", L))
    r.check("params", fs)
    r.keyid = params.get("keyid") if isinstance(params.get("keyid"), str) else None
    r.nonce = params.get("nonce") if isinstance(params.get("nonce"), str) else None
    r.tag = params.get("tag") if isinstance(params.get("tag"), str) else None
    r.alg = params.get("alg").lower() if isinstance(params.get("alg"), str) else None
    if missing or not types_ok:
        r.scope_ok = False
        return r

    # --- covered components & signature base (RFC 9421 §2.5)
    components = [it.value for it in member.value]
    fs = []
    if any(not isinstance(c, str) for c in components) or len(set(components)) != len(components):
        fs.append(reject(TapCode.TAP_SIGNATURE_INPUT_MALFORMED, "covered components must be unique strings", L))
    absent = [c for c in REQUIRED_COMPONENTS if c not in components]
    if absent:
        fs.append(reject(TapCode.TAP_COMPONENT_MISSING, f"signature must cover {absent}", L))
    r.check("components", fs)
    base, bfs = _signature_base(member, components, req, headers, L)
    r.check("signature_base", bfs)
    r.check("content_digest", _content_digest(headers, req.get("body"), L))

    # --- time window & replay (REPO + SPEC)
    created, expires = params["created"], params["expires"]
    fs = []
    if created > now + CREATED_FUTURE_TOLERANCE:
        fs.append(reject(TapCode.TAP_CREATED_IN_FUTURE, f"created {created} is in the future", L))
    if expires < now:
        fs.append(reject(TapCode.TAP_EXPIRED, f"signature expired at {expires}", L))
    if expires - created > MAX_WINDOW or expires < created:
        fs.append(reject(TapCode.TAP_WINDOW_TOO_LONG, "expires - created must be within 0..480 seconds", L))
    r.check("time", fs)
    if not cache.check_and_add(r.keyid, r.nonce, created):
        r.check("nonce", reject(TapCode.TAP_NONCE_REPLAY, "nonce already used with this key inside the window", L))
        r.scope_ok = False
    else:
        r.check("nonce")

    # --- registry & signature
    key = _registry_key(r, fx.tap_registry, L)
    if key is not None and base is not None:
        r.signature_ok = _verify_sig(r.alg, key, sig_member.value, base.encode("utf-8"))
        r.check("signature", None if r.signature_ok else reject(
            TapCode.TAP_SIGNATURE_INVALID, "signature does not verify with the registered key", L))
    else:
        r.check("signature", skipped="no usable key or signature base")

    # --- tag vs operation
    _check_tag(r, req.get("operation"), L)

    # --- body objects
    body_obj = _body_json(req.get("body"))
    if isinstance(body_obj, dict) and "agenticConsumer" in body_obj:
        _check_cro(r, body_obj["agenticConsumer"], fx, now, L)
    if isinstance(body_obj, dict) and "agenticPaymentContainer" in body_obj:
        _check_apc(r, body_obj["agenticPaymentContainer"], fx, L)
    return r


def _signature_base(member, components: list[Any], req: dict[str, Any], headers: dict[str, Any],
                    L: str) -> tuple[str | None, list[Finding]]:
    lines = []
    fs: list[Finding] = []
    for item in member.value:
        cid = item.value
        if not isinstance(cid, str):
            return None, fs
        if item.params:
            fs.append(Finding(TapCode.TAP_COMPONENT_UNSUPPORTED, "indeterminate",
                              f"component parameters on {cid} are not supported", L))
            return None, fs
        if cid == "@authority":
            val = req["authority"].lower()
        elif cid == "@path":
            val = req["path"]
        elif cid == "@method":
            val = req["method"].upper()
        elif cid == "@query":
            val = "?" + (req.get("query") or "")
        elif cid.startswith("@"):
            fs.append(Finding(TapCode.TAP_COMPONENT_UNSUPPORTED, "indeterminate",
                              f"derived component {cid} is not supported", L))
            return None, fs
        else:
            if cid not in headers or not isinstance(headers[cid], str):
                fs.append(reject(TapCode.TAP_COMPONENT_ABSENT, f"covered header '{cid}' is absent", L))
                return None, fs
            val = headers[cid].strip()
        lines.append(f'"{cid}": {val}')
    lines.append(f'"@signature-params": {member.raw}')
    return "\n".join(lines), fs


def _content_digest(headers: dict[str, Any], body: Any, L: str) -> list[Finding]:
    """RFC 9530: when Content-Digest is present, it must match the body."""
    cd = headers.get("content-digest")
    if cd is None:
        return []
    try:
        d = parse_dictionary(cd)
    except SFError:
        return [reject(TapCode.TAP_CONTENT_DIGEST_MALFORMED, "Content-Digest is not a structured dictionary", L)]
    body_bytes = (body or "").encode("utf-8") if isinstance(body, str) or body is None else b""
    algs = {"sha-256": hashlib.sha256, "sha-512": hashlib.sha512}
    known = [(k, m) for k, m in d.items() if k in algs]
    if not known or any(not isinstance(m.value, bytes) for _, m in known):
        return [reject(TapCode.TAP_CONTENT_DIGEST_MALFORMED, "Content-Digest has no sha-256/sha-512 value", L)]
    for k, m in known:
        if algs[k](body_bytes).digest() != m.value:
            return [reject(TapCode.TAP_CONTENT_DIGEST_MISMATCH, f"Content-Digest {k} does not match the body", L)]
    return []


def _registry_key(r: _Req, registry: dict[str, Any], L: str) -> Any:
    matches = [
        (agent, key)
        for agent in registry.get("agents", []) if isinstance(agent, dict)
        for key in agent.get("keys", []) if isinstance(key, dict) and key.get("key_id") == r.keyid
    ]
    if not matches:
        r.check("registry", reject(TapCode.TAP_KEY_UNKNOWN, f"keyid {r.keyid!r} is not in the agent registry", L))
        return None
    if len(matches) > 1:
        r.check("registry", reject(TapCode.TAP_KEY_AMBIGUOUS, f"keyid {r.keyid!r} is registered twice", L))
        return None
    agent, entry = matches[0]
    r.agent, r.key_entry = agent, entry
    fs = []
    # REPO stores status as the strings "true"/"false".
    if agent.get("is_active") != "true":
        fs.append(reject(TapCode.TAP_AGENT_REVOKED, f"agent {agent.get('domain')!r} is not active", L))
    if entry.get("is_active") != "true":
        fs.append(reject(TapCode.TAP_KEY_REVOKED, f"key {r.keyid!r} is not active", L))
    if r.alg not in SUPPORTED_ALGS:
        fs.append(reject(TapCode.TAP_ALG_UNSUPPORTED, f"alg {r.alg!r} is not ed25519 or rsa-pss-sha256", L))
    elif str(entry.get("algorithm", "")).lower() != r.alg:
        fs.append(reject(TapCode.TAP_ALG_KEY_MISMATCH, f"alg {r.alg!r} does not match the registered key", L))
    key = None
    if not fs:
        try:
            key = load_registry_key(entry)
        except ValueError as exc:
            fs.append(reject(TapCode.TAP_KEY_INVALID, f"registered key unusable: {exc}", L))
    r.registry_ok = r.check("registry", fs)
    return key if r.registry_ok else None


def load_registry_key(entry: dict[str, Any]) -> Any:
    """REPO formats: ed25519 = base64 raw 32 bytes; others = PEM SubjectPublicKeyInfo."""
    alg = str(entry.get("algorithm", "")).lower()
    pub = entry.get("public_key")
    if not isinstance(pub, str):
        raise ValueError("public_key missing")
    if alg == "ed25519":
        raw = base64.b64decode(pub)
        if len(raw) != 32:
            raise ValueError("Ed25519 key must be 32 bytes")
        return ed25519.Ed25519PublicKey.from_public_bytes(raw)
    return serialization.load_pem_public_key(pub.encode())


def _verify_sig(alg: str, key: Any, sig: bytes, data: bytes) -> bool:
    try:
        if alg == "ed25519" and isinstance(key, ed25519.Ed25519PublicKey):
            key.verify(sig, data)
            return True
        if alg == "rsa-pss-sha256" and isinstance(key, rsa.RSAPublicKey):
            # REPO: PSS, MGF1-SHA256, maximum salt length (Python PSS.MAX_LENGTH / Node SALTLEN_MAX_SIGN).
            key.verify(sig, data, padding.PSS(mgf=padding.MGF1(hashes.SHA256()),
                                              salt_length=padding.PSS.MAX_LENGTH), hashes.SHA256())
            return True
    except (InvalidSignature, ValueError):
        return False
    return False


def _check_tag(r: _Req, operation: Any, L: str) -> None:
    if r.tag not in TAGS:
        r.check("tag", reject(TapCode.TAP_TAG_UNKNOWN, f"tag {r.tag!r} is not {TAG_BROWSE} or {TAG_PAYER}", L))
        r.scope_ok = False
        return
    if operation not in ("browse", "payment"):
        r.check("tag", warn(TapCode.TAP_OPERATION_NOT_DECLARED,
                            "request has no declared operation; tag/operation binding not checked", L))
        return
    if operation == "payment" and r.tag == TAG_BROWSE:
        r.check("tag", reject(TapCode.TAP_TAG_OPERATION_MISMATCH,
                              "browse tag used for a payment operation", L))
        r.scope_ok = False
    elif operation == "browse" and r.tag == TAG_PAYER:
        r.check("tag", gap("TAP-03", "payer tag on a browse operation: neither repo nor spec defines the outcome", L))
    else:
        r.check("tag")


def _body_json(body: Any) -> Any:
    if not isinstance(body, str):
        return None
    try:
        return json.loads(body)
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Agentic Consumer Recognition Object (SPEC only; advisory)
# --------------------------------------------------------------------------


def _check_cro(r: _Req, cro: Any, fx: Fixtures, now: int, L: str) -> None:
    """SPEC: a failed CRO check means the content 'may be inaccurate' and the merchant
    decides whether to use it — it does not block the request. Findings are warnings."""
    lay = f"{L}.cro"
    if not isinstance(cro, dict):
        r.check("cro", warn(TapCode.TAP_CRO_FIELD_MISSING, "agenticConsumer is not an object", lay))
        return
    fs: list[Finding] = []
    missing = [k for k in CRO_FIELDS if k not in cro]
    if missing:
        fs.append(warn(TapCode.TAP_CRO_FIELD_MISSING, f"agenticConsumer lacks {missing}", lay))
    r.cross["cro_nonce_matches_signature"] = cro.get("nonce") == r.nonce if "nonce" in cro else None
    r.cross["cro_kid_matches_keyid"] = cro.get("kid") == r.keyid if "kid" in cro else None
    if r.cross["cro_nonce_matches_signature"] is False:
        fs.append(warn(TapCode.TAP_CRO_NONCE_MISMATCH, "agenticConsumer nonce differs from the signature nonce", lay))
    if r.cross["cro_kid_matches_keyid"] is False:
        fs.append(warn(TapCode.TAP_CRO_KID_MISMATCH, "agenticConsumer kid differs from the signature keyid", lay))
    if "idToken" in cro:
        problem = _id_token_problem(cro["idToken"], fx, now)
        r.cross["cro_id_token_valid"] = problem is None
        if problem:
            fs.append(warn(TapCode.TAP_CRO_ID_TOKEN_INVALID, f"idToken: {problem}", lay))
    if "signature" in cro:
        fs.append(Finding(TapCode.TAP_CRO_SIGNATURE_UNVERIFIABLE, "warn",
                          "agenticConsumer signature not verifiable: its signature base is undefined (TAP-01); "
                          "advisory object, request verdict unaffected", lay, "TAP-01"))
    r.check("cro", fs)


def _id_token_problem(token: Any, fx: Fixtures, now: int) -> str | None:
    jws, fs = parse_jws(token, "idToken")
    if jws is None:
        return "not a compact JWS"
    h, p = jws.header, jws.payload
    if h.get("alg") not in ID_TOKEN_ALGS:
        return f"alg {h.get('alg')!r} not PS256/RS256"
    kid = h.get("kid")
    found = fx.jwk_by_kid(kid) if isinstance(kid, str) else []
    if len(found) != 1:
        return "kid not resolvable in the issuer JWKS fixture"
    iss, jwk = found[0]
    if p.get("iss") != iss:
        return "iss does not match the issuer that publishes the key"
    try:
        n = int.from_bytes(b64url_decode(jwk["n"]), "big")
        e = int.from_bytes(b64url_decode(jwk["e"]), "big")
        key = rsa.RSAPublicNumbers(e, n).public_key()
        pad = (padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32)
               if h["alg"] == "PS256" else padding.PKCS1v15())
        key.verify(jws.signature, jws.signing_input, pad, hashes.SHA256())
    except (KeyError, ValueError, InvalidSignature):
        return "signature does not verify"
    exp, iat = p.get("exp"), p.get("iat")
    if not isinstance(exp, int) or now > exp:
        return "expired or no exp"
    if isinstance(iat, int) and iat > now + CREATED_FUTURE_TOLERANCE:
        return "iat in the future"
    return None


# --------------------------------------------------------------------------
# Agentic Payment Container (SPEC only)
# --------------------------------------------------------------------------


def _check_apc(r: _Req, apc: Any, fx: Fixtures, L: str) -> None:
    """SPEC: if validation fails the container MUST NOT be used to process a payment."""
    lay = f"{L}.apc"
    if not isinstance(apc, dict):
        r.check("apc", reject(TapCode.TAP_APC_FIELD_MISSING, "agenticPaymentContainer is not an object", lay))
        return
    fs: list[Finding] = []
    missing = [k for k in APC_FIELDS if k not in apc]
    if missing:
        fs.append(reject(TapCode.TAP_APC_FIELD_MISSING, f"agenticPaymentContainer lacks {missing}", lay))
    r.cross["apc_nonce_matches_signature"] = apc.get("nonce") == r.nonce if "nonce" in apc else None
    if r.cross["apc_nonce_matches_signature"] is False:
        fs.append(reject(TapCode.TAP_APC_NONCE_MISMATCH, "container nonce differs from the signature nonce", lay))
    kid = apc.get("kid")
    if isinstance(kid, str):
        known = any(
            isinstance(k, dict) and k.get("key_id") == kid
            for a in fx.tap_registry.get("agents", []) if isinstance(a, dict)
            for k in a.get("keys", [])
        )
        if not known:
            fs.append(reject(TapCode.TAP_APC_KEY_UNKNOWN, f"container kid {kid!r} is not registered", lay))
    if not any(f.effect == "reject" for f in fs) and "signature" in apc:
        fs.append(gap("TAP-01", "agenticPaymentContainer signature cannot be verified: the signature base "
                                "('all fields in the order received') has no defined serialization", lay))
    if any(f.effect == "reject" for f in fs):
        r.scope_ok = False
    r.check("apc", fs)
