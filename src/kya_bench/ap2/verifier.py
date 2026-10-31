"""AP2 v0.2 verifier: delegated SD-JWT mandate chains (human-present / not-present).

Source: github.com/google-agentic-commerce/AP2@e1ea56d — docs/ap2/*.md and
the Python SDK (code/sdk/python/ap2/sdk). AP2 v0.2 replaced v0.1's Intent /
Cart / Payment mandates with open/closed Checkout and Payment Mandates:

=====================  ==========================================  ===============
v0.1 term (brief)      v0.2 artifact                               vct
=====================  ==========================================  ===============
Intent Mandate         open Checkout + open Payment Mandates       mandate.*.open.1
Cart Mandate           closed Checkout Mandate (+ checkout_jwt)    mandate.checkout.1
Payment Mandate        closed Payment Mandate                      mandate.payment.1
=====================  ==========================================  ===============

Chain format (SDK sdjwt/chain.py): tokens joined by ``~~``. Token 0 is an
issuer-signed SD-JWT verified with a trust-list key (``kid``); token i>0 is a
KB-SD-JWT signed by the previous token's ``cnf.jwk``, bound to it by exactly one
of ``sd_hash`` / ``issuer_jwt_hash``. Intermediate hops (``kb+sd-jwt+kb``) carry
``cnf``; the terminal hop (``kb+sd-jwt``) must not. Human-present = one token
(the user/trusted surface signs the closed mandate); human-not-present = open
mandate (user-signed, binds the agent key) ~~ closed mandate (agent-signed).

Bundle (KYA Bench envelope)::

    {"checkout_mandate": "<chain>", "payment_mandate": "<chain>",
     "expected"?: {"checkout_aud", "checkout_nonce", "payment_aud", "payment_nonce"},
     "mandate_context"?: {"total_amount", "total_uses", "last_used_date"}}
"""

from __future__ import annotations

import json
import time
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any

from ..constraints import ConstraintResult, Strictness
from ..context import Fixtures
from ..keys import es256_verify, jwk_to_public_key
from ..parser import ParsedSdJwt, b64url_decode, is_undisclosed_ref, parse_sd_jwt, sha256_b64url, strict_json_loads
from ..reasons import Finding, gap, reject, warn
from ..verifier import Check, Verdict
from . import constraints as c11n

TYP_TERMINAL = ("kb+sd-jwt", "kb-sd-jwt")  # SDK kb_sd_jwt.py
TYP_INTERMEDIATE = ("kb+sd-jwt+kb", "kb-sd-jwt+kb")
CLOCK_SKEW = 300  # SDK chain.verify_chain default
OPEN = {"checkout": "mandate.checkout.open.1", "payment": "mandate.payment.open.1"}
CLOSED = {"checkout": "mandate.checkout.1", "payment": "mandate.payment.1"}
NON_PRESET = {"vct", "cnf", "constraints", "iat", "exp", "_sd", "_sd_alg"}


class Ap2Code(StrEnum):
    AP2_BUNDLE_INVALID = "AP2_BUNDLE_INVALID"
    AP2_MANDATE_MISSING = "AP2_MANDATE_MISSING"
    AP2_TOKEN_MALFORMED = "AP2_TOKEN_MALFORMED"
    AP2_ROOT_KID_MISSING = "AP2_ROOT_KID_MISSING"
    AP2_ROOT_KEY_UNKNOWN = "AP2_ROOT_KEY_UNKNOWN"
    AP2_ALG_UNSUPPORTED = "AP2_ALG_UNSUPPORTED"
    AP2_SIGNATURE_INVALID = "AP2_SIGNATURE_INVALID"
    AP2_TYP_INVALID = "AP2_TYP_INVALID"
    AP2_CNF_MISSING = "AP2_CNF_MISSING"
    AP2_CNF_FORBIDDEN = "AP2_CNF_FORBIDDEN"
    AP2_BINDING_MISSING = "AP2_BINDING_MISSING"
    AP2_BINDING_MISMATCH = "AP2_BINDING_MISMATCH"
    AP2_DELEGATE_PAYLOAD_INVALID = "AP2_DELEGATE_PAYLOAD_INVALID"
    AP2_IAT_MISSING = "AP2_IAT_MISSING"
    AP2_EXPIRED = "AP2_EXPIRED"
    AP2_IAT_FUTURE = "AP2_IAT_FUTURE"
    AP2_AUD_MISMATCH = "AP2_AUD_MISMATCH"
    AP2_NONCE_MISMATCH = "AP2_NONCE_MISMATCH"
    AP2_AUD_NOT_CHECKED = "AP2_AUD_NOT_CHECKED"
    AP2_VCT_UNKNOWN = "AP2_VCT_UNKNOWN"
    AP2_CHAIN_SHAPE = "AP2_CHAIN_SHAPE"
    AP2_MANDATE_FIELD_MISSING = "AP2_MANDATE_FIELD_MISSING"
    AP2_CHECKOUT_HASH_MISMATCH = "AP2_CHECKOUT_HASH_MISMATCH"
    AP2_TRANSACTION_ID_MISMATCH = "AP2_TRANSACTION_ID_MISMATCH"
    AP2_PRESET_CLAIM_CHANGED = "AP2_PRESET_CLAIM_CHANGED"
    AP2_CONSTRAINT_VIOLATION = "AP2_CONSTRAINT_VIOLATION"
    AP2_CONSTRAINT_UNKNOWN = "AP2_CONSTRAINT_UNKNOWN"
    AP2_CHECKOUT_JWT_UNDECODABLE = "AP2_CHECKOUT_JWT_UNDECODABLE"
    AP2_CHECKOUT_JWT_SIGNATURE_NOT_VERIFIED = "AP2_CHECKOUT_JWT_SIGNATURE_NOT_VERIFIED"
    AP2_CART_TOTAL_UNAVAILABLE = "AP2_CART_TOTAL_UNAVAILABLE"


@dataclass
class _Chain:
    side: str  # "checkout" | "payment"
    tokens: list[ParsedSdJwt] = field(default_factory=list)
    items: list[list[dict[str, Any]]] = field(default_factory=list)  # effective delegate items per token
    ok_sig: bool = False
    ok_binding: bool = False
    agent_jwk: dict[str, Any] | None = None
    open: dict[str, Any] | None = None
    closed: dict[str, Any] | None = None

    @property
    def flow(self) -> str | None:
        if not self.tokens:
            return None
        return "human_present" if len(self.tokens) == 1 else "human_not_present"


@dataclass
class _Run:
    fx: Fixtures
    now: int
    bundle: dict[str, Any]
    findings: list[Finding] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    constraints: list[ConstraintResult] = field(default_factory=list)
    cross: dict[str, bool | None] = field(default_factory=dict)

    def check(self, cid: str, fs: list[Finding] | Finding | None = None, *, skipped: str = "") -> bool:
        if skipped:
            self.checks.append(Check(cid, "skipped", skipped))
            return False
        fs = [fs] if isinstance(fs, Finding) else list(fs or [])
        self.findings.extend(fs)
        ok = not any(f.effect == "reject" for f in fs)
        self.checks.append(Check(cid, "pass" if ok else "fail", "; ".join(f.message for f in fs)))
        return ok


def verify_ap2(bundle: Any, *, fixtures: Fixtures, now: int | None = None) -> Verdict:
    now = int(time.time()) if now is None else now
    if isinstance(bundle, str):
        try:
            bundle = json.loads(bundle)
        except ValueError:
            bundle = None
    if not isinstance(bundle, dict):
        bundle = {}
        run = _Run(fixtures, now, bundle)
        run.check("bundle.shape", reject(Ap2Code.AP2_BUNDLE_INVALID, "AP2 bundle must be a JSON object", "bundle"))
        return _finish(run, [])
    run = _Run(fixtures, now, bundle)
    chains: list[_Chain] = []
    for side in ("checkout", "payment"):
        raw = bundle.get(f"{side}_mandate")
        if not isinstance(raw, str):
            run.check(f"{side}.present", reject(Ap2Code.AP2_MANDATE_MISSING,
                                                f"{side} mandate chain missing (verifiers always receive closed "
                                                "checkout and payment mandates, specification.md Modes)", side))
            continue
        ch = _verify_chain(run, side, raw)
        _type_chain(run, ch)
        chains.append(ch)
    by_side = {c.side: c for c in chains}
    _semantics(run, by_side)
    return _finish(run, chains)


# ==========================================================================
# chain (SDK sdjwt/chain.py, kb_sd_jwt.py)
# ==========================================================================


def _split(raw: str) -> list[str]:
    parts = raw.split("~~")
    return [p if i == len(parts) - 1 or p.endswith("~") else p + "~" for i, p in enumerate(parts)]


def _items(tok: ParsedSdJwt) -> list[Any]:
    dp = (tok.resolved or {}).get("delegate_payload")
    return dp if isinstance(dp, list) else []


def _verify_chain(run: _Run, side: str, raw: str) -> _Chain:
    ch = _Chain(side)
    L = side
    segs = _split(raw)
    for i, seg in enumerate(segs):
        tok = parse_sd_jwt(seg, f"{L}[{i}]")
        fs = [Finding(Ap2Code.AP2_TOKEN_MALFORMED, f.effect, f.message, f.layer, f.gap_id, f.detail)
              if f.effect == "reject" else f for f in tok.findings]
        if not run.check(f"{L}[{i}].parse", fs) or tok.jws is None:
            return ch
        ch.tokens.append(tok)
    if len(ch.tokens) > 2:
        run.check(f"{L}.depth", gap("AP2-03", f"{len(ch.tokens)}-token chain: agent-to-agent delegation is outside "
                                              "the AP2 v0.2 specification", L))
    sig_ok, bind_ok = True, True
    prev_cnf: dict[str, Any] | None = None
    for i, tok in enumerate(ch.tokens):
        lay, last = f"{L}[{i}]", i == len(ch.tokens) - 1
        h, p = tok.header, tok.payload
        if h.get("alg") != "ES256":
            run.check(f"{lay}.alg", Finding(Ap2Code.AP2_ALG_UNSUPPORTED, "indeterminate",
                                            f"alg {h.get('alg')!r}: KYA Bench verifies ES256 (the SDK's algorithm)",
                                            lay))
            sig_ok = False
            break
        if i == 0:
            jwk, fs = _root_key(run, tok, lay)
            if not run.check(f"{lay}.trust", fs):
                sig_ok = False
                break
        else:
            fs = []
            if h.get("typ") not in TYP_TERMINAL + TYP_INTERMEDIATE:
                fs.append(reject(Ap2Code.AP2_TYP_INVALID, f"KB hop typ {h.get('typ')!r} is not a KB-SD-JWT type", lay))
            jwk = prev_cnf
            if jwk is None:
                fs.append(reject(Ap2Code.AP2_CNF_MISSING, "previous token carries no cnf.jwk for this hop", lay))
            bind_ok &= run.check(f"{lay}.typ", fs)
            if jwk is None:
                sig_ok = False
                break
        try:
            key = jwk_to_public_key(jwk)
        except ValueError as exc:
            run.check(f"{lay}.signature", reject(Ap2Code.AP2_SIGNATURE_INVALID, f"unusable key: {exc}", lay))
            sig_ok = False
            break
        good = es256_verify(tok.jws.signing_input, tok.jws.signature, key)
        sig_ok &= run.check(f"{lay}.signature", None if good else reject(
            Ap2Code.AP2_SIGNATURE_INVALID, "signature does not verify" + (
                " with the previous hop's cnf.jwk" if i else " with the trust-list key"), lay))
        if not good:
            break
        items, fs = _delegate_items(tok, lay, require_single=not last)
        if i > 0:
            fs += _binding(p, ch.tokens[i - 1], lay)
            if "iat" not in p:
                fs.append(reject(Ap2Code.AP2_IAT_MISSING, "KB hop must carry iat", lay))
            has_cnf = any(isinstance(it.get("cnf"), dict) for it in items)
            if h.get("typ") in TYP_TERMINAL and has_cnf:
                fs.append(reject(Ap2Code.AP2_CNF_FORBIDDEN, "terminal KB-SD-JWT must not carry cnf", lay))
            if h.get("typ") in TYP_INTERMEDIATE and not has_cnf:
                fs.append(reject(Ap2Code.AP2_CNF_MISSING, "intermediate KB-SD-JWT requires cnf", lay))
            if last:
                fs += _expected(run, side, p, lay)
        fs += _time(run.now, [p, *items], lay)
        bind_ok &= run.check(f"{lay}.claims", fs)
        ch.items.append(items)
        prev_cnf = next((it["cnf"]["jwk"] for it in items
                         if isinstance(it.get("cnf"), dict) and isinstance(it["cnf"].get("jwk"), dict)), None)
    ch.ok_sig = sig_ok and len(ch.items) == len(ch.tokens)
    ch.ok_binding = bind_ok and ch.ok_sig
    return ch


def _root_key(run: _Run, tok: ParsedSdJwt, lay: str) -> tuple[dict[str, Any] | None, list[Finding]]:
    kid = tok.header.get("kid")
    if not isinstance(kid, str) or not kid:
        return None, [reject(Ap2Code.AP2_ROOT_KID_MISSING, "root token header needs kid (SDK X5cOrKidPublicKeyProvider; "
                                                          "x5c is not supported offline)", lay)]
    found = run.fx.jwk_by_kid(kid)
    if len(found) != 1:
        return None, [reject(Ap2Code.AP2_ROOT_KEY_UNKNOWN, f"kid {kid!r} is not in the trust list", lay)]
    return found[0][1], []


def _delegate_items(tok: ParsedSdJwt, lay: str, require_single: bool) -> tuple[list[dict[str, Any]], list[Finding]]:
    raw = _items(tok)
    items = [it for it in raw if isinstance(it, dict) and not is_undisclosed_ref(it)]
    fs = []
    if not items:
        fs.append(reject(Ap2Code.AP2_DELEGATE_PAYLOAD_INVALID, "delegate_payload discloses no mandate", lay))
    elif require_single and len(items) > 1:
        fs.append(reject(Ap2Code.AP2_DELEGATE_PAYLOAD_INVALID,
                         f"non-terminal token discloses {len(items)} items, expected exactly 1", lay))
    return items, fs


def _binding(p: dict[str, Any], prev: ParsedSdJwt, lay: str) -> list[Finding]:
    has_sd, has_iss = "sd_hash" in p, "issuer_jwt_hash" in p
    if has_sd == has_iss:
        return [reject(Ap2Code.AP2_BINDING_MISSING, "exactly one of sd_hash / issuer_jwt_hash is required", lay)]
    if prev.payload.get("_sd_alg", "sha-256") != "sha-256":
        return [Finding(Ap2Code.AP2_ALG_UNSUPPORTED, "indeterminate", "only _sd_alg sha-256 is supported", lay)]
    expected = sha256_b64url(prev.serialized) if has_sd else sha256_b64url(prev.base_jwt or "")
    actual = p["sd_hash"] if has_sd else p["issuer_jwt_hash"]
    if actual != expected:
        return [reject(Ap2Code.AP2_BINDING_MISMATCH,
                       f"{'sd_hash' if has_sd else 'issuer_jwt_hash'} does not bind the previous token", lay)]
    return []


def _expected(run: _Run, side: str, p: dict[str, Any], lay: str) -> list[Finding]:
    exp = run.bundle.get("expected") if isinstance(run.bundle.get("expected"), dict) else {}
    fs = []
    for claim, code in (("aud", Ap2Code.AP2_AUD_MISMATCH), ("nonce", Ap2Code.AP2_NONCE_MISMATCH)):
        want = exp.get(f"{side}_{claim}")
        if want is None:
            fs.append(warn(Ap2Code.AP2_AUD_NOT_CHECKED, f"terminal {claim} not checked (no expected value)", lay))
        elif p.get(claim) != want:
            fs.append(reject(code, f"terminal {claim} does not match the expected value", lay))
    return fs


def _time(now: int, payloads: list[dict[str, Any]], lay: str) -> list[Finding]:
    fs = []
    for pl in payloads:
        exp, iat = pl.get("exp"), pl.get("iat")
        if exp is not None and (not isinstance(exp, (int, float)) or now > exp + CLOCK_SKEW):
            fs.append(reject(Ap2Code.AP2_EXPIRED, f"expired at {exp}", lay))
        if iat is not None and (not isinstance(iat, (int, float)) or iat > now + CLOCK_SKEW):
            fs.append(reject(Ap2Code.AP2_IAT_FUTURE, f"iat {iat} is in the future", lay))
    return fs


# ==========================================================================
# mandate semantics
# ==========================================================================


def _type_chain(run: _Run, ch: _Chain) -> None:
    if not ch.ok_sig:
        return
    vcts = [items[0].get("vct") for items in ch.items]
    fs = []
    known = set(OPEN.values()) | set(CLOSED.values())
    for v in vcts:
        if v not in known:
            fs.append(reject(Ap2Code.AP2_VCT_UNKNOWN, f"unrecognized mandate vct {v!r}", ch.side))
    if not fs:
        want = [CLOSED[ch.side]] if len(vcts) == 1 else [OPEN[ch.side], CLOSED[ch.side]]
        if vcts[: len(want)] != want and len(vcts) <= 2:
            fs.append(reject(Ap2Code.AP2_CHAIN_SHAPE,
                             f"{ch.side} chain must be {want} for its flow, got {vcts}", ch.side))
    if run.check(f"{ch.side}.shape", fs):
        ch.closed = ch.items[-1][0]
        if len(ch.items) >= 2:
            ch.open = ch.items[0][0]
            jwk = ch.open.get("cnf", {}).get("jwk") if isinstance(ch.open.get("cnf"), dict) else None
            ch.agent_jwk = jwk if isinstance(jwk, dict) else None
        elif isinstance(ch.closed.get("cnf"), dict):
            ch.agent_jwk = ch.closed["cnf"].get("jwk")


def _need(obj: dict[str, Any], fields: dict[str, type], lay: str) -> list[Finding]:
    return [reject(Ap2Code.AP2_MANDATE_FIELD_MISSING, f"closed mandate needs '{k}' ({t.__name__})", lay)
            for k, t in fields.items() if not isinstance(obj.get(k), t) or isinstance(obj.get(k), bool)]


def _semantics(run: _Run, by_side: dict[str, _Chain]) -> None:
    co, pa = by_side.get("checkout"), by_side.get("payment")
    checkout_payload = None
    if co and co.closed:
        fs = _need(co.closed, {"checkout_jwt": str, "checkout_hash": str}, "checkout")
        cj = co.closed.get("checkout_jwt")
        if isinstance(cj, str) and isinstance(co.closed.get("checkout_hash"), str):
            ok = cj.isascii() and sha256_b64url(cj) == co.closed["checkout_hash"]
            run.cross["checkout_hash_matches_checkout_jwt"] = ok
            if not ok:
                fs.append(reject(Ap2Code.AP2_CHECKOUT_HASH_MISMATCH, "checkout_hash != hash(checkout_jwt)", "checkout"))
            try:
                checkout_payload = strict_json_loads(b64url_decode(cj.split(".")[1]))
                fs.append(warn(Ap2Code.AP2_CHECKOUT_JWT_SIGNATURE_NOT_VERIFIED,
                               "checkout_jwt is merchant-signed; no merchant key fixture, signature not verified",
                               "checkout"))
            except (IndexError, ValueError, UnicodeDecodeError):
                fs.append(warn(Ap2Code.AP2_CHECKOUT_JWT_UNDECODABLE, "checkout_jwt payload not decodable", "checkout"))
        run.check("checkout.closed", fs)
    if pa and pa.closed:
        run.check("payment.closed", _need(pa.closed, {"transaction_id": str, "payee": dict, "payment_amount": dict,
                                                      "payment_instrument": dict}, "payment"))
    if co and pa and co.closed and pa.closed:
        same = pa.closed.get("transaction_id") == co.closed.get("checkout_hash")
        run.cross["payment_transaction_id_matches_checkout_hash"] = same
        run.check("cross.transaction_id", None if same else reject(
            Ap2Code.AP2_TRANSACTION_ID_MISMATCH, "payment transaction_id != checkout checkout_hash", "cross"))
        if co.flow != pa.flow:
            run.check("cross.flow", gap("AP2-02", f"checkout chain is {co.flow}, payment chain is {pa.flow}; mixing "
                                                  "flows is not addressed by the specification", "cross"))
        _cart_amount(run, checkout_payload, pa.closed)
    for ch in (co, pa):
        if ch and ch.open and ch.closed:
            changed = [k for k, v in ch.open.items() if k not in NON_PRESET and ch.closed.get(k) != v]
            run.check(f"{ch.side}.preset", [reject(Ap2Code.AP2_PRESET_CLAIM_CHANGED,
                                                   f"closed mandate changed pre-set claims {changed}", ch.side)]
                      if changed else None)
    # constraints (human-not-present only: open mandates carry them)
    if co and co.open and co.closed:
        ctx = c11n.Ap2Context(checkout_payload=checkout_payload)
        run.constraints += c11n.evaluate(co.open.get("constraints"), "checkout", ctx)
    if pa and pa.open and pa.closed:
        mc = run.bundle.get("mandate_context")
        ctx = c11n.Ap2Context(
            closed_payment=pa.closed,
            open_checkout_hash=sha256_b64url(co.tokens[0].serialized) if co and co.open else None,
            mandate_context=mc if isinstance(mc, dict) else None,
        )
        run.constraints += c11n.evaluate(pa.open.get("constraints"), "payment", ctx)
        refs = [r for r in run.constraints if r.type == "payment.reference"]
        if refs:
            run.cross["payment_reference_matches_open_checkout"] = all(r.status == "pass" for r in refs)
    run.findings.extend(c11n.findings_of(run.constraints))


def _cart_amount(run: _Run, checkout: dict[str, Any] | None, payment: dict[str, Any]) -> None:
    totals = checkout.get("totals") if isinstance(checkout, dict) else None
    total = next((t.get("amount") for t in totals if isinstance(t, dict) and t.get("type") == "total"), None) \
        if isinstance(totals, list) else None
    pa = payment.get("payment_amount") if isinstance(payment.get("payment_amount"), dict) else {}
    if not isinstance(total, int):
        run.cross["cart_total_matches_payment_amount"] = None
        run.check("cross.cart_amount", warn(Ap2Code.AP2_CART_TOTAL_UNAVAILABLE,
                                            "checkout_jwt has no UCP totals[type=total]; amount not compared", "cross"))
        return
    same = total == pa.get("amount") and checkout.get("currency") == pa.get("currency")
    run.cross["cart_total_matches_payment_amount"] = same
    run.check("cross.cart_amount", None if same else gap(
        "AP2-01", "checkout total differs from payment_amount; AP2 binds them only by hash and leaves the "
                  "checkout contents out of scope, so the consequence is undefined", "cross"))


def _finish(run: _Run, chains: list[_Chain]) -> Verdict:
    rejects = any(f.effect == "reject" for f in run.findings)
    verdict = "reject" if rejects else "indeterminate" if any(f.effect == "indeterminate" for f in run.findings) \
        else "accept"
    flows = sorted({c.flow for c in chains if c.flow})
    return Verdict(
        verdict=verdict,
        mode=flows[0] if len(flows) == 1 else None,
        strictness=Strictness.STRICT,
        evaluated_at=run.now,
        identity_ok=len(chains) == 2 and all(c.ok_sig for c in chains),
        delegation_chain_ok=len(chains) == 2 and all(c.ok_binding for c in chains),
        constraints=run.constraints,
        findings=run.findings,
        checks=run.checks,
        protocol="ap2",
        cross_ref_map=run.cross,
        details={
            "flow": {c.side: c.flow for c in chains},
            "agent_jwk": {c.side: c.agent_jwk for c in chains},
        },
    )
