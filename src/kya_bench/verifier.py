"""Verifier core: judge a VI credential bundle (L1 → L2 → L3a/L3b).

``verify()`` never raises on malformed credentials; it returns a ``Verdict``
whose findings carry reason codes. Spec references are to the VI v0.1-draft
documents ``credential-format.md`` (CF) and ``constraints.md`` (C).

Bundle (KYA Bench input envelope — not a VI wire format)::

    {
      "l1": "<SD-JWT as received by the L2 signer>",
      "l2": "<L2 SD-JWT presentation>",
      "l3a": "<L3a>", "l3b": "<L3b>",                  # Autonomous only
      "l2_view_l3a": "<L2 presentation L3a binds to>",  # CF §5.4; defaults to "l2"
      "l2_view_l3b": "<L2 presentation L3b binds to>",
      "expected": {"l2_aud": ..., "l2_nonce": ..., "l3a_aud": ..., ...},
      "network_state": {"cumulative_spent": int, "occurrence_count": int}
    }
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any, Literal

from .constraints import (
    REFERENCE,
    UNKNOWN_HANDLING,
    ConstraintResult,
    Fulfillment,
    NetworkState,
    Strictness,
    check_constraints,
)
from .keys import KeyResolver, PublicKey, es256_verify, jwk_to_public_key
from .parser import ParsedSdJwt, b64url_decode, is_undisclosed_ref, parse_sd_jwt, sha256_b64url, strict_json_loads
from .reasons import Code, Finding, gap, reject, warn

__all__ = ["Strictness", "Verdict", "verify"]

L1_TYP = "sd+jwt"
L2_TYP_IMMEDIATE = "kb-sd-jwt"
L2_TYP_AUTONOMOUS = "kb-sd-jwt+kb"
L3_TYP = "kb-sd-jwt"
MC_CARD_VCT = "https://credentials.mastercard.com/card"
VCT_CHECKOUT_OPEN = "mandate.checkout.open.1"
VCT_PAYMENT_OPEN = "mandate.payment.open.1"
VCT_CHECKOUT = "mandate.checkout.1"
VCT_PAYMENT = "mandate.payment.1"
OPEN_VCTS = {VCT_CHECKOUT_OPEN, VCT_PAYMENT_OPEN}
FINAL_VCTS = {VCT_CHECKOUT, VCT_PAYMENT}

DEFAULT_CLOCK_SKEW = 300  # CF §3.5, §4.7, §5.7
L2_IMMEDIATE_LIFETIME = 15 * 60  # CF §4.3 / §7
L2_AUTONOMOUS_LIFETIME = 30 * 24 * 3600  # CF §4.3 SHOULD
L1_LIFETIME = 366 * 24 * 3600  # CF §3.3 SHOULD (1 year, leap-safe)
L3_MAX_LIFETIME = 3600  # CF §5.3 MUST NOT exceed 1 hour

_URI_RE = re.compile(r"^[A-Za-z][A-Za-z0-9+.\-]*:\S+$")
_BUNDLE_KEYS = {"l1", "l2", "l3a", "l3b", "l2_view_l3a", "l2_view_l3b", "expected", "network_state"}
_EXPECTED_KEYS = {"l2_aud", "l2_nonce", "l3a_aud", "l3a_nonce", "l3b_aud", "l3b_nonce"}

CheckStatus = Literal["pass", "fail", "skipped"]


@dataclass
class Check:
    id: str
    status: CheckStatus
    detail: str = ""

    def to_json(self) -> dict[str, Any]:
        out: dict[str, Any] = {"id": self.id, "status": self.status}
        if self.detail:
            out["detail"] = self.detail
        return out


@dataclass
class Verdict:
    verdict: Literal["accept", "reject", "indeterminate"]
    mode: Literal["immediate", "autonomous"] | None
    strictness: Strictness
    evaluated_at: int
    identity_ok: bool
    delegation_chain_ok: bool
    constraints: list[ConstraintResult]
    findings: list[Finding]
    checks: list[Check]
    protocol: str = "vi"
    cross_ref_map: dict[str, bool | None] | None = None  # protocol-specific cross_refs (non-VI)
    details: dict[str, Any] = field(default_factory=dict)  # protocol-specific extras

    @property
    def reasons(self) -> list[Finding]:
        return [f for f in self.findings if f.effect != "warn"]

    @property
    def warnings(self) -> list[Finding]:
        return [f for f in self.findings if f.effect == "warn"]

    def codes(self) -> set[str]:
        return {str(f.code) for f in self.findings}

    def to_json(self) -> dict[str, Any]:
        from . import SPECS, __version__

        out = {
            "kya_bench_version": __version__,
            "protocol": self.protocol,
            "spec_version": SPECS[self.protocol]["version"],
            "spec": SPECS[self.protocol],
            "verdict": self.verdict,
            "mode": self.mode,
            "strictness": str(self.strictness),
            "evaluated_at": self.evaluated_at,
            "identity_ok": self.identity_ok,
            "delegation_chain_ok": self.delegation_chain_ok,
            "constraints": [c.to_json() for c in self.constraints],
            "cross_refs": self.cross_refs(),
            "unknown_constraints": self.unknown_constraints(),
            "reason_codes": self.reason_codes(),
            "reasons": [f.to_json() for f in self.reasons],
            "warnings": [f.to_json() for f in self.warnings],
            "checks": [c.to_json() for c in self.checks],
        }
        if self.details:
            out["details"] = self.details
        return out

    def reason_codes(self) -> list[str]:
        """Codes behind the verdict (reject / indeterminate), unique, in order of discovery."""
        return list(dict.fromkeys(str(f.code) for f in self.reasons))

    def cross_refs(self) -> dict[str, bool | None]:
        """Result of each cross-layer binding: true / false, or null when not applicable."""
        if self.cross_ref_map is not None:
            return self.cross_ref_map
        status = {c.id: c.status for c in self.checks}

        def from_check(cid: str) -> bool | None:
            return {"pass": True, "fail": False}.get(status.get(cid, ""))

        def checkout_hash(layer: str, cid: str) -> bool | None:
            if any(f.code == Code.CHECKOUT_HASH_MISMATCH and f.layer == layer for f in self.findings):
                return False
            return True if cid in status else None

        return {
            "l3a_l3b_match": from_check("L3.cross_reference"),
            "l3a_l3b_same_pair": from_check("L3.same_pair"),
            "l2_sd_hash_l1": from_check("L2.sd_hash"),
            "l3a_sd_hash_l2_view": from_check("L3a.sd_hash"),
            "l3b_sd_hash_l2_view": from_check("L3b.sd_hash"),
            "l3a_kid_l2_cnf": from_check("L3a.key_binding"),
            "l3b_kid_l2_cnf": from_check("L3b.key_binding"),
            "l2_mandate_pairing": from_check("L2.pairing"),
            "l2_checkout_hash": checkout_hash("L2", "L2.mandates") if self.mode == "immediate" else None,
            "l3b_checkout_hash": checkout_hash("L3b", "L3b.mandate"),
        }

    def unknown_constraints(self) -> list[dict[str, Any]]:
        out = []
        for c in self.constraints:
            if c.registered or c.type is None:
                continue
            handling = next((UNKNOWN_HANDLING[str(f.code)] for f in c.findings if str(f.code) in UNKNOWN_HANDLING), None)
            out.append({"type": c.type, "mandate": c.mandate, "index": c.index, "handling": handling})
        return out


@dataclass
class _Mandate:
    value: dict[str, Any]
    digest: str
    vct: str


@dataclass
class _Pair:
    checkout: _Mandate | None = None
    payment: _Mandate | None = None
    agent_key: PublicKey | None = None
    agent_kid: str | None = None
    reference_ok: bool | None = None


@dataclass
class _Run:
    bundle: Any
    strictness: Strictness
    resolver: KeyResolver
    now: int
    skew: int
    policy: dict[str, Any] | None
    merchant_pointer: str
    findings: list[Finding] = field(default_factory=list)
    checks: list[Check] = field(default_factory=list)
    mode: Literal["immediate", "autonomous"] | None = None
    l1: ParsedSdJwt | None = None
    l2: ParsedSdJwt | None = None
    l3: dict[str, ParsedSdJwt] = field(default_factory=dict)
    user_key: PublicKey | None = None
    l2_sig_ok: bool = False
    pairs: list[_Pair] = field(default_factory=list)
    l2_has_undisclosed: bool = False
    constraint_results: list[ConstraintResult] = field(default_factory=list)

    # -- recording helpers ------------------------------------------------

    def add(self, *fs: Finding) -> None:
        self.findings.extend(fs)

    def check(self, cid: str, failures: list[Finding] | Finding | None = None, *, skipped: str = "") -> bool:
        if skipped:
            self.checks.append(Check(cid, "skipped", skipped))
            return False
        fs = [failures] if isinstance(failures, Finding) else list(failures or [])
        self.add(*fs)
        ok = not any(f.effect == "reject" for f in fs)
        self.checks.append(Check(cid, "pass" if ok else "fail", "; ".join(f.message for f in fs)))
        return ok

    def require(self, obj: dict[str, Any], layer: str, name: str, typ: type | tuple[type, ...]) -> Any:
        """Fetch a required claim; record CLAIM_MISSING / CLAIM_TYPE_INVALID."""
        if name not in obj:
            self.add(reject(Code.CLAIM_MISSING, f"{layer} missing required claim '{name}'", layer))
            return None
        val = obj[name]
        bad_bool = isinstance(val, bool) and typ is int
        if bad_bool or not isinstance(val, typ):
            self.add(reject(Code.CLAIM_TYPE_INVALID, f"{layer} claim '{name}' has wrong type", layer))
            return None
        return val


def verify(
    bundle: Any,
    *,
    strictness: Strictness | str,
    resolver: KeyResolver,
    now: int | None = None,
    clock_skew: int = DEFAULT_CLOCK_SKEW,
    constraint_policy: dict[str, Strictness | str] | None = None,
    merchant_pointer: str = "",
) -> Verdict:
    """Verify a VI bundle and return a normalized verdict.

    ``strictness`` is required (no default): it decides how unknown constraint
    types in *non-open* mandates are handled. Unknown types in open mandates
    are rejected under either setting (C §5.4).

    ``merchant_pointer`` is a JSON Pointer into the ``checkout_jwt`` payload
    locating the merchant object used by ``mandate.checkout.allowed_merchants``.
    The default ``""`` (payload root) is the literal reading of CF §6.3; see
    docs/spec-gaps.md G-02.
    """
    run = _Run(
        bundle=bundle,
        strictness=Strictness(strictness),
        resolver=resolver,
        now=int(time.time()) if now is None else now,
        skew=clock_skew,
        policy=constraint_policy,
        merchant_pointer=merchant_pointer,
    )
    if _check_bundle(run):
        _verify_l1(run)
        _verify_l2(run)
        _verify_l3(run)
    return _finish(run)


# ==========================================================================
# bundle
# ==========================================================================


def _check_bundle(run: _Run) -> bool:
    b = run.bundle
    if isinstance(b, (str, bytes)):
        try:
            b = run.bundle = strict_json_loads(b.encode() if isinstance(b, str) else b)
        except (ValueError, UnicodeDecodeError):
            run.check("bundle.shape", reject(Code.BUNDLE_INVALID, "bundle is not valid JSON", "bundle"))
            return False
    if not isinstance(b, dict):
        run.check("bundle.shape", reject(Code.BUNDLE_INVALID, "bundle must be a JSON object", "bundle"))
        return False
    fs: list[Finding] = []
    for key in ("l1", "l2"):
        if key not in b:
            fs.append(reject(Code.LAYER_MISSING, f"bundle has no '{key}'", "bundle"))
    for key in sorted(set(b) - _BUNDLE_KEYS):
        fs.append(warn(Code.BUNDLE_UNKNOWN_FIELD, f"unknown bundle field '{key}' ignored", "bundle"))
    exp = b.get("expected", {})
    if not isinstance(exp, dict) or set(exp) - _EXPECTED_KEYS:
        fs.append(reject(Code.BUNDLE_INVALID, f"'expected' may only contain {sorted(_EXPECTED_KEYS)}", "bundle"))
    ns = b.get("network_state", {})
    if not isinstance(ns, dict) or any(
        k not in ("cumulative_spent", "occurrence_count") or not isinstance(v, int) or isinstance(v, bool) or v < 0
        for k, v in ns.items()
    ):
        fs.append(reject(Code.BUNDLE_INVALID, "'network_state' must map to non-negative integers", "bundle"))
    return run.check("bundle.shape", fs)


def _expected(run: _Run, key: str) -> Any:
    return run.bundle.get("expected", {}).get(key)


# ==========================================================================
# L1 — issuer credential (CF §3)
# ==========================================================================


def _verify_l1(run: _Run) -> None:
    l1 = run.l1 = parse_sd_jwt(run.bundle["l1"], "L1")
    if not run.check("L1.parse", l1.findings) or l1.jws is None:
        return
    h, p = l1.header, l1.payload

    fs: list[Finding] = []
    if h.get("alg") != "ES256":
        fs.append(reject(Code.HEADER_ALG_INVALID, "L1 alg must be ES256", "L1"))
    if h.get("typ") != L1_TYP:
        fs.append(reject(Code.HEADER_TYP_INVALID, f"L1 typ must be '{L1_TYP}'", "L1"))
    kid = h.get("kid")
    if not isinstance(kid, str) or not kid:
        fs.append(reject(Code.HEADER_KID_MISSING, "L1 header must carry 'kid' (CF §3.2)", "L1"))
    run.check("L1.header", fs)

    n = len(run.findings)
    iss = run.require(p, "L1", "iss", str)
    run.require(p, "L1", "sub", str)
    iat = run.require(p, "L1", "iat", int)
    exp = run.require(p, "L1", "exp", int)
    run.require(p, "L1", "_sd", list)
    sd_alg = run.require(p, "L1", "_sd_alg", str)
    fs = run.findings[n:]
    del run.findings[n:]
    if sd_alg is not None and sd_alg != "sha-256":
        fs.append(reject(Code.SD_ALG_INVALID, "L1 _sd_alg must be 'sha-256'", "L1"))
    vct = p.get("vct")  # must be always-visible: read from the signed payload, not disclosures
    if not isinstance(vct, str) or not _URI_RE.match(vct):
        fs.append(reject(Code.L1_VCT_INVALID, "L1 vct absent, not always-visible, or not a well-formed URI", "L1"))
    elif vct == MC_CARD_VCT:
        for claim in ("pan_last_four", "scheme"):
            if not isinstance(p.get(claim), str):
                fs.append(
                    reject(Code.L1_PROFILE_CLAIM_MISSING, f"Mastercard profile requires visible '{claim}'", "L1")
                )
    if l1.resolved is not None and "sd_hash" in l1.resolved:
        fs.append(reject(Code.L1_SD_HASH_PRESENT, "L1 MUST NOT contain sd_hash (CF §3.5 rule 6)", "L1"))
    run.check("L1.claims", fs)

    cnf = p.get("cnf")
    jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
    if jwk is None:
        run.check("L1.cnf", reject(Code.CNF_MISSING, "L1 must carry cnf.jwk (user key)", "L1"))
    else:
        try:
            run.user_key = jwk_to_public_key(jwk)
            run.check("L1.cnf")
        except ValueError as exc:
            run.check("L1.cnf", reject(Code.JWK_INVALID, f"L1 cnf.jwk unusable: {exc}", "L1"))

    if isinstance(iss, str) and isinstance(kid, str) and kid:
        key, kfs = run.resolver.resolve(iss, kid)
        run.check("L1.jwks", kfs)
        if key is not None:
            ok = es256_verify(l1.jws.signing_input, l1.jws.signature, key)
            run.check("L1.signature", None if ok else reject(Code.SIGNATURE_INVALID, "L1 issuer signature", "L1"))
        else:
            run.check("L1.signature", skipped="issuer key not resolved")
    else:
        run.check("L1.jwks", skipped="iss/kid unavailable")
        run.check("L1.signature", skipped="iss/kid unavailable")

    fs = []
    if exp is not None and run.now > exp + run.skew:
        fs.append(reject(Code.TIME_EXPIRED, f"L1 expired at {exp}", "L1"))
    if exp is not None and iat is not None and exp - iat > L1_LIFETIME:
        fs.append(warn(Code.TIME_LIFETIME_SHOULD, "L1 lifetime exceeds 1 year (CF §3.3 SHOULD)", "L1"))
    run.check("L1.time", fs)


# ==========================================================================
# L2 — user credential (CF §4)
# ==========================================================================


def _verify_l2(run: _Run) -> None:
    l2 = run.l2 = parse_sd_jwt(run.bundle["l2"], "L2")
    if not run.check("L2.parse", l2.findings) or l2.jws is None or l2.resolved is None:
        return
    h, p = l2.header, l2.payload

    if run.user_key is None:
        run.check("L2.signature", skipped="L1 cnf.jwk unavailable")
    else:
        run.l2_sig_ok = es256_verify(l2.jws.signing_input, l2.jws.signature, run.user_key)
        run.check(
            "L2.signature",
            None if run.l2_sig_ok else reject(Code.SIGNATURE_INVALID, "L2 not signed by L1 cnf.jwk", "L2"),
        )

    n = len(run.findings)
    nonce = run.require(p, "L2", "nonce", str)
    aud = run.require(p, "L2", "aud", str)
    iat = run.require(p, "L2", "iat", int)
    exp = run.require(p, "L2", "exp", int)
    sd_hash = run.require(p, "L2", "sd_hash", str)
    run.require(p, "L2", "delegate_payload", list)
    run.require(p, "L2", "_sd", list)
    sd_alg = run.require(p, "L2", "_sd_alg", str)
    fs = run.findings[n:]
    del run.findings[n:]
    if sd_alg is not None and sd_alg != "sha-256":
        fs.append(reject(Code.SD_ALG_INVALID, "L2 _sd_alg must be 'sha-256'", "L2"))
    if "iss" in p and not (isinstance(p["iss"], str) and _URI_RE.match(p["iss"])):
        fs.append(reject(Code.CLAIM_TYPE_INVALID, "L2 iss, when present, MUST be a URI", "L2"))
    if h.get("alg") != "ES256":
        fs.append(reject(Code.HEADER_ALG_INVALID, "L2 alg must be ES256", "L2"))
    run.check("L2.claims", fs)

    if "sd_hash" not in p:
        run.check("L2.sd_hash", reject(Code.SD_HASH_MISSING, "L2 has no sd_hash", "L2"))
    elif sd_hash is not None and run.l1 is not None:
        expected = sha256_b64url(run.l1.serialized) if run.l1.serialized else None
        run.check(
            "L2.sd_hash",
            None if sd_hash == expected else reject(Code.SD_HASH_MISMATCH, "L2 sd_hash != hash(L1 as received)", "L2"),
        )
    else:
        run.check("L2.sd_hash", skipped="sd_hash or L1 unavailable")

    _check_replay(run, "L2", "l2", aud, nonce)
    _check_time(run, "L2", iat, exp)

    mandates = _collect_l2_mandates(run, l2)
    _infer_mode(run, mandates)

    fs = []
    if run.mode is not None:
        want = L2_TYP_AUTONOMOUS if run.mode == "autonomous" else L2_TYP_IMMEDIATE
        if h.get("typ") != want:
            fs.append(reject(Code.HEADER_TYP_INVALID, f"L2 typ must be '{want}' in {run.mode} mode", "L2"))
    run.check("L2.typ", fs)

    if iat is not None and exp is not None:
        fs = []
        if run.mode == "immediate" and exp - iat > L2_IMMEDIATE_LIFETIME:
            fs.append(warn(Code.TIME_LIFETIME_SHOULD, "Immediate L2 lifetime exceeds 15 minutes (G-09)", "L2"))
        if run.mode == "autonomous":
            if exp - iat > L2_AUTONOMOUS_LIFETIME:
                fs.append(warn(Code.TIME_LIFETIME_SHOULD, "Autonomous L2 lifetime exceeds 30 days", "L2"))
            l1_exp = run.l1.payload.get("exp") if run.l1 else None
            if isinstance(l1_exp, int) and exp > l1_exp:
                fs.append(reject(Code.TIME_LIFETIME_EXCEEDED, "Autonomous L2 exp exceeds L1 exp (CF §7)", "L2"))
        run.check("L2.lifetime", fs)

    if run.mode == "immediate":
        _verify_immediate_mandates(run, mandates)
    elif run.mode == "autonomous":
        _verify_autonomous_mandates(run, mandates)


def _collect_l2_mandates(run: _Run, l2: ParsedSdJwt) -> list[_Mandate]:
    raw = l2.payload.get("delegate_payload")
    resolved = l2.resolved.get("delegate_payload") if l2.resolved else None
    if not isinstance(raw, list) or not isinstance(resolved, list):
        return []
    fs: list[Finding] = []
    out: list[_Mandate] = []
    for ref, val in zip(raw, resolved, strict=False):
        if not is_undisclosed_ref(ref):
            fs.append(reject(Code.DELEGATE_PAYLOAD_INVALID, "delegate_payload entries must be {'...': digest}", "L2"))
            continue
        if is_undisclosed_ref(val):
            run.l2_has_undisclosed = True
            continue
        vct = val.get("vct") if isinstance(val, dict) else None
        if vct not in OPEN_VCTS | FINAL_VCTS:
            fs.append(reject(Code.VCT_UNKNOWN, f"L2 mandate has unrecognized or malformed vct {vct!r}", "L2"))
            continue
        out.append(_Mandate(val, ref["..."], vct))
    run.check("L2.delegate_payload", fs)
    return out


def _infer_mode(run: _Run, mandates: list[_Mandate]) -> None:
    """CF §4.6: mode is inferred from mandate VCTs."""
    has_open = any(m.vct in OPEN_VCTS for m in mandates)
    has_final = any(m.vct in FINAL_VCTS for m in mandates)
    if has_open and has_final:
        run.check("L2.mode", reject(Code.MODE_MIXED, "L2 mixes open and final mandate VCTs", "L2"))
    elif has_open or has_final:
        run.mode = "autonomous" if has_open else "immediate"
        run.check("L2.mode")
    elif run.l2 is not None and run.l2.header.get("typ") == L2_TYP_AUTONOMOUS:
        run.check(
            "L2.mode",
            reject(Code.MODE_UNDETERMINED, "Autonomous L2 needs at least one disclosed mandate (CF §13.4.11)", "L2"),
        )
    else:
        run.check("L2.mode", gap("G-14", "no L2 mandate disclosed; mode and pairing cannot be checked", "L2"))
    has_l3 = any(k in run.bundle for k in ("l3a", "l3b"))
    if run.mode == "immediate" and has_l3:
        run.check("mode.l3_presence", reject(Code.MODE_L3_IN_IMMEDIATE, "L3 presented with an Immediate L2", "L2"))


def _forbid(fs: list[Finding], obj: dict[str, Any], layer: str, what: str) -> None:
    if "cnf" in obj:
        fs.append(reject(Code.CNF_FORBIDDEN, f"{what} MUST NOT contain cnf", layer))
    if "constraints" in obj:
        fs.append(reject(Code.MANDATE_CONSTRAINTS_FORBIDDEN, f"{what} MUST NOT contain constraints", layer))


def _need(fs: list[Finding], obj: dict[str, Any], layer: str, what: str, fields: dict[str, type]) -> None:
    for name, typ in fields.items():
        if not isinstance(obj.get(name), typ) or isinstance(obj.get(name), bool):
            fs.append(reject(Code.MANDATE_FIELD_MISSING, f"{what} needs '{name}' ({typ.__name__})", layer))


def _check_instrument(fs: list[Finding], obj: dict[str, Any], layer: str, what: str) -> None:
    pi = obj.get("payment_instrument")
    if isinstance(pi, dict):
        _need(fs, pi, layer, f"{what}.payment_instrument", {"type": str, "id": str})


def _check_final_payment(fs: list[Finding], m: dict[str, Any], layer: str) -> None:
    _need(fs, m, layer, "payment mandate", {
        "payment_instrument": dict, "payment_amount": dict, "payee": dict, "transaction_id": str,
    })
    _check_instrument(fs, m, layer, "payment mandate")
    pa = m.get("payment_amount")
    if isinstance(pa, dict):
        amt = pa.get("amount")
        if not isinstance(amt, int) or isinstance(amt, bool) or amt < 0:
            fs.append(reject(Code.L3_AMOUNT_NOT_INTEGER, "payment_amount.amount must be integer minor units", layer))
        if not isinstance(pa.get("currency"), str):
            fs.append(reject(Code.MANDATE_FIELD_MISSING, "payment_amount.currency must be a string", layer))
    payee = m.get("payee")
    if isinstance(payee, dict):
        _need(fs, payee, layer, "payee", {"name": str, "website": str})


def _check_final_checkout(fs: list[Finding], m: dict[str, Any], layer: str) -> None:
    _need(fs, m, layer, "checkout mandate", {"checkout_jwt": str, "checkout_hash": str})
    cj, ch = m.get("checkout_jwt"), m.get("checkout_hash")
    if isinstance(cj, str) and isinstance(ch, str):
        if not cj.isascii() or sha256_b64url(cj) != ch:
            fs.append(reject(Code.CHECKOUT_HASH_MISMATCH, "checkout_hash != B64U(SHA-256(checkout_jwt))", layer))


def _verify_immediate_mandates(run: _Run, mandates: list[_Mandate]) -> None:
    fs: list[Finding] = []
    checkouts = [m for m in mandates if m.vct == VCT_CHECKOUT]
    payments = [m for m in mandates if m.vct == VCT_PAYMENT]
    for m in checkouts:
        _check_final_checkout(fs, m.value, "L2")
        _forbid(fs, m.value, "L2", "Immediate checkout mandate")
    for m in payments:
        _check_final_payment(fs, m.value, "L2")
        _forbid(fs, m.value, "L2", "Immediate payment mandate")
    run.check("L2.mandates", fs)

    # CF §8.2: pair identifier is checkout_hash == transaction_id.
    fs = []
    by_id: dict[str, _Pair] = {}
    for m in checkouts:
        key = m.value.get("checkout_hash")
        if not isinstance(key, str):
            continue
        if key in by_id:
            fs.append(reject(Code.MANDATE_DUPLICATE_PAIR, "two checkout mandates share a pair identifier", "L2"))
            continue
        by_id[key] = _Pair(checkout=m)
    for m in payments:
        key = m.value.get("transaction_id")
        pair = by_id.get(key) if isinstance(key, str) else None
        if pair is None:
            by_id.setdefault(f"payment:{m.digest}", _Pair(payment=m))
        elif pair.payment is not None:
            fs.append(reject(Code.MANDATE_DUPLICATE_PAIR, "two payment mandates share a pair identifier", "L2"))
        else:
            pair.payment = m
    run.pairs = list(by_id.values())
    _check_orphans(run, fs)


def _check_orphans(run: _Run, fs: list[Finding]) -> None:
    for pair in run.pairs:
        if pair.checkout is None or pair.payment is None:
            if run.l2_has_undisclosed:
                continue  # partner may be among the undisclosed mandates (CF §13.4.11)
            fs.append(reject(Code.MANDATE_ORPHAN, "mandate without a matching pair partner", "L2"))
    run.check("L2.pairing", fs)


def _verify_autonomous_mandates(run: _Run, mandates: list[_Mandate]) -> None:
    fs: list[Finding] = []
    for m in mandates:
        v = m.value
        what = "Autonomous checkout mandate" if m.vct == VCT_CHECKOUT_OPEN else "Autonomous payment mandate"
        cs = v.get("constraints")
        if not isinstance(cs, list):
            fs.append(reject(Code.MANDATE_FIELD_MISSING, f"{what} needs a constraints array", "L2"))
        elif not cs:
            fs.append(reject(Code.MANDATE_CONSTRAINTS_EMPTY, f"{what} MUST contain at least one constraint", "L2"))
        cnf = v.get("cnf")
        jwk = cnf.get("jwk") if isinstance(cnf, dict) else None
        if not isinstance(jwk, dict):
            fs.append(reject(Code.CNF_MISSING, f"{what} MUST contain cnf.jwk (agent key)", "L2"))
        elif not isinstance(jwk.get("kid"), str) or not jwk["kid"]:
            fs.append(reject(Code.CNF_KID_MISSING, f"{what} cnf.jwk MUST include kid", "L2"))
        if m.vct == VCT_PAYMENT_OPEN:
            _need(fs, v, "L2", what, {"payment_instrument": dict})
            _check_instrument(fs, v, "L2", what)
            if isinstance(cs, list) and not any(isinstance(c, dict) and c.get("type") == REFERENCE for c in cs):
                fs.append(reject(Code.PAYMENT_REFERENCE_MISSING, f"{what} needs a {REFERENCE} constraint", "L2"))
    run.check("L2.mandates", fs)

    # CF §8.2: pair via mandate.payment.reference.conditional_transaction_id.
    fs = []
    checkouts = {m.digest: _Pair(checkout=m) for m in mandates if m.vct == VCT_CHECKOUT_OPEN}
    loose: list[_Pair] = []
    for m in (m for m in mandates if m.vct == VCT_PAYMENT_OPEN):
        refs = [
            c.get("conditional_transaction_id")
            for c in m.value.get("constraints", []) if isinstance(c, dict) and c.get("type") == REFERENCE
        ] if isinstance(m.value.get("constraints"), list) else []
        pair = next((checkouts[r] for r in refs if r in checkouts), None)
        if pair is None:
            loose.append(_Pair(payment=m, reference_ok=False if not run.l2_has_undisclosed else None))
        elif pair.payment is not None:
            fs.append(reject(Code.MANDATE_DUPLICATE_PAIR, "two payment mandates reference one checkout", "L2"))
        else:
            pair.payment = m
            pair.reference_ok = True
    run.pairs = list(checkouts.values()) + loose
    _check_orphans(run, fs)

    fs = []
    for pair in run.pairs:
        jwks = [m.value.get("cnf", {}).get("jwk") for m in (pair.checkout, pair.payment) if m is not None]
        jwks = [j for j in jwks if isinstance(j, dict)]
        if len(jwks) == 2 and jwks[0] != jwks[1]:
            fs.append(reject(Code.CNF_PAIR_MISMATCH, "checkout and payment cnf.jwk differ", "L2"))
            continue
        if jwks:
            try:
                pair.agent_key = jwk_to_public_key(jwks[0])
                pair.agent_kid = jwks[0].get("kid")
            except ValueError as exc:
                fs.append(reject(Code.JWK_INVALID, f"agent cnf.jwk unusable: {exc}", "L2"))
    run.check("L2.agent_binding", fs)


# ==========================================================================
# L3 — agent credentials (CF §5)
# ==========================================================================


def _verify_l3(run: _Run) -> None:
    present = [k for k in ("l3a", "l3b") if k in run.bundle]
    if run.mode != "autonomous" or run.l2 is None:
        return
    if not present:
        _evaluate_constraints(run, {}, None)
        return

    final: dict[str, dict[str, Any]] = {}
    pair_of: dict[str, _Pair | None] = {}
    for key in present:
        layer = "L3a" if key == "l3a" else "L3b"
        l3 = run.l3[key] = parse_sd_jwt(run.bundle[key], layer)
        if not run.check(f"{layer}.parse", l3.findings) or l3.jws is None:
            continue
        pair = pair_of[key] = _bind_view(run, key, layer, l3)
        _verify_l3_token(run, key, layer, l3, pair)
        mandate = _l3_mandate(run, key, layer, l3)
        if mandate is not None:
            final[key] = mandate

    if pair_of.get("l3a") is not None and pair_of.get("l3b") is not None:
        run.check(
            "L3.same_pair",
            None if pair_of["l3a"] is pair_of["l3b"] else reject(
                Code.L3_VIEW_PAIR_MISMATCH, "L3a and L3b bind different mandate pairs", "L3"
            ),
        )

    if "l3a" in final and "l3b" in final:
        tid, ch = final["l3a"].get("transaction_id"), final["l3b"].get("checkout_hash")
        run.check(
            "L3.cross_reference",
            None if tid == ch else reject(Code.L3_CROSS_REF_MISMATCH, "L3a.transaction_id != L3b.checkout_hash", "L3"),
        )
    else:
        run.check("L3.cross_reference", skipped="needs both L3a and L3b")

    pair = pair_of.get("l3a") or pair_of.get("l3b")
    if "l3a" in final and pair is not None and pair.payment is not None:
        l2_pi = pair.payment.value.get("payment_instrument")
        l3_pi = final["l3a"].get("payment_instrument")
        run.check(
            "L3a.payment_instrument",
            None if l2_pi == l3_pi else gap(
                "G-12", "L3a payment_instrument differs from L2; the spec defines no binding rule", "L3a"
            ),
        )
    _evaluate_constraints(run, final, pair)


def _bind_view(run: _Run, key: str, layer: str, l3: ParsedSdJwt) -> _Pair | None:
    """Locate the L2 presentation this L3 binds to (CF §5.4) and its mandate pair."""
    view_key = f"l2_view_{key}"
    if view_key in run.bundle:
        view = parse_sd_jwt(run.bundle[view_key], f"L2_view_{key}")
        run.check(f"{layer}.view_parse", view.findings)
    else:
        view = run.l2
        run.add(warn(Code.L3_VIEW_FALLBACK, f"no {view_key}; using the full L2 presentation", layer))
    assert run.l2 is not None
    fs: list[Finding] = []
    if view.jws is None or view.base_jwt != run.l2.base_jwt:
        fs.append(reject(Code.L3_VIEW_BASE_MISMATCH, "L2 view is not built on the presented L2 JWT", layer))
    # A recipient's view may carry disclosures the bundle's L2 presentation withholds,
    # but each must be committed to by the signed L2 JWT (VI lists every digest in _sd).
    sd = run.l2.payload.get("_sd")
    committed = {d.digest for d in run.l2.disclosures}
    if isinstance(sd, list):
        committed |= {x for x in sd if isinstance(x, str)}
    if any(d.digest not in committed for d in view.disclosures):
        fs.append(reject(Code.L3_VIEW_FOREIGN_DISCLOSURE, "L2 view carries disclosures L2 does not commit to", layer))
    sd_hash = l3.payload.get("sd_hash")
    if not isinstance(sd_hash, str):
        fs.append(reject(Code.SD_HASH_MISSING, f"{layer} has no sd_hash", layer))
    elif sd_hash != sha256_b64url(view.serialized):
        fs.append(reject(Code.SD_HASH_MISMATCH, f"{layer} sd_hash != hash(L2 selective presentation)", layer))
    run.check(f"{layer}.sd_hash", fs)

    side = "payment" if key == "l3a" else "checkout"
    view_digests = {d.digest for d in view.disclosures}
    candidates = [p for p in run.pairs if getattr(p, side) is not None and getattr(p, side).digest in view_digests]
    if len(candidates) == 1:
        run.check(f"{layer}.pair")
        return candidates[0]
    if not candidates:
        run.check(f"{layer}.pair", reject(Code.L3_VIEW_NO_MANDATE, f"L2 view has no {side} mandate", layer))
    else:
        run.check(f"{layer}.pair", gap("G-07", f"L2 view matches {len(candidates)} mandate pairs", layer))
    return None


def _verify_l3_token(run: _Run, key: str, layer: str, l3: ParsedSdJwt, pair: _Pair | None) -> None:
    h, p = l3.header, l3.payload
    fs: list[Finding] = []
    if h.get("alg") != "ES256":
        fs.append(reject(Code.HEADER_ALG_INVALID, f"{layer} alg must be ES256", layer))
    if h.get("typ") != L3_TYP:
        fs.append(reject(Code.HEADER_TYP_INVALID, f"{layer} typ must be '{L3_TYP}'", layer))
    if "jwk" in h:
        fs.append(reject(Code.HEADER_JWK_FORBIDDEN, f"{layer} header MUST NOT carry jwk (CF §13.3)", layer))
    kid = h.get("kid")
    if not isinstance(kid, str) or not kid:
        fs.append(reject(Code.HEADER_KID_MISSING, f"{layer} header must carry kid", layer))
    run.check(f"{layer}.header", fs)

    if pair is None or pair.agent_key is None:
        run.check(f"{layer}.key_binding", skipped="no agent key for this L3")
        run.check(f"{layer}.signature", skipped="no agent key for this L3")
    elif kid != pair.agent_kid:
        run.check(f"{layer}.key_binding", reject(Code.L3_KID_MISMATCH, f"{layer} kid != L2 cnf.jwk.kid", layer))
        run.check(f"{layer}.signature", skipped="kid does not resolve to the L2 agent key")
    else:
        run.check(f"{layer}.key_binding")
        ok = es256_verify(l3.jws.signing_input, l3.jws.signature, pair.agent_key)
        run.check(
            f"{layer}.signature",
            None if ok else reject(Code.SIGNATURE_INVALID, f"{layer} not signed by L2 cnf.jwk", layer),
        )

    n = len(run.findings)
    nonce = run.require(p, layer, "nonce", str)
    aud = run.require(p, layer, "aud", str)
    iat = run.require(p, layer, "iat", int)
    exp = run.require(p, layer, "exp", int)
    run.require(p, layer, "delegate_payload", list)
    run.require(p, layer, "_sd", list)
    sd_alg = run.require(p, layer, "_sd_alg", str)
    fs = run.findings[n:]
    del run.findings[n:]
    if sd_alg is not None and sd_alg != "sha-256":
        fs.append(reject(Code.SD_ALG_INVALID, f"{layer} _sd_alg must be 'sha-256'", layer))
    if l3.resolved is not None and "cnf" in l3.resolved:
        fs.append(reject(Code.CNF_FORBIDDEN, f"{layer} payload MUST NOT contain cnf", layer))
    l2_nonce = run.l2.payload.get("nonce") if run.l2 else None
    if nonce is not None and nonce == l2_nonce:
        fs.append(reject(Code.NONCE_REUSED, f"{layer} nonce MUST differ from the L2 nonce", layer))
    run.check(f"{layer}.claims", fs)

    _check_replay(run, layer, key, aud, nonce)
    _check_time(run, layer, iat, exp)
    if iat is not None and exp is not None and exp - iat > L3_MAX_LIFETIME:
        run.check(f"{layer}.lifetime", reject(Code.TIME_LIFETIME_EXCEEDED, f"{layer} lifetime > 1 hour", layer))


def _l3_mandate(run: _Run, key: str, layer: str, l3: ParsedSdJwt) -> dict[str, Any] | None:
    want = VCT_PAYMENT if key == "l3a" else VCT_CHECKOUT
    entries = (l3.resolved or {}).get("delegate_payload")
    fs: list[Finding] = []
    found: list[dict[str, Any]] = []
    for e in entries if isinstance(entries, list) else []:
        if not isinstance(e, dict) or is_undisclosed_ref(e) or "vct" not in e:
            continue  # e.g. the selected merchant object in L3a (CF §11.2)
        if e["vct"] == want:
            found.append(e)
        else:
            fs.append(reject(Code.VCT_UNKNOWN, f"{layer} carries unexpected mandate vct {e['vct']!r}", layer))
    if len(found) != 1:
        fs.append(reject(Code.L3_MANDATE_MISSING, f"{layer} must disclose exactly one {want} mandate", layer))
        run.check(f"{layer}.mandate", fs)
        return None
    m = found[0]
    (_check_final_payment if key == "l3a" else _check_final_checkout)(fs, m, layer)
    _forbid(fs, m, layer, f"{layer} mandate")
    run.check(f"{layer}.mandate", fs)
    return m


# ==========================================================================
# shared helpers
# ==========================================================================


def _check_time(run: _Run, layer: str, iat: int | None, exp: int | None) -> None:
    fs: list[Finding] = []
    if exp is not None and run.now > exp + run.skew:
        fs.append(reject(Code.TIME_EXPIRED, f"{layer} expired at {exp}", layer))
    if iat is not None and iat > run.now + run.skew:
        fs.append(reject(Code.TIME_IAT_FUTURE, f"{layer} iat {iat} is in the future", layer))
    run.check(f"{layer}.time", fs)


def _check_replay(run: _Run, layer: str, prefix: str, aud: Any, nonce: Any) -> None:
    fs: list[Finding] = []
    for claim, actual, mismatch, unchecked in (
        ("aud", aud, Code.AUD_MISMATCH, Code.AUD_NOT_CHECKED),
        ("nonce", nonce, Code.NONCE_MISMATCH, Code.NONCE_NOT_CHECKED),
    ):
        want = _expected(run, f"{prefix}_{claim}")
        if want is None:
            fs.append(warn(unchecked, f"{layer} {claim} not checked (no expected value supplied)", layer))
        elif actual != want:
            fs.append(reject(mismatch, f"{layer} {claim} does not match the expected value", layer))
    run.check(f"{layer}.replay_context", fs)


def _merchant_from_checkout_jwt(run: _Run, checkout_jwt: Any) -> tuple[dict[str, Any] | None, list[Finding]]:
    """Fulfillment ``merchant`` from the checkout_jwt payload (C §2.4, CF §6.3)."""
    fs = [warn(Code.CHECKOUT_JWT_SIGNATURE_NOT_VERIFIED, "checkout_jwt signature not verified (CF §6.3 SHOULD)")]
    try:
        payload = strict_json_loads(b64url_decode(checkout_jwt.split(".")[1]))
    except (AttributeError, IndexError, ValueError, UnicodeDecodeError):
        fs.append(warn(Code.CHECKOUT_JWT_UNDECODABLE, "checkout_jwt payload could not be decoded"))
        return None, fs
    node: Any = payload
    for token in [t for t in run.merchant_pointer.split("/")[1:]]:
        token = token.replace("~1", "/").replace("~0", "~")
        node = node.get(token) if isinstance(node, dict) else None
    if not isinstance(node, dict) or not isinstance(node.get("id"), str) or not node["id"]:
        return None, fs
    return {k: node[k] for k in ("id", "name", "website") if k in node}, fs


def _evaluate_constraints(run: _Run, final: dict[str, dict[str, Any]], bound: _Pair | None) -> None:
    if run.mode != "autonomous":
        return
    ns_raw = run.bundle.get("network_state") or {}
    state = NetworkState(ns_raw.get("cumulative_spent"), ns_raw.get("occurrence_count"))
    for pair in run.pairs:
        ful: Fulfillment | None = None
        if pair is bound and final:
            ful = Fulfillment(has_checkout="l3b" in final, has_payment="l3a" in final)
            if "l3b" in final:
                ful.line_items = final["l3b"].get("line_items")
                ful.merchant, notes = _merchant_from_checkout_jwt(run, final["l3b"].get("checkout_jwt"))
                run.add(*notes)
            if "l3a" in final:
                ful.payee = final["l3a"].get("payee")
                ful.payment_instrument = final["l3a"].get("payment_instrument")
                ful.payment_amount = final["l3a"].get("payment_amount")
        for side, m in (("checkout", pair.checkout), ("payment", pair.payment)):
            if m is None or not isinstance(m.value.get("constraints"), list):
                continue
            results = check_constraints(
                m.value["constraints"],
                ful,
                strictness=run.strictness,
                is_open_mandate=m.vct in OPEN_VCTS,
                mandate=side,
                policy=run.policy,
                network_state=state,
                now=run.now,
                reference_ok=pair.reference_ok if side == "payment" else None,
            )
            run.constraint_results.extend(results)
            for r in results:
                run.add(*r.findings)


def _finish(run: _Run) -> Verdict:
    chain_layers = {"L2", "L3", "L3a", "L3b", "L2_view_l3a", "L2_view_l3b"}
    rejects = [f for f in run.findings if f.effect == "reject"]
    identity_ok = (
        run.l1 is not None
        and run.l1.jws is not None
        and not any(f.layer == "L1" for f in rejects)
        and any(c.id == "L1.signature" and c.status == "pass" for c in run.checks)
    )
    chain_ok = run.l2_sig_ok and not any(f.layer in chain_layers for f in rejects)
    if rejects:
        verdict = "reject"
    elif any(f.effect == "indeterminate" for f in run.findings):
        verdict = "indeterminate"
    else:
        verdict = "accept"
    return Verdict(
        verdict=verdict,
        mode=run.mode,
        strictness=run.strictness,
        evaluated_at=run.now,
        identity_ok=identity_ok,
        delegation_chain_ok=chain_ok,
        constraints=run.constraint_results,
        findings=run.findings,
        checks=run.checks,
    )


def verdict_json(v: Verdict) -> str:
    return json.dumps(v.to_json(), indent=2, sort_keys=False, ensure_ascii=False)
