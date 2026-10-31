"""TAP + AP2 composition: one presentation carrying a TAP-signed request and AP2 mandates.

Neither TAP nor AP2 defines how the two bind, so the binding rule is KYA
Bench's (docs/spec-gaps.md XP-02):

- presenter = the registry agent that owns the TAP signing ``keyid``;
- mandate agent = the registry agent owning a key equal to the AP2 agent key
  (``cnf.jwk`` of the open mandates, or of the closed mandate in a
  human-present flow);
- same agent -> bound; different agents -> ``XPROTO_PRESENTER_MISMATCH``;
  an AP2 agent key that no registry entry holds -> spec gap (indeterminate).

Fixed outcomes (Phase 2 brief): bound -> accept; mismatch -> reject; AP2 alone
-> accept with warning ``XPROTO_IDENTITY_LAYER_ABSENT``; TAP alone follows the
TAP verdict. Component verdicts still apply: any TAP or AP2 rejection rejects
the composition.
"""

from __future__ import annotations

import json
import time
from enum import StrEnum
from typing import Any

from cryptography.hazmat.primitives.asymmetric import ec

from ..ap2.verifier import verify_ap2
from ..constraints import Strictness
from ..context import Fixtures
from ..keys import jwk_to_public_key
from ..reasons import Finding, gap, reject, warn
from ..tap.verifier import load_registry_key, verify_tap
from ..verifier import Check, Verdict


class XCode(StrEnum):
    XPROTO_BUNDLE_INVALID = "XPROTO_BUNDLE_INVALID"
    XPROTO_PRESENTER_MISMATCH = "XPROTO_PRESENTER_MISMATCH"
    XPROTO_IDENTITY_LAYER_ABSENT = "XPROTO_IDENTITY_LAYER_ABSENT"
    XPROTO_MANDATE_AGENT_INCONSISTENT = "XPROTO_MANDATE_AGENT_INCONSISTENT"


def _same_ec_key(jwk: dict[str, Any], pub: Any) -> bool:
    try:
        a = jwk_to_public_key(jwk).public_numbers()
    except ValueError:
        return False
    return isinstance(pub, ec.EllipticCurvePublicKey) and pub.public_numbers() == a


def _agents_holding(jwk: dict[str, Any], registry: dict[str, Any]) -> list[dict[str, Any]]:
    out = []
    for agent in registry.get("agents", []):
        for k in agent.get("keys", []) if isinstance(agent, dict) else []:
            try:
                pub = load_registry_key(k)
            except (ValueError, TypeError):
                continue
            if _same_ec_key(jwk, pub):
                out.append(agent)
                break
    return out


def verify_composition(presentation: Any, *, fixtures: Fixtures, now: int | None = None) -> Verdict:
    now = int(time.time()) if now is None else now
    if isinstance(presentation, str):
        try:
            presentation = json.loads(presentation)
        except ValueError:
            presentation = None
    findings: list[Finding] = []
    checks: list[Check] = []
    if not isinstance(presentation, dict) or not ({"tap", "ap2"} & set(presentation)):
        f = reject(XCode.XPROTO_BUNDLE_INVALID, "presentation needs a 'tap' and/or an 'ap2' part", "composition")
        return _verdict(None, None, [f], [Check("composition.shape", "fail", f.message)], {}, now)
    tap = verify_tap(presentation["tap"], fixtures=fixtures, now=now) if "tap" in presentation else None
    ap2 = verify_ap2(presentation["ap2"], fixtures=fixtures, now=now) if "ap2" in presentation else None
    for part in (tap, ap2):
        if part:
            findings += part.findings
            checks += [Check(f"{part.protocol}.{c.id}", c.status, c.detail) for c in part.checks]
    cross: dict[str, bool | None] = {"tap_present": tap is not None, "ap2_present": ap2 is not None,
                                     "presenter_matches_mandate_agent": None}
    if tap is None:
        f = warn(XCode.XPROTO_IDENTITY_LAYER_ABSENT,
                 "no TAP identity layer: AP2 alone is a valid flow, presenter identity is not established",
                 "composition")
        findings.append(f)
        checks.append(Check("composition.binding", "skipped", f.message))
    elif ap2 is not None:
        fs = _binding(tap, ap2, fixtures, cross)
        findings += fs
        checks.append(Check("composition.binding", "fail" if any(x.effect == "reject" for x in fs) else
                            "pass" if not fs else "skipped", "; ".join(x.message for x in fs)))
    return _verdict(tap, ap2, findings, checks, cross, now)


def _binding(tap: Verdict, ap2: Verdict, fx: Fixtures, cross: dict[str, bool | None]) -> list[Finding]:
    L = "composition"
    presenters = {r.get("agent_id") for r in tap.details.get("requests", []) if r.get("agent_id") is not None}
    if len(presenters) != 1:
        return [gap("XP-01", "TAP presenter agent could not be identified from the registry", L)]
    presenter = presenters.pop()
    jwks = [j for j in ap2.details.get("agent_jwk", {}).values() if isinstance(j, dict)]
    if not jwks:
        return [gap("XP-01", "AP2 mandates name no agent key (human-present closed mandates without cnf); "
                             "nothing to bind the TAP presenter to", L)]
    if any(j != jwks[0] for j in jwks[1:]):
        return [reject(XCode.XPROTO_MANDATE_AGENT_INCONSISTENT,
                       "checkout and payment mandates delegate to different agent keys", L)]
    holders = _agents_holding(jwks[0], fx.tap_registry)
    if not holders:
        return [gap("XP-02", "the AP2 agent key is not in the TAP registry; TAP and AP2 define no "
                             "normative binding between their agent identities", L)]
    same = any(a.get("id") == presenter for a in holders)
    cross["presenter_matches_mandate_agent"] = same
    if not same:
        return [reject(XCode.XPROTO_PRESENTER_MISMATCH,
                       f"TAP presenter (agent {presenter}) is not the agent the AP2 mandates delegate to "
                       f"(agent {holders[0].get('id')})", L)]
    return []


def _verdict(tap: Verdict | None, ap2: Verdict | None, findings: list[Finding], checks: list[Check],
             cross: dict[str, bool | None], now: int) -> Verdict:
    verdict = "reject" if any(f.effect == "reject" for f in findings) else \
        "indeterminate" if any(f.effect == "indeterminate" for f in findings) else "accept"
    return Verdict(
        verdict=verdict,
        mode=ap2.mode if ap2 else None,
        strictness=Strictness.STRICT,
        evaluated_at=now,
        identity_ok=bool(tap and tap.identity_ok),
        delegation_chain_ok=bool(ap2.delegation_chain_ok) if ap2 else bool(tap and tap.delegation_chain_ok),
        constraints=ap2.constraints if ap2 else [],
        findings=findings,
        checks=checks,
        protocol="composition",
        cross_ref_map=cross,
        details={"tap": tap.details if tap else None, "ap2": ap2.details if ap2 else None},
    )
