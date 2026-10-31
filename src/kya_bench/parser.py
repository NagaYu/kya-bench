"""SD-JWT / JWS parsing into structured artifacts.

Parsing never raises on malformed input. Each function returns the structure
it could recover plus a list of ``Finding`` objects with reason codes.

Serialization handled here (RFC 9901 §4, as used by VI credential-format §6.1):

    <header>.<payload>.<signature>~<disclosure>~<disclosure>~...~

Selective-disclosure resolution follows the VI convention: a disclosure is
covered when its digest appears in an object's ``_sd`` array and/or in an
array-element reference ``{"...": <digest>}``, and a digest may be referenced
more than once. VI lists each mandate digest in both ``_sd`` and
``delegate_payload`` (credential-format §11) and the reference implementation
shares merchant disclosures between allowlists; RFC 9901 §7.1 would reject
both. See docs/spec-gaps.md (G-01).
"""

from __future__ import annotations

import base64
import binascii
import hashlib
import json
import re
from dataclasses import dataclass, field
from typing import Any

from .reasons import Code, Finding, reject

_B64URL_RE = re.compile(r"^[A-Za-z0-9_-]*$")


# --------------------------------------------------------------------------
# encoding helpers
# --------------------------------------------------------------------------


def b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def b64url_decode(s: str) -> bytes:
    """Strict unpadded base64url decode (RFC 4648 §5). Raises ValueError."""
    if not isinstance(s, str) or not _B64URL_RE.match(s) or len(s) % 4 == 1:
        raise ValueError("not unpadded base64url")
    try:
        return base64.urlsafe_b64decode(s + "=" * (-len(s) % 4))
    except (binascii.Error, ValueError) as exc:  # pragma: no cover - guarded by regex
        raise ValueError(str(exc)) from exc


def sha256_b64url(text: str) -> str:
    """``B64U(SHA-256(ASCII(text)))`` — the hash used by sd_hash, disclosure digests, checkout_hash."""
    return b64url_encode(hashlib.sha256(text.encode("ascii")).digest())


class _DuplicateKey(ValueError):
    pass


def _no_duplicates(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in pairs:
        if k in out:
            raise _DuplicateKey(k)
        out[k] = v
    return out


def strict_json_loads(raw: bytes) -> Any:
    """UTF-8 JSON decode rejecting duplicate member names. Raises ValueError."""
    return json.loads(raw.decode("utf-8"), object_pairs_hook=_no_duplicates)


# --------------------------------------------------------------------------
# data model
# --------------------------------------------------------------------------


@dataclass(frozen=True)
class Jws:
    """A compact-serialized JWS, keeping the exact received segments."""

    raw: str
    header_b64: str
    payload_b64: str
    signature: bytes
    header: dict[str, Any]
    payload: dict[str, Any]

    @property
    def signing_input(self) -> bytes:
        return f"{self.header_b64}.{self.payload_b64}".encode("ascii")


@dataclass(frozen=True)
class Disclosure:
    raw: str
    digest: str
    salt: str
    name: str | None  # None for array-element disclosures
    value: Any

    @property
    def is_array_element(self) -> bool:
        return self.name is None


@dataclass
class ParsedSdJwt:
    layer: str
    serialized: str
    jws: Jws | None = None
    disclosures: list[Disclosure] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)
    resolved: dict[str, Any] | None = None

    @property
    def ok(self) -> bool:
        return self.jws is not None and not any(f.effect == "reject" for f in self.findings)

    @property
    def base_jwt(self) -> str | None:
        return self.jws.raw if self.jws else None

    @property
    def header(self) -> dict[str, Any]:
        return self.jws.header if self.jws else {}

    @property
    def payload(self) -> dict[str, Any]:
        return self.jws.payload if self.jws else {}

    def disclosure_by_digest(self) -> dict[str, Disclosure]:
        return {d.digest: d for d in self.disclosures}

    def to_json(self) -> dict[str, Any]:
        return {
            "header": self.header,
            "payload": self.payload,
            "disclosures": [
                {"digest": d.digest, "name": d.name, "value": d.value} for d in self.disclosures
            ],
        }


def is_undisclosed_ref(value: Any) -> bool:
    """True for an array-element reference that the presenter did not disclose."""
    return isinstance(value, dict) and set(value) == {"..."} and isinstance(value["..."], str)


# --------------------------------------------------------------------------
# parsing
# --------------------------------------------------------------------------


def parse_jws(token: Any, layer: str) -> tuple[Jws | None, list[Finding]]:
    if not isinstance(token, str) or not token.isascii():
        return None, [reject(Code.SDJWT_NOT_ASCII, "JWS must be an ASCII string", layer)]
    parts = token.split(".")
    if len(parts) != 3:
        return None, [reject(Code.JWT_SEGMENT_COUNT, f"JWS must have 3 segments, got {len(parts)}", layer)]
    h_b64, p_b64, s_b64 = parts
    try:
        h_raw, p_raw, sig = b64url_decode(h_b64), b64url_decode(p_b64), b64url_decode(s_b64)
    except ValueError:
        return None, [reject(Code.JWT_BASE64, "JWS segment is not unpadded base64url", layer)]
    decoded: list[dict[str, Any]] = []
    for label, raw in (("header", h_raw), ("payload", p_raw)):
        try:
            obj = strict_json_loads(raw)
        except _DuplicateKey as exc:
            return None, [reject(Code.JWT_DUPLICATE_KEY, f"JWS {label} has duplicate member {exc}", layer)]
        except (ValueError, UnicodeDecodeError):
            return None, [reject(Code.JWT_JSON, f"JWS {label} is not valid JSON", layer)]
        if not isinstance(obj, dict):
            return None, [reject(Code.JWT_NOT_OBJECT, f"JWS {label} must be a JSON object", layer)]
        decoded.append(obj)
    return Jws(token, h_b64, p_b64, sig, decoded[0], decoded[1]), []


def parse_disclosure(raw: str, layer: str) -> tuple[Disclosure | None, list[Finding]]:
    try:
        arr = strict_json_loads(b64url_decode(raw))
    except _DuplicateKey:
        return None, [reject(Code.DISCLOSURE_JSON, "disclosure has duplicate member names", layer)]
    except ValueError as exc:
        code = Code.DISCLOSURE_JSON if "base64url" not in str(exc) else Code.DISCLOSURE_BASE64
        return None, [reject(code, "disclosure is not base64url-encoded JSON", layer)]
    except UnicodeDecodeError:
        return None, [reject(Code.DISCLOSURE_JSON, "disclosure is not UTF-8 JSON", layer)]
    if not isinstance(arr, list) or len(arr) not in (2, 3) or not isinstance(arr[0], str):
        return None, [reject(Code.DISCLOSURE_SHAPE, "disclosure must be [salt, value] or [salt, name, value]", layer)]
    name = None
    if len(arr) == 3:
        name = arr[1]
        if not isinstance(name, str) or name in ("_sd", "..."):
            return None, [reject(Code.DISCLOSURE_SHAPE, "disclosure claim name invalid", layer)]
    return Disclosure(raw, sha256_b64url(raw), arr[0], name, arr[-1]), []


def parse_sd_jwt(serialized: Any, layer: str) -> ParsedSdJwt:
    """Parse ``<jwt>~<d1>~...~`` and resolve its disclosures into ``resolved``."""
    out = ParsedSdJwt(layer=layer, serialized=serialized if isinstance(serialized, str) else "")
    if not isinstance(serialized, str) or not serialized.isascii():
        out.findings.append(reject(Code.SDJWT_NOT_ASCII, "SD-JWT must be an ASCII string", layer))
        return out
    if not serialized.endswith("~"):
        out.findings.append(
            reject(Code.SDJWT_NO_TRAILING_TILDE, "SD-JWT must end with '~' (no appended KB-JWT in VI)", layer)
        )
        return out
    segments = serialized[:-1].split("~")
    jws, findings = parse_jws(segments[0], layer)
    out.findings.extend(findings)
    if jws is None:
        return out
    out.jws = jws
    seen: set[str] = set()
    for raw in segments[1:]:
        if raw == "":
            out.findings.append(reject(Code.SDJWT_EMPTY_DISCLOSURE, "empty disclosure segment", layer))
            continue
        disc, dfind = parse_disclosure(raw, layer)
        out.findings.extend(dfind)
        if disc is None:
            continue
        if disc.digest in seen:
            out.findings.append(reject(Code.DISCLOSURE_DUPLICATE, "same disclosure presented twice", layer))
            continue
        seen.add(disc.digest)
        out.disclosures.append(disc)
    resolved, rfind = resolve_disclosures(jws.payload, out.disclosures, layer)
    out.findings.extend(rfind)
    out.resolved = resolved
    return out


# --------------------------------------------------------------------------
# selective-disclosure resolution
# --------------------------------------------------------------------------


def resolve_disclosures(
    payload: dict[str, Any], disclosures: list[Disclosure], layer: str
) -> tuple[dict[str, Any], list[Finding]]:
    by_digest = {d.digest: d for d in disclosures}
    sd_listed: set[str] = set()
    array_refs: set[str] = set()
    findings: list[Finding] = []

    def walk(node: Any) -> Any:
        if isinstance(node, list):
            items = []
            for el in node:
                if is_undisclosed_ref(el):
                    digest = el["..."]
                    array_refs.add(digest)
                    disc = by_digest.get(digest)
                    if disc is None:
                        items.append(el)  # undisclosed: keep the reference
                    elif not disc.is_array_element:
                        findings.append(
                            reject(Code.DISCLOSURE_SHAPE, "array reference points at a property disclosure", layer)
                        )
                        items.append(el)
                    else:
                        items.append(walk(disc.value))
                else:
                    items.append(walk(el))
            return items
        if isinstance(node, dict):
            obj: dict[str, Any] = {}
            sd = node.get("_sd")
            for key, val in node.items():
                if key == "_sd" or (key == "_sd_alg" and node is not payload):
                    continue
                obj[key] = walk(val)
            if sd is not None:
                if not isinstance(sd, list) or not all(isinstance(x, str) for x in sd):
                    findings.append(reject(Code.CLAIM_TYPE_INVALID, "_sd must be an array of strings", layer))
                    return obj
                for digest in sd:
                    sd_listed.add(digest)
                    disc = by_digest.get(digest)
                    if disc is None or disc.is_array_element:
                        # Undisclosed, or a VI-style listing of an array-element disclosure.
                        continue
                    if disc.name in obj:
                        findings.append(
                            reject(Code.SD_CLAIM_CONFLICT, f"disclosed claim '{disc.name}' already present", layer)
                        )
                        continue
                    obj[disc.name] = walk(disc.value)
            return obj
        return node

    resolved = walk(payload)
    for d in disclosures:
        if d.digest not in sd_listed and d.digest not in array_refs:
            findings.append(
                reject(Code.DISCLOSURE_UNREFERENCED, "disclosure not referenced by any digest", layer, digest=d.digest)
            )
    return resolved, findings
