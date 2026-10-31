"""Offline trust fixtures shared by all protocol verifiers.

- ``jwks``: issuer JWKS documents keyed by issuer URI (VI L1 issuers, AP2
  root/trust-list keys, the mock TAP ID-token issuer). Stand-in for each
  party's JWKS endpoint.
- ``tap_registry``: the TAP agent registry (stand-in for the Visa-operated
  directory; shape follows the reference agent-registry service).

``Fixtures.from_jwks_path(p)`` loads ``p`` and, when present, the sibling
``tap_registry.json`` — so ``--jwks fixtures/jwks.json`` is all the CLI needs.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .keys import KeyResolver, LocalJwksResolver

TAP_REGISTRY_FILE = "tap_registry.json"


@dataclass
class Fixtures:
    jwks: KeyResolver
    jwks_doc: dict[str, Any] = field(default_factory=dict)
    tap_registry: dict[str, Any] = field(default_factory=lambda: {"agents": []})

    @classmethod
    def from_jwks_path(cls, path: str | Path) -> Fixtures:
        path = Path(path)
        doc = json.loads(path.read_text(encoding="utf-8"))
        reg_path = path.parent / TAP_REGISTRY_FILE
        registry = json.loads(reg_path.read_text(encoding="utf-8")) if reg_path.exists() else {"agents": []}
        return cls(LocalJwksResolver(doc), doc, registry)

    @classmethod
    def coerce(cls, value: Fixtures | KeyResolver) -> Fixtures:
        if isinstance(value, Fixtures):
            return value
        doc = getattr(value, "_jwks", {})
        return cls(value, doc if isinstance(doc, dict) else {})

    def jwk_by_kid(self, kid: str) -> list[tuple[str, dict[str, Any]]]:
        """All (issuer, JWK) pairs whose kid matches, across every issuer JWKS."""
        out = []
        for iss, jwks in self.jwks_doc.items():
            keys = jwks.get("keys") if isinstance(jwks, dict) else None
            for k in keys if isinstance(keys, list) else []:
                if isinstance(k, dict) and k.get("kid") == kid:
                    out.append((iss, k))
        return out
