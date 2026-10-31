from __future__ import annotations

import pytest

from kya_bench import LocalJwksResolver, verify
from kya_bench.testing.builder import NOW, Spec, build, jwks_fixture


@pytest.fixture(scope="session")
def resolver() -> LocalJwksResolver:
    return LocalJwksResolver(jwks_fixture())


@pytest.fixture
def run(resolver):
    """Build (if given a Spec) and verify; returns the Verdict."""

    def _run(spec_or_bundle, strictness: str = "strict", now: int = NOW, **kw):
        bundle = build(spec_or_bundle) if isinstance(spec_or_bundle, Spec) else spec_or_bundle
        return verify(bundle, strictness=strictness, resolver=resolver, now=now, **kw)

    return _run


def constraint(verdict, ctype: str):
    matches = [c for c in verdict.constraints if c.type == ctype]
    assert len(matches) == 1, f"expected one {ctype}, got {len(matches)}"
    return matches[0]
