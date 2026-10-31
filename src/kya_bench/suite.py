"""Conformance suite: vector format, evaluation and the run-suite report.

Vector format v2 (``kya-bench-vector/2``) — one JSON object per ``<id>.json``::

    {id, protocol, kind, category, description, spec_ref, strictness, now,
     <payload>, expected_verdict, expected_reason_codes}

``protocol`` is one of ``vi`` / ``tap`` / ``ap2`` / ``composition`` /
``translation``. ``kind`` names the payload field and how it is evaluated:

=================== =================== =========================================
kind                payload field       evaluated by
=================== =================== =========================================
``bundle``          ``bundle``          the protocol's verifier (VI / TAP / AP2)
``constraint_check`` ``constraint_check`` the VI constraint engine, called directly
``composition``     ``presentation``    TAP + AP2 cross-protocol binding
``translation``     ``translation``     AP2 -> VI translation equivalence
=================== =================== =========================================

Matching. Default (subset): the verdict equals ``expected_verdict`` and every
code in ``expected_reason_codes`` appears among the findings (reasons and
warnings). ``strict_codes``: additionally, no finding code outside
``expected_reason_codes`` may appear. An expected ``indeterminate`` that comes
back ``indeterminate`` is a match (the suite's xfail on a spec gap).
"""

from __future__ import annotations

import json
from collections import Counter
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from .constraints import Fulfillment, NetworkState, check_constraints
from .context import Fixtures
from .keys import KeyResolver
from .reasons import Finding
from .verifier import verify

FORMAT = "kya-bench-vector/2"
COMMON_FIELDS = ("id", "protocol", "kind", "category", "description", "spec_ref", "strictness", "now")
TAIL_FIELDS = ("expected_verdict", "expected_reason_codes")
PAYLOAD_FIELD = {
    "bundle": "bundle",
    "constraint_check": "constraint_check",
    "composition": "presentation",
    "translation": "translation",
}
PROTOCOLS = ("vi", "tap", "ap2", "composition", "translation")
VERDICTS = ("accept", "reject", "indeterminate")
MANIFEST = "manifest.json"


def vector_fields(kind: str) -> tuple[str, ...]:
    return (*COMMON_FIELDS, PAYLOAD_FIELD[kind], *TAIL_FIELDS)


@dataclass
class VectorResult:
    id: str
    category: str
    expected_verdict: str
    verdict: str | None
    expected_codes: list[str]
    codes: list[str] = field(default_factory=list)
    gap_ids: list[str] = field(default_factory=list)
    undecided_codes: list[str] = field(default_factory=list)  # indeterminate findings without a gap id
    error: str | None = None
    protocol: str = "?"
    strict_codes: bool = False

    @property
    def missing_codes(self) -> list[str]:
        return [c for c in self.expected_codes if c not in self.codes]

    @property
    def unexpected_codes(self) -> list[str]:
        return [c for c in self.codes if c not in self.expected_codes] if self.strict_codes else []

    @property
    def match(self) -> bool:
        return (
            self.error is None
            and self.verdict == self.expected_verdict
            and not self.missing_codes
            and not self.unexpected_codes
        )

    def to_json(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "protocol": self.protocol,
            "category": self.category,
            "match": self.match,
            "expected_verdict": self.expected_verdict,
            "verdict": self.verdict,
            "missing_codes": self.missing_codes,
            "unexpected_codes": self.unexpected_codes,
            "gap_ids": self.gap_ids,
            "error": self.error,
        }


def _verdict_of(findings: list[Finding]) -> str:
    if any(f.effect == "reject" for f in findings):
        return "reject"
    if any(f.effect == "indeterminate" for f in findings):
        return "indeterminate"
    return "accept"


def run_constraint_check(spec: dict[str, Any], strictness: str, now: int | None) -> tuple[str, list[Finding]]:
    """Evaluate a ``constraint_check`` vector directly against the constraint engine."""
    ful_raw = spec.get("fulfillment")
    ful = Fulfillment(**ful_raw) if isinstance(ful_raw, dict) else None
    ns = spec.get("network_state")
    results = check_constraints(
        spec.get("constraints"),
        ful,
        strictness=strictness,
        is_open_mandate=bool(spec.get("is_open_mandate")),
        mandate=spec.get("mandate"),
        network_state=NetworkState(**ns) if isinstance(ns, dict) else None,
        now=now,
    )
    findings = [f for r in results for f in r.findings]
    return _verdict_of(findings), findings


def validate_vector(vector: Any) -> str | None:
    if not isinstance(vector, dict):
        return "vector must be a JSON object"
    kind = vector.get("kind")
    if kind not in PAYLOAD_FIELD:
        return f"kind must be one of {sorted(PAYLOAD_FIELD)}"
    missing = [k for k in vector_fields(kind) if k not in vector]
    if missing:
        return f"vector missing fields: {missing}"
    if vector["protocol"] not in PROTOCOLS:
        return f"protocol must be one of {PROTOCOLS}"
    if vector["expected_verdict"] not in VERDICTS:
        return f"expected_verdict must be one of {VERDICTS}"
    if vector["strictness"] not in ("strict", "permissive"):
        return "strictness must be 'strict' or 'permissive'"
    if not isinstance(vector["expected_reason_codes"], list):
        return "expected_reason_codes must be a list"
    return None


def run_vector(vector: dict[str, Any], fixtures: Fixtures) -> tuple[str, list[Finding], dict[str, Any]]:
    """Run one validated vector; return (verdict, findings, normalized verdict JSON)."""
    kind, protocol = vector["kind"], vector["protocol"]
    strictness, now = vector["strictness"], vector["now"]
    if kind == "constraint_check":
        verdict, findings = run_constraint_check(vector["constraint_check"], strictness, now)
        return verdict, findings, {
            "protocol": protocol, "kind": kind, "verdict": verdict, "strictness": strictness,
            "reason_codes": list(dict.fromkeys(str(f.code) for f in findings if f.effect != "warn")),
            "reasons": [f.to_json() for f in findings if f.effect != "warn"],
            "warnings": [f.to_json() for f in findings if f.effect == "warn"],
        }
    if kind == "composition":
        from .xproto.composition import verify_composition

        v = verify_composition(vector["presentation"], fixtures=fixtures, now=now)
    elif kind == "translation":
        from .xproto.translate import check_translation

        v = check_translation(vector["translation"], now=now)
    elif protocol == "tap":
        from .tap.verifier import verify_tap

        v = verify_tap(vector["bundle"], fixtures=fixtures, now=now)
    elif protocol == "ap2":
        from .ap2.verifier import verify_ap2

        v = verify_ap2(vector["bundle"], fixtures=fixtures, now=now)
    else:
        v = verify(vector["bundle"], strictness=strictness, resolver=fixtures.jwks, now=now)
    return v.verdict, v.findings, v.to_json()


def evaluate_payload(vector: dict[str, Any], fixtures: Fixtures) -> tuple[str, list[Finding]]:
    """Run one validated vector and return (verdict, findings)."""
    verdict, findings, _ = run_vector(vector, fixtures)
    return verdict, findings


def evaluate_vector(vector: Any, fixtures: Fixtures | KeyResolver, *, strict_codes: bool = False) -> VectorResult:
    err = validate_vector(vector)
    if err:
        vid = vector.get("id", "?") if isinstance(vector, dict) else "?"
        return VectorResult(str(vid), "invalid", "?", None, [], error=err)
    res = VectorResult(
        vector["id"], vector["category"], vector["expected_verdict"], None, list(vector["expected_reason_codes"]),
        protocol=vector["protocol"], strict_codes=strict_codes,
    )
    verdict, findings = evaluate_payload(vector, Fixtures.coerce(fixtures))
    res.verdict = verdict
    res.codes = list(dict.fromkeys(str(f.code) for f in findings))
    res.gap_ids = sorted({f.gap_id for f in findings if f.gap_id})
    res.undecided_codes = sorted({str(f.code) for f in findings if f.effect == "indeterminate" and not f.gap_id})
    return res


def load_vectors(directory: str | Path) -> list[tuple[Path, Any]]:
    out = []
    for path in sorted(Path(directory).glob("*.json")):
        if path.name == MANIFEST:
            continue
        try:
            out.append((path, json.loads(path.read_text(encoding="utf-8"))))
        except (OSError, ValueError) as exc:
            out.append((path, {"id": path.stem, "__load_error__": str(exc)}))
    return out


@dataclass
class SuiteReport:
    results: list[VectorResult]

    @property
    def mismatches(self) -> list[VectorResult]:
        return [r for r in self.results if not r.match]

    @property
    def ok(self) -> bool:
        return bool(self.results) and not self.mismatches

    def to_json(self) -> dict[str, Any]:
        return {
            "total": len(self.results),
            "matched": len(self.results) - len(self.mismatches),
            "mismatched": len(self.mismatches),
            "by_category": self._by_category(),
            "indeterminate_by_gap": dict(sorted(self._gaps().items())),
            "by_protocol": dict(sorted(Counter(r.protocol for r in self.results).items())),
            "results": [r.to_json() for r in self.results],
        }

    def _by_category(self) -> dict[str, dict[str, int]]:
        cats: dict[str, dict[str, int]] = {}
        for r in self.results:
            row = cats.setdefault(f"{r.protocol}/{r.category}", {"total": 0, "match": 0, "mismatch": 0,
                                               "accept": 0, "reject": 0, "indeterminate": 0})
            row["total"] += 1
            row["match" if r.match else "mismatch"] += 1
            if r.verdict in VERDICTS:
                row[r.verdict] += 1
        return dict(sorted(cats.items()))

    def _gaps(self) -> Counter[str]:
        return Counter(g for r in self.results if r.verdict == "indeterminate"
                       for g in (r.gap_ids + r.undecided_codes) or ["(none)"])

    def format_table(self) -> str:
        cols = ("total", "match", "mismatch", "accept", "reject", "indeterminate")
        cats = self._by_category()
        width = max([len("category"), len("TOTAL")] + [len(c) for c in cats])
        lines = [f"{'category':<{width}}  " + "  ".join(f"{c:>13}" if c == "indeterminate" else f"{c:>8}"
                                                         for c in cols)]
        lines.append("-" * len(lines[0]))
        totals = Counter()
        for cat, row in cats.items():
            totals.update(row)
            lines.append(f"{cat:<{width}}  " + "  ".join(
                f"{row[c]:>13}" if c == "indeterminate" else f"{row[c]:>8}" for c in cols))
        lines.append("-" * len(lines[0]))
        lines.append(f"{'TOTAL':<{width}}  " + "  ".join(
            f"{totals[c]:>13}" if c == "indeterminate" else f"{totals[c]:>8}" for c in cols))
        gaps = self._gaps()
        lines.append("")
        lines.append("indeterminate by spec gap / code: " + (", ".join(f"{g}={n}" for g, n in sorted(gaps.items())) or "none"))
        if self.mismatches:
            lines.append("")
            lines.append("MISMATCHES:")
            for r in self.mismatches:
                if r.error:
                    why = r.error
                elif r.verdict != r.expected_verdict:
                    why = f"expected {r.expected_verdict}, got {r.verdict}"
                elif r.missing_codes:
                    why = f"missing codes {r.missing_codes}"
                else:
                    why = f"unexpected codes {r.unexpected_codes}"
                lines.append(f"  {r.id} [{r.protocol}/{r.category}]: {why}")
        lines.append("")
        lines.append(f"{len(self.results) - len(self.mismatches)}/{len(self.results)} vectors match")
        return "\n".join(lines)


def run_suite(directory: str | Path, fixtures: Fixtures | KeyResolver, *, strict_codes: bool = False) -> SuiteReport:
    results = []
    for path, vector in load_vectors(directory):
        if isinstance(vector, dict) and "__load_error__" in vector:
            results.append(VectorResult(path.stem, "invalid", "?", None, [], error=vector["__load_error__"]))
        else:
            results.append(evaluate_vector(vector, fixtures, strict_codes=strict_codes))
    return SuiteReport(results)
