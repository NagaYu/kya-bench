"""``kya-bench`` command line.

    kya-bench verify BUNDLE.json --jwks JWKS.json [--strictness strict|permissive] [--now UNIX]
    kya-bench run-suite VECTORS_DIR --jwks JWKS.json [--json]

verify prints the normalized verdict JSON. Exit status: 0 accept, 1 reject,
2 indeterminate, 3 usage / unreadable input.

run-suite verifies every vector in a directory against its expected verdict and
prints a per-category table. Exit status: 0 all match, 1 any mismatch, 3 usage.
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

from .context import Fixtures
from .suite import run_suite
from .verifier import Strictness, verdict_json, verify

EXIT = {"accept": 0, "reject": 1, "indeterminate": 2}
EXIT_USAGE = 3


def _policy(values: list[str]) -> dict[str, Strictness]:
    out: dict[str, Strictness] = {}
    for v in values:
        ctype, _, mode = v.rpartition("=")
        if not ctype:
            raise argparse.ArgumentTypeError(f"--policy expects TYPE=strict|permissive, got {v!r}")
        out[ctype] = Strictness(mode)
    return out


def build_parser() -> argparse.ArgumentParser:
    ap = argparse.ArgumentParser(prog="kya-bench", description="Neutral conformance verifier for agent payments")
    sub = ap.add_subparsers(dest="command", required=True)
    v = sub.add_parser("verify", help="verify a VI / TAP / AP2 / composition bundle or a vector file")
    v.add_argument("bundle", help="bundle or conformance-vector JSON file ('-' for stdin)")
    v.add_argument("--jwks", required=True,
                   help="local JWKS fixture {iss: {keys: [...]}}; a sibling tap_registry.json is loaded too")
    v.add_argument(
        "--strictness",
        choices=[s.value for s in Strictness],
        default=None,
        help="unknown-constraint handling for non-open mandates (default: strict, or the vector's own value)",
    )
    v.add_argument(
        "--protocol",
        choices=["vi", "tap", "ap2", "composition", "translation"],
        default=None,
        help="protocol of the input (default: the vector's protocol, else inferred from the bundle shape)",
    )
    v.add_argument("--now", type=int, help="verification time as a Unix timestamp (default: the vector's now, else current time)")
    v.add_argument("--clock-skew", type=int, default=300, help="clock skew tolerance in seconds (default: 300)")
    v.add_argument(
        "--policy",
        action="append",
        default=[],
        metavar="TYPE=MODE",
        help="per-constraint-type strictness override (constraints.md §5.4); repeatable",
    )
    v.add_argument(
        "--merchant-pointer",
        default="",
        help="JSON Pointer to the merchant object in the checkout_jwt payload (default: payload root; see G-02)",
    )
    r = sub.add_parser("run-suite", help="run a directory of conformance vectors and tally the results")
    r.add_argument("vectors_dir", help="directory of <id>.json vectors")
    r.add_argument("--jwks", required=True, help="local issuer JWKS fixture")
    r.add_argument("--json", action="store_true", help="print the report as JSON instead of a table")
    r.add_argument(
        "--strict-codes",
        action="store_true",
        help="also fail a vector when any finding code (warnings included) is not in expected_reason_codes",
    )
    return ap


def _run_suite(args: argparse.Namespace) -> int:
    vdir = Path(args.vectors_dir)
    try:
        fixtures = Fixtures.from_jwks_path(args.jwks)
        if not vdir.is_dir():
            raise OSError(f"not a directory: {vdir}")
    except (OSError, ValueError) as exc:
        print(f"kya-bench: {exc}", file=sys.stderr)
        return EXIT_USAGE
    report = run_suite(vdir, fixtures, strict_codes=args.strict_codes)
    print(json.dumps(report.to_json(), indent=2) if args.json else report.format_table())
    return 0 if report.ok else 1


def detect_protocol(doc: object) -> str:
    """Infer the protocol from a bundle's shape (README "Protocol selection")."""
    if isinstance(doc, dict):
        if "requests" in doc:
            return "tap"
        if "checkout_mandate" in doc or "payment_mandate" in doc:
            return "ap2"
        if "tap" in doc or "ap2" in doc:
            return "composition"
        if "intent" in doc and "probe" in doc:
            return "translation"
    return "vi"


def _verify_other(protocol: str, payload: object, fixtures: Fixtures, now: int | None):
    if protocol == "tap":
        from .tap.verifier import verify_tap

        return verify_tap(payload, fixtures=fixtures, now=now)
    if protocol == "ap2":
        from .ap2.verifier import verify_ap2

        return verify_ap2(payload, fixtures=fixtures, now=now)
    if protocol == "composition":
        from .xproto.composition import verify_composition

        return verify_composition(payload, fixtures=fixtures, now=now)
    from .xproto.translate import check_translation

    return check_translation(payload, now=now)


def main(argv: list[str] | None = None) -> int:
    args = build_parser().parse_args(argv)
    if args.command == "run-suite":
        return _run_suite(args)
    try:
        raw = sys.stdin.read() if args.bundle == "-" else Path(args.bundle).read_text(encoding="utf-8")
        fixtures = Fixtures.from_jwks_path(args.jwks)
        policy = _policy(args.policy)
    except (OSError, ValueError, json.JSONDecodeError, argparse.ArgumentTypeError) as exc:
        print(f"kya-bench: {exc}", file=sys.stderr)
        return EXIT_USAGE
    payload, strictness, now, protocol = raw, args.strictness, args.now, args.protocol
    try:
        doc = json.loads(raw)
    except ValueError:
        doc = None  # not JSON: the verifier reports a bundle error
    if isinstance(doc, dict) and "expected_verdict" in doc:
        # A conformance vector: verify its payload; flags override the vector's settings.
        kind = doc.get("kind", "bundle")
        field = {"bundle": "bundle", "composition": "presentation", "translation": "translation"}.get(kind)
        if field is None or field not in doc:
            print(f"kya-bench: '{kind}' vectors run via 'kya-bench run-suite'", file=sys.stderr)
            return EXIT_USAGE
        payload = doc[field]
        protocol = protocol or doc.get("protocol")
        strictness = strictness or doc.get("strictness")
        now = now if now is not None else doc.get("now")
    elif doc is not None:
        payload = doc
    protocol = protocol or detect_protocol(doc)
    if protocol == "vi":
        verdict = verify(
            payload,
            strictness=strictness or Strictness.STRICT.value,
            resolver=fixtures.jwks,
            now=now,
            clock_skew=args.clock_skew,
            constraint_policy=policy,
            merchant_pointer=args.merchant_pointer,
        )
    else:
        verdict = _verify_other(protocol, payload, fixtures, now)
    print(verdict_json(verdict))
    return EXIT[verdict.verdict]


if __name__ == "__main__":  # pragma: no cover
    sys.exit(main())
