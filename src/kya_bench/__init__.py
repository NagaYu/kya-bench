"""KYA Bench — neutral conformance verifier for agent payment protocols.

Phase 1 covers Mastercard Verifiable Intent (VI) v0.1-draft only.
"""

from .constraints import ConstraintResult, Fulfillment, NetworkState, check_constraints
from .keys import KeyResolver, LocalJwksResolver
from .parser import ParsedSdJwt, parse_sd_jwt
from .reasons import Code, Finding
from .verifier import Strictness, Verdict, verify

__version__ = "0.1.0"
PROTOCOL = "mastercard-verifiable-intent"  # Phase 1 name, kept for API compatibility
SPEC_VERSION = "0.1-draft"

# Pinned primary sources per protocol; emitted as "spec" in every verdict.
SPECS = {
    "vi": {"name": "Mastercard Verifiable Intent", "version": "0.1-draft",
           "source": "github.com/agent-intent/verifiable-intent@356c29635f1c44df7de02edb58699ca9f29bece6"},
    "tap": {"name": "Visa Trusted Agent Protocol", "version": "sample implementation (unversioned)",
            "source": "github.com/visa/trusted-agent-protocol@16d59bdf3f8a542bc538d0962edbb80ea30a02af",
            "secondary": "developer.visa.com/docs/trusted-agent-protocol/trusted-agent-protocol-specifications "
                         "(unversioned; retrieved 2026-10-31)"},
    "ap2": {"name": "Google Agent Payments Protocol", "version": "0.2",
            "source": "github.com/google-agentic-commerce/AP2@e1ea56db72a6385bce3e5c1112b3a56ce60acb43"},
    "composition": {"name": "KYA Bench TAP+AP2 composition", "version": "kya-bench/phase2"},
    "translation": {"name": "KYA Bench AP2->VI translation equivalence", "version": "kya-bench/phase2"},
}

__all__ = [
    "Code",
    "ConstraintResult",
    "Finding",
    "Fulfillment",
    "KeyResolver",
    "LocalJwksResolver",
    "NetworkState",
    "ParsedSdJwt",
    "Strictness",
    "Verdict",
    "check_constraints",
    "parse_sd_jwt",
    "verify",
]
