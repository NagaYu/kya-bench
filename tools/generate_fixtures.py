"""Regenerate fixtures/ (issuer JWKS + conformance vectors). Fully offline and deterministic.

    python tools/generate_fixtures.py [--out DIR]

Running it twice yields byte-identical files. See kya_bench/testing/vectors.py.
"""

from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "src"))

from kya_bench.testing.vectors import main  # noqa: E402

if __name__ == "__main__":
    main()
