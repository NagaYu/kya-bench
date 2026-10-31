#!/usr/bin/env bash
# The CI checks, runnable locally from the repo root: bash tools/ci.sh
# Needs cryptography and pytest (pip install -e '.[test]'). No step uses the network.
set -euo pipefail
cd "$(dirname "$0")/.."
export PYTHONPATH="src${PYTHONPATH:+:$PYTHONPATH}"  # works installed or straight from a checkout

echo "== pytest"
python -m pytest -q

echo "== vector regeneration is deterministic"
python tools/generate_fixtures.py
git diff --exit-code -- fixtures/
untracked=$(git ls-files --others --exclude-standard -- fixtures/)
if [ -n "$untracked" ]; then
  echo "untracked fixture files after regeneration:"; echo "$untracked"; exit 1
fi

if [ -n "$(git ls-files -- hf/)" ]; then  # hf/ lives in the dev tree only
  echo "== hf/ materials are in sync"
  python tools/build_hf.py
  git diff --exit-code -- hf/
  untracked=$(git ls-files --others --exclude-standard -- hf/)
  if [ -n "$untracked" ]; then
    echo "untracked hf/ files after rebuild:"; echo "$untracked"; exit 1
  fi
fi

echo "== run-suite"
python -m kya_bench run-suite fixtures/vectors --jwks fixtures/jwks.json
