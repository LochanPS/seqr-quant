#!/usr/bin/env bash
# Smoke-test the seqrlabs/seqr-ci image: build it, then run the gate against a tiny repo
# with one known quantum-vulnerable pattern. Asserts (1) advisory mode reports the finding
# and exits 0, and (2) an armed --fail-on-drift exits non-zero.
#
# Requires Docker. Run from the repo root:  bash docker/seqr-ci/smoke-test.sh
set -euo pipefail

IMAGE="seqrlabs/seqr-ci:smoke"
ROOT="$(cd "$(dirname "$0")/../.." && pwd)"

echo "== build =="
docker build -f "$ROOT/docker/seqr-ci/Dockerfile" -t "$IMAGE" "$ROOT/cli"

sample="$(mktemp -d)"
trap 'rm -rf "$sample"' EXIT
cat > "$sample/vuln.py" <<'PY'
import jwt
token = jwt.encode(payload, key, algorithm="RS256")   # quantum-vulnerable RSA signature
PY

echo "== advisory (expect exit 0, RS256 reported) =="
out="$(docker run --rm -v "$sample:/src" "$IMAGE" ci . --all)"
echo "$out"
echo "$out" | grep -qi "RS256\|quantum-vulnerable" || { echo "FAIL: finding not reported"; exit 1; }

echo "== armed --fail-on-drift (expect non-zero) =="
if docker run --rm -v "$sample:/src" "$IMAGE" ci . --all --fail-on-drift; then
  echo "FAIL: armed gate should have exited non-zero"; exit 1
fi

echo "PASS: seqr-ci image smoke test green"
