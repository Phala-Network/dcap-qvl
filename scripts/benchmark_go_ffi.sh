#!/usr/bin/env bash
set -euo pipefail

# Benchmark Go SDK FFI memory/time behavior.
#
# Usage:
#   scripts/benchmark_go_ffi.sh <label> [parse_iterations] [verify_iterations]
#
# Example:
#   scripts/benchmark_go_ffi.sh before-callback 200000 5000

LABEL="${1:-}";
if [[ -z "$LABEL" ]]; then
  echo "usage: $0 <label> [parse_iterations] [verify_iterations]" >&2
  exit 2
fi

PARSE_ITERS="${2:-200000}"
VERIFY_ITERS="${3:-5000}"

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT_DIR="$ROOT_DIR/benchmarks/go-ffi"
mkdir -p "$OUT_DIR"

pushd "$ROOT_DIR" >/dev/null

echo "[1/3] Building Rust static library (features=go)..."
cargo build --release --features go >/dev/null

export CGO_ENABLED=1
export CGO_LDFLAGS="-L$ROOT_DIR/target/release"

pushd "$ROOT_DIR/golang-bindings" >/dev/null

echo "[2/3] Running parse benchmark..."
go run ./cmd/ffi-bench --mode parse --iterations "$PARSE_ITERS" > "$OUT_DIR/${LABEL}_parse.json"

echo "[3/3] Running verify benchmark..."
go run ./cmd/ffi-bench --mode verify --iterations "$VERIFY_ITERS" > "$OUT_DIR/${LABEL}_verify.json"

popd >/dev/null

cat > "$OUT_DIR/${LABEL}_meta.txt" <<EOF
label=$LABEL
parse_iterations=$PARSE_ITERS
verify_iterations=$VERIFY_ITERS
git_commit=$(git rev-parse --short HEAD)
date=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
EOF

echo "saved:"
echo "  $OUT_DIR/${LABEL}_parse.json"
echo "  $OUT_DIR/${LABEL}_verify.json"
echo "  $OUT_DIR/${LABEL}_meta.txt"

popd >/dev/null
