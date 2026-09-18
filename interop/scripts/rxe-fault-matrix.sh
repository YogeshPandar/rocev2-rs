#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RESULTS=${1:-"$ROOT/interop/results/faults-$(date -u +%Y%m%dT%H%M%SZ)"}
MATRIX="$ROOT/interop/scripts/rxe-matrix.sh"
SIZES=${ROCEV2_SIZES:-"256 1024 4096 65536"}
MTUS=${ROCEV2_MTUS:-"1024 2048 4096"}
ITERATIONS=${ROCEV2_ITERATIONS:-10}
profiles=(
    "loss 0.1%"
    "duplicate 0.1%"
    "delay 2ms reorder 25% 50%"
)

mkdir -p "$RESULTS"
index=0
for profile in "${profiles[@]}"; do
    index=$((index + 1))
    ROCEV2_NETEM="$profile"     ROCEV2_SIZES="$SIZES"     ROCEV2_MTUS="$MTUS"     ROCEV2_ITERATIONS="$ITERATIONS"         "$MATRIX" "$RESULTS/profile-$index"
done

printf '{"profiles":%d,"status":"pass"}\n' "$index" >"$RESULTS/summary.json"
echo "RXE fault matrix passed: $index profiles"
echo "results: $RESULTS"
