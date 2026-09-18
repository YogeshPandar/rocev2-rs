#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RESULTS=${1:-"$ROOT/interop/results/soak-$(date -u +%Y%m%dT%H%M%SZ)"}
DURATION_SECONDS=${ROCEV2_SOAK_SECONDS:-86400}
SIZES=${ROCEV2_SIZES:-"64 1024 4096 65536"}
MTUS=${ROCEV2_MTUS:-"1024 2048 4096"}
ITERATIONS=${ROCEV2_ITERATIONS:-100}

[[ "$DURATION_SECONDS" =~ ^[1-9][0-9]*$ ]] || { echo "ROCEV2_SOAK_SECONDS must be a positive integer" >&2; exit 2; }
mkdir -p "$RESULTS"
deadline=$((SECONDS + DURATION_SECONDS))
round=0
while (( SECONDS < deadline )); do
    round=$((round + 1))
    ROCEV2_SIZES="$SIZES"     ROCEV2_MTUS="$MTUS"     ROCEV2_ITERATIONS="$ITERATIONS"         "$ROOT/interop/scripts/rxe-matrix.sh" "$RESULTS/round-$round"
done

printf '{"rounds":%d,"duration_seconds":%d,"status":"pass"}\n' "$round" "$DURATION_SECONDS" >"$RESULTS/summary.json"
echo "RXE soak completed: $round rounds"
echo "results: $RESULTS"
