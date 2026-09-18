#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RESULTS=${1:-"$ROOT/interop/results/benchmark-$(date -u +%Y%m%dT%H%M%SZ)"}

export ROCEV2_SIZES=${ROCEV2_SIZES:-"64 128 256 512 1024 4096 16384 65536 262144 1048576"}
export ROCEV2_MTUS=${ROCEV2_MTUS:-"1024 2048 4096"}
export ROCEV2_ITERATIONS=${ROCEV2_ITERATIONS:-1000}
export ROCEV2_PSN=${ROCEV2_PSN:-16777200}

"$ROOT/interop/scripts/rxe-matrix.sh" "$RESULTS"
