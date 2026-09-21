#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)

cargo +1.85.0 build --release --manifest-path "$ROOT/interop/rust-peer/Cargo.toml"
make -C "$ROOT/interop/rxe-peer" clean all
