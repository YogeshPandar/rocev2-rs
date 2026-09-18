#!/usr/bin/env bash
set -euo pipefail

ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)
RUST_PEER="$ROOT/interop/rust-peer/target/release/rocev2-rust-peer"
VERBS_PEER="$ROOT/interop/rxe-peer/rxe-peer"
RESULTS=${1:-"$ROOT/interop/results/rxe-$(date -u +%Y%m%dT%H%M%SZ)"}
RUST_IP=${ROCEV2_RUST_IP:-192.0.2.1}
VERBS_IP=${ROCEV2_VERBS_IP:-192.0.2.2}
PSN=${ROCEV2_PSN:-16777200}
ITERATIONS=${ROCEV2_ITERATIONS:-1}
SIZES=${ROCEV2_SIZES:-"0 1 255 256 257 511 512 513 1023 1024 1025 2047 2048 2049 4095 4096 4097 65536 1048576"}
MTUS=${ROCEV2_MTUS:-"256 512 1024 2048 4096"}
BASE_PORT=${ROCEV2_BASE_PORT:-18150}
NETEM=${ROCEV2_NETEM:-}

if [[ ${EUID} -ne 0 ]]; then
    echo "rxe-matrix requires root for network namespaces, RXE, and raw sockets" >&2
    exit 2
fi
for command in ip rdma modprobe ibv_devinfo ping grep; do
    command -v "$command" >/dev/null || { echo "missing command: $command" >&2; exit 2; }
done
if [[ -n "$NETEM" ]]; then
    command -v tc >/dev/null || { echo "missing command: tc" >&2; exit 2; }
fi
[[ -x "$RUST_PEER" ]] || { echo "build the Rust peer first: interop/scripts/build-peers.sh" >&2; exit 2; }
[[ -x "$VERBS_PEER" ]] || { echo "build the verbs peer first: interop/scripts/build-peers.sh" >&2; exit 2; }

mkdir -p "$RESULTS"
RUST_NS="rv2r$$"
VERBS_NS="rv2v$$"
RUST_IF="r2r$$"
VERBS_IF="r2v$$"
RXE_NAME="rxe$$"
peer_pid=

cleanup() {
    if [[ -n ${peer_pid:-} ]]; then
        kill "$peer_pid" 2>/dev/null || true
        wait "$peer_pid" 2>/dev/null || true
    fi
    ip netns exec "$VERBS_NS" rdma link delete "$RXE_NAME" 2>/dev/null || true
    ip netns del "$RUST_NS" 2>/dev/null || true
    ip netns del "$VERBS_NS" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

modprobe rdma_rxe
ip netns add "$RUST_NS"
ip netns add "$VERBS_NS"
ip link add "$RUST_IF" type veth peer name "$VERBS_IF"
ip link set "$RUST_IF" netns "$RUST_NS"
ip link set "$VERBS_IF" netns "$VERBS_NS"
ip -n "$RUST_NS" link set lo up
ip -n "$VERBS_NS" link set lo up
ip -n "$RUST_NS" link set "$RUST_IF" mtu 9000 up
ip -n "$VERBS_NS" link set "$VERBS_IF" mtu 9000 up
ip -n "$RUST_NS" address add "$RUST_IP/24" dev "$RUST_IF"
ip -n "$VERBS_NS" address add "$VERBS_IP/24" dev "$VERBS_IF"
if [[ -n "$NETEM" ]]; then
    read -r -a netem_args <<<"$NETEM"
    ip netns exec "$RUST_NS" tc qdisc replace dev "$RUST_IF" root netem "${netem_args[@]}"
    ip netns exec "$VERBS_NS" tc qdisc replace dev "$VERBS_IF" root netem "${netem_args[@]}"
    printf '%s\n' "$NETEM" >"$RESULTS/netem.txt"
fi
ip netns exec "$RUST_NS" ping -c 1 -W 1 "$VERBS_IP" >/dev/null
ip netns exec "$VERBS_NS" rdma link add "$RXE_NAME" type rxe netdev "$VERBS_IF"

for _ in $(seq 1 50); do
    if ip netns exec "$VERBS_NS" ibv_devinfo -d "$RXE_NAME" >/dev/null 2>&1; then
        break
    fi
    sleep 0.05
done
ip netns exec "$VERBS_NS" ibv_devinfo -d "$RXE_NAME" >"$RESULTS/ibv_devinfo.txt"
ip netns exec "$VERBS_NS" rdma -d link show >"$RESULTS/rdma-link.txt"
uname -a >"$RESULTS/uname.txt"

case_id=0
for mtu in $MTUS; do
    for size in $SIZES; do
        for operation in 1 2 3; do
            for verbs_requester in 0 1; do
                case_id=$((case_id + 1))
                port=$((BASE_PORT + case_id))
                rust_requester=$((1 - verbs_requester))
                prefix="$RESULTS/case-${case_id}-op${operation}-vr${verbs_requester}-s${size}-m${mtu}"

                ip netns exec "$VERBS_NS" "$VERBS_PEER" \
                    "$RXE_NAME" "$VERBS_IP" "$port" "$operation" "$verbs_requester" \
                    "$size" "$mtu" "$PSN" "$ITERATIONS" >"$prefix-verbs.log" 2>&1 &
                peer_pid=$!

                ready=0
                for _ in $(seq 1 400); do
                    if grep -q '^LISTENING$' "$prefix-verbs.log"; then
                        ready=1
                        break
                    fi
                    if ! kill -0 "$peer_pid" 2>/dev/null; then
                        break
                    fi
                    sleep 0.01
                done
                if [[ $ready -ne 1 ]]; then
                    cat "$prefix-verbs.log" >&2
                    echo "verbs peer did not become ready for case $case_id" >&2
                    exit 1
                fi

                if ! ip netns exec "$RUST_NS" "$RUST_PEER" \
                    "$RUST_IP" "$VERBS_IP" "$port" "$operation" "$rust_requester" \
                    "$size" "$mtu" "$PSN" "$ITERATIONS" >"$prefix-rust.log" 2>&1; then
                    cat "$prefix-rust.log" >&2
                    cat "$prefix-verbs.log" >&2
                    exit 1
                fi
                if ! wait "$peer_pid"; then
                    peer_pid=
                    cat "$prefix-rust.log" >&2
                    cat "$prefix-verbs.log" >&2
                    exit 1
                fi
                peer_pid=
                grep '"status":"pass"' "$prefix-rust.log" >>"$RESULTS/results.jsonl"
                grep '"status":"pass"' "$prefix-verbs.log" >>"$RESULTS/results.jsonl"
            done
        done
    done
done

printf '{"cases":%d,"status":"pass"}\n' "$case_id" >>"$RESULTS/results.jsonl"
echo "RXE interoperability matrix passed: $case_id cases"
echo "results: $RESULTS"
