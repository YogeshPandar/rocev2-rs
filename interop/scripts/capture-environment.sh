#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 INTERFACE [RDMA_DEVICE]" >&2
    exit 2
fi

interface=$1
rdma_device=${2:-}

echo '### git'
git rev-parse HEAD 2>/dev/null || true
git status --short 2>/dev/null || true
echo '### rust'
rustc --version --verbose 2>/dev/null || true
cargo --version 2>/dev/null || true
echo '### uname'
uname -a
echo '### interface'
ip -details link show dev "$interface"
echo '### addresses'
ip -details address show dev "$interface"
if command -v ethtool >/dev/null; then
    echo '### driver'
    ethtool -i "$interface" || true
    echo '### channels'
    ethtool -l "$interface" || true
    echo '### rings'
    ethtool -g "$interface" || true
    echo '### coalescing'
    ethtool -c "$interface" || true
    echo '### offloads'
    ethtool -k "$interface" || true
fi
if command -v rdma >/dev/null; then
    echo '### rdma system'
    rdma system show || true
    echo '### rdma links'
    rdma -d link show || true
fi
if command -v ibv_devinfo >/dev/null; then
    echo '### verbs'
    if [[ -n $rdma_device ]]; then
        ibv_devinfo -d "$rdma_device" || true
    else
        ibv_devinfo || true
    fi
fi
echo '### cpu topology'
lscpu || true
echo '### numa'
command -v numactl >/dev/null && numactl --hardware || true

echo '### interface numa node'
cat "/sys/class/net/$interface/device/numa_node" 2>/dev/null || true
echo '### interrupt affinity'
grep -E "^[[:space:]]*[0-9]+:.*$interface" /proc/interrupts 2>/dev/null || true
echo '### process affinity'
taskset -pc $$ 2>/dev/null || true
echo '### cpu governors'
for governor in /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor; do
    [[ -r "$governor" ]] || continue
    printf '%s=' "$governor"
    cat "$governor"
done
