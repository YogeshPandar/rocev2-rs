#!/usr/bin/env bash
set -euo pipefail

if [[ $# -lt 1 || $# -gt 2 ]]; then
    echo "usage: $0 INTERFACE [RDMA_DEVICE]" >&2
    exit 2
fi

interface=$1
rdma_device=${2:-}

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
fi
if command -v rdma >/dev/null; then
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
