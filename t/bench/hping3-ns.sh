#!/bin/bash
# Run hping3 from a throwaway netns so packets ingress a veth, not lo.
# Attach voidgate to the host veth this script prints (-i), not ens3.
#
#   sudo t/bench/hping3-ns.sh
#   sudo t/bench/hping3-ns.sh -- --udp -p 9 -c 1000
#   sudo t/bench/hping3-ns.sh 198.51.100.10 --flood --udp -p 53
set -euo pipefail

if [[ ${EUID} -ne 0 ]]; then
    echo "run as root" >&2
    exit 1
fi

if ! command -v hping3 >/dev/null; then
    echo "hping3 not found (apt install hping3)" >&2
    exit 1
fi

DEST=198.51.100.10
HPING_ARGS=()

if [[ $# -gt 0 ]]; then
    if [[ $1 == -- ]]; then
        shift
        HPING_ARGS=("$@")
    elif [[ $1 == *.* || $1 == *:* ]]; then
        DEST=$1
        shift
        if [[ ${1:-} == -- ]]; then
            shift
        fi
        HPING_ARGS=("$@")
    else
        HPING_ARGS=("$@")
    fi
fi

if [[ ${#HPING_ARGS[@]} -eq 0 ]]; then
    HPING_ARGS=(--udp --flood --rand-source -p 53)
fi

NS=vghp$$
HA=vha$$
HB=vhb$$

cleanup() {
    ip netns del "$NS" 2>/dev/null || true
    ip link del "$HA" 2>/dev/null || true
}
trap cleanup EXIT

ip netns add "$NS"
ip link add "$HA" type veth peer name "$HB"
ip link set "$HB" netns "$NS"
ip addr add 198.51.100.10/24 dev "$HA"
ip link set "$HA" up
ip netns exec "$NS" ip addr add 198.51.100.1/24 dev "$HB"
ip netns exec "$NS" ip link set "$HB" up
ip netns exec "$NS" ip link set lo up

echo "host veth $HA 198.51.100.10  (attach voidgate here)"
echo "  sudo ./voidgate -c configs/voidgate.conf -i $HA"
echo "flood ns  $NS 198.51.100.1 -> $DEST"
echo "hping3 ${HPING_ARGS[*]} $DEST"
echo

ip netns exec "$NS" hping3 "${HPING_ARGS[@]}" "$DEST"
