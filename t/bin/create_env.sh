# SPDX-License-Identifier: Apache-2.0
# Source from a test script. Re-execs the caller in private namespaces.

if [[ ${1:-} != --isolated ]]; then
    # sudo resets the environment: keep what picks the hook
    exec sudo env ${VG_HOOK:+VG_HOOK=$VG_HOOK} ${VG_NO_TCX:+VG_NO_TCX=1} \
        ${SW_FLOWD:+SW_FLOWD=$SW_FLOWD} \
        unshare --mount-proc --net --pid --fork --kill-child \
        --propagation private bash "$0" --isolated \
        "$(readlink /proc/self/ns/mnt)" "$@"
fi
if [[ -z ${2:-} || $(readlink /proc/self/ns/mnt) == "$2" ]]; then
    echo "refusing to run without mount isolation" >&2
    exit 1
fi
shift 2

# Callers live in t/bin or t/integration: the repo root is two levels up.
root=$(cd "$(dirname "$0")/../.." && pwd)
work=/tmp/voidgate

mount -t tmpfs -o mode=755 tmpfs /run
mount -t tmpfs -o mode=755 tmpfs /tmp
# libxdp keeps its dispatchers' state here: the host's is not ours
mount -t bpf bpf /sys/fs/bpf
mkdir "$work"

ip link add test0 type veth peer name peer0

for interface in lo test0 peer0; do
    ip link set "$interface" up
done
