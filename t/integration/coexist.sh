#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Sharing the XDP hook: voidgate joins libxdp's dispatcher, or makes one;
# when another program holds the hook without one, it is left alone and
# voidgate judges at TC ingress (degraded). What a voidgate killed with
# SIGKILL leaves on the NIC goes on its next start. Needs root, clang and
# xdp-tools (xdp-loader, xdp-filter); skips without them.
set -euo pipefail
. "$(dirname "$0")/../bin/create_env.sh"

for tool in clang xdp-loader xdp-filter; do
    if ! command -v "$tool" > /dev/null; then
        echo "coexist.sh: skipped, no $tool"
        exit 0
    fi
done

directory=$(mktemp -d /tmp/voidgate-XXXXXX)
pid=

cleanup() {
    local result=$?
    trap - EXIT
    if [[ -n $pid ]]; then
        kill -TERM "$pid" 2>/dev/null || true
    fi
    if (( result != 0 )); then
        cat "$work"/log/*.log launch.err 2>/dev/null >&2 || true
    fi
    cd /
    rm -rf -- "$directory"
    exit "$result"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM

cd "$directory"
umask 022
cp "$root/t/conf/idle.conf" base.conf
mkdir "$work/log"
printf 'log_file = %s\n' "$work/log/voidgate.log" >> base.conf

# The customer's program: not libxdp's, attached with ip link. No headers:
# Debian's asm/ is under a multiarch directory clang -target bpf won't see.
cat > pass.bpf.c << 'EOF'
struct xdp_md;
__attribute__((section("xdp"), used)) int customer(struct xdp_md *ctx)
{
    return 2;  /* XDP_PASS */
}
char LICENSE[] __attribute__((section("license"), used)) = "GPL";
EOF
clang -O2 -target bpf -c pass.bpf.c -o pass.bpf.o

start_daemon() {
    timeout --kill-after=2 10 "$root/voidgate" -d "$@" \
        > launch.out 2> launch.err
    [[ $(< launch.err) =~ ^voidgate\ daemon\ started\ \(pid\ ([0-9]+)\)$ ]]
    pid=${BASH_REMATCH[1]}
}

stop_daemon() {
    "$root/voidgate" -s stop -c base.conf
    pid=
}

kill_daemon() {
    kill -KILL "$pid"
    while kill -0 "$pid" 2>/dev/null; do
        sleep 0.05
    done
    pid=
}

status() {
    timeout 2 "$root/voidgatectl" status
}

# voidgate's programs in test0's dispatcher
in_dispatcher() {
    xdp-loader status test0 | grep -c ' voidgate_xdp ' || true
}

xdp_id() {
    ip -details link show test0 | sed -n 's/.*prog\/xdp id \([0-9]*\).*/\1/p'
}

tc_filter() {
    tc filter show dev test0 ingress | grep -c voidgate_tc || true
}

# The hook is free: voidgate makes the dispatcher, and takes it off on exit.
start_daemon -c base.conf
[[ $(status) == *' hook=xdp-skb degraded=0' ]]
xdp-loader status test0 | grep -q 'xdp_dispatcher'
xdp-loader status test0 | grep -q ' 10 *voidgate_xdp '
stop_daemon
[[ -z $(xdp_id) ]]

# A jumbo MTU: native XDP takes a dispatcher with frags, which voidgate's
# program must ask libxdp for.
ip link set dev peer0 mtu 9000
ip link set dev test0 mtu 9000
cp base.conf native.conf
printf 'xdp_mode = native\n' >> native.conf
start_daemon -c native.conf
[[ $(status) == *' hook=xdp-native degraded=0' ]]
stop_daemon
ip link set dev test0 mtu 1500
ip link set dev peer0 mtu 1500

# xdp_mode auto on a driver without native XDP: skb.
cp base.conf auto.conf
printf 'xdp_mode = auto\n' >> auto.conf
ip link add dummy0 type dummy
ip link set dev dummy0 up
start_daemon -c auto.conf -i dummy0
[[ $(status) == *' hook=xdp-skb degraded=0' ]]
grep -q 'native XDP attach failed' "$work/log/voidgate.log"
stop_daemon
ip link del dummy0

# A dispatcher is there: voidgate joins it, in its mode (xdp_mode auto
# would take native on a veth), and leaves it to the other.
xdp-filter load -m skb test0
start_daemon -c auto.conf
[[ $(status) == *' hook=xdp-skb degraded=0' ]]
[[ $(in_dispatcher) == 1 ]]
xdp-loader status test0 | grep -q 'xdpfilt_'
stop_daemon
[[ $(in_dispatcher) == 0 ]]
xdp-loader status test0 | grep -q 'xdpfilt_'
xdp-filter unload test0 --all
[[ -z $(xdp_id) ]]

# Another program holds the hook: it stays, and voidgate goes to tcx.
ip link set dev test0 xdpgeneric obj pass.bpf.o sec xdp
customer=$(xdp_id)
start_daemon -c base.conf
[[ $(status) == *' hook=tcx degraded=1' ]]
[[ $(xdp_id) == "$customer" ]]
bpftool net show dev test0 | grep -q 'tcx/ingress voidgate_tc'
grep -q 'degraded: customer holds' "$work/log/voidgate.log"
stop_daemon
[[ $(xdp_id) == "$customer" ]]
[[ $(bpftool net show dev test0) != *voidgate_tc* ]]
# the hook it left, named as it was, not as the closed link reads
grep -q 'detached tcx from ifindex' "$work/log/voidgate.log"
[[ $(< "$work/log/voidgate.log") != *'detached tc from ifindex'* ]]

# Classic TC on a kernel without tcx.
SW_NO_TCX=1 start_daemon -c base.conf
[[ $(status) == *' hook=tc degraded=1' ]]
[[ $(tc_filter) == 1 ]]
stop_daemon
[[ $(tc_filter) == 0 ]]
grep -q 'detached tc from ifindex' "$work/log/voidgate.log"

# hook = xdp will not fall back.
cp base.conf xdp.conf
printf 'hook = xdp\n' >> xdp.conf
result=0
timeout --kill-after=2 10 "$root/voidgate" -d -c xdp.conf \
    > launch.out 2> launch.err || result=$?
[[ $result == 1 ]]
[[ $(xdp_id) == "$customer" ]]
ip link set dev test0 xdpgeneric off

# A voidgate killed in the dispatcher: the next takes its program out.
start_daemon -c base.conf
kill_daemon
[[ $(in_dispatcher) == 1 ]]
start_daemon -c base.conf
[[ $(in_dispatcher) == 1 ]]
grep -q "left in ifindex [0-9]*'s dispatcher" "$work/log/voidgate.log"
stop_daemon
[[ -z $(xdp_id) ]]

# A voidgate killed at classic TC: its filter, with its own drop list, goes
# whichever hook the next one takes.
cp base.conf tc.conf
printf 'hook = tc\n' >> tc.conf
SW_NO_TCX=1 start_daemon -c tc.conf
kill_daemon
[[ $(tc_filter) == 1 ]]
start_daemon -c base.conf
[[ $(status) == *' hook=xdp-skb degraded=0' ]]
[[ $(tc_filter) == 0 ]]
stop_daemon

echo "coexist.sh: ok"
