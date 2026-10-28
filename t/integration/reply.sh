#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Integration: replies to the host's own flows (Seawall proposal 0007),
# with sw_flowd (0009) recording them at egress, its table bound when
# voidgate starts. A download from the peer arms the gate and survives
# it, a manual drop of its server too; a flood from the same address is
# still dropped; without sw_flowd's table the download gets its server
# banned, as before. VG_HOOK=tc judges at TC ingress. Needs
# sw_flowd built (SW_FLOWD, or ../sw_flowd/sw_flowd); skips without it.
# Runs in private namespaces (t/bin/create_env.sh).
set -euo pipefail
. "$(dirname "$0")/../bin/create_env.sh"
BIN="$root/voidgate"
CTL="$root/voidgatectl"
FLOWD=${SW_FLOWD:-$root/../sw_flowd/sw_flowd}
CONF=$work/reply.conf
FCONF=$work/sw_flowd.conf
LOG=$work/voidgate.log
NS=peer
SIZE=$((24 * 1024 * 1024))
DAEMON_PID=
FLOWD_PID=

if [[ ! -x $FLOWD ]]; then
    echo "skip: no sw_flowd at $FLOWD (set SW_FLOWD)" >&2
    exit 0
fi

cleanup() {
    local result=$?
    trap - EXIT
    if [[ $result != 0 && -e $LOG ]]; then
        echo "--- voidgate log" >&2
        cat "$LOG" >&2
    fi
    [[ -n $DAEMON_PID ]] && kill "$DAEMON_PID" 2>/dev/null || true
    [[ -n $FLOWD_PID ]] && kill "$FLOWD_PID" 2>/dev/null || true
    jobs -p | xargs -r kill 2>/dev/null || true
    ip netns del "$NS" 2>/dev/null || true
    exit "$result"
}
trap cleanup EXIT

fail() {
    echo "reply.sh: $*" >&2
    "$CTL" stats >&2 || true
    "$CTL" drops >&2 || true
    exit 1
}

# The download arms the gate (wake_mbps) and is over threshold_mbps on
# its own, as the incident in 0007 had it; nothing else wakes it.
write_conf() {
    cat > "$CONF" <<EOF
interface = test0
xdp_mode = skb
wake_pps = 1000000000
wake_mbps = 20
idle_poll_ms = 200
clear_seconds = 600
threshold_pps = 1000000000
threshold_mbps = 5
ban_time = 600
local_networks = 198.51.100.10/32, 2001:db8::10/128
allow_ports = 22
metrics_port = 0
hook = ${VG_HOOK:-auto}
EOF
}

write_conf
printf 'interfaces = test0\ntick_ms = 200\n' > "$FCONF"

ip netns add "$NS"
ip link set peer0 netns "$NS"
ip addr add 198.51.100.10/24 dev test0
ip addr add 2001:db8::10/64 dev test0 nodad
ip netns exec "$NS" ip addr add 198.51.100.1/24 dev peer0
ip netns exec "$NS" ip addr add 2001:db8::1/64 dev peer0 nodad
ip netns exec "$NS" ip link set peer0 up
ip netns exec "$NS" ip link set lo up

# The peer serves $SIZE bytes on 8080, paced to about 12 MB/s: two
# seconds, long enough for the gate to arm and judge it.
ip netns exec "$NS" python3 - "$SIZE" <<'PY' &
import socket, sys, threading, time

size = int(sys.argv[1])

def serve(c):
    chunk = b"x" * 65536
    sent, start = 0, time.time()
    try:
        while sent < size:
            c.sendall(chunk[:min(len(chunk), size - sent)])
            sent += min(len(chunk), size - sent)
            ahead = sent / 12e6 - (time.time() - start)
            if ahead > 0:
                time.sleep(ahead)
    except OSError:
        pass
    c.close()

s = socket.socket(socket.AF_INET6, socket.SOCK_STREAM)
s.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 0)
s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
s.bind(("::", 8080))
s.listen(16)
while True:
    threading.Thread(target=serve, args=(s.accept()[0],), daemon=True).start()
PY

# download <address>: the bytes received, within 8 s
download() {
    python3 - "$1" <<'PY' || true
import socket, sys
n = 0
try:
    c = socket.create_connection((sys.argv[1], 8080), timeout=8)
    while True:
        b = c.recv(1 << 20)
        if not b:
            break
        n += len(b)
except OSError:
    pass
print(n)
PY
}

# flood: two seconds of UDP from the peer to a port no flow uses
flood() {
    ip netns exec "$NS" python3 - <<'PY'
import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
end = time.time() + 2
while time.time() < end:
    s.sendto(b"x" * 512, ("198.51.100.10", 9))
PY
}

stat() {
    "$CTL" stats | tr ' ' '\n' | sed -n "s/^$1=//p"
}

dropped() {
    "$CTL" drops | grep -q "^$1 "
}

wait_log() {
    local i
    for i in $(seq 50); do
        grep -q -- "$1" "$LOG" && return 0
        sleep 0.1
    done
    return 1
}

start_vg() {
    # in the foreground the log is stderr
    "$BIN" -c "$CONF" 2>> "$LOG" &
    DAEMON_PID=$!
    for _ in $(seq 50); do
        "$CTL" status >/dev/null 2>&1 && return 0
        sleep 0.1
    done
    fail "voidgate did not start"
}

stop_vg() {
    kill "$DAEMON_PID"
    wait "$DAEMON_PID" 2>/dev/null || true
    DAEMON_PID=
}

start_flowd() {
    "$FLOWD" -c "$FCONF" >> "$work/sw_flowd.log" 2>&1 &
    FLOWD_PID=$!
    sleep 0.5   # its pins, and its first sync: the ephemeral port range
}

stop_flowd() {
    kill "$FLOWD_PID"
    wait "$FLOWD_PID" 2>/dev/null || true
    FLOWD_PID=
}

# voidgate binds sw_flowd's table when it starts: started first, it runs
# without, and a table that comes later is not picked up
start_vg
[[ $(stat flows) == none ]] || fail "expected flows=none before sw_flowd"
grep -q 'no sw_flowd flow table' "$LOG" || fail "expected the no-table line"
start_flowd
[[ $(stat flows) == none ]] || fail "a running voidgate picked up a new table"
echo "ok - voidgate started before sw_flowd runs without its table"

stop_vg
start_vg
grep -q "reading sw_flowd's flow table" "$LOG" \
    || fail "voidgate did not bind sw_flowd's table at start"
[[ $(stat flows) == sw_flowd ]] || fail "expected flows=sw_flowd"
echo "ok - voidgate started after sw_flowd reads its table"

got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download got $got of $SIZE bytes"
[[ $(stat state) == active ]] || fail "the download should have armed the gate"
dropped 198.51.100.1/32 && fail "the download got its server dropped"
(( $(stat reply_passed) > 0 )) || fail "expected reply_passed > 0"
echo "ok - a download that arms the gate completes, its server not dropped"

flood
sleep 0.5
dropped 198.51.100.1/32 || fail "the flood from the same address was not dropped"
"$CTL" drops | grep -q '^198.51.100.1/32 reason=2 ' \
    || fail "expected a policy drop of the flooding address"
echo "ok - a flood from the same address is still dropped"

got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download after the policy drop got $got"
echo "ok - a flow the host opens survives a policy drop of its server"

got=$(download 2001:db8::1)
[[ $got == "$SIZE" ]] || fail "IPv6 download got $got of $SIZE bytes"
dropped 2001:db8::1/128 && fail "the IPv6 download got its server dropped"
echo "ok - and over IPv6"

# sw_flowd restarted: the pinned maps stay, and voidgate keeps them
stop_flowd
start_flowd
[[ $(stat flows) == sw_flowd ]] || fail "expected flows=sw_flowd"
# the server's policy drop is still there: only the table lets this in
got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download after sw_flowd's restart got $got"
echo "ok - a restart of sw_flowd needs no restart of voidgate"

# a /30 holds the peer, not this host, and the policy /32 is inside it
"$CTL" drop 198.51.100.0/30 > /dev/null
got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download under a manual drop got $got"
"$CTL" undrop 198.51.100.0/30 > /dev/null
echo "ok - a flow the host opens survives a manual drop of its server"

# sw_flowd purged: a voidgate started after that runs without a table,
# and the download gets its server banned, as before 0007
stop_flowd
"$FLOWD" -P >> "$work/sw_flowd.log" 2>&1
stop_vg
: > "$LOG"
start_vg
[[ $(stat flows) == none ]] || fail "expected flows=none after sw_flowd -P"
"$CTL" undrop 198.51.100.1/32 > /dev/null 2>&1 || true
download 198.51.100.1 > /dev/null
sleep 0.5
dropped 198.51.100.1/32 || fail "without the table the server should be dropped"
echo "ok - after sw_flowd -P, a restarted voidgate runs without the table"

# a table of another layout (the config of an older sw_flowd.h) is
# refused, not misread
PINS=/sys/fs/bpf/seawall/flows
mkdir -p "$PINS"
bpftool map create "$PINS/outbound" type lru_hash key 24 value 8 \
    entries 1024 name outbound
bpftool map create "$PINS/config" type array key 4 value 8 entries 1 \
    name config
stop_vg
start_vg
grep -q "is not the layout this voidgate reads" "$LOG" \
    || fail "voidgate did not refuse a table of another layout"
[[ $(stat flows) == none ]] || fail "expected flows=none for that table"
rm -f "$PINS/outbound" "$PINS/config"
echo "ok - a table of another layout is refused"

echo "reply test passed"
