#!/bin/bash
# SPDX-License-Identifier: Apache-2.0
# Integration: replies to the host's own flows (Seawall proposal 0015),
# with sw_flowd recording them at egress, its table bound when
# voidgate starts. A download from the peer arms the gate and survives
# it, a manual block of its server too; a flood from the same address is
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
    "$CTL" -r status >&2 || true
    "$CTL" -r stats >&2 || true
    "$CTL" blocks >&2 || true
    exit 1
}

# The download arms the gate (wake_mbps) and is over threshold_mbps on
# its own, as the incident in 0015 had it; nothing else wakes it.
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

# icmp_err <type> <code> <proto> <sport> <dport> <count>: ICMP errors
# from the peer about a packet this host sent it, of protocol proto from
# sport to dport; the 8 bytes of L4 an error carries
icmp_err() {
    ip netns exec "$NS" python3 - "$@" <<'PY'
import socket, struct, sys
t, c, proto, sport, dport, n = map(int, sys.argv[1:])
inner = struct.pack("!BBHHHBBH4s4s", 0x45, 0, 28, 0, 0, 64, proto, 0,
                    socket.inet_aton("198.51.100.10"),
                    socket.inet_aton("198.51.100.1"))
inner += struct.pack("!HHHH", sport, dport, 8, 0)
msg = struct.pack("!BBHI", t, c, 0, 0) + inner
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
for _ in range(n):
    s.sendto(msg, ("198.51.100.10", 0))
PY
}

# icmp6_err <type> <code> <proto> <sport> <dport> <count>: ICMPv6 errors
# from the peer about a packet this host sent it; the kernel sums them
icmp6_err() {
    ip netns exec "$NS" python3 - "$@" <<'PY'
import socket, struct, sys
t, c, proto, sport, dport, n = map(int, sys.argv[1:])
inner = struct.pack("!IHBB16s16s", 0x60000000, 8, proto, 64,
                    socket.inet_pton(socket.AF_INET6, "2001:db8::10"),
                    socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
inner += struct.pack("!HHHH", sport, dport, 8, 0)
msg = struct.pack("!BBHI", t, c, 0, 1280 if t == 2 else 0) + inner
s = socket.socket(socket.AF_INET6, socket.SOCK_RAW, socket.IPPROTO_ICMPV6)
for _ in range(n):
    s.sendto(msg, ("2001:db8::10", 0))
PY
}

# rst_to <lport> <count>: RSTs without ACK from the peer's 8080 to this
# host's lport, out of window: what a peer's RST to an old segment is
rst_to() {
    ip netns exec "$NS" python3 - "$@" <<'PY'
import socket, struct, sys
lport, n = map(int, sys.argv[1:])
tcp = struct.pack("!HHIIBBHHH", 8080, lport, 12345, 0, 5 << 4, 0x04,
                  0, 0, 0)
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_TCP)
for _ in range(n):
    s.sendto(tcp, ("198.51.100.10", 0))
PY
}

# udp_from <sport> <dport> <count>: UDP from the peer's sport to this host
udp_from() {
    ip netns exec "$NS" python3 - "$@" <<'PY'
import socket, sys
sport, dport, n = map(int, sys.argv[1:])
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("198.51.100.1", sport))
for _ in range(n):
    s.sendto(b"q", ("198.51.100.10", dport))
PY
}

stat() {
    { "$CTL" -r status; "$CTL" -r stats; } | tr ' ' '\n' \
        | sed -n "s/^$1=//p"
}

blocked() {
    "$CTL" -r blocks | grep -q " cidr=$1 "
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
grep -q '\[CRIT\] no sw_flowd flow table' "$LOG" \
    || fail "expected the no-table line, at crit"
# a broken install: status says so first, and voidgatectl stats with it
# (Seawall proposal 0015 §6); the counters alone don't
"$CTL" status | head -1 | grep -q '^CRITICAL: no sw_flowd flow table' \
    || fail "expected status to start with CRITICAL"
"$CTL" stats | head -1 | grep -q '^CRITICAL: ' \
    || fail "expected voidgatectl stats to start with CRITICAL"
"$CTL" -r stats | grep -q 'CRITICAL' \
    && fail "the counters should not carry the CRITICAL line"
start_flowd
[[ $(stat flows) == none ]] || fail "a running voidgate picked up a new table"
echo "ok - voidgate started before sw_flowd runs without its table"

stop_vg
start_vg
grep -q "reading sw_flowd's flow table" "$LOG" \
    || fail "voidgate did not bind sw_flowd's table at start"
[[ $(stat flows) == sw_flowd ]] || fail "expected flows=sw_flowd"
"$CTL" status | grep -q '^CRITICAL' && fail "status CRITICAL with the table"
"$CTL" -r status | grep -q 'flows=sw_flowd' || fail "expected status flows=sw_flowd"
echo "ok - voidgate started after sw_flowd reads its table"

got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download got $got of $SIZE bytes"
[[ $(stat state) == active ]] || fail "the download should have armed the gate"
blocked 198.51.100.1/32 && fail "the download got its server blocked"
(( $(stat reply_passed) > 0 )) || fail "expected reply_passed > 0"
echo "ok - a download that arms the gate completes, its server not dropped"

flood
sleep 0.5
blocked 198.51.100.1/32 || fail "the flood from the same address was not blocked"
"$CTL" -r blocks | grep -q ' cidr=198.51.100.1/32 reason=policy ' \
    || fail "expected a policy block of the flooding address"
echo "ok - a flood from the same address is still dropped"

got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download after the policy block got $got"
echo "ok - a flow the host opens survives a policy block of its server"

got=$(download 2001:db8::1)
[[ $got == "$SIZE" ]] || fail "IPv6 download got $got of $SIZE bytes"
blocked 2001:db8::1/128 && fail "the IPv6 download got its server blocked"
echo "ok - and over IPv6"

# sw_flowd restarted: the pinned maps stay, and voidgate keeps them
stop_flowd
start_flowd
[[ $(stat flows) == sw_flowd ]] || fail "expected flows=sw_flowd"
# the server's policy block is still there: only the table lets this in
got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download after sw_flowd's restart got $got"
echo "ok - a restart of sw_flowd needs no restart of voidgate"

# a /30 holds the peer, not this host, and the policy /32 is inside it
"$CTL" block 198.51.100.0/30 > /dev/null
got=$(download 198.51.100.1)
[[ $got == "$SIZE" ]] || fail "download under a manual block got $got"
echo "ok - a flow the host opens survives a manual block of its server"

# the download armed the gate; the server is still dropped: its echo
# replies are the host's own (Seawall proposal 0015 §2)
[[ $(stat state) == active ]] || fail "the download should have armed the gate"
ping -c 1 -W 2 198.51.100.1 > /dev/null \
    || fail "ping to a dropped server got no reply"
echo "ok - so do the echo replies of the host's ping"

# ICMP errors about the host's own UDP flow pass, uncounted; path MTU
# errors about no flow of the host's don't, from the dropped server
python3 -c 'import socket
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(("0.0.0.0", 50500)); s.sendto(b"q", ("198.51.100.1", 9999))'
sleep 0.5
passed=$(stat reply_passed)
drops=$(stat dropped)
icmp_err 3 3 17 50500 9999 50
sleep 0.2
(( $(stat reply_passed) - passed >= 50 )) \
    || fail "errors about the host's flow were not passed as replies"
(( $(stat dropped) - drops < 5 )) \
    || fail "errors about the host's flow were dropped"
echo "ok - ICMP errors about the host's flow pass its server's block"

passed=$(stat reply_passed)
drops=$(stat dropped)
icmp_err 3 4 6 50600 443 50
sleep 0.2
(( $(stat dropped) - drops >= 50 )) \
    || fail "path MTU errors about no flow passed a dropped source"
(( $(stat reply_passed) - passed < 5 )) \
    || fail "path MTU errors about no flow were passed as replies"
echo "ok - path MTU errors about no flow of the host's are still dropped"

# a RST without ACK on a connection the host opened passes too: one
# answering a segment with ACK carries no ACK of its own
python3 -c 'import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
s.bind(("0.0.0.0", 50700)); s.settimeout(2)
s.connect(("198.51.100.1", 8080)); time.sleep(3)' &
held=$!
sleep 0.5
drops=$(stat dropped)
rst_to 50700 50
sleep 0.2
(( $(stat dropped) - drops < 5 )) \
    || fail "RSTs without ACK on the host's connection were dropped"
kill "$held" 2> /dev/null; wait "$held" 2> /dev/null || true
echo "ok - a RST without ACK on the host's connection passes its block"

# classic ntpd listens on 123 and queries from it: sw_flowd's
# record_udp_ports records it, and its server's answers pass the block;
# to 124, not listed, they are dropped (Seawall proposal 0015 §7)
for port in 123 124; do
    python3 -c "import socket, time
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.bind(('0.0.0.0', $port)); time.sleep(0.6)
s.sendto(b'q', ('198.51.100.1', 123))"
done
sleep 0.3
passed=$(stat reply_passed)
drops=$(stat dropped)
udp_from 123 123 50
sleep 0.2
(( $(stat reply_passed) - passed >= 50 )) \
    || fail "answers to ntpd's queries from 123 were not passed as replies"
(( $(stat dropped) - drops < 5 )) || fail "answers to ntpd were dropped"
drops=$(stat dropped)
udp_from 123 124 50
sleep 0.2
(( $(stat dropped) - drops >= 50 )) \
    || fail "answers to a port not in record_udp_ports passed the block"
echo "ok - ntpd's queries from 123 get their answers through a block; 124's don't"

# DHCP is as before 0015: voidgate passes a server's answers, 67 to 68,
# before its drop lists, a dropped source's too, counted against the
# source but no reply (0015 §7)
drops=$(stat dropped)
passed=$(stat reply_passed)
udp_from 67 68 50
sleep 0.2
(( $(stat dropped) - drops < 5 )) || fail "DHCP's answers were dropped"
(( $(stat reply_passed) - passed < 5 )) \
    || fail "DHCP's answers were passed as replies"
echo "ok - DHCP's answers pass a block of their source, as before, not as replies"
"$CTL" unblock 198.51.100.0/30 > /dev/null

# IPv6: the server dropped too, its echo replies and ICMPv6 errors about
# the host's flow pass; packet too big about no flow doesn't
"$CTL" block 2001:db8::1/128 > /dev/null
ping -6 -c 1 -W 2 2001:db8::1 > /dev/null \
    || fail "ping over IPv6 to a dropped server got no reply"
python3 -c 'import socket
s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)
s.bind(("::", 50510)); s.sendto(b"q", ("2001:db8::1", 9999))'
sleep 0.5
passed=$(stat reply_passed)
drops=$(stat dropped)
icmp6_err 1 4 17 50510 9999 50
sleep 0.2
(( $(stat reply_passed) - passed >= 50 )) \
    || fail "ICMPv6 errors about the host's flow were not passed as replies"
(( $(stat dropped) - drops < 5 )) \
    || fail "ICMPv6 errors about the host's flow were dropped"
drops=$(stat dropped)
icmp6_err 2 0 6 50600 443 50
sleep 0.2
(( $(stat dropped) - drops >= 50 )) \
    || fail "packet too big about no flow passed a dropped source"
"$CTL" unblock 2001:db8::1/128 > /dev/null
echo "ok - and over IPv6: echo replies, errors about a flow, not without one"

# sw_flowd purged: a voidgate started after that runs without a table,
# and the download gets its server banned, as without the table
stop_flowd
"$FLOWD" -P >> "$work/sw_flowd.log" 2>&1
stop_vg
: > "$LOG"
start_vg
[[ $(stat flows) == none ]] || fail "expected flows=none after sw_flowd -P"
"$CTL" unblock 198.51.100.1/32 > /dev/null 2>&1 || true
download 198.51.100.1 > /dev/null
sleep 0.5
blocked 198.51.100.1/32 || fail "without the table the server should be blocked"
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
grep -q "\[CRIT\] .*is not the layout this voidgate reads" "$LOG" \
    || fail "voidgate did not refuse a table of another layout, at crit"
[[ $(stat flows) == none ]] || fail "expected flows=none for that table"
"$CTL" status | head -1 \
    | grep -q "^CRITICAL: sw_flowd's flow table under .* is not the layout" \
    || fail "expected status to say the table is of another layout"
"$CTL" status | head -1 | grep -q "sw_flowd -P" \
    || fail "expected status to say what to do about another layout"
rm -f "$PINS/outbound" "$PINS/config"
echo "ok - a table of another layout is refused"

echo "reply test passed"
